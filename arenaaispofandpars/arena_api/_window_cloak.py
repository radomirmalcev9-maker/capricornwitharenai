"""Internal OS window cloaking, CDP overrides, and CDP UTF-8 recovery helpers.

Separates low-level Chromium / CDP / Win32 window-management primitives from
the high-level session discovery and Direct Chat orchestration in
:mod:`arena_api.auto`. Kept free of eager optional dependencies so importing
:mod:`arena_api` stays lightweight.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- #
# Chromium CDP text/plain UTF-8 recovery
# --------------------------------------------------------------------------- #


def _build_whatwg_win1252_inv() -> dict[int, int]:
    inv: dict[int, int] = {}
    for b in range(256):
        if 0x80 <= b <= 0x9F:
            try:
                cp = ord(bytes((b,)).decode("cp1252"))
            except UnicodeDecodeError:
                cp = b
        else:
            cp = b
        inv[cp] = b
    return inv


_WHATWG_WIN1252_INV: dict[int, int] = _build_whatwg_win1252_inv()


def _recover_cdp_utf8_bytes(text: str, content_type: str = "") -> bytes:
    """Recover raw UTF-8 wire bytes from Chromium CDP ``text/plain`` bodies.

    When an HTTP response omits ``; charset=utf-8`` on ``text/plain`` (as
    ``arena.ai``'s ``create-evaluation`` stream does), Blink's
    ``TextResourceDecoder`` decodes the raw UTF-8 wire bytes via the WHATWG
    ``windows-1252`` bijection before Playwright's driver re-encodes that
    string as UTF-8. Inverting the 256-codepoint bijection restores the exact
    original UTF-8 bytes whenever they form valid UTF-8.
    """
    if not text or text.isascii():
        return text.encode("utf-8")
    lowered_ct = content_type.lower()
    if "utf-8" in lowered_ct or "utf8" in lowered_ct:
        return text.encode("utf-8")
    inv = _WHATWG_WIN1252_INV
    try:
        raw = bytes(inv[ord(ch)] for ch in text)
    except KeyError:
        return text.encode("utf-8")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return text.encode("utf-8")
    return raw


def _recover_cdp_utf8_text(text: str, content_type: str = "") -> str:
    if not text or text.isascii():
        return text
    return _recover_cdp_utf8_bytes(text, content_type).decode(
        "utf-8", errors="replace"
    )


# --------------------------------------------------------------------------- #
# CDP User-Agent & Client-Hints sanitization (headless fallback)
# --------------------------------------------------------------------------- #


def _build_clean_ua_metadata(
    clean_ua: str, product: str = "", channel: str | None = None
) -> dict[str, Any] | None:
    full_ver = ""
    if "/" in product:
        cand = product.split("/", 1)[1].strip()
        if cand and cand[0].isdigit():
            full_ver = cand
    if not full_ver:
        m = re.search(r"Chrome/([0-9]+(?:\.[0-9]+)*)", clean_ua)
        if m:
            full_ver = m.group(1)
    if not full_ver:
        return None
    major = full_ver.split(".", 1)[0]
    ch_lower = (channel or "").lower()
    if "edg" in ch_lower or "Edg/" in clean_ua:
        primary_brand = "Microsoft Edge"
    elif ch_lower.startswith("chrome") and ch_lower != "chromium":
        primary_brand = "Google Chrome"
    else:
        primary_brand = "Chromium"

    brands = [
        {"brand": "Not:A-Brand", "version": "99"},
        {"brand": "Chromium", "version": major},
    ]
    full_list = [
        {"brand": "Not:A-Brand", "version": "99.0.0.0"},
        {"brand": "Chromium", "version": full_ver},
    ]
    if primary_brand != "Chromium":
        brands.insert(1, {"brand": primary_brand, "version": major})
        full_list.insert(1, {"brand": primary_brand, "version": full_ver})

    if "Windows NT" in clean_ua:
        plat, plat_ver = "Windows", "15.0.0"
    elif "Macintosh" in clean_ua:
        plat, plat_ver = "macOS", "14.5.0"
    else:
        plat, plat_ver = "Linux", "6.8.0"
    arch = "arm" if ("aarch64" in clean_ua or "ARM64" in clean_ua) else "x86"

    return {
        "brands": brands,
        "fullVersionList": full_list,
        "platform": plat,
        "platformVersion": plat_ver,
        "architecture": arch,
        "model": "",
        "mobile": False,
        "bitness": "64",
        "wow64": False,
    }


async def _sanitize_headless_page_cdp(
    context: Any, page: Any, *, channel: str | None = None
) -> Any:
    """Strip ``HeadlessChrome`` from UA and Client Hints via CDP on headless tabs."""
    if context is None:
        return None
    new_cdp = getattr(context, "new_cdp_session", None)
    if not callable(new_cdp):
        return None
    cdp: Any = None
    try:
        cdp = await new_cdp(page)
        ver_info = await cdp.send("Browser.getVersion")
        if not isinstance(ver_info, Mapping):
            await cdp.detach()
            return None
        raw_ua = str(ver_info.get("userAgent") or "")
        product = str(ver_info.get("product") or "")
        if not raw_ua or "Headless" not in raw_ua:
            await cdp.detach()
            return None
        clean_ua = (
            raw_ua.replace("HeadlessChrome/", "Chrome/")
            .replace("HeadlessEdg/", "Edg/")
            .replace("Headless", "")
        )
        override_params: dict[str, Any] = {"userAgent": clean_ua}
        ua_meta = _build_clean_ua_metadata(clean_ua, product, channel=channel)
        if ua_meta is not None:
            override_params["userAgentMetadata"] = ua_meta
        await cdp.send("Emulation.setUserAgentOverride", override_params)
        return cdp
    except Exception:  # noqa: BLE001
        if cdp is not None:
            try:
                await cdp.detach()
            except Exception:  # noqa: BLE001
                pass
        return None


# --------------------------------------------------------------------------- #
# Off-screen headful window cloaking (Preferences + CDP + Win32 ToolWindow)
# --------------------------------------------------------------------------- #

_OFFSCREEN_HEADFUL_SWITCHES: tuple[str, ...] = (
    "--window-position=-32000,-32000",
    "--window-size=1480,960",
    "--disable-features=CalculateNativeWinOcclusion",
    "--disable-backgrounding-occluded-windows",
    "--disable-renderer-backgrounding",
    "--disable-background-timer-throttling",
)


def _prepare_profile_window_placement(
    profile_dir: str | Path | None, *, hidden: bool
) -> None:
    """Ensure saved Chromium ``window_placement`` matches ``hidden`` vs visible mode."""
    if profile_dir is None:
        return
    try:
        default_dir = Path(profile_dir).expanduser() / "Default"
        default_dir.mkdir(parents=True, exist_ok=True)
        prefs_file = default_dir / "Preferences"
        prefs: dict[str, Any] = {}
        if prefs_file.is_file():
            try:
                loaded = json.loads(prefs_file.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    prefs = loaded
            except Exception:  # noqa: BLE001
                return
        browser_cfg = prefs.get("browser")
        if not isinstance(browser_cfg, dict):
            browser_cfg = {}
            prefs["browser"] = browser_cfg
        placement = browser_cfg.get("window_placement")
        if not isinstance(placement, dict):
            placement = {}
        changed = False
        if hidden:
            target = {
                "bottom": -31040,
                "left": -32000,
                "maximized": False,
                "right": -30520,
                "top": -32000,
                "work_area_bottom": 1040,
                "work_area_left": 0,
                "work_area_right": 1920,
                "work_area_top": 0,
            }
            if any(placement.get(k) != v for k, v in target.items()):
                placement.update(target)
                browser_cfg["window_placement"] = placement
                changed = True
        else:
            left_val = placement.get("left")
            if isinstance(left_val, (int, float)) and left_val <= -10000:
                placement.update(
                    {
                        "bottom": 980,
                        "left": 80,
                        "maximized": False,
                        "right": 1520,
                        "top": 80,
                    }
                )
                browser_cfg["window_placement"] = placement
                changed = True
        if changed:
            prefs_file.write_text(
                json.dumps(prefs, separators=(",", ":")), encoding="utf-8"
            )
    except Exception:  # noqa: BLE001
        return


async def _maybe_reset_headless_poisoned_cookies(
    context: Any, profile_dir: str | Path | None
) -> None:
    """Clear stale headless-flagged ``_GRECAPTCHA`` once when migrating to cloaked headful."""
    if context is None or profile_dir is None:
        return
    try:
        marker = Path(profile_dir).expanduser() / ".headful_cloaked_v1"
        if marker.exists():
            return
        clear_fn = getattr(context, "clear_cookies", None)
        if callable(clear_fn):
            await clear_fn(name=re.compile(r"^_GRECAPTCHA"))
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("1\n", encoding="utf-8")
    except Exception:  # noqa: BLE001
        return


async def _hide_headed_page_window_cdp(context: Any, page: Any) -> None:
    """Move a headful browser window off-screen via CDP without minimizing or occluding."""
    if context is None:
        return
    new_cdp = getattr(context, "new_cdp_session", None)
    if not callable(new_cdp):
        return
    cdp: Any = None
    try:
        cdp = await new_cdp(page)
        win_info = await cdp.send("Browser.getWindowForTarget")
        if isinstance(win_info, Mapping) and win_info.get("windowId") is not None:
            win_id = win_info["windowId"]
            try:
                await cdp.send(
                    "Browser.setWindowBounds",
                    {"windowId": win_id, "bounds": {"windowState": "normal"}},
                )
            except Exception:  # noqa: BLE001
                pass
            await cdp.send(
                "Browser.setWindowBounds",
                {
                    "windowId": win_id,
                    "bounds": {
                        "left": -32000,
                        "top": -32000,
                        "width": 1480,
                        "height": 960,
                    },
                },
            )
    except Exception:  # noqa: BLE001
        pass
    finally:
        if cdp is not None:
            try:
                await cdp.detach()
            except Exception:  # noqa: BLE001
                pass


def _windows_descendant_pids(root_pid: int) -> set[int]:
    """Return ``root_pid`` and all transitive child PIDs on Windows via Toolhelp32."""
    if sys.platform != "win32":
        return set()
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            ]

        CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
        CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        CreateToolhelp32Snapshot.restype = wintypes.HANDLE

        Process32FirstW = kernel32.Process32FirstW
        Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
        Process32FirstW.restype = wintypes.BOOL

        Process32NextW = kernel32.Process32NextW
        Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
        Process32NextW.restype = wintypes.BOOL

        CloseHandle = kernel32.CloseHandle
        CloseHandle.argtypes = [wintypes.HANDLE]
        CloseHandle.restype = wintypes.BOOL

        snap = CreateToolhelp32Snapshot(0x00000002, 0)
        invalid_handle = ctypes.c_void_p(-1).value
        if not snap or snap == invalid_handle:
            return {root_pid}
        children_by_parent: dict[int, list[int]] = {}
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            ok = Process32FirstW(snap, ctypes.byref(entry))
            while ok:
                pid = int(entry.th32ProcessID)
                ppid = int(entry.th32ParentProcessID)
                children_by_parent.setdefault(ppid, []).append(pid)
                ok = Process32NextW(snap, ctypes.byref(entry))
        finally:
            CloseHandle(snap)

        descendants: set[int] = {root_pid}
        stack = [root_pid]
        while stack:
            cur = stack.pop()
            for child in children_by_parent.get(cur, ()):
                if child not in descendants:
                    descendants.add(child)
                    stack.append(child)
        return descendants
    except Exception:  # noqa: BLE001
        return {root_pid}


class _WindowsBrowserCloaker:
    """Cloak newly spawned Chromium windows on Windows (no taskbar/Alt-Tab/focus)."""

    def __init__(self, *, enabled: bool = True) -> None:
        self._enabled = bool(enabled) and sys.platform == "win32"
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._root_pid = os.getpid()
        self._preexisting_hwnds: set[int] = set()
        self._prior_fg_hwnd: int = 0

    def start(self) -> None:
        if not self._enabled:
            return
        self._preexisting_hwnds = self._enum_all_hwnds()
        self._prior_fg_hwnd = self._get_foreground_hwnd()
        self._thread = threading.Thread(
            target=self._run,
            name="arena-win32-window-cloaker",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None

    @staticmethod
    def _get_foreground_hwnd() -> int:
        if sys.platform != "win32":
            return 0
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.WinDLL("user32", use_last_error=True)
            GetForegroundWindow = user32.GetForegroundWindow
            GetForegroundWindow.argtypes = []
            GetForegroundWindow.restype = wintypes.HWND
            return int(GetForegroundWindow() or 0)
        except Exception:  # noqa: BLE001
            return 0

    @staticmethod
    def _enum_all_hwnds() -> set[int]:
        if sys.platform != "win32":
            return set()
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.WinDLL("user32", use_last_error=True)
            WNDENUMPROC = ctypes.WINFUNCTYPE(
                wintypes.BOOL, wintypes.HWND, wintypes.LPARAM
            )
            EnumWindows = user32.EnumWindows
            EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
            EnumWindows.restype = wintypes.BOOL

            found: set[int] = set()

            @WNDENUMPROC
            def _cb(hwnd: Any, lparam: Any) -> bool:
                if hwnd:
                    found.add(int(hwnd))
                return True

            EnumWindows(_cb, 0)
            return found
        except Exception:  # noqa: BLE001
            return set()

    def _cloak_once(self) -> None:
        if sys.platform != "win32":
            return
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.WinDLL("user32", use_last_error=True)
            WNDENUMPROC = ctypes.WINFUNCTYPE(
                wintypes.BOOL, wintypes.HWND, wintypes.LPARAM
            )
            EnumWindows = user32.EnumWindows
            EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
            EnumWindows.restype = wintypes.BOOL

            IsWindow = user32.IsWindow
            IsWindow.argtypes = [wintypes.HWND]
            IsWindow.restype = wintypes.BOOL

            IsWindowVisible = user32.IsWindowVisible
            IsWindowVisible.argtypes = [wintypes.HWND]
            IsWindowVisible.restype = wintypes.BOOL

            IsIconic = user32.IsIconic
            IsIconic.argtypes = [wintypes.HWND]
            IsIconic.restype = wintypes.BOOL

            IsZoomed = user32.IsZoomed
            IsZoomed.argtypes = [wintypes.HWND]
            IsZoomed.restype = wintypes.BOOL

            ShowWindow = user32.ShowWindow
            ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
            ShowWindow.restype = wintypes.BOOL

            GetClassNameW = user32.GetClassNameW
            GetClassNameW.argtypes = [
                wintypes.HWND,
                wintypes.LPWSTR,
                ctypes.c_int,
            ]
            GetClassNameW.restype = ctypes.c_int

            GetWindowThreadProcessId = user32.GetWindowThreadProcessId
            GetWindowThreadProcessId.argtypes = [
                wintypes.HWND,
                ctypes.POINTER(wintypes.DWORD),
            ]
            GetWindowThreadProcessId.restype = wintypes.DWORD

            GetWindowRect = user32.GetWindowRect
            GetWindowRect.argtypes = [
                wintypes.HWND,
                ctypes.POINTER(wintypes.RECT),
            ]
            GetWindowRect.restype = wintypes.BOOL

            GetForegroundWindow = user32.GetForegroundWindow
            GetForegroundWindow.argtypes = []
            GetForegroundWindow.restype = wintypes.HWND

            SetForegroundWindow = user32.SetForegroundWindow
            SetForegroundWindow.argtypes = [wintypes.HWND]
            SetForegroundWindow.restype = wintypes.BOOL

            long_ptr_t: Any = ctypes.c_ssize_t
            if hasattr(user32, "GetWindowLongPtrW") and hasattr(
                user32, "SetWindowLongPtrW"
            ):
                GetWindowLongPtr = user32.GetWindowLongPtrW
                SetWindowLongPtr = user32.SetWindowLongPtrW
            else:
                GetWindowLongPtr = user32.GetWindowLongW
                SetWindowLongPtr = user32.SetWindowLongW
                long_ptr_t = ctypes.c_long

            GetWindowLongPtr.argtypes = [wintypes.HWND, ctypes.c_int]
            GetWindowLongPtr.restype = long_ptr_t
            SetWindowLongPtr.argtypes = [wintypes.HWND, ctypes.c_int, long_ptr_t]
            SetWindowLongPtr.restype = long_ptr_t

            SetWindowPos = user32.SetWindowPos
            SetWindowPos.argtypes = [
                wintypes.HWND,
                wintypes.HWND,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int,
                wintypes.UINT,
            ]
            SetWindowPos.restype = wintypes.BOOL

            GWL_EXSTYLE = -20
            WS_EX_TOOLWINDOW = 0x00000080
            WS_EX_APPWINDOW = 0x00040000
            WS_EX_NOACTIVATE = 0x08000000
            SW_SHOWNOACTIVATE = 4
            SWP_NOSIZE = 0x0001
            SWP_NOACTIVATE = 0x0010
            SWP_FRAMECHANGED = 0x0020
            SWP_NOOWNERZORDER = 0x0200
            HWND_BOTTOM = wintypes.HWND(1)

            descendants = _windows_descendant_pids(self._root_pid)
            preexisting = self._preexisting_hwnds
            prior_fg = self._prior_fg_hwnd

            @WNDENUMPROC
            def _cb(hwnd: Any, lparam: Any) -> bool:
                try:
                    hwnd_int = int(hwnd or 0)
                    if not hwnd_int or hwnd_int in preexisting:
                        return True
                    if not IsWindowVisible(hwnd):
                        return True
                    cls_buf = ctypes.create_unicode_buffer(64)
                    if GetClassNameW(hwnd, cls_buf, 64) <= 0:
                        return True
                    if not cls_buf.value.startswith("Chrome_WidgetWin_"):
                        return True

                    pid_val = wintypes.DWORD(0)
                    GetWindowThreadProcessId(hwnd, ctypes.byref(pid_val))
                    rect = wintypes.RECT()
                    has_rect = bool(GetWindowRect(hwnd, ctypes.byref(rect)))
                    born_offscreen = (
                        has_rect
                        and not IsIconic(hwnd)
                        and rect.left <= -25000
                        and rect.top <= -25000
                    )
                    if int(pid_val.value) not in descendants and not born_offscreen:
                        return True

                    cur_ex = int(GetWindowLongPtr(hwnd, GWL_EXSTYLE) or 0)
                    desired_ex = (
                        cur_ex | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE
                    ) & ~WS_EX_APPWINDOW
                    style_changed = desired_ex != cur_ex
                    if style_changed:
                        SetWindowLongPtr(hwnd, GWL_EXSTYLE, long_ptr_t(desired_ex))

                    if IsZoomed(hwnd):
                        ShowWindow(hwnd, SW_SHOWNOACTIVATE)
                        style_changed = True

                    if (
                        style_changed
                        or not has_rect
                        or rect.left > -25000
                        or rect.top > -25000
                    ):
                        SetWindowPos(
                            hwnd,
                            HWND_BOTTOM,
                            -32000,
                            -32000,
                            0,
                            0,
                            SWP_NOSIZE
                            | SWP_NOACTIVATE
                            | SWP_NOOWNERZORDER
                            | SWP_FRAMECHANGED,
                        )

                    if (
                        prior_fg
                        and prior_fg != hwnd_int
                        and int(GetForegroundWindow() or 0) == hwnd_int
                        and IsWindow(wintypes.HWND(prior_fg))
                    ):
                        SetForegroundWindow(wintypes.HWND(prior_fg))
                except Exception:  # noqa: BLE001
                    return True
                return True

            EnumWindows(_cb, 0)
        except Exception:  # noqa: BLE001
            return

    def _run(self) -> None:
        started = time.monotonic()
        while not self._stop.is_set():
            self._cloak_once()
            interval = 0.008 if (time.monotonic() - started) < 3.0 else 0.08
            self._stop.wait(interval)


# --------------------------------------------------------------------------- #
# Browser channel & launch failure classifiers
# --------------------------------------------------------------------------- #


def _windows_installed_channels() -> list[str]:
    if sys.platform != "win32":
        return []
    roots = [
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
        os.environ.get("LOCALAPPDATA"),
    ]
    probes = (
        ("chrome", Path("Google") / "Chrome" / "Application" / "chrome.exe"),
        ("msedge", Path("Microsoft") / "Edge" / "Application" / "msedge.exe"),
    )
    found: list[str] = []
    for channel, rel in probes:
        for root in roots:
            if root and (Path(root) / rel).is_file():
                found.append(channel)
                break
    return found


def _is_missing_browser_error(exc: BaseException) -> bool:
    msg = str(exc)
    return (
        "Executable doesn't exist" in msg
        or "is not found at" in msg
        or "Chromium distribution" in msg
    )


def _is_missing_display_error(exc: BaseException) -> bool:
    lowered = str(exc).lower()
    return any(
        marker in lowered
        for marker in (
            "missing x server",
            "cannot open display",
            "$display",
            "ozone_platform",
            "headed browser without having a xserver",
        )
    )

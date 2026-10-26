"""Session extraction from the user's local Firefox profile.

This module reuses *your own* signed-in Firefox session instead of imitating
a browser or reverse-engineering any protection:

* Cookies are extracted with ``rookiepy`` (a Rust library that reads the
  profile's ``cookies.sqlite``). When rookiepy is missing, the cookie store
  is locked by a running Firefox, or it returns nothing, a dependency-free
  fallback snapshots ``cookies.sqlite`` (plus its ``-wal``/``-shm``
  sidecars) into a private temporary directory and reads it with the
  standard :mod:`sqlite3` module — no lock contention with the browser.
* The default profile is resolved from ``profiles.ini`` (the ``[Install*]``
  section first, then the profile flagged ``Default=1``), falling back to the
  conventional ``*.default-release`` directory name.
* Request headers (:meth:`FirefoxSessionManager.firefox_headers`) are derived
  from the same profile — a Firefox User-Agent for the current OS and the
  installed Firefox version, ``Sec-GPC``, and ``Sec-Fetch-*`` — so the
  client's header fingerprint matches the real browser the session came from.
* :meth:`FirefoxSessionManager.refresh_session` is the hook the clients
  install for HTTP 403 / ``ChallengeRequiredError``: it prints guidance,
  waits for the user to refresh the page in Firefox, and re-reads the
  profile. No challenge is ever solved automatically here.

``load_cookies()`` returns a flat ``{"name": "value"}`` mapping that can be
passed directly to ``curl_cffi.requests.Session`` (or ``httpx.Client``);
:meth:`~FirefoxSessionManager.to_curl_cffi` provides a domain-grouped export
for curl_cffi's domain-aware cookie jar.
"""

from __future__ import annotations

import configparser
import json
import locale
import math
import os
import platform
import re
import shutil
import sqlite3
import sys
import tempfile
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, TextIO, runtime_checkable

__all__ = [
    "DEFAULT_COOKIE_DOMAINS",
    "FIREFOX_PROFILE_ENV",
    "FIREFOX_ROOT_ENV",
    "FirefoxSessionError",
    "FirefoxSessionManager",
    "SessionManager",
    "cookies_from_rookiepy",
    "default_profiles_root",
    "firefox_profiles_roots",
    "read_firefox_cookie_records",
    "read_firefox_cookies",
]


#: Domains queried when the caller does not specify any.
DEFAULT_COOKIE_DOMAINS: tuple[str, ...] = ("arena.ai", "lmarena.ai")

#: Point the reader at a root (or a ``profiles.ini``) it would not guess -- a
#: portable install, a second root, a profile on another disk.
FIREFOX_ROOT_ENV = "ARENA_FIREFOX_ROOT"
#: Name or absolute path of the profile to use, skipping discovery entirely.
FIREFOX_PROFILE_ENV = "ARENA_FIREFOX_PROFILE"

#: Roots tried after the platform default. Distribution packaging puts the real
#: profile inside a sandbox, where ``~/.mozilla/firefox`` does not exist at all;
#: on such a machine every discovery attempt used to end in "not found".
_SANDBOX_PROFILE_ROOTS: dict[str, tuple[str, ...]] = {
    "linux": (
        "~/snap/firefox/common/.mozilla/firefox",
        "~/.var/app/org.mozilla.firefox/.mozilla/firefox",
        "~/snap/firefox/current/.mozilla/firefox",
    ),
}

# Profile directory suffixes tried, in order, when profiles.ini gives no hint.
DEFAULT_PROFILE_HINTS: tuple[str, ...] = ("default-release", "default")

# Used only when the profile's compatibility.ini cannot be read.
FALLBACK_FIREFOX_VERSION = "156.0"

# Firefox froze the Gecko trail version ("rv:") at 109.0 only in releases
# 110..119 (bug 1805967) and unfroze it in Firefox 120 (bug 1852935), where both
# ``rv:`` and ``Firefox/`` carry ``MOZILLA_UAVERSION`` (``<major>.0``, hiding
# security patch levels per bugs 572659 and 870868).
FROZEN_GECKO_TRAIL_VERSION = "109.0"

STALE_SESSION_TEMPLATE = (
    "Сессия устарела. Откройте {host} в Firefox, обновите страницу, затем "
    "нажмите Enter..."
)

_LOCK_MARKERS = (
    "database is locked",
    "database table is locked",
    "database is busy",
    "unable to open database file",
)

_LAST_VERSION_RE = re.compile(r"LastVersion\s*=\s*(\d+(?:\.\d+)*)")
_ACCEPT_LANGUAGES_RE = re.compile(
    r'user_pref\(\s*"intl\.accept_languages"\s*,\s*"([^"]*)"\s*\)'
)
_LOCALE_REQUESTED_RE = re.compile(
    r'user_pref\(\s*"intl\.locale\.requested"\s*,\s*"([^"]*)"\s*\)'
)
_UA_OVERRIDE_RE = re.compile(
    r'user_pref\(\s*"general\.useragent\.override"\s*,\s*"([^"]*)"\s*\)'
)
_PREF_ENTRY_RE = re.compile(
    r'user_pref\(\s*"([^"]+)"\s*,\s*("(?:[^"\\]|\\.)*"|true|false|-?\d+)\s*\)'
)
_BCP47_TAG_RE = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$")

_COOKIE_RECORD_QUERY = """
SELECT host, name, value, path, expiry, isSecure, isHttpOnly
FROM moz_cookies
WHERE (host = :exact OR host = :dotted OR host LIKE :subdomain)
ORDER BY LENGTH(host) DESC, name COLLATE NOCASE
"""


class FirefoxSessionError(RuntimeError):
    """The Firefox profile or its cookie store could not be read."""


@runtime_checkable
class SessionManager(Protocol):
    """Duck-typed interface accepted as ``session_source`` by the clients."""

    def load_cookies(self, domains: Sequence[str] | None = None) -> dict[str, str]:
        """Return a flat ``{name: value}`` cookie mapping."""
        ...

    def firefox_headers(self, *, navigation: bool = False) -> dict[str, str]:
        """Return browser-consistent request headers."""
        ...

    def refresh_session(
        self, reason: BaseException | None = None
    ) -> dict[str, str] | None:
        """Re-read the session after an auth failure, or return ``None``."""
        ...


def default_profiles_root() -> Path:
    """Return the default Firefox profiles root for the current platform."""
    home = Path.home()
    if sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA")
        base = Path(appdata) if appdata else home / "AppData" / "Roaming"
        return base / "Mozilla" / "Firefox"
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Firefox"
    return home / ".mozilla" / "firefox"


def _platform_profile_roots() -> tuple[str, ...]:
    """Sandboxed roots for this platform (snap/Flatpak packaging)."""
    if sys.platform.startswith("linux"):
        return _SANDBOX_PROFILE_ROOTS.get("linux", ())
    return ()


def firefox_profiles_roots() -> tuple[Path, ...]:
    """Every Firefox profiles root worth searching, most likely first.

    The platform default comes first, then the sandboxed locations a snap or a
    Flatpak install uses (``~/snap/firefox/common/.mozilla/firefox`` and
    ``~/.var/app/org.mozilla.firefox/.mozilla/firefox`` on Linux), because on
    those distributions the conventional ``~/.mozilla/firefox`` does not exist.

    ``ARENA_FIREFOX_ROOT`` -- a profiles directory, or the ``profiles.ini``
    inside one -- is prepended, which covers a portable install or a copy of a
    profile restored somewhere else.

    Roots that do not exist are included: callers report them, and a report
    that names the paths it searched is what a stuck user needs.
    """
    roots: list[Path] = []
    override = os.environ.get(FIREFOX_ROOT_ENV, "").strip()
    if override:
        candidate = Path(override).expanduser()
        roots.append(
            candidate.parent if candidate.name == "profiles.ini" else candidate
        )
    roots.append(default_profiles_root())
    roots.extend(Path(item).expanduser() for item in _platform_profile_roots())
    unique: list[Path] = []
    for root in roots:
        if root not in unique:
            unique.append(root)
    return tuple(unique)


def _normalize_domains(domains: Sequence[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for item in domains:
        host = str(item).strip().lstrip(".").lower()
        if host and host not in normalized:
            normalized.append(host)
    if not normalized:
        raise ValueError("at least one cookie domain is required")
    return tuple(normalized)


def _as_profiles_root(path: Path) -> Path:
    """Accept either a profiles directory or the ``profiles.ini`` inside one."""
    return path.parent if path.name == "profiles.ini" else path


def _read_profiles_ini(root: Path) -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser(strict=False)
    try:
        parser.read(root / "profiles.ini", encoding="utf-8")
    except (OSError, configparser.Error):
        pass
    return parser


def _candidate_profile_dirs(root: Path) -> list[Path]:
    """List profile-shaped directories under ``root`` (and ``Profiles/``)."""
    candidates: list[Path] = []
    for base in (root, root / "Profiles"):
        if not base.is_dir():
            continue
        try:
            candidates.extend(
                sorted(entry for entry in base.iterdir() if entry.is_dir())
            )
        except OSError:
            continue
    return candidates


def _path_from_ini_value(root: Path, value: str) -> Path:
    path = Path(value.strip())
    return path if path.is_absolute() else root / path


def _looks_locked(error: BaseException) -> bool:
    text = str(error).lower()
    return any(marker in text for marker in _LOCK_MARKERS)


#: Mozilla LZ4 header on ``recovery.jsonlz4`` / ``sessionstore.jsonlz4``.
_MOZLZ4_MAGIC = b"mozLz40\x00"
#: Guard against a corrupt header claiming gigabytes of uncompressed JSON.
_MAX_SESSIONSTORE_BYTES = 64 * 1024 * 1024
#: ``SessionCookies.sys.mjs`` uses ``Number.MAX_SAFE_INTEGER`` for "session".
_SESSIONSTORE_MAX_EXPIRY = (1 << 53) - 1
#: Session-cookie stores inside a Firefox profile, live backup first.
_SESSIONSTORE_FILES: tuple[str, ...] = (
    "sessionstore-backups/recovery.jsonlz4",
    "sessionstore-backups/recovery.baklz4",
    "sessionstore.jsonlz4",
    "sessionstore.js",
)

# Disjoint epoch unit cutoffs: seconds (< 3e11 covers 1970..9999), milliseconds
# (< 3e14 covers 1979..9999, used by Firefox schema >= 16), microseconds
# (< 3e17 covers 1979..9999, older/exported formats), nanoseconds (>= 3e17).
_SECONDS_UPPER_BOUND = 3e11
_MILLISECONDS_UPPER_BOUND = 3e14
_MICROSECONDS_UPPER_BOUND = 3e17


def _domain_matches(host: str, targets: Sequence[str]) -> bool:
    """Whether ``host`` belongs to one of ``targets`` (exact or subdomain)."""
    candidate = str(host).strip().lstrip(".").lower()
    if not candidate:
        return False
    for target in targets:
        wanted = str(target).strip().lstrip(".").lower()
        if wanted and (candidate == wanted or candidate.endswith("." + wanted)):
            return True
    return False


def _expiry_seconds(expires: Any) -> float | None:
    """Normalize a cookie expiry to epoch **seconds**; ``None`` = session cookie.

    Modern Firefox (cookie schema >= 16, Firefox 136+) stores
    ``moz_cookies.expiry`` in **milliseconds** (~1.8e12 today), earlier schemas
    stored **seconds** (~1.8e9), and some older profile exports carry
    **microseconds** (~1.8e15) or **nanoseconds** (~1.8e18). ``rookiepy`` passes
    ``moz_cookies.expiry`` through unchanged, so it hands back milliseconds on
    current Firefox too. Mixing the units up silently makes every live cookie
    look expired in January 1970 (dividing ms by 1e6) or immortal, so every
    value goes through here exactly once.
    """
    if expires is None or isinstance(expires, bool):
        return None
    if isinstance(expires, (int, float)):
        number = float(expires)
    elif isinstance(expires, str):
        text = expires.strip()
        if not text:
            return None
        try:
            number = float(text)
        except ValueError:
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                return None
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
    else:
        return None
    if not math.isfinite(number) or number <= 0:
        return None
    if number >= _MICROSECONDS_UPPER_BOUND:
        number /= 1_000_000_000.0
    elif number >= _MILLISECONDS_UPPER_BOUND:
        number /= 1_000_000.0
    elif number >= _SECONDS_UPPER_BOUND:
        number /= 1_000.0
    return number


def _cookie_expired(expires: Any) -> bool:
    """Whether an expiry value is in the past; ``0``/``None`` means "session"."""
    moment = _expiry_seconds(expires)
    return moment is not None and moment < time.time()


def _decompress_mozlz4(data: bytes) -> bytes:
    """Decompress a Mozilla ``mozLz40\\0`` file (stdlib-only raw LZ4 block).

    Firefox writes session cookies (cookies without ``Expires``/``Max-Age``) to
    ``sessionstore-backups/recovery.jsonlz4`` rather than ``cookies.sqlite``.
    The format is an 8-byte ``mozLz40\\0`` magic, a 4-byte little-endian
    uncompressed byte length, and a single raw LZ4 block.
    """
    if len(data) < 12 or data[:8] != _MOZLZ4_MAGIC:
        raise ValueError("not a mozLz40 container")
    expected = int.from_bytes(data[8:12], "little")
    if expected > _MAX_SESSIONSTORE_BYTES:
        raise ValueError(f"mozLz40 payload too large ({expected} bytes)")
    if expected == 0:
        return b""
    src = memoryview(data)[12:]
    pos = 0
    end = len(src)
    out = bytearray()
    while pos < end:
        token = src[pos]
        pos += 1
        lit_len = token >> 4
        if lit_len == 15:
            while True:
                if pos >= end:
                    raise ValueError("truncated mozLz40 literal length")
                extra = src[pos]
                pos += 1
                lit_len += extra
                if extra != 255:
                    break
        if pos + lit_len > end or len(out) + lit_len > expected:
            raise ValueError("mozLz40 literal overruns block")
        if lit_len:
            out.extend(src[pos : pos + lit_len])
            pos += lit_len
        if pos >= end:
            break
        if pos + 2 > end:
            raise ValueError("truncated mozLz40 match offset")
        offset = src[pos] | (src[pos + 1] << 8)
        pos += 2
        if offset == 0 or offset > len(out):
            raise ValueError("invalid mozLz40 match offset")
        match_len = token & 0x0F
        if match_len == 15:
            while True:
                if pos >= end:
                    raise ValueError("truncated mozLz40 match length")
                extra = src[pos]
                pos += 1
                match_len += extra
                if extra != 255:
                    break
        match_len += 4
        if len(out) + match_len > expected:
            raise ValueError("mozLz40 match overruns expected size")
        start = len(out) - offset
        if offset >= match_len:
            out.extend(out[start : start + match_len])
        else:
            chunk = bytes(out[start:])
            repeats, remainder = divmod(match_len, offset)
            if repeats:
                out.extend(chunk * repeats)
            if remainder:
                out.extend(chunk[:remainder])
    if len(out) != expected:
        raise ValueError(
            f"mozLz40 decompressed size mismatch ({len(out)} != {expected})"
        )
    return bytes(out)


def _format_origin_attributes(value: Any) -> str:
    """Turn Firefox ``originAttributes`` (str or JSON dict) into a short tag."""
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        parts = [
            f"{key}={val}"
            for key, val in sorted(value.items())
            if val not in ("", 0, False, None)
        ]
        return "^" + "&".join(parts) if parts else ""
    return ""


def _sessionstore_cookie_rows(
    profile: Path,
) -> tuple[str | None, list[dict[str, Any]]]:
    """Read session cookies from ``recovery.jsonlz4`` / ``sessionstore.*``.

    Returns ``(relative_source_name, rows)``. Firefox replaces
    ``recovery.jsonlz4`` atomically while running, and writes
    ``sessionstore.jsonlz4`` on clean exit; ``recovery.baklz4`` covers a
    truncated file on filesystems without atomic rename.
    """
    existing: list[tuple[float, int, str, Path]] = []
    for index, relpath in enumerate(_SESSIONSTORE_FILES):
        candidate = profile / relpath
        try:
            if candidate.is_file():
                existing.append(
                    (candidate.stat().st_mtime, -index, relpath, candidate)
                )
        except OSError:
            continue
    existing.sort(reverse=True)

    payload: Any = None
    chosen: str | None = None
    for _, _, relpath, candidate in existing:
        try:
            raw = candidate.read_bytes()
            if raw.startswith(_MOZLZ4_MAGIC):
                text = _decompress_mozlz4(raw).decode("utf-8", errors="replace")
            else:
                text = raw.decode("utf-8", errors="replace")
            parsed = json.loads(text)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if isinstance(parsed, Mapping):
            payload = parsed
            chosen = relpath
            break

    if payload is None:
        return None, []

    raw_entries: list[Mapping[str, Any]] = []
    top_cookies = payload.get("cookies")
    if isinstance(top_cookies, list):
        raw_entries.extend(
            item for item in top_cookies if isinstance(item, Mapping)
        )
    windows = payload.get("windows")
    if isinstance(windows, list):
        for window in windows:
            if not isinstance(window, Mapping):
                continue
            win_cookies = window.get("cookies")
            if isinstance(win_cookies, list):
                raw_entries.extend(
                    item for item in win_cookies if isinstance(item, Mapping)
                )

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for entry in raw_entries:
        host = str(entry.get("host") or "")
        name = str(entry.get("name") or "")
        value = entry.get("value")
        if not host or not name or not isinstance(value, str):
            continue
        path = str(entry.get("path") or "/")
        container = _format_origin_attributes(entry.get("originAttributes"))
        key = (host, name, path, container)
        if key in seen:
            continue
        seen.add(key)
        raw_expiry = entry.get("expiry", 0)
        if isinstance(raw_expiry, (int, float)) and raw_expiry >= _SESSIONSTORE_MAX_EXPIRY:
            raw_expiry = 0
        same_site = entry.get("sameSite", 0)
        rows.append(
            {
                "host": host,
                "name": name,
                "value": value,
                "path": path,
                "expiry": raw_expiry,
                "isSecure": bool(entry.get("secure", False)),
                "isHttpOnly": bool(
                    entry.get("httponly", entry.get("httpOnly", False))
                ),
                "sameSite": same_site if isinstance(same_site, int) else 0,
                "originAttributes": container,
            }
        )
    return chosen, rows


def _normalize_rookiepy_records(
    records: Any, domains: Sequence[str] | None = None
) -> list[dict[str, Any]]:
    """Validate rookiepy's cookie list and drop unusable/expired entries."""
    normalized: list[dict[str, Any]] = []
    if not isinstance(records, (list, tuple)):
        return normalized
    targets = _normalize_domains(domains) if domains is not None else None
    for record in records:
        if not isinstance(record, Mapping):
            continue
        name = record.get("name")
        value = record.get("value")
        if not isinstance(name, str) or not name or not isinstance(value, str):
            continue
        domain = str(record.get("domain") or "")
        if targets is not None and domain and not _domain_matches(domain, targets):
            continue
        if _cookie_expired(record.get("expires")):
            continue
        moment = _expiry_seconds(record.get("expires"))
        normalized.append(
            {
                "name": name,
                "value": value,
                "domain": domain,
                "path": str(record.get("path") or "/"),
                "expires": int(moment) if moment is not None else 0,
                "secure": bool(record.get("secure")),
                "http_only": bool(record.get("http_only")),
            }
        )
    return normalized


def _records_to_cookies(records: Iterable[Mapping[str, Any]]) -> dict[str, str]:
    """Flatten cookie records into ``{name: value}``; first record of a name wins."""
    result: dict[str, str] = {}
    for record in records:
        result.setdefault(str(record["name"]), str(record["value"]))
    return result


def cookies_from_rookiepy(records: Any) -> dict[str, str]:
    """Convert a rookiepy cookie record list into a flat ``{name: value}`` dict."""
    return _records_to_cookies(_normalize_rookiepy_records(records))


def _query_cookie_snapshot(
    snapshot: Path,
    domains: Sequence[str],
    sessionstore_rows: Sequence[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str]] = set()
    connection = sqlite3.connect(str(snapshot))
    try:
        connection.row_factory = sqlite3.Row
        now = time.time()
        for domain in domains:
            rows = connection.execute(
                _COOKIE_RECORD_QUERY,
                {
                    "exact": domain,
                    "dotted": f".{domain}",
                    "subdomain": f"%.{domain}",
                },
            ).fetchall()
            for row in rows:
                name = row["name"]
                value = row["value"]
                if not name or value is None:
                    continue
                moment = _expiry_seconds(row["expiry"])
                if moment is not None and moment < now:
                    continue
                host = str(row["host"])
                path = str(row["path"])
                seen_keys.add((host, str(name), path))
                records.append(
                    {
                        "name": name,
                        "value": value,
                        "domain": host,
                        "path": path,
                        "expires": int(moment) if moment is not None else 0,
                        "secure": bool(row["isSecure"]),
                        "http_only": bool(row["isHttpOnly"]),
                    }
                )
            for item in sessionstore_rows:
                host = str(item.get("host") or "")
                if not _domain_matches(host, (domain,)):
                    continue
                name = str(item.get("name") or "")
                value = item.get("value")
                if not name or not isinstance(value, str):
                    continue
                path = str(item.get("path") or "/")
                if (host, name, path) in seen_keys:
                    continue
                moment = _expiry_seconds(item.get("expiry"))
                if moment is not None and moment < now:
                    continue
                seen_keys.add((host, name, path))
                records.append(
                    {
                        "name": name,
                        "value": value,
                        "domain": host,
                        "path": path,
                        "expires": int(moment) if moment is not None else 0,
                        "secure": bool(item.get("isSecure")),
                        "http_only": bool(item.get("isHttpOnly")),
                    }
                )
    finally:
        connection.close()
    return records


def _sessionstore_records_only(
    sessionstore_rows: Sequence[Mapping[str, Any]], domains: Sequence[str]
) -> list[dict[str, Any]]:
    """Filter sessionstore cookie rows when ``cookies.sqlite`` is absent."""
    records: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str]] = set()
    now = time.time()
    for domain in domains:
        for item in sessionstore_rows:
            host = str(item.get("host") or "")
            if not _domain_matches(host, (domain,)):
                continue
            name = str(item.get("name") or "")
            value = item.get("value")
            if not name or not isinstance(value, str):
                continue
            path = str(item.get("path") or "/")
            if (host, name, path) in seen_keys:
                continue
            moment = _expiry_seconds(item.get("expiry"))
            if moment is not None and moment < now:
                continue
            seen_keys.add((host, name, path))
            records.append(
                {
                    "name": name,
                    "value": value,
                    "domain": host,
                    "path": path,
                    "expires": int(moment) if moment is not None else 0,
                    "secure": bool(item.get("isSecure")),
                    "http_only": bool(item.get("isHttpOnly")),
                }
            )
    return records


def read_firefox_cookie_records(
    database: Path, domains: Sequence[str]
) -> list[dict[str, Any]]:
    """Read full cookie records from a Firefox profile's ``cookies.sqlite``.

    Firefox keeps the database in WAL mode and may hold it open while running,
    and keeps session cookies (those without ``Expires``/``Max-Age``) in
    ``sessionstore-backups/recovery.jsonlz4`` instead of SQLite. The database
    and its ``-wal``/``-shm`` sidecars are copied to a private temporary
    directory first, so SQLite replays any uncheckpointed WAL writes without
    contending for locks with a running browser, and sessionstore cookies from
    the same profile directory are merged in. Cookie values are stored in plain
    text; no key material is needed.
    """
    database = Path(database)
    targets = _normalize_domains(domains)
    _, sessionstore_rows = _sessionstore_cookie_rows(database.parent)
    with tempfile.TemporaryDirectory(prefix="arena-api-firefox-") as temporary:
        snapshot = Path(temporary) / database.name
        shutil.copy2(database, snapshot)
        for suffix in ("-wal", "-shm"):
            sidecar = database.with_name(database.name + suffix)
            if sidecar.is_file():
                shutil.copy2(
                    sidecar, snapshot.with_name(snapshot.name + suffix)
                )
        return _query_cookie_snapshot(snapshot, targets, sessionstore_rows)


def read_firefox_cookies(database: Path, domains: Sequence[str]) -> dict[str, str]:
    """Lock-safe flat ``{name: value}`` read of a Firefox cookie database."""
    return _records_to_cookies(read_firefox_cookie_records(database, domains))


def _platform_token() -> str:
    """Return the Firefox User-Agent platform token for the current OS."""
    if sys.platform.startswith("win"):
        return "Windows NT 10.0; Win64; x64"
    if sys.platform == "darwin":
        return "Macintosh; Intel Mac OS X 10.15"
    machine = platform.machine().lower()
    arch = "aarch64" if machine in ("arm64", "aarch64") else "x86_64"
    return f"X11; Linux {arch}"


def _clean_bcp47_tag(raw: str | None) -> str | None:
    """Validate and normalize a POSIX/BCP-47 locale tag, rejecting Windows CRT
    English names such as ``Russian_Russia`` or ``English_United States``."""
    if not raw:
        return None
    base = raw.strip().split(".")[0].split("@")[0].split(":")[0].strip()
    if not base or base in ("C", "POSIX"):
        return None
    tag = base.replace("_", "-")
    return tag if _BCP47_TAG_RE.match(tag) else None


def _windows_ui_locale_tag() -> str | None:
    """Resolve the active Windows UI language into an ISO/BCP-47 tag."""
    if not sys.platform.startswith("win"):
        return None
    try:
        import ctypes

        windll = getattr(ctypes, "windll", None)
        if windll is None:
            return None
        lang_id = int(windll.kernel32.GetUserDefaultUILanguage())
    except Exception:  # noqa: BLE001 - defensive on non-standard runtimes
        return None
    posix = locale.windows_locale.get(lang_id)
    return _clean_bcp47_tag(posix)


def _system_locale_tag() -> str | None:
    win_tag = _windows_ui_locale_tag()
    if win_tag:
        return win_tag
    try:
        current = locale.getlocale()
    except ValueError:
        current = None
    if current and current[0]:
        cleaned = _clean_bcp47_tag(current[0])
        if cleaned:
            return cleaned
    for variable in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        cleaned = _clean_bcp47_tag(os.environ.get(variable))
        if cleaned:
            return cleaned
    return None


def _ua_versions(raw_version: str, *, explicit: bool) -> tuple[str, str]:
    """Return ``(rv_version, firefox_version)`` matching ``nsHttpHandler.cpp``.

    Firefox builds ``MOZILLA_UAVERSION`` as ``<major>.0`` (hiding ``.patch``
    point releases such as ``148.0.2``) and uses it for both ``rv:`` and
    ``Firefox/`` since Firefox 120 (releases 110..119 froze ``rv:109.0``).
    An explicit ``firefox_version=`` override keeps its exact string in the
    trailing ``Firefox/<version>`` token.
    """
    major_text = raw_version.strip().split(".", 1)[0]
    try:
        major = int(major_text)
    except ValueError:
        return (FROZEN_GECKO_TRAIL_VERSION, raw_version)
    ua_milestone = f"{major}.0"
    rv = FROZEN_GECKO_TRAIL_VERSION if 110 <= major < 120 else ua_milestone
    shown = raw_version if explicit else ua_milestone
    return rv, shown


def _normalize_accept_language(value: str) -> str:
    """Turn a locale tag or preference list into a Firefox Accept-Language."""
    text = " ".join(value.split())
    if "," in text:
        return text
    tag = text.replace("_", "-")
    language = tag.split("-")[0].casefold()
    if language == "en":
        return "en-US,en;q=0.5"
    return f"{tag},{language};q=0.8,en-US;q=0.5,en;q=0.3"


def _bracket_proxy_host(host: str) -> str:
    cleaned = host.strip()
    if ":" in cleaned and not cleaned.startswith("["):
        return f"[{cleaned}]"
    return cleaned


def _firefox_no_proxy_matches(host: str | None, raw_patterns: str) -> bool:
    if not host:
        return False
    target = host.strip().strip("[]").lower()
    if not target:
        return False
    for token in re.split(r"[\s,]+", raw_patterns.strip()):
        pattern = token.strip().lower()
        if not pattern:
            continue
        pattern = pattern.split(":", 1)[0] if pattern.count(":") == 1 else pattern.strip("[]")
        if pattern in ("*", "<local>") and "." not in target:
            return True
        if pattern == "*":
            return True
        stripped = pattern.lstrip(".")
        if target == stripped or target.endswith("." + stripped):
            return True
    return False


def _parse_firefox_proxy(
    prefs_text: str, *, scheme: str = "https", host: str | None = None
) -> str | None:
    """Extract a manual proxy URL from Firefox ``prefs.js`` when configured.

    Firefox uses ``network.proxy.type == 1`` for manual proxy settings; its
    default (``5``) delegates to the OS proxy, which ``urllib.request`` already
    reads. Only manual settings are returned here so ``network.proxy.type == 0``
    ("No proxy") or stale host fields left behind after switching back to
    system proxy are ignored.
    """
    prefs: dict[str, Any] = {}
    for key, raw_val in _PREF_ENTRY_RE.findall(prefs_text):
        if not key.startswith("network.proxy."):
            continue
        if raw_val.startswith('"') and raw_val.endswith('"'):
            prefs[key] = raw_val[1:-1].replace(r"\"", '"').replace(r"\\", "\\")
        elif raw_val == "true":
            prefs[key] = True
        elif raw_val == "false":
            prefs[key] = False
        else:
            try:
                prefs[key] = int(raw_val)
            except ValueError:
                continue

    if prefs.get("network.proxy.type") != 1:
        return None
    no_proxies_on = str(prefs.get("network.proxy.no_proxies_on", "localhost, 127.0.0.1"))
    if _firefox_no_proxy_matches(host, no_proxies_on):
        return None

    target_scheme = scheme.lower() or "https"
    if target_scheme == "https":
        ssl_host = str(prefs.get("network.proxy.ssl") or "").strip()
        ssl_port = prefs.get("network.proxy.ssl_port")
        if ssl_host and isinstance(ssl_port, int) and ssl_port > 0:
            return f"http://{_bracket_proxy_host(ssl_host)}:{ssl_port}"
        if prefs.get("network.proxy.share_proxy_settings") is True:
            http_host = str(prefs.get("network.proxy.http") or "").strip()
            http_port = prefs.get("network.proxy.http_port")
            if http_host and isinstance(http_port, int) and http_port > 0:
                return f"http://{_bracket_proxy_host(http_host)}:{http_port}"
    elif target_scheme == "http":
        http_host = str(prefs.get("network.proxy.http") or "").strip()
        http_port = prefs.get("network.proxy.http_port")
        if http_host and isinstance(http_port, int) and http_port > 0:
            return f"http://{_bracket_proxy_host(http_host)}:{http_port}"

    socks_host = str(prefs.get("network.proxy.socks") or "").strip()
    socks_port = prefs.get("network.proxy.socks_port")
    socks_version = prefs.get("network.proxy.socks_version", 5)
    if (
        socks_host
        and isinstance(socks_port, int)
        and socks_port > 0
        and socks_version == 5
    ):
        remote_dns = bool(prefs.get("network.proxy.socks_remote_dns", False))
        socks_scheme = "socks5h" if remote_dns else "socks5"
        return f"{socks_scheme}://{_bracket_proxy_host(socks_host)}:{socks_port}"
    return None


class FirefoxSessionManager:
    """Load, validate, and refresh an Arena session from local Firefox.

    Parameters
    ----------
    domains:
        Cookie domains to extract. Defaults to ``("arena.ai", "lmarena.ai")``.
    profiles_root:
        Override the Firefox profiles directory (portable installs, tests).
        ``None`` searches every root of
        :func:`firefox_profiles_roots` — the platform default *and* the
        snap/Flatpak locations — and honours ``ARENA_FIREFOX_ROOT``.
    profile_name:
        Explicit profile directory name or absolute path. When omitted, every
        profile of every root is ranked by ``profiles.ini`` (the ``[Install*]``
        section's ``Default`` entry, then the profile flagged ``Default=1``,
        then ``*.default-release``/``*.default`` names, then the newest
        ``cookies.sqlite``) and the first one that actually stores cookies for
        the requested domains wins — with several profiles, the configured
        default is often not the one holding the session. Honours
        ``ARENA_FIREFOX_PROFILE``.
    cookie_database:
        Explicit ``cookies.sqlite`` path, bypassing profile resolution for
        the cookie store itself.
    interactive:
        When ``True`` (default), :meth:`refresh_session` waits for the user
        to press Enter after the stale-session message. Set to ``False`` for
        headless use — cookies are then re-read immediately.
    prompt:
        Callable used to wait for user input (injectable for tests).
    output:
        Stream guidance messages are printed to (defaults to ``sys.stderr``).
    language:
        Explicit ``Accept-Language`` value; otherwise the profile's
        ``intl.accept_languages`` preference or the system locale is used.
    firefox_version:
        Override the Firefox version used in the User-Agent. Otherwise it is
        read from the profile's ``compatibility.ini``.
    max_cookie_attempts:
        Attempts per extraction when the cookie store is locked (``>= 1``).
    lock_retry_delay:
        Base delay in seconds between lock retries (grows linearly).
    """

    def __init__(
        self,
        *,
        domains: Sequence[str] | None = None,
        profiles_root: str | Path | None = None,
        profile_name: str | None = None,
        cookie_database: str | Path | None = None,
        interactive: bool = True,
        prompt: Callable[[str], str] = input,
        output: TextIO | None = None,
        language: str | None = None,
        firefox_version: str | None = None,
        max_cookie_attempts: int = 3,
        lock_retry_delay: float = 0.35,
    ) -> None:
        if domains is None:
            self.domains = DEFAULT_COOKIE_DOMAINS
        else:
            self.domains = _normalize_domains(domains)
        self.profiles_root = (
            _as_profiles_root(Path(profiles_root).expanduser())
            if profiles_root is not None
            else None
        )
        # Environment overrides let a portable install, a second root or a
        # non-default profile be used through ``arena-api --status`` -- without
        # editing code -- when nothing on the command line says otherwise.
        if self.profiles_root is None:
            override_root = os.environ.get(FIREFOX_ROOT_ENV, "").strip()
            if override_root:
                self.profiles_root = _as_profiles_root(
                    Path(override_root).expanduser()
                )
        self.profile_name = profile_name or (
            os.environ.get(FIREFOX_PROFILE_ENV, "").strip() or None
        )
        self.cookie_database = (
            Path(cookie_database).expanduser()
            if cookie_database is not None
            else None
        )
        self.interactive = interactive
        self._prompt = prompt
        self._output = output if output is not None else sys.stderr
        self.language = language
        self.firefox_version = firefox_version
        if (
            not isinstance(max_cookie_attempts, int)
            or isinstance(max_cookie_attempts, bool)
            or max_cookie_attempts < 1
        ):
            raise ValueError("max_cookie_attempts must be an integer >= 1")
        if not math.isfinite(lock_retry_delay) or lock_retry_delay < 0:
            raise ValueError(
                "lock_retry_delay must be a finite, non-negative number"
            )
        self.max_cookie_attempts = max_cookie_attempts
        self.lock_retry_delay = lock_retry_delay
        self._profile_path: Path | None = None
        # profile -> number of matching cookies, filled by profile discovery.
        self._profile_counts: dict[Path, int] = {}

    # ------------------------------------------------------------------ #
    # Profile and database discovery
    # ------------------------------------------------------------------ #

    def profile_path(self) -> Path:
        """Return the default Firefox profile directory for this machine."""
        if self._profile_path is None:
            self._profile_path = self._resolve_profile()
        return self._profile_path

    def profiles_roots(self) -> tuple[Path, ...]:
        """Roots this manager searches, most likely first."""
        if self.profiles_root is not None:
            return (Path(self.profiles_root).expanduser(),)
        return firefox_profiles_roots()

    def _root_candidates(self, root: Path) -> list[Path]:
        """Profile directories under one root, most likely first.

        ``profiles.ini`` records the installation's default profile and a
        profile flagged ``Default=1``; anything else is guessed by the usual
        ``*.default-release`` name and then by which cookie database was
        written most recently. All of them are returned rather than the first
        hit -- see :meth:`profile_candidates` for why.
        """
        if not root.is_dir():
            return []
        ordered: list[Path] = []

        def remember(path: Path) -> None:
            if path.is_dir() and path not in ordered:
                ordered.append(path)

        ini = _read_profiles_ini(root)
        # Firefox 67+ records each installation's default profile here.
        for section in ini.sections():
            if not section.startswith("Install"):
                continue
            value = ini.get(section, "Default", fallback=None)
            if value:
                remember(_path_from_ini_value(root, value))
        for section in ini.sections():
            if not section.startswith("Profile"):
                continue
            if ini.getboolean(section, "Default", fallback=False):
                value = ini.get(section, "Path", fallback=None)
                if value:
                    remember(_path_from_ini_value(root, value))
        candidates = _candidate_profile_dirs(root)
        for hint in DEFAULT_PROFILE_HINTS:
            for candidate in candidates:
                if candidate.name.endswith(f".{hint}"):
                    remember(candidate)
        with_database = [
            candidate
            for candidate in candidates
            if (candidate / "cookies.sqlite").is_file()
        ]
        for candidate in sorted(
            with_database,
            key=lambda item: (item / "cookies.sqlite").stat().st_mtime,
            reverse=True,
        ):
            remember(candidate)
        for candidate in candidates:
            # A container directory (``Profiles``, ``Crash Reports``) is not a
            # profile; a real one always carries at least one of these.
            if any(
                (candidate / marker).exists()
                for marker in ("prefs.js", "times.json", "cookies.sqlite")
            ):
                remember(candidate)
        return ordered

    def profile_candidates(self) -> list[Path]:
        """Every profile worth reading, most likely first.

        A machine can hold several profiles, and the one ``profiles.ini``
        calls the default is frequently *not* the one holding the signed-in
        session (a separate profile made with ``about:profiles``, a work
        profile, a leftover from an older install). Discovery therefore keeps
        the whole list and picks by content in :meth:`_resolve_profile`.
        """
        if self.profile_name:
            name = Path(self.profile_name).expanduser()
            if name.is_absolute():
                if name.is_dir():
                    return [name]
                raise FirefoxSessionError(f"Firefox profile not found: {name}")
            found: list[Path] = []
            for root in self.profiles_roots():
                # ``<root>/<name>`` (unusual), ``<root>/Profiles/<name>`` (the
                # layout Firefox creates) and any directory of this root whose
                # name matches -- a profile made with about:profiles is named
                # by the user and only the directory name is predictable.
                for candidate in (
                    root / name,
                    root / "Profiles" / name,
                    *(
                        item
                        for item in self._root_candidates(root)
                        if item.name == name
                    ),
                ):
                    if candidate.is_dir() and candidate not in found:
                        found.append(candidate)
            if not found:
                raise FirefoxSessionError(f"Firefox profile not found: {name}")
            return found
        roots = self.profiles_roots()
        existing = [root for root in roots if root.is_dir()]
        if not existing:
            listed = ", ".join(str(root) for root in roots)
            raise FirefoxSessionError(
                f"Firefox profiles directory not found: {listed}"
            )
        ordered: list[Path] = []
        for root in existing:
            for candidate in self._root_candidates(root):
                if candidate not in ordered:
                    ordered.append(candidate)
        if not ordered:
            listed = ", ".join(str(root) for root in existing)
            raise FirefoxSessionError(
                f"No Firefox profile found under {listed}. Install Firefox, "
                "open arena.ai in it, and sign in."
            )
        return ordered

    def _default_profile_candidates(self) -> list[Path]:
        """Installation-ranked profiles across searched roots (ignoring ``profile_name``)."""
        ordered: list[Path] = []
        for root in self.profiles_roots():
            if not root.is_dir():
                continue
            for candidate in self._root_candidates(root):
                if candidate not in ordered:
                    ordered.append(candidate)
        return ordered

    def profile_cookie_count(self, profile: Path) -> int:
        """Matching cookie names stored by one profile (0 when unreadable/absent).

        Permission to fail quietly is deliberate: this runs during discovery,
        where a locked or half-written database of *one* profile must not stop
        the reader from trying the others.
        """
        cached = self._profile_counts.get(profile)
        if cached is not None:
            return cached
        database = profile / "cookies.sqlite"
        count = 0
        if database.is_file():
            try:
                count = len(read_firefox_cookies(database, self.domains))
            except (sqlite3.DatabaseError, OSError, ValueError):
                count = 0
        else:
            _, session_rows = _sessionstore_cookie_rows(profile)
            if session_rows:
                count = len(
                    _records_to_cookies(
                        _sessionstore_records_only(session_rows, self.domains)
                    )
                )
        self._profile_counts[profile] = count
        return count

    def selection_reason(self) -> str:
        """One line explaining which profile was chosen and why."""
        profile = self.profile_path()
        count = self.profile_cookie_count(profile)
        domains = ", ".join(self.domains)
        if count:
            return (
                f"{profile} ({count} cookie names for {domains} -- the "
                "profile that actually holds the session)"
            )
        return f"{profile} (no cookies for {domains})"

    def _resolve_profile(self) -> Path:
        candidates = self.profile_candidates()
        for candidate in candidates:
            if self.profile_cookie_count(candidate):
                if candidate != candidates[0]:
                    self._emit(
                        "[arena-api] using Firefox profile "
                        f"{candidate} (it holds the cookies; "
                        f"{candidates[0].name} does not)"
                    )
                return candidate
        return candidates[0]

    def cookie_database_path(self) -> Path:
        """Return the cookie database of the selected profile."""
        if self.cookie_database is not None:
            database = self.cookie_database
        else:
            database = self.profile_path() / "cookies.sqlite"
        if not database.is_file():
            raise FirefoxSessionError(
                f"Firefox cookie database not found: {database}"
            )
        return database

    # ------------------------------------------------------------------ #
    # Cookie extraction
    # ------------------------------------------------------------------ #

    def load_cookies(
        self, domains: Sequence[str] | None = None
    ) -> dict[str, str]:
        """Return ``{"cookie_name": "value"}`` cookies for the given domains.

        The mapping is ready for direct use as the ``cookies`` argument of
        ``curl_cffi.requests.Session`` (or ``httpx.Client``). The preferred
        extraction path is ``rookiepy.firefox(domains=...)``; the lock-safe
        SQLite snapshot reader is used as a fallback. Cookie names from
        earlier domains win when the same name exists on several domains.
        """
        return _records_to_cookies(self._session_records(domains))

    def cookie_records(
        self, domains: Sequence[str] | None = None
    ) -> list[dict[str, Any]]:
        """Return full cookie records (domain, path, expiry, flags, ...)."""
        return self._session_records(domains)

    def to_curl_cffi(
        self, domains: Sequence[str] | None = None
    ) -> dict[str, dict[str, str]]:
        """Group cookies by domain for curl_cffi's domain-aware cookie jar.

        The flat :meth:`load_cookies` mapping already works as
        ``curl_cffi.requests.Session(cookies=...)``; this export keeps the
        domain attribution::

            session = curl_cffi.requests.Session(impersonate="firefox")
            for domain, jar in manager.to_curl_cffi().items():
                for name, value in jar.items():
                    session.cookies.set(name, value, domain=domain)
        """
        grouped: dict[str, dict[str, str]] = {}
        for record in self._session_records(domains):
            host = str(record.get("domain") or "").lstrip(".")
            grouped.setdefault(host, {})[record["name"]] = record["value"]
        return grouped

    def _uses_injected_rookiepy(self) -> bool:
        """Whether a test double was attached directly to this manager."""
        return "_rookiepy_module" in self.__dict__

    def _is_platform_root(self, root: Path) -> bool:
        """Whether ``root`` is one of the standard OS locations rookiepy reads."""
        platform_roots = (
            default_profiles_root(),
            *(Path(item).expanduser() for item in _platform_profile_roots()),
        )
        try:
            target = root.expanduser().resolve()
        except OSError:
            target = root.expanduser()
        for candidate in platform_roots:
            try:
                resolved = candidate.resolve()
            except OSError:
                resolved = candidate
            if target == resolved:
                return True
        return False

    def _rookiepy_is_reading_the_selected_profile(self) -> bool:
        """Whether ``rookiepy`` would open the exact profile and state we want.

        ``rookiepy.firefox()`` has three hard limitations:

        1. It ignores ``--profile-root`` / ``ARENA_FIREFOX_ROOT`` and searches
           only the platform default directories.
        2. It always opens the installation's *default* profile. When discovery
           or ``--profile`` picked another one -- a work profile, a second
           ``about:profiles`` entry, a leftover install -- asking rookiepy
           returns that other profile's cookies.
        3. It opens ``cookies.sqlite?mode=ro&immutable=1``, which causes SQLite
           to ignore ``cookies.sqlite-wal``. While Firefox is running and has
           uncheckpointed WAL writes (a fresh sign-in or page refresh), rookiepy
           reads stale pre-WAL rows.

        Whenever any of those applies, our snapshot + sessionstore reader is
        used directly so the chosen profile and its live WAL are read.
        """
        if self.cookie_database is not None:
            return False
        injected = self._uses_injected_rookiepy()
        if (
            not injected
            and self.profiles_root is not None
            and not self._is_platform_root(self.profiles_root)
        ):
            return False
        try:
            default_candidates = self._default_profile_candidates()
            selected = self.profile_path()
        except (FirefoxSessionError, OSError):
            if self.profiles_root is not None or self.profile_name is not None:
                return False
            # Nothing to compare against: let rookiepy have its usual turn.
            return True
        if not default_candidates:
            return False
        try:
            same_profile = selected.resolve() == default_candidates[0].resolve()
        except OSError:
            same_profile = selected == default_candidates[0]
        if not same_profile:
            return False
        if not injected:
            wal = selected / "cookies.sqlite-wal"
            try:
                if wal.is_file() and wal.stat().st_size > 0:
                    return False
            except OSError:
                pass
        return True

    def _session_records(
        self, domains: Sequence[str] | None = None
    ) -> list[dict[str, Any]]:
        targets = (
            _normalize_domains(domains) if domains is not None else self.domains
        )
        warnings: list[str] = []
        if self._rookiepy_is_reading_the_selected_profile():
            records = self._rookiepy_records(targets, warnings)
        else:
            records = None
        if records is None:
            # Reported apart from the notes above: what a caller needs to read
            # is why the store could not be read, not that an optional
            # accelerator was absent or skipped.
            failures: list[str] = []
            records = self._sqlite_records(targets, failures)
            if records is None:
                raise FirefoxSessionError(
                    "; ".join(failures + warnings)
                    or "the Firefox cookie store could not be read"
                )
        return records

    def _rookiepy_module(self) -> Any | None:
        """Import rookiepy lazily so the module stays an optional dependency."""
        try:
            import rookiepy  # optional dependency; mypy config silences the missing stubs
        except ImportError:
            return None
        return rookiepy

    def _rookiepy_records(
        self, domains: tuple[str, ...], warnings: list[str]
    ) -> list[dict[str, Any]] | None:
        rookiepy = self._rookiepy_module()
        if rookiepy is None:
            warnings.append(
                "rookiepy is not installed; reading cookies.sqlite directly "
                "(pip install rookiepy for the supported path)"
            )
            return None
        for attempt in range(self.max_cookie_attempts):
            try:
                records = rookiepy.firefox(domains=list(domains))
            except Exception as exc:  # rookiepy surfaces plain runtime errors
                headline = (str(exc).strip().splitlines() or [str(exc)])[0]
                if _looks_locked(exc) and attempt + 1 < self.max_cookie_attempts:
                    warnings.append(
                        f"rookiepy hit a locked cookie store ({headline}); retrying"
                    )
                    time.sleep(self.lock_retry_delay * (attempt + 1))
                    continue
                warnings.append(f"rookiepy failed: {type(exc).__name__}: {headline}")
                return None
            normalized = _normalize_rookiepy_records(records, domains=domains)
            if normalized:
                return normalized
            warnings.append(
                "rookiepy returned no cookies for: " + ", ".join(domains)
            )
            return None
        return None

    def _sqlite_records(
        self, domains: tuple[str, ...], warnings: list[str]
    ) -> list[dict[str, Any]] | None:
        try:
            database = self.cookie_database_path()
        except FirefoxSessionError as exc:
            if self.cookie_database is None:
                try:
                    profile = self.profile_path()
                except FirefoxSessionError:
                    profile = None
                if profile is not None:
                    _, session_rows = _sessionstore_cookie_rows(profile)
                    if session_rows:
                        return _sessionstore_records_only(session_rows, domains)
            warnings.append(str(exc))
            return None
        last_error: Exception | None = None
        for attempt in range(self.max_cookie_attempts):
            try:
                return read_firefox_cookie_records(database, domains)
            except (sqlite3.DatabaseError, OSError) as exc:
                last_error = exc
                if attempt + 1 < self.max_cookie_attempts:
                    warnings.append(
                        f"cookies.sqlite read failed ({exc}); "
                        "retrying with a fresh snapshot"
                    )
                    time.sleep(self.lock_retry_delay * (attempt + 1))
                    continue
        warnings.append(f"could not read {database}: {last_error}")
        return None

    # ------------------------------------------------------------------ #
    # Browser-consistent headers
    # ------------------------------------------------------------------ #

    def _compatibility_files(self) -> list[Path]:
        files: list[Path] = []
        if self.cookie_database is not None:
            files.append(self.cookie_database.parent / "compatibility.ini")
        try:
            files.append(self.profile_path() / "compatibility.ini")
        except FirefoxSessionError:
            pass
        return files

    def _installed_version(self) -> str:
        if self.firefox_version:
            return self.firefox_version
        for candidate in self._compatibility_files():
            try:
                text = candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            match = _LAST_VERSION_RE.search(text)
            if match:
                return match.group(1)
        return FALLBACK_FIREFOX_VERSION

    def _prefs_text(self) -> str | None:
        try:
            profile = self.profile_path()
        except FirefoxSessionError:
            return None
        prefs = profile / "prefs.js"
        if not prefs.is_file():
            return None
        try:
            return prefs.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def _profile_ua_override(self) -> str | None:
        text = self._prefs_text()
        if not text:
            return None
        match = _UA_OVERRIDE_RE.search(text)
        if match and match.group(1).strip():
            return match.group(1).strip()
        return None

    def user_agent(self) -> str:
        """Return the User-Agent of the Firefox build matching this profile."""
        if not self.firefox_version:
            override = self._profile_ua_override()
            if override:
                return override
        version = self._installed_version()
        rv, shown = _ua_versions(version, explicit=bool(self.firefox_version))
        return (
            f"Mozilla/5.0 ({_platform_token()}; "
            f"rv:{rv}) Gecko/20100101 "
            f"Firefox/{shown}"
        )

    def _profile_accept_language(self) -> str | None:
        text = self._prefs_text()
        if not text:
            return None
        match = _ACCEPT_LANGUAGES_RE.search(text)
        if match and match.group(1).strip():
            return match.group(1).strip()
        requested = _LOCALE_REQUESTED_RE.search(text)
        if requested and requested.group(1).strip():
            first = requested.group(1).split(",")[0].strip()
            cleaned = _clean_bcp47_tag(first)
            if cleaned:
                return cleaned
        return None

    def accept_language(self) -> str:
        """Return a Firefox-style ``Accept-Language`` for this machine."""
        if self.language:
            return _normalize_accept_language(self.language)
        for source in (self._profile_accept_language(), _system_locale_tag()):
            if source:
                return _normalize_accept_language(source)
        return "en-US,en;q=0.5"

    def proxy_url(
        self, *, scheme: str = "https", host: str | None = None
    ) -> str | None:
        """Return the manual proxy URL configured in ``prefs.js``, if any."""
        text = self._prefs_text()
        if not text:
            return None
        return _parse_firefox_proxy(text, scheme=scheme, host=host)

    def firefox_headers(self, *, navigation: bool = False) -> dict[str, str]:
        """Return request headers matching a real Firefox on this machine.

        The default set describes a ``fetch``/XHR call made from the Arena
        site itself; ``navigation=True`` returns document-navigation headers.
        ``Accept-Encoding`` is deliberately omitted so the HTTP backend
        (httpx, curl_cffi) advertises only the codecs it can actually decode.
        """
        headers: dict[str, str] = {
            "User-Agent": self.user_agent(),
            "Accept-Language": self.accept_language(),
            "Sec-GPC": "1",
        }
        if navigation:
            headers.update(
                {
                    "Accept": (
                        "text/html,application/xhtml+xml,"
                        "application/xml;q=0.9,*/*;q=0.8"
                    ),
                    "Upgrade-Insecure-Requests": "1",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-User": "?1",
                }
            )
        else:
            headers.update(
                {
                    "Accept": "text/event-stream, application/json, text/plain, */*",
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "same-origin",
                }
            )
        return headers

    # ------------------------------------------------------------------ #
    # Stale-session recovery
    # ------------------------------------------------------------------ #

    def refresh_session(
        self, reason: BaseException | None = None
    ) -> dict[str, str] | None:
        """Reload cookies after asking the user to re-verify in Firefox.

        The clients install this as their auth-error hook: it prints the
        stale-session guidance, waits for the user to press Enter (unless
        ``interactive=False``), and re-reads the profile. Returns the fresh
        cookie mapping, or ``None`` when no usable session is available.
        """
        host = self.domains[0] if self.domains else "arena.ai"
        message = STALE_SESSION_TEMPLATE.format(host=host)
        if reason is not None:
            message = f"{message}\nПричина: {reason}"
        self._emit(message)
        if self.interactive:
            try:
                self._prompt("")
            except (EOFError, KeyboardInterrupt):
                return None
        try:
            cookies = self.load_cookies()
        except FirefoxSessionError as exc:
            self._emit(
                f"Не удалось перечитать cookie из Firefox: {exc}"
            )
            return None
        if not cookies:
            self._emit(f"В профиле Firefox нет cookie для {host}.")
            return None
        return cookies

    def _emit(self, message: str) -> None:
        print(message, file=self._output, flush=True)

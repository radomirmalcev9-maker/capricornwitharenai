"""Tests for the determinism init script and browser-environment wiring."""

from __future__ import annotations

import json

import pytest

from arena_api.auth.environment import (
    ANIMATION_FREEZE_CSS,
    DEFAULT_INIT_SCRIPT,
    HIDE_WEBDRIVER_SCRIPT,
    DeterminismOptions,
    build_init_script,
)
from arena_api.auth.browser import (
    SYNTHETIC_MONITOR_HEADER,
    BrowserEnvironment,
    BrowserEnvironmentOptions,
)

# Marker strings that would indicate a stealth / anti-detection patch.
STEALTH_MARKERS = (
    "navigator.webdriver",
    "navigator.plugins",
    "navigator.mimeTypes",
    "UNMASKED_VENDOR_WEBGL",
    "UNMASKED_RENDERER_WEBGL",
    "getParameter",
    "toDataURL",
    "permissions.query",
    "window.chrome",
    "Notification.permission",
    "oncdpconnection",
)


def test_default_script_is_stable_and_non_empty() -> None:
    assert len(DEFAULT_INIT_SCRIPT) > 500
    assert build_init_script(DeterminismOptions()) == DEFAULT_INIT_SCRIPT


def test_script_contains_no_stealth_or_fingerprint_spoofing() -> None:
    script = build_init_script(
        DeterminismOptions(
            freeze_animations=True,
            finish_web_animations=True,
            deterministic_random=True,
            anchor_clock=True,
            identify_automation=True,
        )
    )
    for marker in STEALTH_MARKERS:
        assert marker not in script, f"init script must not contain {marker!r}"


def test_the_default_script_stays_honest() -> None:
    """The webdriver mask is opt-in, so it must never leak into the default.

    ``test_script_contains_no_stealth_or_fingerprint_spoofing`` already checks
    the markers; this pins the reason: the mask exists, and is downloadable on
    purpose (the sign-in window), not by accident.
    """
    assert "webdriver" in HIDE_WEBDRIVER_SCRIPT
    assert "webdriver" not in DEFAULT_INIT_SCRIPT
    assert "webdriver" not in build_init_script(DeterminismOptions(identify_automation=False))


def test_the_webdriver_mask_survives_a_refusing_delete() -> None:
    """A hardened build can throw on ``delete``; the script must still mask."""
    assert "try {" in HIDE_WEBDRIVER_SCRIPT
    assert "Object.defineProperty" in HIDE_WEBDRIVER_SCRIPT
    assert "configurable: true" in HIDE_WEBDRIVER_SCRIPT


def test_script_freezes_animations_and_caret() -> None:
    script = build_init_script(DeterminismOptions(freeze_animations=True))
    assert "animation-duration" in script
    assert "transition-duration" in script
    assert "caret-color" in script
    assert "0.001s" in script


def test_freeze_animations_can_be_disabled() -> None:
    script = build_init_script(DeterminismOptions(freeze_animations=False))
    assert "animation-duration" not in script


def test_animation_freeze_css_keeps_event_listeners_alive() -> None:
    # Zeroing durations (rather than disabling) keeps transitionend firing.
    assert "animation: none" not in ANIMATION_FREEZE_CSS
    assert "0.001s" in ANIMATION_FREEZE_CSS


def test_deterministic_random_installs_seeded_prng() -> None:
    script = build_init_script(
        DeterminismOptions(deterministic_random=True, random_seed=4242)
    )
    assert "Math.random = function" in script
    assert "(4242)" in script


def test_random_can_be_left_alone() -> None:
    script = build_init_script(DeterminismOptions(deterministic_random=False))
    assert "Math.random = function" not in script


def test_clock_anchor_uses_explicit_instant() -> None:
    script = build_init_script(
        DeterminismOptions(anchor_clock=True, frozen_time="2026-01-01T00:00:00Z")
    )
    assert "PatchedDate" in script
    assert "2026-01-01T00:00:00Z" in script
    # Timers must keep working: performance.now() is deliberately untouched.
    assert "performance.now" not in script


def test_clock_anchor_defaults_to_epoch() -> None:
    script = build_init_script(DeterminismOptions(anchor_clock=True))
    assert "PatchedDate" in script
    assert "(0)" in script


def test_clock_not_anchored_by_default() -> None:
    assert "PatchedDate" not in DEFAULT_INIT_SCRIPT


def test_automation_is_identified_by_default() -> None:
    script = DEFAULT_INIT_SCRIPT
    assert "__arenaSynthetic" in script
    assert "arena-api" in script


def test_identify_automation_can_be_disabled() -> None:
    script = build_init_script(DeterminismOptions(identify_automation=False))
    assert "__arenaSynthetic" not in script


def test_hooks_expose_settle_and_font_waiting() -> None:
    script = DEFAULT_INIT_SCRIPT
    assert "__arenaTestHooks" in script
    assert "waitForFonts" in script
    assert "requestAnimationFrame" in script
    assert "performance.mark" in script


def test_extra_hooks_are_injected_as_json() -> None:
    options = DeterminismOptions(extra_hooks={"build": "ci-42", "shard": 3})
    script = build_init_script(options)
    assert '"build": "ci-42"' in script
    assert '"shard": 3' in script


def test_hook_payload_is_json_serialisable() -> None:
    payload = DeterminismOptions(extra_hooks={"a": 1}).to_hook_payload()
    assert json.loads(json.dumps(payload))["random_seed"] == 1337


# --------------------------------------------------------------------------- #
# Browser environment options
# --------------------------------------------------------------------------- #


def test_context_kwargs_cover_locale_timezone_and_viewport() -> None:
    options = BrowserEnvironmentOptions(
        locale="de-DE",
        timezone_id="Europe/Berlin",
        viewport={"width": 1280, "height": 720},
    )
    kwargs = options.context_kwargs()
    assert kwargs["locale"] == "de-DE"
    assert kwargs["timezone_id"] == "Europe/Berlin"
    assert kwargs["viewport"] == {"width": 1280, "height": 720}
    assert kwargs["reduced_motion"] == "reduce"
    # navigator.languages is set by Playwright's locale option, not by a patch.
    assert "add_init_script" not in kwargs


def test_context_kwargs_announce_synthetic_monitoring() -> None:
    kwargs = BrowserEnvironmentOptions().context_kwargs()
    headers = kwargs["extra_http_headers"]
    assert headers[SYNTHETIC_MONITOR_HEADER].startswith("arena-api/")


def test_synthetic_header_can_be_overridden() -> None:
    options = BrowserEnvironmentOptions(
        extra_http_headers={SYNTHETIC_MONITOR_HEADER: "my-monitor/1.0"}
    )
    headers = options.context_kwargs()["extra_http_headers"]
    assert headers[SYNTHETIC_MONITOR_HEADER] == "my-monitor/1.0"


def test_identify_automation_can_be_turned_off() -> None:
    kwargs = BrowserEnvironmentOptions(identify_automation=False).context_kwargs()
    assert SYNTHETIC_MONITOR_HEADER not in kwargs.get("extra_http_headers", {})


def test_no_viewport_mode() -> None:
    kwargs = BrowserEnvironmentOptions(viewport=None).context_kwargs()
    assert kwargs["no_viewport"] is True


def test_launch_args_are_container_safe_by_default() -> None:
    kwargs = BrowserEnvironmentOptions().launch_kwargs()
    assert "--disable-dev-shm-usage" in kwargs["args"]
    assert kwargs["chromium_sandbox"] is True
    assert kwargs["headless"] is True


def test_disabling_the_sandbox_is_opt_in() -> None:
    kwargs = BrowserEnvironmentOptions(no_sandbox=True).launch_kwargs()
    assert kwargs["chromium_sandbox"] is False
    assert "--no-sandbox" not in kwargs["args"]


def test_artifacts_require_a_directory() -> None:
    environment = BrowserEnvironment(BrowserEnvironmentOptions())
    assert environment.artifacts_dir is None
    with pytest.raises(RuntimeError):
        environment._artifact_path("trace.zip")


def test_artifacts_dir_is_created_on_demand(tmp_path) -> None:
    environment = BrowserEnvironment(
        BrowserEnvironmentOptions(artifacts_dir=tmp_path / "nested")
    )
    path = environment._artifact_path("shot.png")
    assert path.parent.is_dir()
    assert path.name == "shot.png"


def test_unstarted_environment_reports_state() -> None:
    environment = BrowserEnvironment()
    assert environment.started is False
    with pytest.raises(RuntimeError):
        _ = environment.browser


def test_stamp_is_utc_and_sortable() -> None:
    first = BrowserEnvironment.stamp()
    second = BrowserEnvironment.stamp()
    assert first.endswith("Z")
    assert first <= second


def test_launch_kwargs_configures_playwright_proxy() -> None:
    assert "proxy" not in BrowserEnvironmentOptions().launch_kwargs()

    http_kwargs = BrowserEnvironmentOptions(
        proxy="http://127.0.0.1:10809"
    ).launch_kwargs()
    assert http_kwargs["proxy"] == {"server": "http://127.0.0.1:10809"}

    socks_kwargs = BrowserEnvironmentOptions(
        proxy="socks5h://alice:s%40cret@127.0.0.1:10808"
    ).launch_kwargs()
    assert socks_kwargs["proxy"] == {
        "server": "socks5://127.0.0.1:10808",
        "username": "alice",
        "password": "s@cret",
    }

    with pytest.raises(ValueError, match="Unsupported browser proxy"):
        BrowserEnvironmentOptions(proxy="ftp://127.0.0.1:21").launch_kwargs()


def test_hide_webdriver_script_sets_boolean_false_on_prototype() -> None:
    """Real Chromium/Edge exposes ``navigator.webdriver === false`` rather than ``undefined``."""
    assert "delete navigator.webdriver" in HIDE_WEBDRIVER_SCRIPT
    assert "delete proto.webdriver" not in HIDE_WEBDRIVER_SCRIPT
    assert "get: () => false" in HIDE_WEBDRIVER_SCRIPT


def test_context_kwargs_allows_native_host_locale_and_timezone() -> None:
    opts = BrowserEnvironmentOptions(locale=None, timezone_id=None)
    ctx_kwargs = opts.context_kwargs()
    assert "locale" not in ctx_kwargs
    assert "timezone_id" not in ctx_kwargs


def test_hide_webdriver_script_skips_redefine_when_already_false() -> None:
    """When ``--disable-blink-features=AutomationControlled`` sets native ``false``, keep C++ getter."""
    assert "if (navigator.webdriver === false)" in HIDE_WEBDRIVER_SCRIPT


def test_persistent_context_reuses_initial_page_and_closes_cleanly(
    tmp_path, monkeypatch
) -> None:
    import asyncio
    import sys
    import types

    launched_persistent: list[tuple[str, dict[str, object]]] = []
    closed_contexts: list[object] = []

    class FakePage:
        def __init__(self, tag: str) -> None:
            self.tag = tag
            self.init_scripts: list[str] = []

        async def add_init_script(self, script: str) -> None:
            self.init_scripts.append(script)

    class FakePersistentContext:
        def __init__(self) -> None:
            self.pages = [FakePage("initial-blank")]
            self.default_timeout: float | None = None
            self.nav_timeout: float | None = None

        def set_default_timeout(self, timeout: float) -> None:
            self.default_timeout = timeout

        def set_default_navigation_timeout(self, timeout: float) -> None:
            self.nav_timeout = timeout

        async def new_page(self) -> FakePage:
            page = FakePage(f"page-{len(self.pages)}")
            self.pages.append(page)
            return page

        async def close(self) -> None:
            closed_contexts.append(self)

    class FakeChromium:
        async def launch_persistent_context(self, user_data_dir: str, **kwargs: object):
            launched_persistent.append((user_data_dir, dict(kwargs)))
            return FakePersistentContext()

        async def launch(self, **kwargs: object):  # pragma: no cover
            raise AssertionError("ephemeral launch should not be used")

    class FakePlaywright:
        def __init__(self) -> None:
            self.chromium = FakeChromium()
            self.stopped = False

        async def stop(self) -> None:
            self.stopped = True

    pw_instance = FakePlaywright()

    class FakeAPIManager:
        async def start(self) -> FakePlaywright:
            return pw_instance

    fake_async_api = types.ModuleType("playwright.async_api")
    fake_async_api.async_playwright = lambda: FakeAPIManager()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright.async_api", fake_async_api)

    profile_dir = tmp_path / "direct_browser_profile"
    opts = BrowserEnvironmentOptions(
        user_data_dir=profile_dir,
        storage_state=tmp_path / "unused_state.json",
        locale=None,
        timezone_id=None,
        install_determinism_script=False,
    )
    p_kwargs = opts.persistent_context_kwargs()
    assert "storage_state" not in p_kwargs

    async def _exercise() -> tuple[FakePage, FakePage]:
        async with BrowserEnvironment(opts) as env:
            p1 = await env.new_page()
            p2 = await env.new_page()
            return p1, p2

    first_page, second_page = asyncio.run(_exercise())
    assert first_page.tag == "initial-blank"
    assert second_page.tag == "page-1"
    assert len(launched_persistent) == 1
    assert launched_persistent[0][0] == str(profile_dir)
    assert profile_dir.is_dir()
    assert len(closed_contexts) == 1
    assert pw_instance.stopped is True


def test_persistent_context_lock_falls_back_to_ephemeral_launch(
    tmp_path, monkeypatch
) -> None:
    import asyncio
    import sys
    import types

    ephemeral_launches: list[dict[str, object]] = []

    class FakeContext:
        pages: list[object] = []

        def set_default_timeout(self, timeout: float) -> None:
            return None

        def set_default_navigation_timeout(self, timeout: float) -> None:
            return None

        async def new_page(self) -> object:
            return types.SimpleNamespace(add_init_script=lambda **kw: None)

        async def close(self) -> None:
            return None

    class FakeBrowser:
        async def new_context(self, **kwargs: object) -> FakeContext:
            return FakeContext()

        async def close(self) -> None:
            return None

    class FakeChromium:
        async def launch_persistent_context(self, user_data_dir: str, **kwargs: object):
            raise RuntimeError(
                "Target page, context or browser has been closed: ProcessSingleton: The profile appears to be in use by another Google Chrome process"
            )

        async def launch(self, **kwargs: object) -> FakeBrowser:
            ephemeral_launches.append(dict(kwargs))
            return FakeBrowser()

    class FakePlaywright:
        chromium = FakeChromium()

        async def stop(self) -> None:
            return None

    class FakeAPIManager:
        async def start(self) -> FakePlaywright:
            return FakePlaywright()

    fake_async_api = types.ModuleType("playwright.async_api")
    fake_async_api.async_playwright = lambda: FakeAPIManager()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright.async_api", fake_async_api)

    opts = BrowserEnvironmentOptions(
        user_data_dir=tmp_path / "locked_profile",
        install_determinism_script=False,
    )

    async def _run() -> None:
        async with BrowserEnvironment(opts) as env:
            ctx = await env.new_context()
            assert isinstance(ctx, FakeContext)

    asyncio.run(_run())
    assert len(ephemeral_launches) == 1





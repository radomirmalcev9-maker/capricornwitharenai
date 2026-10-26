"""Lifecycle tests for the browser wrapper, login flow and session refresh.

No browser binary is needed. Playwright is swapped for a recording fake at the
``playwright.async_api`` boundary -- which is precisely where
:mod:`arena_api.auth.browser` imports it -- so the wrapper's real control flow
(start, context/page creation, tracing, artefact capture, teardown) runs
unchanged. These tests cover the paths that unit tests on plain objects cannot:
the actual sequencing of Playwright calls.
"""

from __future__ import annotations

import asyncio
import json
import sys
import types
from pathlib import Path

import pytest

from arena_api.auth.browser import BrowserEnvironment, BrowserEnvironmentOptions, run_sync
from arena_api.auth.kinematics import KinematicMouse, KinematicMouseSync, Point
from arena_api.auth.session import BrowserSessionManager, FormLoginFlow
from arena_api.exceptions import AuthenticationError, ChallengeRequiredError


# --------------------------------------------------------------------------- #
# Playwright fakes
# --------------------------------------------------------------------------- #


class FakeTracing:
    def __init__(self) -> None:
        self.started: list[dict] = []
        self.stopped: list[str] = []

    async def start(self, **kwargs) -> None:
        self.started.append(kwargs)

    async def stop(self, path: str | None = None) -> None:
        self.stopped.append(str(path))


class FakeMouse:
    def __init__(self) -> None:
        self.moves: list[tuple[float, float]] = []
        self.presses: list[str] = []
        self.wheels: list[tuple[float, float]] = []

    async def move(self, x: float, y: float) -> None:
        self.moves.append((x, y))

    async def down(self, button: str = "left") -> None:
        self.presses.append(f"down:{button}")

    async def up(self, button: str = "left") -> None:
        self.presses.append(f"up:{button}")

    async def wheel(self, dx: float, dy: float) -> None:
        self.wheels.append((dx, dy))


class FakeKeyboard:
    def __init__(self) -> None:
        self.typed: list[str] = []

    async def type(self, text: str) -> None:
        self.typed.append(text)

    async def press(self, key: str) -> None:
        self.typed.append(f"<{key}>")


class FakeLocator:
    """Locator stand-in used when a flow targets an element by selector."""

    def __init__(self, page: "FakePage", selector: str) -> None:
        self.page = page
        self.selector = selector
        self.box: dict[str, float] | None = {"x": 0.0, "y": 0.0, "width": 120.0, "height": 40.0}
        self.scrolled = False

    async def scroll_into_view_if_needed(self, timeout=None) -> None:
        self.scrolled = True

    async def bounding_box(self, timeout=None):
        return self.box


class FakePage:
    """Records every Playwright call the wrapper makes."""

    def __init__(self, context: "FakeContext | None" = None) -> None:
        self.context = context
        self.locators: list[FakeLocator] = []
        self.url = "https://example.test/app"
        self.frames: list = []
        self.mouse = FakeMouse()
        self.keyboard = FakeKeyboard()
        self.init_scripts: list[str] = []
        self.routes: list[tuple[str, object]] = []
        self.screenshots: list[dict] = []
        self.evaluations: list = []
        self.gotos: list[dict] = []
        self.fills: list[tuple[str, str]] = []
        self.checks: list[str] = []
        self.clicks: list[str] = []
        self.waited_selector: list = []
        self.waited_url: list = []
        self.waited_state: list = []
        self.listeners: dict[str, list] = {}
        self.evaluate_result: dict = {
            "selectors": [],
            "frames": [],
            "text": "",
            "title": "app",
        }
        self.evaluate_value: object = 1
        self.raise_on_evaluate: bool = False

    async def add_init_script(self, script: str | None = None, path: str | None = None) -> None:
        self.init_scripts.append(script or "")

    async def route(self, url: str, handler) -> None:
        self.routes.append((url, handler))

    async def evaluate(self, script: str, arg=None):
        if self.raise_on_evaluate:
            raise RuntimeError("evaluate exploded")
        if "visualViewport" in script:
            return self.evaluate_value
        self.evaluations.append(script)
        return self.evaluate_result

    async def goto(self, url: str, **kwargs) -> None:
        self.gotos.append({"url": url, **kwargs})

    async def fill(self, selector: str, value: str, **kwargs) -> None:
        self.fills.append((selector, value))

    async def check(self, selector: str, **kwargs) -> None:
        self.checks.append(selector)

    async def click(self, selector: str, **kwargs) -> None:
        self.clicks.append(selector)

    async def wait_for_selector(self, selector: str, **kwargs) -> None:
        self.waited_selector.append((selector, kwargs))

    async def wait_for_url(self, matcher, **kwargs) -> None:
        self.waited_url.append((matcher, kwargs))

    async def wait_for_load_state(self, state: str = "load", **kwargs) -> None:
        self.waited_state.append((state, kwargs))

    async def screenshot(self, path: str | None = None, **kwargs) -> bytes:
        self.screenshots.append({"path": path, **kwargs})
        if path:
            Path(path).write_bytes(b"\x89PNG\r\n\x1a\n")
        return b""

    async def content(self) -> str:
        return "<html><body>app</body></html>"

    def on(self, event: str, handler) -> None:
        self.listeners.setdefault(event, []).append(handler)

    def locator(self, selector: str) -> FakeLocator:
        locator = FakeLocator(self, selector)
        self.locators.append(locator)
        return locator


class FakeContext:
    def __init__(self, kwargs: dict) -> None:
        self.kwargs = kwargs
        self.pages: list[FakePage] = []
        self.closed = False
        self.timeouts: dict[str, float] = {}
        self.storage_calls: list[str | None] = []
        self.tracing = FakeTracing()
        self.storage_payload: dict = {
            "cookies": [
                {
                    "name": "session",
                    "value": "fresh",
                    "domain": "example.test",
                    "path": "/",
                    "secure": True,
                    "httpOnly": False,
                }
            ],
            "origins": [],
        }
        self.raise_on_close = False

    async def new_page(self) -> FakePage:
        page = FakePage(self)
        self.pages.append(page)
        return page

    def set_default_timeout(self, value: float) -> None:
        self.timeouts["default"] = value

    def set_default_navigation_timeout(self, value: float) -> None:
        self.timeouts["navigation"] = value

    async def storage_state(self, path: str | None = None) -> dict:
        self.storage_calls.append(path)
        if path:
            Path(path).write_text(json.dumps(self.storage_payload), encoding="utf-8")
        return self.storage_payload

    async def close(self) -> None:
        self.closed = True
        if self.raise_on_close:
            raise RuntimeError("context close failed")


class FakeBrowser:
    def __init__(self) -> None:
        self.launches: list[dict] = []
        self.contexts: list[FakeContext] = []
        self.closed = False

    async def new_context(self, **kwargs) -> FakeContext:
        context = FakeContext(kwargs)
        self.contexts.append(context)
        return context

    async def close(self) -> None:
        self.closed = True

    async def launch(self, **kwargs) -> "FakeBrowser":
        self.launches.append(kwargs)
        return self


class FakeChromium:
    def __init__(self, browser: FakeBrowser) -> None:
        self.browser = browser

    async def launch(self, **kwargs) -> FakeBrowser:
        self.browser.launches.append(kwargs)
        return self.browser


class FakePlaywright:
    def __init__(self, browser: FakeBrowser) -> None:
        self.chromium = FakeChromium(browser)
        self.stopped = False

    async def stop(self) -> None:
        self.stopped = True


class FakeStarter:
    def __init__(self, playwright: FakePlaywright) -> None:
        self.playwright = playwright

    async def start(self) -> FakePlaywright:
        return self.playwright


@pytest.fixture
def fake_playwright(monkeypatch):
    """Install a fake ``playwright.async_api`` and return the recorder."""
    browser = FakeBrowser()
    playwright = FakePlaywright(browser)
    module = types.ModuleType("playwright.async_api")
    module.async_playwright = lambda: FakeStarter(playwright)
    monkeypatch.setitem(sys.modules, "playwright.async_api", module)
    return browser


# --------------------------------------------------------------------------- #
# BrowserEnvironment lifecycle
# --------------------------------------------------------------------------- #


def test_start_launches_with_configured_options(fake_playwright, tmp_path) -> None:
    options = BrowserEnvironmentOptions(artifacts_dir=tmp_path, headless=True, slow_mo=5)

    async def scenario():
        async with BrowserEnvironment(options) as env:
            assert env.started is True
            assert env.browser is fake_playwright
        return env

    env = asyncio.run(scenario())
    assert fake_playwright.launches[0]["slow_mo"] == 5
    assert fake_playwright.launches[0]["chromium_sandbox"] is True
    assert fake_playwright.closed is True
    assert env.started is False


def test_double_start_is_idempotent(fake_playwright) -> None:
    async def scenario():
        env = BrowserEnvironment()
        await env.start()
        await env.start()
        assert len(fake_playwright.launches) == 1
        await env.close()

    asyncio.run(scenario())


def test_new_context_applies_defaults(fake_playwright) -> None:
    async def scenario():
        env = BrowserEnvironment(
            BrowserEnvironmentOptions(
                locale="fr-FR", timezone_id="Europe/Paris", default_timeout=1234.0
            )
        )
        context = await env.new_context()
        await env.close()
        return context

    context = asyncio.run(scenario())
    assert context.kwargs["locale"] == "fr-FR"
    assert context.kwargs["timezone_id"] == "Europe/Paris"
    assert context.timeouts == {"default": 1234.0, "navigation": 30_000.0}


def test_new_context_records_har_when_enabled(fake_playwright, tmp_path) -> None:
    async def scenario():
        env = BrowserEnvironment(
            BrowserEnvironmentOptions(artifacts_dir=tmp_path, record_har=True)
        )
        context = await env.new_context()
        await env.close()
        return context

    context = asyncio.run(scenario())
    assert context.kwargs["record_har_path"].endswith("network.har")
    assert context.kwargs["record_har_content"] == "omit"


def test_new_page_installs_the_determinism_script(fake_playwright) -> None:
    async def scenario():
        env = BrowserEnvironment()
        page = await env.new_page()
        await env.close()
        return page

    page = asyncio.run(scenario())
    assert len(page.init_scripts) == 1
    assert "Math.random = function" in page.init_scripts[0]
    assert "__arenaTestHooks" in page.init_scripts[0]


def test_determinism_script_can_be_disabled(fake_playwright) -> None:
    async def scenario():
        env = BrowserEnvironment(BrowserEnvironmentOptions(install_determinism_script=False))
        page = await env.new_page()
        await env.close()
        return page

    assert asyncio.run(scenario()).init_scripts == []


def test_extra_init_scripts_reach_the_page_before_navigation(fake_playwright) -> None:
    """The sign-in window needs its mask installed on the very first page."""
    mask = "/* webdriver mask */"

    async def scenario():
        env = BrowserEnvironment(
            BrowserEnvironmentOptions(
                install_determinism_script=False,
                extra_init_scripts=(mask,),
            )
        )
        page = await env.new_page()
        await env.close()
        return page

    page = asyncio.run(scenario())
    assert page.init_scripts == [mask]
    assert page.gotos == [], "the script is installed before anything is loaded"


def test_resource_blocking_aborts_only_the_configured_types(fake_playwright) -> None:
    async def scenario():
        env = BrowserEnvironment(
            BrowserEnvironmentOptions(block_resource_types=("media", "font"))
        )
        page = await env.new_page()
        await env.close()
        return page

    page = asyncio.run(scenario())
    assert len(page.routes) == 1
    _, handler = page.routes[0]

    class FakeRequest:
        def __init__(self, resource_type):
            self.resource_type = resource_type

    class FakeRoute:
        def __init__(self):
            self.aborted = False
            self.continued = False

        async def abort(self):
            self.aborted = True

        async def continue_(self):
            self.continued = True

    async def exercise(resource_type):
        route = FakeRoute()
        await handler(route, FakeRequest(resource_type))
        return route

    blocked = asyncio.run(exercise("media"))
    allowed = asyncio.run(exercise("script"))
    assert blocked.aborted is True and blocked.continued is False
    assert allowed.continued is True and allowed.aborted is False


def test_mouse_factory_returns_a_kinematic_mouse(fake_playwright) -> None:
    async def scenario():
        env = BrowserEnvironment()
        page = await env.new_page()
        mouse = env.mouse(page, seed=5)
        await env.close()
        return mouse

    assert isinstance(asyncio.run(scenario()), KinematicMouse)


def test_screenshot_writes_a_file_with_stabilisers(fake_playwright, tmp_path) -> None:
    async def scenario():
        env = BrowserEnvironment(BrowserEnvironmentOptions(artifacts_dir=tmp_path))
        page = await env.new_page()
        path = await env.screenshot(page, "shot.png")
        await env.close()
        return path, page.screenshots[0]

    path, call = asyncio.run(scenario())
    assert path.is_file()
    assert call["animations"] == "disabled"
    assert call["caret"] == "hide"
    assert call["full_page"] is True


def test_screenshot_stabilisers_can_be_overridden(fake_playwright, tmp_path) -> None:
    async def scenario():
        env = BrowserEnvironment(BrowserEnvironmentOptions(artifacts_dir=tmp_path))
        page = await env.new_page()
        await env.screenshot(page, "s.png", caret="initial", full_page=False)
        await env.close()
        return page.screenshots[0]

    call = asyncio.run(scenario())
    assert call["caret"] == "initial"
    assert call["full_page"] is False


def test_save_storage_state(fake_playwright, tmp_path) -> None:
    async def scenario():
        env = BrowserEnvironment(BrowserEnvironmentOptions(artifacts_dir=tmp_path))
        context = await env.new_context()
        path = await env.save_storage_state(context, "state.json")
        await env.close()
        return path

    path = asyncio.run(scenario())
    assert json.loads(path.read_text())["cookies"][0]["name"] == "session"


def test_close_stops_tracing_and_closes_everything(fake_playwright, tmp_path) -> None:
    async def scenario():
        env = BrowserEnvironment(
            BrowserEnvironmentOptions(artifacts_dir=tmp_path, record_trace=True)
        )
        context = await env.new_context()
        await env.new_page(context)
        await env.close()
        return context

    context = asyncio.run(scenario())
    assert context.tracing.started == [{"screenshots": True, "snapshots": True, "sources": True}]
    assert context.tracing.stopped and context.tracing.stopped[0].endswith("trace.zip")
    assert context.closed is True
    assert fake_playwright.closed is True


def test_close_survives_a_failing_context(fake_playwright) -> None:
    """Teardown must not mask the original failure."""
    async def scenario():
        env = BrowserEnvironment()
        context = await env.new_context()
        context.raise_on_close = True
        await env.close()
        return fake_playwright.closed

    assert asyncio.run(scenario()) is True


def test_close_before_start_is_a_no_op() -> None:
    asyncio.run(BrowserEnvironment().close())


def test_screenshot_on_close_captures_open_pages(fake_playwright, tmp_path) -> None:
    async def scenario():
        env = BrowserEnvironment(
            BrowserEnvironmentOptions(artifacts_dir=tmp_path, screenshot_on_close=True)
        )
        context = await env.new_context()
        await env.new_page(context)
        await env.close()
        return sorted(p.name for p in tmp_path.glob("close-page-*.png"))

    assert asyncio.run(scenario()) == ["close-page-0.png"]


# --------------------------------------------------------------------------- #
# run_sync
# --------------------------------------------------------------------------- #


def test_run_sync_without_a_running_loop() -> None:
    async def coroutine():
        return "done"

    assert run_sync(coroutine()) == "done"


def test_run_sync_from_inside_a_running_loop() -> None:
    """The blocking wrappers must work even when called from async code."""

    async def inner():
        return "from-thread"

    async def outer():
        return run_sync(inner())

    assert asyncio.run(outer()) == "from-thread"


def test_run_sync_propagates_exceptions() -> None:
    async def boom():
        raise ValueError("kaboom")

    with pytest.raises(ValueError, match="kaboom"):
        run_sync(boom())


# --------------------------------------------------------------------------- #
# FormLoginFlow
# --------------------------------------------------------------------------- #


def make_flow(**kwargs) -> FormLoginFlow:
    kwargs.setdefault("login_url", "https://example.test/login")
    kwargs.setdefault("username_selector", "#email")
    kwargs.setdefault("password_selector", "#password")
    kwargs.setdefault("submit_selector", "button[type=submit]")
    kwargs.setdefault("username", "user")
    kwargs.setdefault("password", "secret")
    return FormLoginFlow(**kwargs)


def test_login_flow_fills_and_submits() -> None:
    page = FakePage()
    asyncio.run(make_flow().run(page))
    assert page.gotos[0]["url"] == "https://example.test/login"
    assert page.fills == [("#email", "user"), ("#password", "secret")]
    assert page.clicks == ["button[type=submit]"]
    assert page.waited_state[0][0] == "networkidle"


def test_login_flow_waits_for_a_success_selector() -> None:
    page = FakePage()
    flow = make_flow(success_selector="[data-authenticated]")
    asyncio.run(flow.run(page))
    assert page.waited_selector[0][0] == "[data-authenticated]"
    assert page.waited_selector[0][1]["state"] == "visible"


def test_login_flow_waits_for_a_success_url() -> None:
    page = FakePage()
    flow = make_flow(success_url_contains="/app")
    asyncio.run(flow.run(page))
    matcher = page.waited_url[0][0]
    assert matcher("https://example.test/app") is True
    assert matcher("https://example.test/login") is False


def test_login_flow_checks_remember_me_when_configured() -> None:
    page = FakePage()
    flow = make_flow(remember_selector="#remember")
    asyncio.run(flow.run(page))
    assert page.checks == ["#remember"]


def test_login_flow_can_drive_the_form_with_kinematic_input() -> None:
    page = FakePage()
    flow = make_flow(human_input=True, success_selector="main")
    asyncio.run(flow.run(page))
    assert "".join(c for c in page.keyboard.typed if len(c) == 1) == "usersecret"
    assert page.mouse.moves, "kinematic mode must move the pointer"
    assert page.mouse.presses[:2] == ["down:left", "up:left"]
    assert page.fills == []
    # Fields and the submit button are all targeted by selector, in order,
    # and each is scrolled into view before its box is measured.
    assert [locator.selector for locator in page.locators] == [
        "#email",
        "#password",
        "button[type=submit]",
    ]
    assert all(locator.scrolled for locator in page.locators)


# --------------------------------------------------------------------------- #
# Session refresh
# --------------------------------------------------------------------------- #


class FakeEnvironment:
    """Stands in for BrowserEnvironment during a refresh."""

    instances: list["FakeEnvironment"] = []
    #: Set by tests that need the login to yield an empty cookie jar.
    storage_payload_override: dict | None = None

    def __init__(self, options, page: FakePage | None = None) -> None:
        self.options = options
        self.page = page or FakePage()
        self.context = FakeContext({})
        if FakeEnvironment.storage_payload_override is not None:
            self.context.storage_payload = FakeEnvironment.storage_payload_override
        self.entered = False
        self.exited = False
        FakeEnvironment.instances.append(self)

    async def __aenter__(self) -> "FakeEnvironment":
        self.entered = True
        return self

    async def __aexit__(self, *exc_info) -> None:
        self.exited = True

    async def new_context(self, **kwargs) -> FakeContext:
        return self.context

    async def new_page(self, context=None, **kwargs) -> FakePage:
        return self.page


@pytest.fixture
def patch_environment(monkeypatch):
    FakeEnvironment.instances.clear()
    FakeEnvironment.storage_payload_override = None
    from arena_api.auth import session as session_module

    page = FakePage()
    monkeypatch.setattr(
        session_module, "BrowserEnvironment", lambda options: FakeEnvironment(options, page)
    )
    return page


def test_refresh_runs_the_login_flow_and_persists_state(patch_environment, tmp_path) -> None:
    manager = BrowserSessionManager(
        base_url="https://example.test",
        storage_path=tmp_path / "state.json",
        login_flow=make_flow(),
    )
    cookies = asyncio.run(manager.arefresh_session())
    assert cookies == {"session": "fresh"}
    assert (tmp_path / "state.json").is_file()

    environment = FakeEnvironment.instances[0]
    assert environment.entered is True and environment.exited is True
    assert environment.options.storage_state == tmp_path / "state.json"
    assert environment.context.storage_calls == [str(tmp_path / "state.json")]
    # The refresh path installs challenge detection on the page it drives.
    assert "response" in patch_environment.listeners


def test_refresh_without_storage_path_keeps_state_in_memory(patch_environment) -> None:
    manager = BrowserSessionManager(
        base_url="https://example.test", login_flow=make_flow()
    )
    cookies = asyncio.run(manager.arefresh_session())
    assert cookies == {"session": "fresh"}
    assert FakeEnvironment.instances[0].context.storage_calls == [None]


def test_refresh_aborts_when_a_challenge_appears(patch_environment, tmp_path) -> None:
    page = patch_environment
    page.evaluate_result = {
        "selectors": [".cf-turnstile"],
        "frames": [],
        "text": "Just a moment",
        "title": "Just a moment",
    }
    manager = BrowserSessionManager(
        base_url="https://example.test",
        storage_path=tmp_path / "state.json",
        login_flow=make_flow(),
    )
    with pytest.raises(ChallengeRequiredError) as caught:
        asyncio.run(manager.arefresh_session())
    assert "challenge" in str(caught.value).lower()
    assert not (tmp_path / "state.json").exists(), "no state is persisted on a challenge"


def test_refresh_fails_when_the_login_yields_no_cookies(patch_environment, tmp_path) -> None:
    """A completed login that produced no cookies is a failure, not a success."""
    FakeEnvironment.storage_payload_override = {"cookies": [], "origins": []}
    manager = BrowserSessionManager(
        base_url="https://example.test",
        storage_path=tmp_path / "state.json",
        login_flow=make_flow(),
    )
    with pytest.raises(AuthenticationError, match="no cookies"):
        asyncio.run(manager.arefresh_session())
    assert patch_environment.gotos, "the login flow must still have run"


def test_blocking_refresh_uses_the_thread_safe_helper(patch_environment, tmp_path) -> None:
    manager = BrowserSessionManager(
        base_url="https://example.test",
        storage_path=tmp_path / "state.json",
        login_flow=make_flow(),
    )
    assert manager.refresh_session() == {"session": "fresh"}


def test_blocking_refresh_works_from_inside_a_running_loop(patch_environment, tmp_path) -> None:
    manager = BrowserSessionManager(
        base_url="https://example.test",
        storage_path=tmp_path / "state.json",
        login_flow=make_flow(),
    )

    async def outer():
        return manager.refresh_session()

    assert asyncio.run(outer()) == {"session": "fresh"}


def test_refresh_without_a_login_flow_is_refused(tmp_path) -> None:
    manager = BrowserSessionManager(
        base_url="https://example.test", storage_path=tmp_path / "state.json"
    )
    with pytest.raises(AuthenticationError, match="login_flow"):
        asyncio.run(manager.arefresh_session())


def test_ensure_valid_refreshes_then_revalidates(patch_environment, tmp_path) -> None:
    """The full loop: stale -> refresh -> re-validate -> cookies returned."""
    from arena_api.auth.session import RawResponse

    manager = BrowserSessionManager(
        base_url="https://example.test",
        storage_path=tmp_path / "state.json",
        login_flow=make_flow(),
        max_refresh_attempts=1,
    )
    calls: list[dict] = []

    class RecordingProbe:
        def __call__(self, url, *, cookies, headers, timeout):
            calls.append(dict(cookies))
            status = 200 if cookies.get("session") == "fresh" else 401
            return RawResponse(status, {"content-type": "text/html"}, "<html></html>")

    manager.probe = RecordingProbe()
    cookies = asyncio.run(manager.aensure_valid())
    assert cookies == {"session": "fresh"}
    assert calls == [{}, {"session": "fresh"}], (
        "the first probe runs with no cookies, the second with the refreshed ones"
    )


def test_ensure_valid_gives_up_after_the_configured_attempts(patch_environment, tmp_path) -> None:
    from arena_api.auth.session import RawResponse

    FakeEnvironment.storage_payload_override = {"cookies": [], "origins": []}
    manager = BrowserSessionManager(
        base_url="https://example.test",
        storage_path=tmp_path / "state.json",
        login_flow=make_flow(),
        max_refresh_attempts=2,
        probe=lambda url, *, cookies, headers, timeout: RawResponse(
            401, {"content-type": "text/html"}, "<html></html>"
        ),
    )
    with pytest.raises(AuthenticationError):
        asyncio.run(manager.aensure_valid())


# --------------------------------------------------------------------------- #
# Remaining kinematics surface
# --------------------------------------------------------------------------- #


def test_async_drag_presses_travels_and_releases() -> None:
    page = FakePage()
    mouse = KinematicMouse(page, seed=3)

    async def scenario():
        return await mouse.drag_to(Point(10, 10), Point(300, 200))

    trajectory = asyncio.run(scenario())
    assert page.mouse.presses == ["down:left", "up:left"]
    assert page.mouse.moves[0] != page.mouse.moves[-1]
    assert trajectory.samples[-1].x == 300


def test_async_scroll_emits_discrete_wheel_events() -> None:
    page = FakePage()
    mouse = KinematicMouse(page, seed=3)
    asyncio.run(mouse.scroll_by(0, 500, steps=5))
    assert len(page.mouse.wheels) == 5
    assert sum(dy for _, dy in page.mouse.wheels) == pytest.approx(500)


def test_sync_drag_and_typing() -> None:
    class SyncPage:
        def __init__(self):
            self.mouse = SyncMouse()
            self.keyboard = SyncKeyboard()

    class SyncMouse:
        def __init__(self):
            self.moves = []
            self.presses = []

        def move(self, x, y):
            self.moves.append((x, y))

        def down(self, button="left"):
            self.presses.append("down")

        def up(self, button="left"):
            self.presses.append("up")

        def wheel(self, dx, dy):
            self.moves.append((dx, dy))

    class SyncKeyboard:
        def __init__(self):
            self.typed = []

        def type(self, text):
            self.typed.append(text)

        def press(self, key):
            self.typed.append(f"<{key}>")

    page = SyncPage()
    mouse = KinematicMouseSync(page, seed=4)
    mouse.drag_to(Point(0, 0), Point(120, 90))
    assert page.mouse.presses == ["down", "up"]
    mouse.type_text(Point(1, 1), "hi", press_enter=True)
    assert page.keyboard.typed[-1] == "<Enter>"
    mouse.scroll_by(0, 200, steps=2)
    assert len(page.mouse.moves) > 2


def test_sync_element_resolution_uses_the_box_centre() -> None:
    from arena_api.auth.kinematics import resolve_element_center_sync

    class Locator:
        page = types.SimpleNamespace(evaluate=lambda script: 1)

        def scroll_into_view_if_needed(self, timeout=None):
            return None

        def bounding_box(self, timeout=None):
            return {"x": 10.0, "y": 20.0, "width": 40.0, "height": 10.0}

    assert resolve_element_center_sync(Locator()) == Point(30.0, 25.0)


def test_trajectory_geometry_helpers() -> None:
    from arena_api.auth.kinematics import TrajectoryPlanner

    trajectory = TrajectoryPlanner(seed=8).plan((0, 0), (400, 0))
    assert len(trajectory) == len(trajectory.samples)
    assert list(trajectory) == list(trajectory.samples)
    assert trajectory.length >= trajectory.distance
    assert trajectory.straightness >= 1.0


def test_selector_string_without_a_page_raises_a_clear_error() -> None:
    from arena_api.auth.kinematics import (
        resolve_element_center,
        resolve_element_center_sync,
    )

    with pytest.raises(ValueError, match="needs a page"):
        asyncio.run(resolve_element_center("#email"))
    with pytest.raises(ValueError, match="needs a page"):
        resolve_element_center_sync("#email")


def test_selector_string_resolves_against_the_supplied_page() -> None:
    from arena_api.auth.kinematics import resolve_element_center

    class Locator:
        def __init__(self, page):
            self.page = page

        async def scroll_into_view_if_needed(self, timeout=None):
            return None

        async def bounding_box(self, timeout=None):
            return {"x": 0.0, "y": 0.0, "width": 100.0, "height": 50.0}

    class Page:
        def locator(self, selector):
            self.selector = selector
            return Locator(self)

        async def evaluate(self, script):
            return 1

    page = Page()
    centre = asyncio.run(resolve_element_center("#email", page=page))
    assert page.selector == "#email"
    assert centre == Point(50.0, 25.0)

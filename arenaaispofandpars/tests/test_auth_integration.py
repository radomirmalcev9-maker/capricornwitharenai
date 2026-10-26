"""Integration tests: real HTTP + real curl_cffi, and Playwright API conformance.

Two kinds of check live here.

1. **Live HTTP.** A threaded :mod:`http.server` is started on an ephemeral
   port and the *real* :class:`~arena_api.auth.session.CurlCffiProbe` makes
   real requests against it. This exercises request construction, cookie
   handling, redirect following, status classification and challenge
   detection over an actual socket -- everything short of a browser.

2. **Playwright API conformance.** No browser binary is required to prove the
   wrapper speaks the right API: the keyword arguments it generates are bound
   against the real ``playwright.async_api`` signatures, so a renamed or
   mistyped option fails here instead of at 3 a.m. in CI.
"""

from __future__ import annotations

import inspect
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from arena_api.auth.browser import BrowserEnvironmentOptions
from arena_api.auth.challenge import ChallengeHandler, ChallengeKind
from arena_api.auth.session import (
    BrowserSessionManager,
    CurlCffiProbe,
    SessionValidation,
)
from arena_api.exceptions import ChallengeRequiredError

pytest.importorskip("curl_cffi")

CHALLENGE_PAGE = (
    "<!doctype html><html><head><title>Just a moment...</title></head><body>"
    "Checking if the site connection is secure"
    "<iframe src='https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/orchestrate'"
    "></iframe></body></html>"
)

CLEAN_PAGE = "<!doctype html><html><body><h1>Dashboard</h1></body></html>"


class _Handler(BaseHTTPRequestHandler):
    """Routes used by the live tests."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:  # keep pytest output clean
        return None

    def _send(self, status: int, body: bytes, headers: dict[str, str]) -> None:
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        route = self.path.split("?", 1)[0]
        cookie = self.headers.get("Cookie", "")

        if route == "/api/me":
            if "session=good" in cookie:
                body = json.dumps({"user": "tester"}).encode()
                self._send(200, body, {"Content-Type": "application/json"})
            else:
                self._send(401, b'{"error":"unauthorized"}', {"Content-Type": "application/json"})
        elif route == "/challenge":
            self._send(
                403,
                CHALLENGE_PAGE.encode(),
                {
                    "Content-Type": "text/html; charset=utf-8",
                    "CF-Mitigated": "challenge",
                    "Server": "cloudflare",
                    "CF-RAY": "deadbeef-LHR",
                },
            )
        elif route == "/limited":
            self._send(429, CLEAN_PAGE.encode(), {"Content-Type": "text/html"})
        elif route == "/redirect":
            self._send(302, b"", {"Location": "/ok"})
        elif route == "/ok":
            self._send(200, CLEAN_PAGE.encode(), {"Content-Type": "text/html"})
        elif route == "/echo":
            payload = {
                "headers": {key: value for key, value in self.headers.items()},
                "path": self.path,
                "cookies": cookie,
            }
            body = json.dumps(payload).encode()
            self._send(200, body, {"Content-Type": "application/json"})
        elif route == "/login":
            self._send(
                200,
                CLEAN_PAGE.encode(),
                {
                    "Content-Type": "text/html",
                    "Set-Cookie": "session=good; Path=/; HttpOnly",
                },
            )
        else:
            self._send(404, b"not found", {"Content-Type": "text/plain"})


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.fixture
def origin(server) -> str:
    host, port = server.server_address[:2]
    return f"http://{host}:{port}"


def make_manager(origin: str, **kwargs) -> BrowserSessionManager:
    kwargs.setdefault("probe", CurlCffiProbe())
    return BrowserSessionManager(base_url=origin, storage_path=None, **kwargs)


# --------------------------------------------------------------------------- #
# Live validation over a real socket
# --------------------------------------------------------------------------- #


def test_live_probe_accepts_a_valid_session(origin: str) -> None:
    manager = make_manager(origin, validate_paths=("/api/me",))
    manager.import_cookies({"session": "good"})
    result = manager.validate()
    assert result.ok is True, result.describe()
    assert result.status == 200
    assert result.latency > 0


def test_live_probe_rejects_a_stale_session(origin: str) -> None:
    manager = make_manager(origin, validate_paths=("/api/me",))
    manager.import_cookies({"session": "stale"})
    result = manager.validate()
    assert result.ok is False
    assert result.status == 401
    assert "expired" in result.reason


def test_live_probe_detects_a_challenge_response(origin: str) -> None:
    manager = make_manager(origin, validate_paths=("/challenge",))
    result = manager.validate()
    assert result.ok is False
    assert result.challenge is not None
    assert result.challenge.kind is ChallengeKind.CLOUDFLARE_MANAGED
    assert result.challenge.headers.get("CF-Ray") or result.challenge.headers.get("cf-ray")


def test_live_probe_detects_rate_limiting(origin: str) -> None:
    manager = make_manager(origin, validate_paths=("/limited",))
    result = manager.validate()
    assert result.ok is False
    assert "rate limited" in result.reason


def test_live_probe_follows_redirects(origin: str) -> None:
    manager = make_manager(origin, validate_paths=("/redirect",))
    assert manager.validate().status == 200


def test_live_probe_sends_the_configured_headers(origin: str) -> None:
    """The headers we build must actually reach the wire."""
    manager = make_manager(origin, validate_paths=("/echo",))
    manager.import_cookies({"session": "good"})

    captured: dict = {}

    class EchoProbe:
        def __call__(self, url, *, cookies, headers, timeout):
            captured.update({"url": url, "cookies": cookies, "headers": headers})
            return CurlCffiProbe()(
                url, cookies=cookies, headers=headers, timeout=timeout
            )

    manager.probe = EchoProbe()
    result = manager.validate()
    assert result.ok is True
    body = json.loads(CurlCffiProbe()(origin + "/echo", cookies={}, headers={}, timeout=5).body)
    assert body["path"] == "/echo"

    manager.probe = EchoProbe()
    manager.validate()
    assert captured["headers"]["User-Agent"].startswith("Mozilla/5.0")
    assert captured["headers"]["Sec-Fetch-Mode"] == "navigate"
    assert captured["cookies"] == {"session": "good"}


def test_live_headers_are_visible_to_the_server(origin: str) -> None:
    """Ask the server what it received, rather than trusting our own copy."""
    probe = CurlCffiProbe()
    manager = make_manager(origin, validate_paths=("/echo",))
    response = probe(
        origin + "/echo",
        cookies={"session": "good"},
        headers=manager.headers(navigation=True),
        timeout=10.0,
    )
    echo = json.loads(response.body)
    assert echo["headers"]["User-Agent"] == manager.headers(navigation=True)["User-Agent"]
    assert "session=good" in echo["cookies"]


def test_ensure_valid_raises_a_challenge_error_live(origin: str, tmp_path: Path) -> None:
    handler = ChallengeHandler(capture_dir=tmp_path, raise_on_detection=False)
    manager = make_manager(
        origin, validate_paths=("/challenge",), challenge_handler=handler
    )
    with pytest.raises(ChallengeRequiredError) as caught:
        manager.ensure_valid()
    message = str(caught.value)
    assert "challenge" in message.lower()
    assert "allowlist" in message.lower()


def test_session_export_round_trip_is_loadable(origin: str, tmp_path: Path) -> None:
    manager = BrowserSessionManager(
        base_url=origin, storage_path=tmp_path / "state.json"
    )
    manager.import_cookies({"session": "good"})
    exported = manager.export_cookies(tmp_path / "cookies.json")
    payload = json.loads(exported.read_text())
    assert payload[0] == {
        "name": "session",
        "value": "good",
        "domain": manager.host,
        "path": "/",
    }
    # The exported file is in the shape the README documents for cookies=.
    from arena_api import normalize_cookies

    assert normalize_cookies(str(exported)) == {"session": "good"}


def test_cookie_domain_excludes_the_port(origin: str) -> None:
    """Staging origins run on odd ports; cookie domains carry no port."""
    manager = make_manager(origin)
    assert ":" not in manager.host
    assert manager.domains == (manager.host,)
    manager.import_cookies({"session": "good"})
    assert manager.load_cookies() == {"session": "good"}


def test_validation_object_is_serialisable_for_logging(origin: str) -> None:
    manager = make_manager(origin, validate_paths=("/api/me",))
    manager.import_cookies({"session": "good"})
    result: SessionValidation = manager.validate()
    assert "ok [200]" in result.describe()


# --------------------------------------------------------------------------- #
# Playwright API conformance (no browser binary needed)
# --------------------------------------------------------------------------- #


def _bind(function, *args, **kwargs):
    """Bind ``args``/``kwargs`` against the real Playwright signature.

    ``None`` stands in for ``self``, which the generated API methods all take.
    """
    return inspect.signature(function).bind(None, *args, **kwargs)


def test_launch_kwargs_bind_to_the_real_api() -> None:
    from playwright.async_api import BrowserType

    for options in (
        BrowserEnvironmentOptions(),
        BrowserEnvironmentOptions(no_sandbox=True, channel="chromium", slow_mo=50),
    ):
        _bind(BrowserType.launch, **options.launch_kwargs())


def test_context_kwargs_bind_to_the_real_api() -> None:
    from playwright.async_api import Browser

    options = BrowserEnvironmentOptions(
        locale="de-DE",
        timezone_id="Europe/Berlin",
        viewport={"width": 800, "height": 600},
        device_scale_factor=2.0,
        user_agent="ua/1.0",
        reduced_motion="reduce",
        color_scheme="dark",
        forced_colors="active",
        java_script_enabled=True,
        extra_http_headers={"X-Test": "1"},
        storage_state="/tmp/state.json",
    )
    _bind(Browser.new_context, **options.context_kwargs())


def test_context_kwargs_bind_with_har_recording() -> None:
    from playwright.async_api import Browser

    kwargs = BrowserEnvironmentOptions().context_kwargs()
    kwargs["record_har_path"] = "/tmp/net.har"
    kwargs["record_har_content"] = "omit"
    _bind(Browser.new_context, **kwargs)


def test_context_kwargs_bind_with_no_viewport() -> None:
    from playwright.async_api import Browser

    _bind(Browser.new_context, **BrowserEnvironmentOptions(viewport=None).context_kwargs())


def test_tracing_and_screenshot_kwargs_bind_to_the_real_api() -> None:
    from playwright._impl._tracing import Tracing
    from playwright.async_api import Page

    _bind(Tracing.start, screenshots=True, snapshots=True, sources=True)
    _bind(Tracing.stop, path="/tmp/trace.zip")
    _bind(Page.add_init_script, script="void 0;")
    _bind(Page.screenshot, path="/tmp/shot.png", animations="disabled", caret="hide", full_page=True)


def test_route_and_timeout_calls_bind_to_the_real_api() -> None:
    from playwright.async_api import BrowserContext, Page

    _bind(BrowserContext.set_default_timeout, 30_000.0)
    _bind(BrowserContext.set_default_navigation_timeout, 30_000.0)
    _bind(BrowserContext.storage_state, path="/tmp/state.json")
    _bind(Page.route, url="**/*", handler=lambda route: None)
    _bind(BrowserContext.new_page)

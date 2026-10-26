from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from arena_api import (
    ArenaClient,
    AsyncArenaClient,
    AuthenticationError,
    ChallengeRequiredError,
    FirefoxSessionError,
    FirefoxSessionManager,
    SessionManager,
)

CONFIG = {
    "dependencies": [
        {"fn_index": 4, "api_name": "chat", "queue": True},
    ],
    "components": [
        {
            "type": "dropdown",
            "props": {"label": "Model", "choices": [["m1", "Model One"]]},
        }
    ],
}


class StubSessionManager:
    """Minimal SessionManager implementation for deterministic tests."""

    def __init__(
        self,
        cookies: dict[str, str] | None = None,
        *,
        refresh_cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.cookies = dict(cookies or {})
        self.refresh_cookies = (
            dict(refresh_cookies)
            if refresh_cookies is not None
            else {"session": "fresh"}
        )
        self.headers = headers or {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) "
            "Gecko/20100101 Firefox/141.0",
            "Sec-GPC": "1",
        }
        self.refreshes: list[BaseException | None] = []

    def load_cookies(self, domains=None) -> dict[str, str]:
        return dict(self.cookies)

    def firefox_headers(self, *, navigation: bool = False) -> dict[str, str]:
        return dict(self.headers)

    def refresh_session(
        self, reason: BaseException | None = None
    ) -> dict[str, str] | None:
        self.refreshes.append(reason)
        return dict(self.refresh_cookies)


class DecliningSessionManager(StubSessionManager):
    def refresh_session(
        self, reason: BaseException | None = None
    ) -> dict[str, str] | None:
        self.refreshes.append(reason)
        return None


class AsyncMockTransport(httpx.AsyncBaseTransport):
    def __init__(self, handler):
        self.handler = handler

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return self.handler(request)


def _response(
    request: httpx.Request,
    status: int,
    body: bytes,
    content_type: str = "application/json",
) -> httpx.Response:
    return httpx.Response(
        status, request=request, headers={"content-type": content_type}, content=body
    )


def test_stub_satisfies_the_session_manager_protocol() -> None:
    assert isinstance(StubSessionManager(), SessionManager)
    assert isinstance(FirefoxSessionManager(interactive=False), SessionManager)
    assert not isinstance("firefox", SessionManager)


def test_client_applies_session_cookies_and_headers_at_start() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _response(request, 200, json.dumps(CONFIG).encode())

    stub = StubSessionManager(
        {"session": "initial", "cf_clearance": "cf"},
        headers={"User-Agent": "Firefox-Test-UA", "Sec-GPC": "1"},
    )
    client = ArenaClient(
        base_url="https://arena.test",
        cookies={"session": "user-supplied", "extra": "static"},
        session_source=stub,
        http_transport=httpx.MockTransport(handler),
    )
    try:
        assert client.session_manager is stub
        assert [model.id for model in client.get_models()] == ["m1"]
        assert len(requests) == 1
        cookie_header = requests[0].headers.get("cookie")
        # Session cookies overlay the static mapping; static extras survive.
        assert "session=initial" in cookie_header
        assert "extra=static" in cookie_header
        assert "user-supplied" not in cookie_header
        assert requests[0].headers.get("user-agent") == "Firefox-Test-UA"
        assert requests[0].headers.get("sec-gpc") == "1"
    finally:
        client.close()


def test_client_refreshes_and_retries_once_on_403() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return _response(request, 403, b"Forbidden", "text/plain")
        return _response(request, 200, json.dumps(CONFIG).encode())

    stub = StubSessionManager({"session": "stale"})
    client = ArenaClient(
        base_url="https://arena.test",
        session_source=stub,
        http_transport=httpx.MockTransport(handler),
    )
    try:
        assert [model.id for model in client.get_models()] == ["m1"]
        assert len(requests) == 2
        assert len(stub.refreshes) == 1
        assert isinstance(stub.refreshes[0], AuthenticationError)
        assert "session=fresh" in requests[1].headers.get("cookie")
    finally:
        client.close()


def test_client_refreshes_on_challenge_page_with_200_status() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return _response(
                request,
                200,
                b"<html><title>Just a moment...</title></html>",
                "text/html",
            )
        return _response(request, 200, json.dumps(CONFIG).encode())

    stub = StubSessionManager({"session": "stale"})
    client = ArenaClient(
        base_url="https://arena.test",
        session_source=stub,
        http_transport=httpx.MockTransport(handler),
    )
    try:
        assert [model.id for model in client.get_models()] == ["m1"]
        assert len(requests) == 2
        assert isinstance(stub.refreshes[0], ChallengeRequiredError)
    finally:
        client.close()


def test_client_stream_retries_after_refresh_on_join_403() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/queue/join":
            if len(requests) == 1:
                return _response(request, 403, b"Forbidden", "text/plain")
            return _response(request, 200, b"{}")
        if request.url.path == "/queue/data":
            events = [
                {"msg": "process_generating", "output": {"data": ["Hel"]}},
                {"msg": "process_completed", "output": {"data": ["Hello"]}},
            ]
            body = "".join(f"data: {json.dumps(e)}\n\n" for e in events).encode()
            return _response(request, 200, body, "text/event-stream")
        raise AssertionError(f"unexpected request: {request.url}")

    stub = StubSessionManager({"session": "stale"})
    client = ArenaClient(
        base_url="https://arena.test",
        chat_fn_index=4,
        session_source=stub,
        http_transport=httpx.MockTransport(handler),
    )
    try:
        assert client.complete("prompt") == "Hello"
        assert [request.url.path for request in requests] == [
            "/queue/join",
            "/queue/join",
            "/queue/data",
        ]
        assert "session=fresh" in requests[1].headers.get("cookie")
    finally:
        client.close()


def test_client_gives_up_after_exhausted_refresh_attempts() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _response(request, 403, b"Forbidden", "text/plain")

    stub = StubSessionManager({"session": "stale"})
    client = ArenaClient(
        base_url="https://arena.test",
        session_source=stub,
        max_auth_refreshes=1,
        http_transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(AuthenticationError):
            client.get_models()
        assert len(requests) == 2  # initial + one refreshed retry
        assert len(stub.refreshes) == 1
    finally:
        client.close()


def test_client_without_refresh_budget_raises_immediately() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _response(request, 403, b"Forbidden", "text/plain")

    stub = StubSessionManager({"session": "stale"})
    client = ArenaClient(
        base_url="https://arena.test",
        session_source=stub,
        max_auth_refreshes=0,
        http_transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(AuthenticationError):
            client.get_models()
        assert len(requests) == 1
        assert stub.refreshes == []
    finally:
        client.close()


def test_declined_refresh_surfaces_the_original_error() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _response(request, 403, b"Forbidden", "text/plain")

    stub = DecliningSessionManager({"session": "stale"})
    client = ArenaClient(
        base_url="https://arena.test",
        session_source=stub,
        http_transport=httpx.MockTransport(handler),
    )
    try:
        with pytest.raises(AuthenticationError):
            client.get_models()
        assert len(requests) == 1
        assert len(stub.refreshes) == 1
    finally:
        client.close()


def test_403_without_session_source_never_retries() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _response(request, 403, b"Forbidden", "text/plain")

    client = ArenaClient(
        base_url="https://arena.test",
        http_transport=httpx.MockTransport(handler),
    )
    try:
        assert client.session_manager is None
        with pytest.raises(AuthenticationError):
            client.get_models()
        assert len(requests) == 1
    finally:
        client.close()


def test_invalid_session_sources_are_rejected() -> None:
    with pytest.raises(ValueError, match="Unsupported session_source"):
        ArenaClient(base_url="https://arena.test", session_source="chrome")
    with pytest.raises(TypeError):
        ArenaClient(
            base_url="https://arena.test", session_source=123  # type: ignore[arg-type]
        )


def test_empty_session_cookies_fail_fast() -> None:
    stub = StubSessionManager({})
    with pytest.raises(AuthenticationError, match="No cookies"):
        ArenaClient(
            base_url="https://arena.test",
            session_source=stub,
            http_transport=httpx.MockTransport(
                lambda request: _response(request, 200, b"{}")
            ),
        )


def test_async_client_refreshes_and_retries_on_403() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return _response(request, 403, b"Forbidden", "text/plain")
        return _response(request, 200, json.dumps(CONFIG).encode())

    async def run() -> None:
        stub = StubSessionManager({"session": "stale"})
        client = AsyncArenaClient(
            base_url="https://arena.test",
            session_source=stub,
            http_transport=AsyncMockTransport(handler),
        )
        async with client:
            assert client.session_manager is stub
            assert [model.id for model in await client.get_models()] == ["m1"]
            assert len(requests) == 2
            assert len(stub.refreshes) == 1
            assert "session=fresh" in requests[1].headers.get("cookie")

    asyncio.run(run())


def test_async_client_stream_retries_after_refresh() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/queue/join":
            if len(requests) == 1:
                return _response(request, 403, b"Forbidden", "text/plain")
            return _response(request, 200, b"{}")
        if request.url.path == "/queue/data":
            event = {"msg": "process_completed", "output": {"data": ["ok"]}}
            return _response(
                request,
                200,
                f"data: {json.dumps(event)}\n\n".encode(),
                "text/event-stream",
            )
        raise AssertionError(f"unexpected request: {request.url}")

    async def run() -> None:
        stub = StubSessionManager({"session": "stale"})
        client = AsyncArenaClient(
            base_url="https://arena.test",
            chat_fn_index=4,
            session_source=stub,
            http_transport=AsyncMockTransport(handler),
        )
        async with client:
            assert await client.acomplete("prompt") == "ok"
            assert [request.url.path for request in requests] == [
                "/queue/join",
                "/queue/join",
                "/queue/data",
            ]

    asyncio.run(run())


def test_async_declined_refresh_surfaces_the_original_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _response(request, 403, b"Forbidden", "text/plain")

    async def run() -> None:
        stub = DecliningSessionManager({"session": "stale"})
        client = AsyncArenaClient(
            base_url="https://arena.test",
            session_source=stub,
            http_transport=AsyncMockTransport(handler),
        )
        async with client:
            with pytest.raises(AuthenticationError):
                await client.get_models()
            assert len(stub.refreshes) == 1

    asyncio.run(run())


def test_transport_validates_max_auth_refreshes() -> None:
    from arena_api.transport import ArenaTransport

    with pytest.raises(ValueError, match="max_auth_refreshes"):
        ArenaTransport(
            "https://arena.test", max_auth_refreshes=-1, http_transport=None
        )


def test_session_cookies_replace_removed_ones_on_refresh() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return _response(request, 403, b"Forbidden", "text/plain")
        return _response(request, 200, json.dumps(CONFIG).encode())

    stub = StubSessionManager(
        {"session": "stale", "removed_by_browser": "old"},
        refresh_cookies={"session": "fresh"},  # removed_by_browser is gone
    )
    client = ArenaClient(
        base_url="https://arena.test",
        session_source=stub,
        http_transport=httpx.MockTransport(handler),
    )
    try:
        client.get_models()
        cookie_header = requests[1].headers.get("cookie")
        assert "session=fresh" in cookie_header
        assert "removed_by_browser" not in cookie_header
    finally:
        client.close()


def test_empty_session_cookies_name_the_custom_source() -> None:
    """A non-Firefox manager must not be blamed on a Firefox profile."""
    stub = StubSessionManager({})
    with pytest.raises(AuthenticationError) as info:
        ArenaClient(base_url="https://arena.test", session_source=stub)
    message = str(info.value)
    assert "StubSessionManager" in message
    assert "Firefox profile" not in message
    assert "Sign in to https://arena.test" in message


def test_empty_firefox_session_still_points_at_the_profile(monkeypatch) -> None:
    """The ``"firefox"`` shortcut keeps its profile-specific remediation."""

    class EmptyFirefox(FirefoxSessionManager):
        def load_cookies(self, domains=None):
            return {}

    monkeypatch.setattr("arena_api.client.FirefoxSessionManager", EmptyFirefox)
    with pytest.raises(AuthenticationError) as info:
        ArenaClient(base_url="https://arena.test", session_source="firefox")
    message = str(info.value)
    assert "local Firefox profile" in message
    assert "Open https://arena.test in Firefox" in message


def test_unreadable_custom_source_is_not_blamed_on_firefox(monkeypatch) -> None:
    class Broken:
        def load_cookies(self, domains=None):
            raise FirefoxSessionError("cookie store is locked")

        def firefox_headers(self, *, navigation: bool = False):
            return {}

        def refresh_session(self, reason=None):
            return None

    with pytest.raises(AuthenticationError) as info:
        ArenaClient(base_url="https://arena.test", session_source=Broken())
    message = str(info.value)
    assert "Broken" in message
    assert "cookie store is locked" in message
    assert "Could not read the session from" in message

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from arena_api.exceptions import (
    ArenaError,
    AuthenticationError,
    ChallengeRequiredError,
    ClientClosedError,
    ProtocolError,
    RateLimitError,
)
from arena_api.transport import (
    ArenaTransport,
    AsyncArenaTransport,
    SSEParser,
    _raise_for_status,
    normalize_cookies,
    parse_cookie_header,
)


def test_parse_cookie_header_preserves_equals_and_values() -> None:
    assert parse_cookie_header(" session=abc== ; cf_clearance=xyz; empty= ") == {
        "session": "abc==",
        "cf_clearance": "xyz",
        "empty": "",
    }


def test_normalize_cookies_supports_browser_exports_and_json_files(tmp_path) -> None:
    assert normalize_cookies({"cookie": "session=one; other=two"}) == {
        "session": "one",
        "other": "two",
    }
    assert normalize_cookies({"session": 123}) == {"session": "123"}
    path = tmp_path / "cookies.json"
    path.write_text(
        json.dumps(
            {
                "cookies": [
                    {"name": "session", "value": "from-file", "domain": "arena.ai"}
                ]
            }
        ),
        encoding="utf-8",
    )
    assert normalize_cookies(path) == {"session": "from-file"}
    assert normalize_cookies(str(path)) == {"session": "from-file"}


def test_sse_parser_handles_split_utf8_multiline_and_crlf() -> None:
    wire = "event: token\r\ndata: Привет\r\ndata: мир\r\n\r\n: heartbeat\r\n"
    encoded = wire.encode("utf-8")
    parser = SSEParser()
    events = []
    for byte in encoded:
        events.extend(parser.feed(bytes([byte])))
    events.extend(parser.close())
    assert events == [("token", "Привет\nмир")]


def test_sse_parser_flushes_unterminated_final_event() -> None:
    parser = SSEParser()
    assert parser.feed(b'data: {"ok": true}') == []
    assert parser.close() == [("message", '{"ok": true}')]
    assert parser.close() == []


def test_http_status_errors_map_to_public_exceptions() -> None:
    with pytest.raises(ChallengeRequiredError):
        _raise_for_status(403, "", {"cf-mitigated": "challenge"})
    with pytest.raises(ChallengeRequiredError):
        _raise_for_status(503, "<html>Just a moment... challenge-platform</html>")
    with pytest.raises(AuthenticationError):
        _raise_for_status(401)
    with pytest.raises(RateLimitError) as raised:
        _raise_for_status(429, headers={"retry-after": "5"})
    assert raised.value.retry_after == 5


def test_transport_sse_stream_and_cookie_header() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("cookie") == "session=secret"
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=b'event: process_completed\ndata: {"msg":"process_completed"}\n\n',
        )

    transport = ArenaTransport(
        "https://arena.test",
        cookies={"session": "secret"},
        http_transport=httpx.MockTransport(handler),
    )
    try:
        assert list(
            transport.sse("/queue/data", params={"session_hash": "a"}, timeout=2)
        ) == [("process_completed", {"msg": "process_completed"})]
    finally:
        transport.close()


def test_transport_blocks_redirects_to_protect_cookie_credentials() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            302,
            request=request,
            headers={"location": "https://other.test/collect"},
        )

    transport = ArenaTransport(
        "https://arena.test", http_transport=httpx.MockTransport(handler)
    )
    try:
        with pytest.raises(ProtocolError, match="redirected"):
            transport.get_text("/config")
        assert calls == 1
    finally:
        transport.close()


def test_transport_reports_interactive_challenge_without_retrying() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            403,
            headers={"cf-mitigated": "challenge"},
            content=b"challenge",
        )

    transport = ArenaTransport(
        "https://arena.test", http_transport=httpx.MockTransport(handler)
    )
    try:
        with pytest.raises(ChallengeRequiredError):
            list(transport.sse("/queue/data", params={}, timeout=1))
        assert calls == 1
    finally:
        transport.close()


def _json_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            request=request,
            headers={"content-type": "application/json"},
            content=b"{}",
        )

    return httpx.MockTransport(handler)


def test_requests_through_a_closed_sync_transport_are_library_errors() -> None:
    transport = ArenaTransport("https://arena.test", http_transport=_json_transport())
    transport.close()
    transport.close()  # idempotent
    with pytest.raises(ClientClosedError) as info:
        transport.get_json("/config")
    assert isinstance(info.value, ArenaError)
    assert "closed" in str(info.value)


def test_streams_through_a_closed_sync_transport_are_library_errors() -> None:
    transport = ArenaTransport("https://arena.test", http_transport=_json_transport())
    transport.close()
    with pytest.raises(ClientClosedError):
        with transport.stream_request("GET", "/queue/data"):
            pass  # pragma: no cover - the guard fires before the body runs


def test_closed_transport_still_reports_its_url() -> None:
    transport = ArenaTransport("https://arena.test", http_transport=_json_transport())
    transport.close()
    assert transport.url("/config") == "https://arena.test/config"


def test_requests_through_a_closed_async_transport_are_library_errors() -> None:
    async def run() -> list[str]:
        transport = AsyncArenaTransport(
            "https://arena.test", http_transport=_json_transport()
        )
        await transport.close()
        await transport.close()  # idempotent
        errors = []
        try:
            await transport.get_json("/config")
        except ClientClosedError as exc:
            errors.append(f"request: {exc}")
        try:
            async with transport.stream_request("GET", "/queue/data"):
                pass  # pragma: no cover
        except ClientClosedError as exc:
            errors.append(f"stream: {exc}")
        return errors

    errors = asyncio.run(run())
    assert len(errors) == 2, errors


def test_nextjs_404_and_passive_jsd_beacon_are_not_misread_as_challenges() -> None:
    """Cloudflare injects ``/cdn-cgi/challenge-platform/scripts/jsd/main.js`` into
    normal origin 200/404 HTML pages, and Next.js bundles mention ``turnstile``.
    Neither is a blocking challenge screen."""
    nextjs_html = (
        "<!DOCTYPE html><html><head><title>404: This page could not be found.</title>"
        '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
        "</head><body><div>404</div>"
        "<script>a.src='/cdn-cgi/challenge-platform/scripts/jsd/main.js';</script>"
        "</body></html>"
    )
    with pytest.raises(ArenaError, match="HTTP 404") as exc_info:
        _raise_for_status(404, nextjs_html, {"server": "cloudflare", "content-type": "text/html"})
    assert not isinstance(exc_info.value, ChallengeRequiredError)

    def ok_page(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            request=request,
            headers={"content-type": "text/html", "server": "cloudflare"},
            content=nextjs_html.encode("utf-8"),
        )

    with ArenaTransport("https://arena.test", http_transport=httpx.MockTransport(ok_page)) as tr:
        assert "404" in tr.get_text("/text/direct")


def test_raise_for_status_preserves_json_detail_and_separates_verification_rejections() -> None:
    with pytest.raises(AuthenticationError, match="User not found"):
        _raise_for_status(401, '{"message": "User not found"}')

    with pytest.raises(ProtocolError, match="recaptcha validation failed") as exc_info:
        _raise_for_status(403, '{"error": "recaptcha validation failed"}')
    assert not isinstance(exc_info.value, AuthenticationError)

    with pytest.raises(ArenaError, match="modelAId is invalid"):
        _raise_for_status(400, '{"error": {"message": "modelAId is invalid"}}')


def test_stream_request_skips_session_refresh_on_recaptcha_403_and_regenerates_body_on_401() -> None:
    refreshes = 0

    def refresher(_exc: BaseException) -> dict[str, str]:
        nonlocal refreshes
        refreshes += 1
        return {"session": f"fresh-{refreshes}"}

    def recaptcha_403_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            request=request,
            headers={"content-type": "application/json"},
            content=b'{"error":"recaptcha token score too low"}',
        )

    with ArenaTransport(
        "https://arena.test",
        session_cookies={"session": "initial"},
        session_refresher=refresher,
        http_transport=httpx.MockTransport(recaptcha_403_handler),
    ) as tr:
        with pytest.raises(ProtocolError, match="recaptcha token score too low"):
            with tr.stream_request("POST", "/nextjs-api/stream/create-evaluation"):
                pass  # pragma: no cover
    assert refreshes == 0

    seen_bodies: list[str] = []

    def auth_401_then_200(request: httpx.Request) -> httpx.Response:
        seen_bodies.append(request.content.decode("utf-8"))
        if len(seen_bodies) == 1:
            return httpx.Response(
                401,
                request=request,
                headers={"content-type": "application/json"},
                content=b'{"message":"User not found"}',
            )
        return httpx.Response(
            200,
            request=request,
            headers={"content-type": "text/event-stream"},
            content=b'a0:"ok"\n',
        )

    counter = 0

    def make_body() -> str:
        nonlocal counter
        counter += 1
        return json.dumps({"recaptchaV3Token": f"tok-{counter}"})

    with ArenaTransport(
        "https://arena.test",
        session_cookies={"session": "stale"},
        session_refresher=refresher,
        http_transport=httpx.MockTransport(auth_401_then_200),
    ) as tr:
        with tr.stream_request(
            "POST",
            "/nextjs-api/stream/create-evaluation",
            content_factory=make_body,
        ) as resp:
            assert resp.read() == b'a0:"ok"\n'

    assert refreshes == 1
    assert [json.loads(b)["recaptchaV3Token"] for b in seen_bodies] == [
        "tok-1",
        "tok-2",
    ]



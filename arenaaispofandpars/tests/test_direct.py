from __future__ import annotations

import asyncio
import json
import uuid

import httpx

from arena_api import (
    AsyncDirectArenaClient,
    DirectArenaClient,
    GenerationConfig,
    ProtocolError,
)
from arena_api.direct import AIDataStreamParser, _models_from_markup

MODEL_ID = "12345678-1234-1234-1234-123456789abc"
PAGE = (
    '<html><script id="__NEXT_DATA__" type="application/json">'
    + json.dumps(
        {
            "props": {
                "pageProps": {"models": [{"id": MODEL_ID, "publicName": "Model A"}]}
            }
        }
    )
    + "</script></html>"
)


class AsyncMockTransport(httpx.AsyncBaseTransport):
    def __init__(self, handler):
        self.handler = handler

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return self.handler(request)


def test_ai_data_parser_handles_split_utf8_and_final_record() -> None:
    parser = AIDataStreamParser()
    wire = 'a0:"Привет"\na0:" мир"\nad:{"finishReason":"stop"}'
    result = []
    for byte in wire.encode():
        result.extend(parser.feed(bytes([byte])))
    result.extend(parser.close())
    assert result == [
        ("a0", "Привет"),
        ("a0", " мир"),
        ("ad", {"finishReason": "stop"}),
    ]


def test_model_parser_handles_json_scripts_and_escaped_flight_data() -> None:
    assert _models_from_markup(PAGE)[0].display_name == "Model A"
    escaped = (
        r"{\"id\":\"12345678-1234-1234-1234-123456789abc\",\"publicName\":\"Model B\"}"
    )
    models = _models_from_markup(escaped)
    assert models[0].display_name == "Model B"
    flight_payload = json.dumps(json.dumps({"id": MODEL_ID, "publicName": "Model C"}))
    flight_page = f"<script>self.__next_f.push([1,{flight_payload}]);</script>"
    assert _models_from_markup(flight_page)[0].display_name == "Model C"


def test_sync_direct_stream_uses_supplied_token_and_isolates_chat_id() -> None:
    calls: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/text/direct":
            return httpx.Response(
                200,
                request=request,
                headers={"content-type": "text/html"},
                content=PAGE.encode(),
            )
        if request.url.path == "/nextjs-api/stream/create-evaluation":
            payload = json.loads(request.content)
            calls.append(payload)
            return httpx.Response(
                200,
                request=request,
                headers={"content-type": "text/plain"},
                content=b'a0:"Hello"\na0:" there"\nad:{"finishReason":"stop"}\n',
            )
        raise AssertionError(request.url)

    client = DirectArenaClient(
        base_url="https://arena.test",
        verification_token="caller-supplied-token",
        http_transport=httpx.MockTransport(handler),
    )
    try:
        chat_one = client.chat(model="Model A")
        assert chat_one.send_message("Hi") == "Hello there"
        assert chat_one.turn_id == 1
        assert client.chat(model="Model A").conversation_id is None
        assert calls[0]["recaptchaV3Token"] == "caller-supplied-token"
        assert uuid.UUID(calls[0]["id"]).version == 7
    finally:
        client.close()


def test_direct_stream_requires_a_completion_record() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/text/direct":
            return httpx.Response(
                200,
                request=request,
                content=PAGE.encode(),
                headers={"content-type": "text/html"},
            )
        if request.url.path == "/nextjs-api/stream/create-evaluation":
            return httpx.Response(
                200,
                request=request,
                content=b'a0:"partial"\n',
                headers={"content-type": "text/plain"},
            )
        raise AssertionError(request.url)

    client = DirectArenaClient(
        base_url="https://arena.test",
        verification_token="provided-token",
        http_transport=httpx.MockTransport(handler),
    )
    try:
        try:
            list(client.stream("Hi", model="Model A"))
        except ProtocolError as exc:
            assert "completion" in str(exc)
        else:
            raise AssertionError("an unterminated stream should fail")
    finally:
        client.close()


def test_async_direct_stream_and_session() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/text/direct":
            return httpx.Response(
                200,
                request=request,
                headers={"content-type": "text/html"},
                content=PAGE.encode(),
            )
        if request.url.path == "/nextjs-api/stream/create-evaluation":
            return httpx.Response(
                200,
                request=request,
                headers={"content-type": "text/plain"},
                content=b'0:"Async answer"\nd:{"finishReason":"stop"}\n',
            )
        raise AssertionError(request.url)

    async def run() -> None:
        client = AsyncDirectArenaClient(
            base_url="https://arena.test",
            verification_token=lambda: "fresh-caller-value",
            http_transport=AsyncMockTransport(handler),
        )
        async with client:
            chat = client.chat(
                model="Model A", config=GenerationConfig(temperature=0.3)
            )
            assert await chat.send_message("Hi") == "Async answer"
            assert chat.turn_id == 1
            assert len(chat.history) == 2

    asyncio.run(run())


def test_direct_stream_parses_ai_frames_over_event_stream_and_preserves_repeated_prefixes() -> None:
    seen_content_types: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/text/direct":
            return httpx.Response(
                200,
                request=request,
                headers={"content-type": "text/html"},
                content=PAGE.encode(),
            )
        if request.url.path == "/nextjs-api/stream/create-evaluation":
            seen_content_types.append(request.headers.get("content-type", ""))
            return httpx.Response(
                200,
                request=request,
                headers={"content-type": "text/event-stream; charset=utf-8"},
                content=(
                    b'a0:"1"\n'
                    b'a2:[{"type":"heartbeat"}]\n'
                    b'a0:"100"\n'
                    b'ad:{"finishReason":"stop"}\n'
                ),
            )
        raise AssertionError(request.url)

    with DirectArenaClient(
        base_url="https://arena.test",
        verification_token="tok",
        http_transport=httpx.MockTransport(handler),
    ) as client:
        assert client.complete("Count", model="Model A") == "1100"
    assert seen_content_types == ["application/json"]


def test_direct_stream_still_parses_standard_sse_events() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/text/direct":
            return httpx.Response(
                200,
                request=request,
                headers={"content-type": "text/html"},
                content=PAGE.encode(),
            )
        if request.url.path == "/nextjs-api/stream/create-evaluation":
            return httpx.Response(
                200,
                request=request,
                headers={"content-type": "text/event-stream"},
                content=b'data: {"delta": "SSE "}\n\ndata: {"delta": "ok"}\n\ndata: [DONE]\n\n',
            )
        raise AssertionError(request.url)

    with DirectArenaClient(
        base_url="https://arena.test",
        verification_token="tok",
        http_transport=httpx.MockTransport(handler),
    ) as client:
        assert client.complete("Hi", model="Model A") == "SSE ok"


def test_direct_stream_surfaces_a3_and_arena_error_frames() -> None:
    payloads = [
        b'a3:"reCAPTCHA token rejected"\n',
        b'a0:"hasArenaError"\nad:{"finishReason":"stop"}\n',
        b'ad:{"finishReason":"error"}\n',
    ]
    for wire in payloads:
        def handler(request: httpx.Request, body: bytes = wire) -> httpx.Response:
            if request.url.path == "/text/direct":
                return httpx.Response(
                    200,
                    request=request,
                    headers={"content-type": "text/html"},
                    content=PAGE.encode(),
                )
            return httpx.Response(
                200,
                request=request,
                headers={"content-type": "text/event-stream"},
                content=body,
            )

        with DirectArenaClient(
            base_url="https://arena.test",
            verification_token="tok",
            http_transport=httpx.MockTransport(handler),
        ) as client:
            try:
                client.complete("Hi", model="Model A")
            except ProtocolError:
                pass
            else:
                raise AssertionError(f"expected ProtocolError for {wire!r}")


def test_resolve_model_prefers_ranked_chat_uuid_over_webdev_twin() -> None:
    webdev_uuid = "11111111-1111-1111-1111-111111111111"
    chat_uuid = "22222222-2222-2222-2222-222222222222"
    twin_page = (
        '<html><script id="__NEXT_DATA__" type="application/json">'
        + json.dumps(
            {
                "props": {
                    "pageProps": {
                        "models": [
                            {
                                "id": webdev_uuid,
                                "publicName": "gemini-2.5-flash",
                                "userSelectable": False,
                                "capabilities": {
                                    "inputCapabilities": {"text": True},
                                    "outputCapabilities": {"text": False, "web": True},
                                },
                                "rankByModality": {"chat": 9007199254740991},
                            },
                            {
                                "id": chat_uuid,
                                "publicName": "gemini-2.5-flash",
                                "userSelectable": True,
                                "capabilities": {
                                    "inputCapabilities": {"text": True},
                                    "outputCapabilities": {"text": True},
                                },
                                "rankByModality": {"chat": 3},
                            },
                        ]
                    }
                }
            }
        )
        + "</script></html>"
    )
    chosen_ids: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/text/direct":
            return httpx.Response(
                200,
                request=request,
                headers={"content-type": "text/html"},
                content=twin_page.encode(),
            )
        payload = json.loads(request.content)
        chosen_ids.append(payload["modelAId"])
        return httpx.Response(
            200,
            request=request,
            headers={"content-type": "text/event-stream"},
            content=b'a0:"ok"\nad:{"finishReason":"stop"}\n',
        )

    with DirectArenaClient(
        base_url="https://arena.test",
        verification_token="tok",
        http_transport=httpx.MockTransport(handler),
    ) as client:
        assert client.complete("Hi", model="gemini-2.5-flash") == "ok"
    assert chosen_ids == [chat_uuid]


def test_direct_multi_turn_uses_post_to_evaluation_and_sends_origin_referer() -> None:
    paths: list[str] = []
    ids: list[str] = []
    headers_seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/text/direct":
            return httpx.Response(
                200,
                request=request,
                headers={"content-type": "text/html"},
                content=PAGE.encode(),
            )
        paths.append(request.url.path)
        payload = json.loads(request.content)
        ids.append(payload["id"])
        headers_seen.append(
            (request.headers.get("origin", ""), request.headers.get("referer", ""))
        )
        return httpx.Response(
            200,
            request=request,
            headers={"content-type": "text/event-stream"},
            content=b'a0:"ok"\nad:{"finishReason":"stop"}\n',
        )

    with DirectArenaClient(
        base_url="https://arena.test",
        verification_token="tok",
        http_transport=httpx.MockTransport(handler),
    ) as client:
        assert client.complete("One", model="Model A") == "ok"
        assert client.complete("Two", model="Model A") == "ok"
        assert ids[0] != ids[1]

        chat = client.chat(model="Model A")
        assert chat.send_message("Turn 1") == "ok"
        assert chat.send_message("Turn 2") == "ok"

    assert paths[2] == "/nextjs-api/stream/create-evaluation"
    assert paths[3] == f"/nextjs-api/stream/post-to-evaluation/{chat.conversation_id}"
    assert headers_seen[0] == (
        "https://arena.test",
        "https://arena.test/text/direct?model_a=max",
    )


def test_direct_client_attaches_cx_and_remints_token_on_auth_refresh() -> None:
    from arena_api.direct import PROGRAMMATIC_CX

    class StubManager:
        def __init__(self) -> None:
            self.refresh_calls = 0

        def load_cookies(self, domains=None) -> dict[str, str]:
            return {"arena-auth-prod-v1.0": "initial"}

        def firefox_headers(self, *, navigation: bool = False) -> dict[str, str]:
            return {}

        def refresh_session(self, reason: BaseException | None = None) -> dict[str, str]:
            self.refresh_calls += 1
            return {"arena-auth-prod-v1.0": f"refreshed-{self.refresh_calls}"}

    sent_payloads: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/text/direct":
            return httpx.Response(
                200,
                request=request,
                headers={"content-type": "text/html"},
                content=PAGE.encode(),
            )
        payload = json.loads(request.content)
        sent_payloads.append(payload)
        if len(sent_payloads) == 1:
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
            content=b'a0:"Recovered"\nad:{"finishReason":"stop"}\n',
        )

    minted = iter(["v3-first", "v3-second"])
    manager = StubManager()
    with DirectArenaClient(
        base_url="https://arena.test",
        session_source=manager,
        verification_token=lambda: next(minted),
        http_transport=httpx.MockTransport(handler),
    ) as client:
        assert client.complete("Ping", model="Model A") == "Recovered"

    assert manager.refresh_calls == 1
    assert [p["recaptchaV3Token"] for p in sent_payloads] == [
        "v3-first",
        "v3-second",
    ]
    assert sent_payloads[0]["cx"] == PROGRAMMATIC_CX
    assert sent_payloads[0]["userMessageId"] != sent_payloads[1]["userMessageId"]


def test_direct_client_does_not_loop_session_refresh_on_recaptcha_403() -> None:
    class StubManager:
        def __init__(self) -> None:
            self.refresh_calls = 0

        def load_cookies(self, domains=None) -> dict[str, str]:
            return {"arena-auth-prod-v1.0": "valid"}

        def firefox_headers(self, *, navigation: bool = False) -> dict[str, str]:
            return {}

        def refresh_session(self, reason: BaseException | None = None) -> dict[str, str]:
            self.refresh_calls += 1
            return {"arena-auth-prod-v1.0": "still-valid"}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/text/direct":
            return httpx.Response(
                200,
                request=request,
                headers={"content-type": "text/html"},
                content=PAGE.encode(),
            )
        return httpx.Response(
            403,
            request=request,
            headers={"content-type": "application/json"},
            content=b'{"error":"reCAPTCHA verification failed"}',
        )

    manager = StubManager()
    with DirectArenaClient(
        base_url="https://arena.test",
        session_source=manager,
        verification_token="tok",
        http_transport=httpx.MockTransport(handler),
    ) as client:
        try:
            client.complete("Ping", model="Model A")
        except ProtocolError as exc:
            assert "reCAPTCHA verification failed" in str(exc)
        else:
            raise AssertionError("expected ProtocolError")
    assert manager.refresh_calls == 0




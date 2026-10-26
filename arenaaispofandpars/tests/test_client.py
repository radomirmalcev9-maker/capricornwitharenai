from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from arena_api import (
    ArenaClient,
    AsyncArenaClient,
    BattleResponse,
    ChatSession,
    ModelInfo,
    ModelUnavailableError,
    ProtocolError,
    QueueTimeoutError,
    StreamChunk,
)
from arena_api.client import _find_endpoint, _models_from_config

CONFIG = {
    "dependencies": [
        {"fn_index": 4, "api_name": "chat", "queue": True},
        {"fn_index": 8, "api_name": "battle", "queue": True},
        {"fn_index": 9, "api_name": "direct_predict", "queue": False},
    ],
    "components": [
        {
            "type": "dropdown",
            "props": {
                "label": "Model",
                "choices": [["m1", "Model One"], ["m2", "Model Two"]],
            },
        },
        {
            "type": "dropdown",
            "props": {"label": "Language", "choices": ["English", "French"]},
        },
    ],
}


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


def test_endpoint_discovery_distinguishes_chat_and_battle() -> None:
    assert _find_endpoint(CONFIG, "chat").fn_index == 4
    assert _find_endpoint(CONFIG, "battle").fn_index == 8
    assert _models_from_config(CONFIG) == [
        ModelInfo(id="m1", display_name="Model One"),
        ModelInfo(id="m2", display_name="Model Two"),
    ]


def test_battle_discovery_requires_an_explicit_battle_callback() -> None:
    with pytest.raises(ModelUnavailableError):
        _find_endpoint(
            {"dependencies": [{"api_name": "chat", "queue": True}]}, "battle"
        )


def test_sync_stream_uses_join_hash_and_reconstructs_deltas() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/config":
            return _response(request, 200, json.dumps(CONFIG).encode())
        if request.url.path == "/queue/join":
            payload = json.loads(request.content)
            captured["join"] = payload
            return _response(request, 200, b"{}")
        if request.url.path == "/queue/data":
            captured["query"] = request.url.params.get("session_hash")
            events = [
                {
                    "msg": "process_generating",
                    "output": {"data": [[["user", "prompt"], ["assistant", "Hel"]]]},
                },
                {
                    "msg": "process_generating",
                    "output": {"data": [[["user", "prompt"], ["assistant", "Hello"]]]},
                },
                {
                    "msg": "process_completed",
                    "output": {"data": [[["user", "prompt"], ["assistant", "Hello"]]]},
                },
            ]
            body = "".join(
                f"data: {json.dumps(event)}\n\n" for event in events
            ).encode()
            return _response(request, 200, body, "text/event-stream")
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = ArenaClient(
        base_url="https://arena.test", http_transport=httpx.MockTransport(handler)
    )
    try:
        chunks = list(client.stream("prompt"))
        assert "".join(chunk.delta for chunk in chunks) == "Hello"
        assert chunks[-1].finished is True
        join = captured["join"]
        assert isinstance(join, dict)
        assert join["fn_index"] == 4
        assert join["session_hash"] == captured["query"]
        assert len(join["session_hash"]) == 32
    finally:
        client.close()


def test_explicit_callback_index_does_not_require_config_fetch() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/queue/join":
            assert json.loads(request.content)["fn_index"] == 17
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

    client = ArenaClient(
        base_url="https://arena.test",
        chat_fn_index=17,
        http_transport=httpx.MockTransport(handler),
    )
    try:
        assert client.complete("prompt") == "ok"
    finally:
        client.close()


def test_chat_session_sends_previous_turn_and_rolls_back_on_failure() -> None:
    joins: list[dict[str, object]] = []
    prompt_index = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal prompt_index
        if request.url.path == "/config":
            return _response(request, 200, json.dumps(CONFIG).encode())
        if request.url.path == "/queue/join":
            payload = json.loads(request.content)
            joins.append(payload)
            prompt_index += 1
            return _response(request, 200, b"{}")
        if request.url.path == "/queue/data":
            text = "Ada" if prompt_index == 2 else "Hello"
            event = {
                "msg": "process_completed",
                "output": {"data": [["user", "prompt"], ["assistant", text]]},
            }
            return _response(
                request,
                200,
                f"data: {json.dumps(event)}\n\n".encode(),
                "text/event-stream",
            )
        raise AssertionError(request.url)

    client = ArenaClient(
        base_url="https://arena.test", http_transport=httpx.MockTransport(handler)
    )
    try:
        chat = client.chat()
        assert chat.send_message("My name is Ada.") == "Hello"
        assert chat.send_message("What is my name?") == "Ada"
        assert chat.turn_id == 2
        assert [message.role for message in chat.history] == [
            "user",
            "assistant",
            "user",
            "assistant",
        ]
        second_data = joins[1]["data"]
        assert isinstance(second_data, list)
        extra = second_data[-1]
        assert isinstance(extra, dict)
        assert [item["content"] for item in extra["history"]] == [
            "My name is Ada.",
            "Hello",
        ]
    finally:
        client.close()


def test_chat_session_rolls_back_partial_turn_without_completion() -> None:
    class PartialClient:
        def stream(self, prompt, *, model=None, config=None, history=()):
            yield StreamChunk(
                text="partial", delta="partial", event="process_generating"
            )

    chat = ChatSession(PartialClient())
    with pytest.raises(ProtocolError):
        list(chat.stream_message("question"))
    assert chat.history == []
    assert chat.turn_id == 0
    assert chat.parent_message_id is None


def test_battle_returns_both_answers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/config":
            return _response(request, 200, json.dumps(CONFIG).encode())
        if request.url.path == "/queue/join":
            return _response(request, 200, b"{}")
        if request.url.path == "/queue/data":
            event = {
                "msg": "process_completed",
                "output": {"data": ["left answer", "right answer"]},
            }
            return _response(
                request,
                200,
                f"data: {json.dumps(event)}\n\n".encode(),
                "text/event-stream",
            )
        raise AssertionError(request.url)

    client = ArenaClient(
        base_url="https://arena.test", http_transport=httpx.MockTransport(handler)
    )
    try:
        result = client.battle("question", left_model="A", right_model="B")
        assert result == BattleResponse("left answer", "right answer", "A", "B")
    finally:
        client.close()


def test_stream_raises_if_queue_ends_without_terminal_event() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/config":
            return _response(request, 200, json.dumps(CONFIG).encode())
        if request.url.path == "/queue/join":
            return _response(request, 200, b"{}")
        if request.url.path == "/queue/data":
            event = {"msg": "process_generating", "output": {"data": ["partial"]}}
            return _response(
                request,
                200,
                f"data: {json.dumps(event)}\n\n".encode(),
                "text/event-stream",
            )
        raise AssertionError(request.url)

    client = ArenaClient(
        base_url="https://arena.test", http_transport=httpx.MockTransport(handler)
    )
    try:
        with pytest.raises(QueueTimeoutError):
            list(client.stream("question"))
    finally:
        client.close()


def test_async_client_stream_and_models() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/config":
            return _response(request, 200, json.dumps(CONFIG).encode())
        if request.url.path == "/queue/join":
            return _response(request, 200, b"{}")
        if request.url.path == "/queue/data":
            events = [
                {"msg": "process_generating", "output": {"data": ["A"]}},
                {"msg": "process_completed", "output": {"data": ["Answer"]}},
            ]
            body = "".join(f"data: {json.dumps(item)}\n\n" for item in events).encode()
            return _response(request, 200, body, "text/event-stream")
        raise AssertionError(request.url)

    async def run() -> None:
        client = AsyncArenaClient(
            base_url="https://arena.test",
            http_transport=AsyncMockTransport(handler),
        )
        async with client:
            assert [model.id for model in await client.get_models()] == ["m1", "m2"]
            assert await client.acomplete("prompt") == "Answer"

    asyncio.run(run())


def test_async_battle_returns_both_answers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/config":
            return _response(request, 200, json.dumps(CONFIG).encode())
        if request.url.path == "/queue/join":
            return _response(request, 200, b"{}")
        if request.url.path == "/queue/data":
            event = {
                "msg": "process_completed",
                "output": {"data": ["left async", "right async"]},
            }
            return _response(
                request,
                200,
                f"data: {json.dumps(event)}\n\n".encode(),
                "text/event-stream",
            )
        raise AssertionError(request.url)

    async def run() -> None:
        client = AsyncArenaClient(
            base_url="https://arena.test",
            http_transport=AsyncMockTransport(handler),
        )
        async with client:
            result = await client.abattle("question", left_model="A", right_model="B")
            assert result == BattleResponse("left async", "right async", "A", "B")

    asyncio.run(run())

"""Stateful, client-side conversation contexts."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterator, Sequence
from typing import TYPE_CHECKING

from .exceptions import ProtocolError
from .models import GenerationConfig, Message, StreamChunk

if TYPE_CHECKING:
    from .client import ArenaClient, AsyncArenaClient


def _copy_history(history: Sequence[Message] | None) -> list[Message]:
    if not history:
        return []
    return [
        Message(role=item.role, content=item.content, id=item.id) for item in history
    ]


def _remove_identity(items: list[Message], target: Message) -> None:
    for index in range(len(items) - 1, -1, -1):
        if items[index] is target:
            del items[index]
            return


class ChatSession:
    """A local transcript and turn counter for a Gradio chat callback.

    Arena callback schemas differ between deployments. The session stores
    ``history``, ``turn_id`` and ``parent_message_id`` locally, and also makes
    the prior transcript available to a client's custom ``chat_payload_factory``
    (or as the default payload's ``history`` option).
    """

    def __init__(
        self,
        client: ArenaClient,
        *,
        model: str | None = None,
        config: GenerationConfig | None = None,
        history: Sequence[Message] | None = None,
    ) -> None:
        self.client = client
        self.model = model
        self.config = config or GenerationConfig()
        self.history = _copy_history(history)
        self.turn_id = sum(message.role == "assistant" for message in self.history)
        self.parent_message_id = next(
            (
                message.id
                for message in reversed(self.history)
                if message.role == "assistant"
            ),
            None,
        )

    def _turn_config(self, prior_history: Sequence[Message]) -> GenerationConfig:
        extra = dict(self.config.extra)
        extra.setdefault("history", [message.as_dict() for message in prior_history])
        extra.setdefault("turn_id", self.turn_id)
        extra.setdefault("parent_message_id", self.parent_message_id)
        return GenerationConfig(
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            top_p=self.config.top_p,
            queue_timeout=self.config.queue_timeout,
            extra=extra,
        )

    def stream_message(self, content: str) -> Iterator[StreamChunk]:
        prior_history = tuple(self.history)
        turn_config = self._turn_config(prior_history)
        user = Message("user", content, uuid.uuid4().hex)
        self.history.append(user)
        collected: list[str] = []
        committed = False
        try:
            for chunk in self.client.stream(
                content,
                model=self.model,
                config=turn_config,
                history=prior_history,
            ):
                if chunk.delta:
                    collected.append(chunk.delta)
                if chunk.finished:
                    assistant = Message(
                        "assistant", "".join(collected), uuid.uuid4().hex
                    )
                    self.history.append(assistant)
                    self.turn_id += 1
                    self.parent_message_id = assistant.id
                    committed = True
                yield chunk
            if not committed:
                raise ProtocolError("Chat stream ended without a completion chunk.")
        finally:
            if not committed:
                _remove_identity(self.history, user)

    def send_message(self, content: str) -> str:
        return "".join(chunk.delta for chunk in self.stream_message(content))

    def clear(self) -> None:
        """Forget the local transcript and reset turn metadata."""
        self.history.clear()
        self.turn_id = 0
        self.parent_message_id = None


class AsyncChatSession:
    """Async counterpart of :class:`ChatSession`."""

    def __init__(
        self,
        client: AsyncArenaClient,
        *,
        model: str | None = None,
        config: GenerationConfig | None = None,
        history: Sequence[Message] | None = None,
    ) -> None:
        self.client = client
        self.model = model
        self.config = config or GenerationConfig()
        self.history = _copy_history(history)
        self.turn_id = sum(message.role == "assistant" for message in self.history)
        self.parent_message_id = next(
            (
                message.id
                for message in reversed(self.history)
                if message.role == "assistant"
            ),
            None,
        )

    def _turn_config(self, prior_history: Sequence[Message]) -> GenerationConfig:
        extra = dict(self.config.extra)
        extra.setdefault("history", [message.as_dict() for message in prior_history])
        extra.setdefault("turn_id", self.turn_id)
        extra.setdefault("parent_message_id", self.parent_message_id)
        return GenerationConfig(
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            top_p=self.config.top_p,
            queue_timeout=self.config.queue_timeout,
            extra=extra,
        )

    async def stream_message(self, content: str) -> AsyncIterator[StreamChunk]:
        prior_history = tuple(self.history)
        turn_config = self._turn_config(prior_history)
        user = Message("user", content, uuid.uuid4().hex)
        self.history.append(user)
        collected: list[str] = []
        committed = False
        try:
            async for chunk in self.client.astream(
                content,
                model=self.model,
                config=turn_config,
                history=prior_history,
            ):
                if chunk.delta:
                    collected.append(chunk.delta)
                if chunk.finished:
                    assistant = Message(
                        "assistant", "".join(collected), uuid.uuid4().hex
                    )
                    self.history.append(assistant)
                    self.turn_id += 1
                    self.parent_message_id = assistant.id
                    committed = True
                yield chunk
            if not committed:
                raise ProtocolError("Chat stream ended without a completion chunk.")
        finally:
            if not committed:
                _remove_identity(self.history, user)

    async def send_message(self, content: str) -> str:
        return "".join([chunk.delta async for chunk in self.stream_message(content)])

    def clear(self) -> None:
        self.history.clear()
        self.turn_id = 0
        self.parent_message_id = None

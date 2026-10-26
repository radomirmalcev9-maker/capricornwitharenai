"""Typed public value objects used by the sync and async clients."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass(frozen=True, slots=True)
class ModelInfo:
    """A model exposed by the currently selected Arena frontend."""

    id: str
    display_name: str | None = None
    available: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Message:
    """One item in a client-side conversation transcript."""

    role: Literal["user", "assistant", "system"]
    content: str
    id: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        """Return a JSON-friendly representation."""
        return {"role": self.role, "content": self.content, "id": self.id}


@dataclass(slots=True)
class GenerationConfig:
    """Generation controls plus deployment-specific queue options.

    The Gradio adapter passes the explicitly set model parameters, merged with
    ``extra``, as its final data item. Use a custom payload factory when the
    selected callback expects a different argument order.
    """

    temperature: float | None = None
    max_tokens: int | None = None
    top_p: float | None = None
    queue_timeout: float = 180.0
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.temperature is not None and (
            not math.isfinite(self.temperature) or self.temperature < 0
        ):
            raise ValueError("temperature must be a finite, non-negative number")
        if self.max_tokens is not None and self.max_tokens <= 0:
            raise ValueError("max_tokens must be greater than zero")
        if self.top_p is not None and (
            not math.isfinite(self.top_p) or not 0 <= self.top_p <= 1
        ):
            raise ValueError("top_p must be between 0 and 1")
        if not math.isfinite(self.queue_timeout) or self.queue_timeout <= 0:
            raise ValueError("queue_timeout must be a finite, positive number")
        if not isinstance(self.extra, dict):
            raise TypeError("extra must be a dict")

    def model_parameters(self) -> dict[str, Any]:
        """Return only generation parameters explicitly set by the caller."""
        result: dict[str, Any] = {}
        if self.temperature is not None:
            result["temperature"] = self.temperature
        if self.max_tokens is not None:
            result["max_tokens"] = self.max_tokens
        if self.top_p is not None:
            result["top_p"] = self.top_p
        result.update(self.extra)
        return result


@dataclass(frozen=True, slots=True)
class StreamChunk:
    """One text update from a streaming generation."""

    text: str
    delta: str
    event: str
    finished: bool = False
    raw: Any = None


@dataclass(frozen=True, slots=True)
class BattleStreamChunk:
    """A simultaneous update to one or both sides of a battle response."""

    left_text: str
    right_text: str
    left_delta: str = ""
    right_delta: str = ""
    event: str = "message"
    finished: bool = False
    raw: Any = None


@dataclass(frozen=True, slots=True)
class BattleResponse:
    """Final answers from an Arena side-by-side battle callback."""

    left: str
    right: str
    left_model: str | None = None
    right_model: str | None = None


@dataclass(frozen=True, slots=True)
class QueueEndpoint:
    """A discovered or explicitly configured queued Gradio callback."""

    fn_index: int
    api_name: str | None = None
    queue: bool = True

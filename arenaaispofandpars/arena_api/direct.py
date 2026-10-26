"""Client for the Arena Next.js Direct Chat streaming frontend.

These routes are undocumented and can change at any time. This adapter accepts
only verification assertions explicitly supplied by the caller.
"""

from __future__ import annotations

import codecs
import html
import json
import re
import secrets
import time
import uuid
from collections.abc import AsyncIterator, Callable, Iterator, Mapping, Sequence
from html.parser import HTMLParser
from typing import Any

import httpx

from .client import SessionSource, _resolve_session_source, resolve_impersonation
from .constants import (
    DEFAULT_BASE_URL,
    DEFAULT_QUEUE_TIMEOUT,
    DEFAULT_TIMEOUT,
    DIRECT_PAGE_PATH,
    DIRECT_STREAM_PATH,
)
from .exceptions import ModelUnavailableError, ProtocolError, QueueTimeoutError
from .auth.firefox_session import SessionManager
from .models import GenerationConfig, Message, ModelInfo, StreamChunk
from .transport import (
    ArenaTransport,
    AsyncArenaTransport,
    CookieInput,
    ProxyInput,
    SSEParser,
    _raise_if_challenge_page,
)

VerificationToken = str | Callable[[], str]

_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_FIELD_QUOTE = r"(?:\\+)?\""
_ID_FIELD_RE = re.compile(
    rf"{_FIELD_QUOTE}(?:id|modelId|model_id){_FIELD_QUOTE}\s*:\s*"
    rf"{_FIELD_QUOTE}(?P<value>{_UUID}){_FIELD_QUOTE}",
    re.IGNORECASE,
)
_NAME_FIELD_RE = re.compile(
    rf"{_FIELD_QUOTE}(?:publicName|public_name|displayName|display_name|name){_FIELD_QUOTE}\s*:\s*"
    rf"{_FIELD_QUOTE}(?P<value>(?:\\.|[^\"\\])*){_FIELD_QUOTE}",
    re.IGNORECASE,
)
_NEXT_FLIGHT_RE = re.compile(
    r"__next_f\.push\(\[\s*\d+\s*,\s*(\"(?:\\.|[^\"\\])*\")\s*\]\)",
    re.DOTALL,
)


def uuid7() -> str:
    """Generate a standards-shaped UUIDv7 on Python versions before 3.14."""
    millis = time.time_ns() // 1_000_000
    value = (millis & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76
    value |= secrets.randbits(12) << 64
    value |= 0b10 << 62
    value |= secrets.randbits(62)
    return str(uuid.UUID(int=value))


class AIDataStreamParser:
    """Incremental decoder for newline-delimited AI data-stream records.

    Arena has used prefixed records such as ``a0:`` and ``ad:``; the parser
    also accepts the Vercel AI SDK's common ``0:`` text and ``d:`` finish
    records. UTF-8 sequences split between network reads are preserved.
    """

    def __init__(self) -> None:
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._buffer = ""
        self._closed = False

    def feed(self, wire: bytes | str) -> list[tuple[str, Any]]:
        if self._closed:
            raise RuntimeError("cannot feed a closed AIDataStreamParser")
        self._buffer += (
            self._decoder.decode(wire, final=False) if isinstance(wire, bytes) else wire
        )
        events: list[tuple[str, Any]] = []
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            record = self._parse_line(line.rstrip("\r"))
            if record is not None:
                events.append(record)
        return events

    def close(self) -> list[tuple[str, Any]]:
        if self._closed:
            return []
        self._buffer += self._decoder.decode(b"", final=True)
        events: list[tuple[str, Any]] = []
        if self._buffer:
            record = self._parse_line(self._buffer.rstrip("\r"))
            if record is not None:
                events.append(record)
        self._buffer = ""
        self._closed = True
        return events

    @staticmethod
    def _parse_line(line: str) -> tuple[str, Any] | None:
        if not line:
            return None
        if line.strip() == "[DONE]":
            return "ad", True
        kind, separator, payload = line.partition(":")
        if not separator:
            return "unknown", line
        try:
            return kind, json.loads(payload)
        except json.JSONDecodeError:
            return kind, payload


class _ScriptCollector(HTMLParser):
    """Collect script element bodies without requiring an HTML dependency."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[str] = []
        self._current: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "script":
            self._current = []

    def handle_data(self, data: str) -> None:
        if self._current is not None:
            self._current.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._current is not None:
            self.scripts.append("".join(self._current))
            self._current = None


def _walk_models(value: Any, models: dict[str, ModelInfo]) -> None:
    if isinstance(value, Mapping):
        model_id = next(
            (
                value.get(key)
                for key in ("id", "modelId", "model_id")
                if value.get(key) is not None
            ),
            None,
        )
        display = next(
            (
                value.get(key)
                for key in (
                    "publicName",
                    "public_name",
                    "displayName",
                    "display_name",
                    "name",
                )
                if value.get(key) is not None
            ),
            None,
        )
        if model_id is not None and display is not None:
            model_id = str(model_id)
            candidate = ModelInfo(
                id=model_id,
                display_name=str(display),
                available=bool(value.get("available", value.get("active", True))),
                metadata=dict(value),
            )
            existing = models.get(model_id)
            if existing is None or len(candidate.metadata) > len(existing.metadata):
                models[model_id] = candidate
        for child in value.values():
            _walk_models(child, models)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _walk_models(child, models)


def _decode_json_string(value: str) -> str:
    try:
        return str(json.loads('"' + value + '"'))
    except (json.JSONDecodeError, TypeError):
        return html.unescape(value.replace(r"\"", '"').replace(r"\\", "\\"))


def _models_from_markup(markup: str) -> list[ModelInfo]:
    """Extract model records from Next.js JSON and escaped flight payloads."""
    result: dict[str, ModelInfo] = {}
    collector = _ScriptCollector()
    collector.feed(markup)

    candidates = [markup, html.unescape(markup), *collector.scripts]
    for match in _NEXT_FLIGHT_RE.finditer(markup):
        try:
            candidates.append(json.loads(match.group(1)))
        except json.JSONDecodeError:
            continue

    decoder = json.JSONDecoder()
    for candidate in candidates:
        _walk_models(_try_json(candidate), result)
        # Next.js may serialize model objects inside a string rather than a
        # standalone JSON script; scan object starts without relying on a fixed
        # React/Next payload version.
        position = 0
        while True:
            start = candidate.find("{", position)
            if start < 0:
                break
            try:
                value, end = decoder.raw_decode(candidate, start)
            except json.JSONDecodeError:
                position = start + 1
            else:
                _walk_models(value, result)
                position = max(end, start + 1)

    # Use regex only as a last-resort fallback; parsing JSON first avoids a
    # loosely matched escaped string overriding a structured model record.
    if not result:
        for candidate in candidates:
            _regex_models(candidate, result)

    return sorted(
        result.values(), key=lambda item: (item.display_name or item.id).casefold()
    )


def _try_json(value: str) -> Any:
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return None


def _regex_models(candidate: str, result: dict[str, ModelInfo]) -> None:
    for id_match in _ID_FIELD_RE.finditer(candidate):
        next_id = _ID_FIELD_RE.search(candidate, id_match.end())
        limit = (
            next_id.start()
            if next_id is not None
            else min(len(candidate), id_match.end() + 1200)
        )
        segment = candidate[id_match.end() : limit]
        name_match = _NAME_FIELD_RE.search(segment)
        if name_match is None:
            # Some serializers place the public name before the UUID.
            previous_id = candidate.rfind(
                '"id"', max(0, id_match.start() - 1200), id_match.start()
            )
            before = candidate[
                max(previous_id, id_match.start() - 1200) : id_match.start()
            ]
            name_match = None
            for candidate_name in _NAME_FIELD_RE.finditer(before):
                name_match = candidate_name
        if name_match is None:
            continue
        name = _decode_json_string(name_match.group("value"))
        model_id = id_match.group("value")
        result.setdefault(
            model_id,
            ModelInfo(id=model_id, display_name=name, metadata={"public_name": name}),
        )


def _is_text_frame(kind: str) -> bool:
    return kind in {"0", "a0", "text", "text_delta", "text-delta", "message"}


def _is_done_frame(kind: str, value: Any) -> bool:
    if kind in {
        "ad",
        "d",
        "done",
        "finish",
        "finished",
        "complete",
        "completed",
        "process_completed",
    }:
        return True
    if isinstance(value, Mapping):
        if value.get("finished") is True or value.get("done") is True:
            return True
        return str(value.get("type", "")).casefold() in {
            "finish",
            "finished",
            "completed",
            "message_end",
            "finish_message",
        }
    return False


def _update_direct_text(
    kind: str, value: Any, previous: str
) -> tuple[str, StreamChunk | None, bool]:
    if kind in {"3", "a3", "b3", "error"} or (
        isinstance(value, Mapping) and value.get("error")
    ):
        detail = value.get("error", value) if isinstance(value, Mapping) else value
        raise ProtocolError(f"Arena Direct Chat stream reported an error: {detail}")
    if kind in {"0", "a0", "b0"} and value == "hasArenaError":
        raise ProtocolError("Arena Direct Chat stream reported an error: hasArenaError")

    text_value: Any = value
    is_delta_field = kind in {"0", "a0", "text_delta", "text-delta"}
    if isinstance(value, Mapping):
        if isinstance(value.get("delta"), str):
            text_value = value["delta"]
            is_delta_field = True
        elif isinstance(value.get("textDelta"), str):
            text_value = value["textDelta"]
            is_delta_field = True
        else:
            text_value = next(
                (
                    value.get(key)
                    for key in ("text", "content")
                    if isinstance(value.get(key), str)
                ),
                None,
            )
        if text_value is None and _is_text_frame(kind):
            text_value = value.get("value")
    if text_value is None and kind == "message" and isinstance(value, str):
        text_value = value

    current = previous
    chunk: StreamChunk | None = None
    if _is_text_frame(kind) and isinstance(text_value, str):
        if is_delta_field:
            current = previous + text_value
            delta = text_value
        else:
            current = (
                text_value
                if (previous and text_value.startswith(previous))
                else previous + text_value
            )
            delta = current[len(previous) :]
        if delta:
            chunk = StreamChunk(
                text=current, delta=delta, event="text", raw={kind: value}
            )
    finished = _is_done_frame(kind, value)
    if finished:
        if (
            isinstance(value, Mapping)
            and value.get("finishReason") == "error"
            and not current
        ):
            raise ProtocolError(
                "Arena Direct Chat stream finished with finishReason='error'."
            )
        chunk = StreamChunk(
            text=current, delta="", event="completed", finished=True, raw={kind: value}
        )
    return current, chunk, finished


def _records_from_sse_event(event_name: str, data: str) -> list[tuple[str, Any]]:
    if data.strip() == "[DONE]":
        return [("ad", True)]
    try:
        value: Any = json.loads(data)
    except json.JSONDecodeError:
        value = data
    if isinstance(value, Mapping):
        kind = str(value.get("type", event_name or "message"))
        if (
            "delta" in value
            or "text" in value
            or "content" in value
            or value.get("done")
        ):
            return [(kind, value)]
        if value.get("error"):
            return [("error", value)]
    return [(event_name or "message", value)]


#: v2 programmatic client-interaction telemetry blob accepted by arena.ai's
#: Direct Chat stream endpoints when no DOM event tracker ran.
PROGRAMMATIC_CX = "Ahbd4XIDxKpTIU7vpGSu"


def _check_direct_prefix(
    wire: bytes, headers: Mapping[str, Any] | None = None
) -> None:
    prefix = wire[:4096].decode("utf-8", "replace")
    if prefix.lstrip().lower().startswith(("<!doctype html", "<html")):
        _raise_if_challenge_page(prefix, headers)
        raise ProtocolError("Direct Chat expected a stream but received HTML.")


_SSE_PREFIXES: tuple[str, ...] = ("data:", "event:", "id:", "retry:", ":")
_MAX_REASONABLE_CHAT_RANK = 100_000
_MEDIA_ONLY_HINTS: tuple[str, ...] = (
    "image",
    "video",
    "flux",
    "imagen",
    "midjourney",
    "ideogram",
    "recraft",
    "seedream",
    "suno",
    "veo",
    "sora",
    "kling",
    "hailuo",
    "runway",
    "pika",
    "luma",
    "kontext",
)


def _looks_like_standard_sse(prefix_bytes: bytes) -> bool:
    stripped = prefix_bytes.decode("utf-8", "replace").lstrip()
    return stripped.startswith(_SSE_PREFIXES)


def _has_capability(caps: Any, key: str) -> bool:
    if isinstance(caps, Mapping):
        return bool(caps.get(key))
    if isinstance(caps, (list, tuple, set)):
        return key in caps
    return False


def model_chat_score(item: ModelInfo) -> int:
    """Rank how suitable ``item`` is for text Direct Chat (lower is better).

    ``initialModels`` on ``arena.ai`` mixes ranked Direct Chat models with
    hidden, image/video-only, or webdev-only twin UUIDs whose ``chat`` rank is
    a huge sentinel and which 404 on ``create-evaluation`` in ``chat`` mode.
    """
    meta = item.metadata or {}
    score = 0
    if meta.get("userSelectable") is False:
        score += 1_000_000
    caps = meta.get("capabilities")
    if isinstance(caps, Mapping):
        in_caps = caps.get("inputCapabilities")
        if in_caps is not None and not _has_capability(in_caps, "text"):
            score += 100_000
        out_caps = caps.get("outputCapabilities")
        if out_caps is not None and not _has_capability(out_caps, "text"):
            score += 50_000
    else:
        label = f"{item.display_name or ''} {item.id}".casefold()
        if any(hint in label for hint in _MEDIA_ONLY_HINTS):
            score += 50_000
    rank_by_mod = meta.get("rankByModality")
    chat_rank = (
        rank_by_mod.get("chat") if isinstance(rank_by_mod, Mapping) else None
    )
    if isinstance(chat_rank, (int, float)) and not isinstance(chat_rank, bool):
        r = int(chat_rank)
        score += r if r < _MAX_REASONABLE_CHAT_RANK else 100_000 + min(r, 1_000_000)
    elif isinstance(meta.get("rank"), (int, float)) and not isinstance(
        meta.get("rank"), bool
    ):
        score += 10_000 + int(meta["rank"])
    elif caps is not None or rank_by_mod is not None:
        score += 20_000
    return score


def _iter_wire_records(
    chunks: Iterator[bytes],
    *,
    content_type: str = "",
    headers: Mapping[str, Any] | None = None,
) -> Iterator[tuple[str, Any]]:
    lowered_ct = content_type.lower()
    chunk_iter = iter(chunks)
    head = bytearray()
    for wire in chunk_iter:
        if not wire:
            continue
        head.extend(wire)
        if b":" in head or b"\n" in head or len(head) >= 64:
            break
    if not head:
        return
    head_bytes = bytes(head)
    _check_direct_prefix(head_bytes, headers)
    if "text/event-stream" in lowered_ct and _looks_like_standard_sse(head_bytes):
        sse_parser = SSEParser()
        for event_name, data in sse_parser.feed(head_bytes):
            yield from _records_from_sse_event(event_name, data)
        for wire in chunk_iter:
            for event_name, data in sse_parser.feed(wire):
                yield from _records_from_sse_event(event_name, data)
        for event_name, data in sse_parser.close():
            yield from _records_from_sse_event(event_name, data)
        return
    ai_parser = AIDataStreamParser()
    yield from ai_parser.feed(head_bytes)
    for wire in chunk_iter:
        yield from ai_parser.feed(wire)
    yield from ai_parser.close()


def _iter_response_records(response: httpx.Response) -> Iterator[tuple[str, Any]]:
    yield from _iter_wire_records(
        response.iter_bytes(),
        content_type=response.headers.get("content-type", ""),
        headers=response.headers,
    )


async def _aiter_wire_records(
    chunks: AsyncIterator[bytes],
    *,
    content_type: str = "",
    headers: Mapping[str, Any] | None = None,
) -> AsyncIterator[tuple[str, Any]]:
    lowered_ct = content_type.lower()
    head = bytearray()
    async for wire in chunks:
        if not wire:
            continue
        head.extend(wire)
        if b":" in head or b"\n" in head or len(head) >= 64:
            break
    if not head:
        return
    head_bytes = bytes(head)
    _check_direct_prefix(head_bytes, headers)
    if "text/event-stream" in lowered_ct and _looks_like_standard_sse(head_bytes):
        sse_parser = SSEParser()
        for event_name, data in sse_parser.feed(head_bytes):
            for item in _records_from_sse_event(event_name, data):
                yield item
        async for wire in chunks:
            for event_name, data in sse_parser.feed(wire):
                for item in _records_from_sse_event(event_name, data):
                    yield item
        for event_name, data in sse_parser.close():
            for item in _records_from_sse_event(event_name, data):
                yield item
        return
    ai_parser = AIDataStreamParser()
    for item in ai_parser.feed(head_bytes):
        yield item
    async for wire in chunks:
        for item in ai_parser.feed(wire):
            yield item
    for item in ai_parser.close():
        yield item


async def _aiter_response_records(
    response: httpx.Response,
) -> AsyncIterator[tuple[str, Any]]:
    async for item in _aiter_wire_records(
        response.aiter_bytes(),
        content_type=response.headers.get("content-type", ""),
        headers=response.headers,
    ):
        yield item


def _uses_browser_stream(
    verification_token: Any,
    supplied: str | None,
    *,
    custom_http_transport: bool,
) -> bool:
    if supplied is not None or custom_http_transport or verification_token is None:
        return False
    if not (
        callable(getattr(verification_token, "stream_evaluation", None))
        and callable(getattr(verification_token, "astream_evaluation", None))
    ):
        return False
    afetch = getattr(verification_token, "afetch", None)
    raw_fn = getattr(afetch, "__func__", afetch)
    if afetch is not None and not getattr(raw_fn, "_is_default_direct_afetch", False):
        return False
    return True


class _DirectMixin:
    verification_token: VerificationToken | None
    _models: list[ModelInfo] | None
    conversation_id: str | None
    direct_page_path: str
    direct_stream_path: str

    def _token(self, supplied: str | None) -> str:
        token: VerificationToken | None = (
            supplied if supplied is not None else self.verification_token
        )
        if callable(token):
            token = token()
        if not isinstance(token, str) or not token.strip():
            raise ProtocolError(
                "Arena Direct Chat requires a fresh verification assertion supplied by the caller."
            )
        return token

    @staticmethod
    def _request_body(
        prompt: str,
        model_id: str,
        token: str,
        conversation_id: str,
        config: GenerationConfig,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "id": conversation_id,
            "mode": "direct-battle",
            "modelAId": model_id,
            "userMessageId": uuid7(),
            "modelAMessageId": uuid7(),
            "userMessage": {
                "content": prompt,
                "experimental_attachments": [],
                "metadata": {},
            },
            "modality": "chat",
            "recaptchaV3Token": token,
            "cx": PROGRAMMATIC_CX,
        }
        parameters = config.model_parameters()
        if parameters:
            body["generationConfig"] = parameters
        return body

    @staticmethod
    def _resolve_model(model: str | None, known: list[ModelInfo]) -> str:
        if model is None:
            available_all = [item for item in known if item.available]
            if not available_all:
                raise ModelUnavailableError(
                    "No available Direct Chat models were found."
                )
            return min(available_all, key=model_chat_score).id
        for item in known:
            if model == item.id:
                if not item.available:
                    raise ModelUnavailableError(
                        f"Model {model!r} is currently unavailable."
                    )
                return item.id
        folded = model.casefold()
        matches: list[ModelInfo] = []
        for item in known:
            meta = item.metadata or {}
            candidates = (
                item.display_name,
                meta.get("publicName"),
                meta.get("public_name"),
                meta.get("displayName"),
                meta.get("display_name"),
                meta.get("name"),
            )
            if any(
                isinstance(name, str) and (model == name or folded == name.casefold())
                for name in candidates
            ):
                matches.append(item)
        if matches:
            available = [item for item in matches if item.available]
            if not available:
                raise ModelUnavailableError(
                    f"Model {model!r} is currently unavailable."
                )
            return min(available, key=model_chat_score).id
        examples: list[str] = []
        for item in sorted(
            (m for m in known if m.available), key=model_chat_score
        ):
            label = str(item.display_name or item.id)
            if label not in examples:
                examples.append(label)
            if len(examples) >= 5:
                break
        suffix = f" Examples: {', '.join(examples)}." if examples else ""
        raise ModelUnavailableError(
            f"Model {model!r} was not found in the current Direct Chat model list.{suffix}"
        )

    def _stream_endpoint_path(self, chat_id: str, *, follow_up: bool) -> str:
        if follow_up and self.direct_stream_path == DIRECT_STREAM_PATH:
            return f"/nextjs-api/stream/post-to-evaluation/{chat_id}"
        return self.direct_stream_path

    def _stream_headers(self, base_url: str) -> dict[str, str]:
        origin = base_url.rstrip("/")
        referer = f"{origin}/{self.direct_page_path.lstrip('/')}"
        return {
            "content-type": "application/json",
            "accept": "text/event-stream, text/plain, */*",
            "origin": origin,
            "referer": referer,
        }


class DirectArenaClient(_DirectMixin):
    """Blocking client for the current Arena Direct Chat frontend.

    Accepts the same ``session_source`` as
    :class:`~arena_api.client.ArenaClient` (``"firefox"`` or any
    :class:`~arena_api.auth.SessionManager`), so a stale session is re-read and
    the request replayed instead of surfacing a 403.
    """

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        cookies: CookieInput = None,
        session_source: SessionSource = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        http2: bool = True,
        verify: bool | str = True,
        proxy: ProxyInput = None,
        verification_token: VerificationToken | None = None,
        direct_page_path: str = DIRECT_PAGE_PATH,
        direct_stream_path: str = DIRECT_STREAM_PATH,
        http_transport: httpx.BaseTransport | None = None,
        impersonate: str | bool | None = None,
        max_auth_refreshes: int = 2,
    ) -> None:
        session = _resolve_session_source(session_source, base_url)
        merged_headers: dict[str, str] = {}
        if session is not None:
            merged_headers.update(session.headers)
        if headers:
            merged_headers.update(headers)
        self.transport = ArenaTransport(
            base_url,
            cookies=cookies,
            session_cookies=session.cookies if session is not None else None,
            headers=merged_headers or None,
            timeout=timeout,
            http2=http2,
            verify=verify,
            proxy=proxy,
            fallback_proxy=session.proxy if session is not None else None,
            http_transport=http_transport,
            impersonate=resolve_impersonation(
                impersonate,
                session.impersonate if session is not None else None,
                http_transport=http_transport,
            ),
            session_refresher=(
                session.manager.refresh_session if session is not None else None
            ),
            max_auth_refreshes=max_auth_refreshes,
        )
        self.session_manager: SessionManager | None = (
            session.manager if session is not None else None
        )
        self.verification_token = verification_token
        self.direct_page_path = direct_page_path
        self.direct_stream_path = direct_stream_path
        self._models = None
        self.conversation_id: str | None = None

    def __enter__(self) -> DirectArenaClient:  # noqa: PYI034 - Self is not in typing until Python 3.11
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        token_close = getattr(self.verification_token, "close", None)
        if callable(token_close):
            token_close()
        self.transport.close()

    def get_models(self, *, refresh: bool = False) -> list[ModelInfo]:
        if refresh or self._models is None:
            self._models = _models_from_markup(
                self.transport.get_text(self.direct_page_path)
            )
            if not self._models:
                raise ProtocolError(
                    "Could not find model metadata in Arena's Direct Chat page."
                )
        return list(self._models)

    def stream(
        self,
        prompt: str,
        *,
        model: str | None = None,
        verification_token: str | None = None,
        config: GenerationConfig | None = None,
        conversation_id: str | None = None,
        follow_up: bool = False,
    ) -> Iterator[StreamChunk]:
        generation = config or GenerationConfig(queue_timeout=DEFAULT_QUEUE_TIMEOUT)
        use_browser = _uses_browser_stream(
            self.verification_token,
            verification_token,
            custom_http_transport=self.transport._custom_http_transport,
        )
        explicit_model_id: str | None = (
            self._resolve_model(model, self.get_models())
            if model is not None
            else None
        )
        chat_id = conversation_id or uuid7()
        if conversation_id is None:
            self.conversation_id = chat_id
        endpoint_path = self._stream_endpoint_path(chat_id, follow_up=follow_up)
        finished = False
        text = ""
        deadline = time.monotonic() + generation.queue_timeout
        if use_browser:
            browser_runner: Any = self.verification_token

            def _fallback_body(tok: str) -> dict[str, Any]:
                resolved_id = explicit_model_id or self._resolve_model(
                    None, self.get_models()
                )
                return self._request_body(
                    prompt, resolved_id, tok, chat_id, generation
                )

            with browser_runner.stream_evaluation(
                endpoint_path,
                _fallback_body,
                timeout=generation.queue_timeout,
                prompt=prompt,
                model_id_override=explicit_model_id,
                generation_params=generation.model_parameters() or None,
                follow_up=follow_up,
            ) as (content_type, wire_chunks):
                stream_deadline = time.monotonic() + generation.queue_timeout
                for kind, value in _iter_wire_records(
                    wire_chunks, content_type=content_type
                ):
                    if time.monotonic() >= stream_deadline:
                        raise QueueTimeoutError(
                            "Direct Chat stream exceeded its configured timeout."
                        )
                    text, chunk, done = _update_direct_text(kind, value, text)
                    if chunk is not None:
                        yield chunk
                    if done:
                        finished = True
                        return
            if not finished:
                raise ProtocolError(
                    "Arena Direct Chat stream ended without a completion record."
                )
            return

        model_id = explicit_model_id or self._resolve_model(None, self.get_models())
        initial_token: str | None = self._token(verification_token)

        def build_content() -> str:
            nonlocal initial_token
            if initial_token is not None:
                tok = initial_token
                initial_token = None
            else:
                tok = self._token(verification_token)
            body = self._request_body(prompt, model_id, tok, chat_id, generation)
            return json.dumps(body, separators=(",", ":"))

        with self.transport.stream_request(
            "POST",
            endpoint_path,
            headers=self._stream_headers(self.transport.base_url),
            content_factory=build_content,
            timeout=httpx.Timeout(generation.queue_timeout),
        ) as response:
            for kind, value in _iter_response_records(response):
                if time.monotonic() >= deadline:
                    raise QueueTimeoutError(
                        "Direct Chat stream exceeded its configured timeout."
                    )
                text, chunk, done = _update_direct_text(kind, value, text)
                if chunk is not None:
                    yield chunk
                if done:
                    finished = True
                    return
        if not finished:
            raise ProtocolError(
                "Arena Direct Chat stream ended without a completion record."
            )

    def complete(
        self,
        prompt: str,
        *,
        model: str | None = None,
        verification_token: str | None = None,
        config: GenerationConfig | None = None,
        conversation_id: str | None = None,
    ) -> str:
        return "".join(
            chunk.delta
            for chunk in self.stream(
                prompt,
                model=model,
                verification_token=verification_token,
                config=config,
                conversation_id=conversation_id,
            )
        )

    def chat(
        self,
        *,
        model: str,
        config: GenerationConfig | None = None,
    ) -> DirectChatSession:
        return DirectChatSession(self, model=model, config=config)


def _copy_messages(history: Sequence[Message] | None) -> list[Message]:
    if not history:
        return []
    return [
        Message(role=item.role, content=item.content, id=item.id) for item in history
    ]


class DirectChatSession:
    """Multi-turn Direct Chat state; each session owns its conversation UUID."""

    def __init__(
        self,
        client: DirectArenaClient,
        *,
        model: str,
        config: GenerationConfig | None = None,
        history: Sequence[Message] | None = None,
    ) -> None:
        self.client = client
        self.model = model
        self.config = config or GenerationConfig()
        self.history = _copy_messages(history)
        self.turn_id = sum(item.role == "assistant" for item in self.history)
        self.parent_message_id = next(
            (item.id for item in reversed(self.history) if item.role == "assistant"),
            None,
        )
        self.conversation_id: str | None = None

    def stream_message(
        self, content: str, *, verification_token: str | None = None
    ) -> Iterator[StreamChunk]:
        user = Message("user", content, uuid.uuid4().hex)
        self.history.append(user)
        prior_conversation_id = self.conversation_id
        self.conversation_id = self.conversation_id or uuid7()
        collected: list[str] = []
        committed = False
        try:
            for chunk in self.client.stream(
                content,
                model=self.model,
                verification_token=verification_token,
                config=self.config,
                conversation_id=self.conversation_id,
                follow_up=prior_conversation_id is not None,
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
                raise ProtocolError(
                    "Direct Chat stream ended without a completion chunk."
                )
        finally:
            if not committed:
                for index in range(len(self.history) - 1, -1, -1):
                    if self.history[index] is user:
                        del self.history[index]
                        break
                self.conversation_id = prior_conversation_id

    def send_message(
        self, content: str, *, verification_token: str | None = None
    ) -> str:
        return "".join(
            chunk.delta
            for chunk in self.stream_message(
                content, verification_token=verification_token
            )
        )

    def clear(self) -> None:
        self.history.clear()
        self.turn_id = 0
        self.parent_message_id = None
        self.conversation_id = None


class AsyncDirectArenaClient(_DirectMixin):
    """Async client for the same Direct Chat frontend.

    Supports ``session_source`` exactly like :class:`DirectArenaClient`; the
    (possibly blocking) refresh runs in a worker thread.
    """

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        cookies: CookieInput = None,
        session_source: SessionSource = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        http2: bool = True,
        verify: bool | str = True,
        proxy: ProxyInput = None,
        verification_token: VerificationToken | None = None,
        direct_page_path: str = DIRECT_PAGE_PATH,
        direct_stream_path: str = DIRECT_STREAM_PATH,
        http_transport: httpx.AsyncBaseTransport | None = None,
        impersonate: str | bool | None = None,
        max_auth_refreshes: int = 2,
    ) -> None:
        session = _resolve_session_source(session_source, base_url)
        merged_headers: dict[str, str] = {}
        if session is not None:
            merged_headers.update(session.headers)
        if headers:
            merged_headers.update(headers)
        self.transport = AsyncArenaTransport(
            base_url,
            cookies=cookies,
            session_cookies=session.cookies if session is not None else None,
            headers=merged_headers or None,
            timeout=timeout,
            http2=http2,
            verify=verify,
            proxy=proxy,
            fallback_proxy=session.proxy if session is not None else None,
            http_transport=http_transport,
            impersonate=resolve_impersonation(
                impersonate,
                session.impersonate if session is not None else None,
                http_transport=http_transport,
            ),
            session_refresher=(
                session.manager.refresh_session if session is not None else None
            ),
            max_auth_refreshes=max_auth_refreshes,
        )
        self.session_manager: SessionManager | None = (
            session.manager if session is not None else None
        )
        self.verification_token = verification_token
        self.direct_page_path = direct_page_path
        self.direct_stream_path = direct_stream_path
        self._models = None
        self.conversation_id: str | None = None

    async def __aenter__(self) -> AsyncDirectArenaClient:  # noqa: PYI034 - Self is not in typing until Python 3.11
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        token_aclose = getattr(self.verification_token, "aclose", None)
        if callable(token_aclose):
            await token_aclose()
        else:
            token_close = getattr(self.verification_token, "close", None)
            if callable(token_close):
                token_close()
        await self.transport.close()

    async def get_models(self, *, refresh: bool = False) -> list[ModelInfo]:
        if refresh or self._models is None:
            self._models = _models_from_markup(
                await self.transport.get_text(self.direct_page_path)
            )
            if not self._models:
                raise ProtocolError(
                    "Could not find model metadata in Arena's Direct Chat page."
                )
        return list(self._models)

    async def astream(
        self,
        prompt: str,
        *,
        model: str | None = None,
        verification_token: str | None = None,
        config: GenerationConfig | None = None,
        conversation_id: str | None = None,
        follow_up: bool = False,
    ) -> AsyncIterator[StreamChunk]:
        generation = config or GenerationConfig(queue_timeout=DEFAULT_QUEUE_TIMEOUT)
        use_browser = _uses_browser_stream(
            self.verification_token,
            verification_token,
            custom_http_transport=self.transport._custom_http_transport,
        )
        explicit_model_id: str | None = (
            self._resolve_model(model, await self.get_models())
            if model is not None
            else None
        )
        chat_id = conversation_id or uuid7()
        if conversation_id is None:
            self.conversation_id = chat_id
        endpoint_path = self._stream_endpoint_path(chat_id, follow_up=follow_up)
        text = ""
        deadline = time.monotonic() + generation.queue_timeout
        if use_browser:
            browser_runner: Any = self.verification_token
            cached_default_id: str | None = explicit_model_id
            if cached_default_id is None and self._models is not None:
                cached_default_id = self._resolve_model(None, self._models)

            def _fallback_body(tok: str) -> dict[str, Any]:
                resolved_id = cached_default_id or "00000000-0000-0000-0000-000000000000"
                return self._request_body(
                    prompt, resolved_id, tok, chat_id, generation
                )

            async with browser_runner.astream_evaluation(
                endpoint_path,
                _fallback_body,
                timeout=generation.queue_timeout,
                prompt=prompt,
                model_id_override=explicit_model_id,
                generation_params=generation.model_parameters() or None,
                follow_up=follow_up,
            ) as (content_type, wire_chunks):
                stream_deadline = time.monotonic() + generation.queue_timeout
                async for kind, value in _aiter_wire_records(
                    wire_chunks, content_type=content_type
                ):
                    if time.monotonic() >= stream_deadline:
                        raise QueueTimeoutError(
                            "Direct Chat stream exceeded its configured timeout."
                        )
                    text, chunk, done = _update_direct_text(kind, value, text)
                    if chunk is not None:
                        yield chunk
                    if done:
                        return
            raise ProtocolError(
                "Arena Direct Chat stream ended without a completion record."
            )

        model_id = explicit_model_id or self._resolve_model(
            None, await self.get_models()
        )
        initial_token: str | None = self._token(verification_token)

        def build_content() -> str:
            nonlocal initial_token
            if initial_token is not None:
                tok = initial_token
                initial_token = None
            else:
                tok = self._token(verification_token)
            body = self._request_body(prompt, model_id, tok, chat_id, generation)
            return json.dumps(body, separators=(",", ":"))

        async with self.transport.stream_request(
            "POST",
            endpoint_path,
            headers=self._stream_headers(self.transport.base_url),
            content_factory=build_content,
            timeout=httpx.Timeout(generation.queue_timeout),
        ) as response:
            async for kind, value in _aiter_response_records(response):
                if time.monotonic() >= deadline:
                    raise QueueTimeoutError(
                        "Direct Chat stream exceeded its configured timeout."
                    )
                text, chunk, done = _update_direct_text(kind, value, text)
                if chunk is not None:
                    yield chunk
                if done:
                    return
        raise ProtocolError(
            "Arena Direct Chat stream ended without a completion record."
        )

    async def acomplete(
        self,
        prompt: str,
        *,
        model: str | None = None,
        verification_token: str | None = None,
        config: GenerationConfig | None = None,
        conversation_id: str | None = None,
    ) -> str:
        return "".join(
            [
                chunk.delta
                async for chunk in self.astream(
                    prompt,
                    model=model,
                    verification_token=verification_token,
                    config=config,
                    conversation_id=conversation_id,
                )
            ]
        )

    def chat(
        self,
        *,
        model: str,
        config: GenerationConfig | None = None,
    ) -> AsyncDirectChatSession:
        return AsyncDirectChatSession(self, model=model, config=config)


class AsyncDirectChatSession:
    """Async multi-turn Direct Chat state."""

    def __init__(
        self,
        client: AsyncDirectArenaClient,
        *,
        model: str,
        config: GenerationConfig | None = None,
        history: Sequence[Message] | None = None,
    ) -> None:
        self.client = client
        self.model = model
        self.config = config or GenerationConfig()
        self.history = _copy_messages(history)
        self.turn_id = sum(item.role == "assistant" for item in self.history)
        self.parent_message_id = next(
            (item.id for item in reversed(self.history) if item.role == "assistant"),
            None,
        )
        self.conversation_id: str | None = None

    async def stream_message(
        self,
        content: str,
        *,
        verification_token: str | None = None,
    ) -> AsyncIterator[StreamChunk]:
        user = Message("user", content, uuid.uuid4().hex)
        self.history.append(user)
        prior_conversation_id = self.conversation_id
        self.conversation_id = self.conversation_id or uuid7()
        collected: list[str] = []
        committed = False
        try:
            async for chunk in self.client.astream(
                content,
                model=self.model,
                verification_token=verification_token,
                config=self.config,
                conversation_id=self.conversation_id,
                follow_up=prior_conversation_id is not None,
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
                raise ProtocolError(
                    "Direct Chat stream ended without a completion chunk."
                )
        finally:
            if not committed:
                for index in range(len(self.history) - 1, -1, -1):
                    if self.history[index] is user:
                        del self.history[index]
                        break
                self.conversation_id = prior_conversation_id

    async def send_message(
        self, content: str, *, verification_token: str | None = None
    ) -> str:
        return "".join(
            [
                chunk.delta
                async for chunk in self.stream_message(
                    content,
                    verification_token=verification_token,
                )
            ]
        )

    def clear(self) -> None:
        self.history.clear()
        self.turn_id = 0
        self.parent_message_id = None
        self.conversation_id = None

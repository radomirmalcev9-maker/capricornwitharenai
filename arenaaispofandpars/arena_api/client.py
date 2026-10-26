"""Synchronous and asynchronous clients for Gradio-style Arena frontends.

The Gradio callback schema is deployment-specific. The built-in payload is a
small conventional default; use ``chat_payload_factory`` or
``stream_queue()`` when the selected frontend has different callback inputs.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator, Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeAlias
from urllib.parse import urlparse

import httpx

from .auth.firefox_session import (
    FirefoxSessionError,
    FirefoxSessionManager,
    SessionManager,
)
from .constants import (
    CONFIG_PATH,
    DEFAULT_BASE_URL,
    DEFAULT_QUEUE_TIMEOUT,
    DEFAULT_TIMEOUT,
    QUEUE_DATA_PATH,
    QUEUE_JOIN_PATH,
)
from .exceptions import (
    AuthenticationError,
    ModelUnavailableError,
    ProtocolError,
    QueueTimeoutError,
)
from .models import (
    BattleResponse,
    BattleStreamChunk,
    GenerationConfig,
    Message,
    ModelInfo,
    QueueEndpoint,
    StreamChunk,
)
from .transport import (
    ArenaTransport,
    AsyncArenaTransport,
    CookieInput,
    ProxyInput,
    impersonation_available,
)

if TYPE_CHECKING:
    from .session import AsyncChatSession, ChatSession


ChatPayloadFactory = Callable[
    [str, str | None, GenerationConfig, Sequence[Message]], Sequence[Any]
]
BattlePayloadFactory = Callable[
    [str, str | None, str | None, GenerationConfig], Sequence[Any]
]
SessionSource: TypeAlias = "str | SessionManager | None"


@dataclass(frozen=True, slots=True)
class _ResolvedSessionSource:
    """Materialized session source: cookies, headers, and a refresh hook."""

    manager: SessionManager
    cookies: dict[str, str]
    headers: dict[str, str]
    #: curl_cffi profile matching the browser this session came from, when the
    #: source knows it -- a Firefox manager knows it is Firefox.
    impersonate: str | None = None
    #: Manual proxy configured in the browser profile itself, if any.
    proxy: str | None = None


def _base_host(base_url: str) -> str | None:
    return urlparse(base_url).hostname


def _derived_proxy(manager: SessionManager, base_url: str) -> str | None:
    getter = getattr(manager, "proxy_url", None)
    if not callable(getter):
        return None
    parsed = urlparse(base_url)
    try:
        value = getter(scheme=parsed.scheme or "https", host=parsed.hostname)
    except Exception:  # noqa: BLE001 - optional profile metadata
        return None
    return value if isinstance(value, str) and value.strip() else None


def _derived_impersonation(manager: SessionManager, *, from_string: bool) -> str | None:
    """The profile that matches a session source, if it can be identified.

    ``session_source="firefox"`` and a :class:`FirefoxSessionManager` are
    Firefox by construction. Any other manager may say so itself through an
    ``impersonate`` attribute (``BrowserSessionManager`` has the field, and
    ``arena_api.auto`` fills it in from the browser it discovered).
    """
    if from_string or isinstance(manager, FirefoxSessionManager):
        return "firefox"
    value = getattr(manager, "impersonate", None)
    return value if isinstance(value, str) and value.strip() else None


def resolve_impersonation(
    requested: str | bool | None,
    derived: str | None,
    *,
    http_transport: object | None = None,
) -> str | None:
    """Decide which fingerprint a client should present.

    Cases, in order:

    * ``http_transport=`` -- the caller brought their own wire, so nothing is
      derived on top of it (an explicit ``impersonate=`` still collides loudly,
      because impersonation *is* a transport);
    * ``False`` -- never impersonate, whatever the session source says;
    * a profile name -- use exactly that (missing dependencies then raise);
    * ``None`` -- follow the session source (``derived``), but only when the
      optional dependency is actually installed, because this branch is a
      silent default and must never turn a working setup into an error.
    """
    if requested is False:
        return None
    if isinstance(requested, str) and requested.strip():
        return requested.strip()
    if http_transport is not None:
        return None
    if requested is None and derived and impersonation_available():
        return derived
    return None


def _resolve_session_source(
    session_source: SessionSource, base_url: str
) -> _ResolvedSessionSource | None:
    """Turn ``session_source`` into cookies, headers, and a refresh hook.

    ``"firefox"`` builds a :class:`FirefoxSessionManager` for the base URL's
    host; an object implementing :class:`~arena_api.auth.SessionManager` (any
    ``FirefoxSessionManager`` instance) is used as-is, which keeps tests and
    custom backends injectable.
    """
    if session_source is None:
        return None
    if isinstance(session_source, str):
        if session_source.strip().casefold() != "firefox":
            raise ValueError(
                f"Unsupported session_source {session_source!r}; "
                "only 'firefox' is currently available."
            )
        host = _base_host(base_url)
        manager: SessionManager = FirefoxSessionManager(
            domains=(host,) if host else None
        )
    elif isinstance(session_source, SessionManager):
        manager = session_source
    else:
        raise TypeError(
            "session_source must be 'firefox', a SessionManager instance, or None."
        )
    site = _base_host(base_url) or "arena.ai"
    # The remediation differs per source: only "firefox" is about a profile.
    from_firefox = isinstance(session_source, str)
    source_label = (
        "the local Firefox profile"
        if from_firefox
        else f"the session source ({type(manager).__name__})"
    )
    try:
        cookies = manager.load_cookies()
    except FirefoxSessionError as exc:
        raise AuthenticationError(
            f"Could not read the session from {source_label}: {exc}"
        ) from exc
    if not cookies:
        hint = (
            f"Open https://{site} in Firefox, sign in, and start the client again."
            if from_firefox
            else f"Sign in to https://{site} and let {type(manager).__name__} "
            "return the cookies for it."
        )
        raise AuthenticationError(
            f"No cookies for {site} were found in {source_label}. {hint}"
        )
    return _ResolvedSessionSource(
        manager=manager,
        cookies=cookies,
        headers=manager.firefox_headers(),
        impersonate=_derived_impersonation(manager, from_string=from_firefox),
        proxy=_derived_proxy(manager, base_url),
    )


_BATTLE_MARKERS = ("battle", "side_by_side", "side-by-side")
_CHAT_MARKERS = ("chat", "add_text", "send_message", "submit")


def _session_hash() -> str:
    """Return a fresh random Gradio queue identifier."""
    return secrets.token_hex(16)


def _dependencies(config: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = config.get("dependencies", [])
    if not isinstance(raw, (list, tuple)):
        return []
    return [item for item in raw if isinstance(item, Mapping)]


def _dependency_text(dependency: Mapping[str, Any]) -> str:
    values: list[str] = []
    for key in ("api_name", "trigger_mode", "label", "name"):
        value = dependency.get(key)
        if isinstance(value, (str, int)):
            values.append(str(value))
    targets = dependency.get("targets", [])
    if isinstance(targets, (list, tuple)):
        values.extend(str(item) for item in targets if isinstance(item, str))
    return " ".join(values).casefold()


def _find_endpoint(config: Mapping[str, Any], purpose: str) -> QueueEndpoint:
    if purpose not in {"chat", "battle"}:
        raise ValueError("purpose must be 'chat' or 'battle'")
    dependencies = _dependencies(config)
    candidates: list[tuple[int, QueueEndpoint]] = []
    for index, dependency in enumerate(dependencies):
        if dependency.get("queue", True) is False:
            continue
        text = _dependency_text(dependency)
        is_battle = any(marker in text for marker in _BATTLE_MARKERS)
        if purpose == "battle":
            if not is_battle:
                continue
            score = (
                2
                if any(
                    marker in text
                    for marker in ("battle", "side_by_side", "side-by-side")
                )
                else 1
            )
        else:
            # Avoid accidentally routing a normal chat request to a battle
            # dependency merely because it contains a generic "submit" target.
            if is_battle or not any(marker in text for marker in _CHAT_MARKERS):
                continue
            score = 2 if "chat" in text or "send_message" in text else 1
        api_name = dependency.get("api_name")
        endpoint = QueueEndpoint(
            fn_index=int(dependency.get("fn_index", index)),
            api_name=str(api_name) if api_name is not None else None,
            queue=True,
        )
        candidates.append((score, endpoint))
    if not candidates:
        raise ModelUnavailableError(
            f"No queued {purpose} callback was discoverable in /config. "
            f"Pass {purpose}_fn_index explicitly after inspecting the authorized frontend config."
        )
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def _model_info(value: Any) -> ModelInfo | None:
    if isinstance(value, Mapping):
        model_id = next(
            (
                value.get(key)
                for key in ("id", "model_id", "name", "value")
                if value.get(key) is not None
            ),
            None,
        )
        if model_id is None:
            return None
        display = next(
            (
                value.get(key)
                for key in (
                    "display_name",
                    "public_name",
                    "publicName",
                    "label",
                    "title",
                )
                if value.get(key) is not None
            ),
            model_id,
        )
        available = value.get(
            "available", value.get("active", value.get("enabled", True))
        )
        return ModelInfo(
            id=str(model_id),
            display_name=str(display),
            available=bool(available),
            metadata=dict(value),
        )
    if isinstance(value, (str, int)):
        return ModelInfo(id=str(value), display_name=str(value))
    return None


def _models_from_config(config: Mapping[str, Any]) -> list[ModelInfo]:
    """Read explicit model metadata or model dropdown choices from /config."""
    models: dict[str, ModelInfo] = {}
    for key in ("models", "model_list", "model_names"):
        raw_models = config.get(key)
        if isinstance(raw_models, (list, tuple)):
            for value in raw_models:
                info = _model_info(value)
                if info is not None:
                    models.setdefault(info.id, info)
            if models:
                break

    components = config.get("components", [])
    if isinstance(components, Mapping):
        component_items = list(components.values())
    elif isinstance(components, (list, tuple)):
        component_items = list(components)
    else:
        component_items = []

    for component in component_items:
        if not isinstance(component, Mapping):
            continue
        props = component.get("props", {})
        if not isinstance(props, Mapping):
            continue
        choices = props.get("choices", [])
        if not isinstance(choices, (list, tuple)):
            continue
        descriptor = " ".join(
            str(value)
            for value in (
                component.get("type"),
                component.get("label"),
                component.get("key"),
                component.get("id"),
                props.get("label"),
                props.get("elem_id"),
                props.get("name"),
                props.get("info"),
            )
            if value is not None
        ).casefold()
        if "model" not in descriptor:
            continue
        for choice in choices:
            if isinstance(choice, (list, tuple)) and choice:
                info = ModelInfo(
                    id=str(choice[0]),
                    display_name=str(choice[1]) if len(choice) > 1 else str(choice[0]),
                )
            elif isinstance(choice, Mapping):
                info = _model_info(choice)
                if info is None:
                    continue
            else:
                info = _model_info(choice)
                if info is None:
                    continue
            if info.id and info.id.casefold() not in {"none", "null"}:
                models.setdefault(info.id, info)

    return sorted(
        models.values(), key=lambda item: (item.display_name or item.id).casefold()
    )


def _collect_text(value: Any, candidates: list[str]) -> None:
    if isinstance(value, str):
        candidates.append(value)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _collect_text(child, candidates)
    elif isinstance(value, Mapping):
        role = value.get("role")
        content = value.get("content")
        if role == "assistant" and isinstance(content, str):
            candidates.append(content)
            return
        # Prefer conventional response fields over walking arbitrary metadata.
        for key in ("text", "response", "content", "message"):
            item = value.get(key)
            if isinstance(item, str) and (key != "content" or role != "user"):
                candidates.append(item)
        for key, child in value.items():
            if key not in {
                "text",
                "response",
                "content",
                "message",
                "error",
                "metadata",
            }:
                _collect_text(child, candidates)


def _assistant_text(event: Any) -> str | None:
    """Extract the latest assistant text from common Gradio output shapes."""
    if not isinstance(event, Mapping):
        return event if isinstance(event, str) else None
    if event.get("error"):
        raise ProtocolError(f"Arena queue reported an error: {event['error']}")
    payload = event.get("output", event)
    if not isinstance(payload, Mapping):
        return payload if isinstance(payload, str) else None
    for key in ("text", "response", "content"):
        value = payload.get(key)
        if isinstance(value, str):
            return value
    data = payload.get("data")
    candidates: list[str] = []
    _collect_text(data, candidates)
    return candidates[-1] if candidates else None


def _battle_texts(event: Any) -> tuple[str, str] | None:
    if not isinstance(event, Mapping):
        return None
    payload = event.get("output", event)
    if not isinstance(payload, Mapping):
        return None
    direct_pairs = (
        ("left", "right"),
        ("response_a", "response_b"),
        ("model_a", "model_b"),
    )
    for left_key, right_key in direct_pairs:
        left, right = payload.get(left_key), payload.get(right_key)
        if isinstance(left, str) and isinstance(right, str):
            return left, right
    data = payload.get("data")
    if not isinstance(data, (list, tuple)) or len(data) < 2:
        return None
    found: list[str] = []
    for value in data:
        text = _assistant_text({"output": {"data": [value]}})
        if text is not None:
            found.append(text)
    return (found[-2], found[-1]) if len(found) >= 2 else None


def _terminal(event: Any) -> bool:
    return isinstance(event, Mapping) and event.get("msg") in {
        "process_completed",
        "process_failed",
        "queue_full",
    }


def _check_queue_event(event_name: str, event: Any) -> None:
    if event_name.casefold() == "error":
        detail = event.get("error", event) if isinstance(event, Mapping) else event
        raise ProtocolError(f"Arena queue returned an error event: {detail}")
    if not isinstance(event, Mapping):
        return
    msg = event.get("msg")
    if msg == "process_failed":
        detail = event.get("error") or event.get("output") or "generation failed"
        raise ProtocolError(f"Arena queue failed: {detail}")
    if msg == "queue_full":
        raise QueueTimeoutError(
            "Arena queue is full; retry after the current load subsides."
        )
    if event.get("error"):
        raise ProtocolError(f"Arena queue reported an error: {event['error']}")


def _merge_text(previous: str, update: str) -> tuple[str, str]:
    """Accept either cumulative snapshots or append-only token deltas."""
    full = update if update.startswith(previous) else previous + update
    return full, full[len(previous) :]


class _ArenaClientMixin:
    """Protocol helpers shared by the blocking and async clients."""

    chat_fn_index: int | None
    battle_fn_index: int | None
    chat_payload_factory: ChatPayloadFactory | None
    battle_payload_factory: BattlePayloadFactory | None
    _config: Mapping[str, Any] | None

    def _selected_endpoint(
        self, purpose: str, config: Mapping[str, Any] | None = None
    ) -> QueueEndpoint:
        if purpose not in {"chat", "battle"}:
            raise ValueError("purpose must be 'chat' or 'battle'")
        explicit = self.chat_fn_index if purpose == "chat" else self.battle_fn_index
        if explicit is not None:
            if explicit < 0:
                raise ValueError(f"{purpose}_fn_index must be non-negative")
            return QueueEndpoint(fn_index=explicit)
        if config is None:
            raise ValueError(
                "config is required when no explicit callback index is configured"
            )
        return _find_endpoint(config, purpose)

    def _chat_data(
        self,
        prompt: str,
        model: str | None,
        config: GenerationConfig,
        history: Sequence[Message],
    ) -> list[Any]:
        if self.chat_payload_factory is not None:
            result = self.chat_payload_factory(prompt, model, config, tuple(history))
            if isinstance(result, (str, bytes)):
                raise TypeError(
                    "chat_payload_factory must return a sequence of callback inputs"
                )
            return list(result)
        options = config.model_parameters()
        if history:
            options.setdefault("history", [message.as_dict() for message in history])
        data: list[Any] = [prompt]
        if model is not None:
            data.append(model)
        data.extend((None, options))
        return data

    def _battle_data(
        self,
        prompt: str,
        left_model: str | None,
        right_model: str | None,
        config: GenerationConfig,
    ) -> list[Any]:
        if self.battle_payload_factory is not None:
            result = self.battle_payload_factory(
                prompt, left_model, right_model, config
            )
            if isinstance(result, (str, bytes)):
                raise TypeError(
                    "battle_payload_factory must return a sequence of callback inputs"
                )
            return list(result)
        return [prompt, left_model, right_model, None, config.model_parameters()]

    @staticmethod
    def _check_join(joined: Any) -> None:
        if isinstance(joined, Mapping):
            if joined.get("error"):
                raise ProtocolError(
                    f"Arena rejected the queue request: {joined['error']}"
                )
            if joined.get("msg") == "queue_full":
                raise QueueTimeoutError(
                    "Arena queue is full; retry after the current load subsides."
                )


class ArenaClient(_ArenaClientMixin):
    """Synchronous client for a Gradio-powered Arena deployment.

    Cookies are optional for publicly accessible routes. For an authenticated
    session, supply your own cookie mapping, Cookie header, or cookies.json
    export — or pass ``session_source="firefox"`` to reuse the signed-in
    session of the local Firefox profile (see
    :class:`arena_api.auth.FirefoxSessionManager`). When the session goes
    stale, the client prints guidance, waits for you to re-verify in Firefox,
    re-reads the profile, and retries the request transparently (up to
    ``max_auth_refreshes`` times).

    ``impersonate`` decides which wire the request travels on. ``None`` (the
    default) follows the session source: a Firefox session is sent with
    Firefox's TLS and HTTP/2 fingerprint when the optional ``[impersonate]``
    extra is installed, because an edge that issued the cookies may otherwise
    answer a correct session with a challenge. ``False`` turns that off and a
    profile name (``"firefox"``, ``"chrome"``, ``"firefox147"``) forces one.
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
        chat_fn_index: int | None = None,
        battle_fn_index: int | None = None,
        chat_payload_factory: ChatPayloadFactory | None = None,
        battle_payload_factory: BattlePayloadFactory | None = None,
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
        self.chat_fn_index = chat_fn_index
        self.battle_fn_index = battle_fn_index
        self.chat_payload_factory = chat_payload_factory
        self.battle_payload_factory = battle_payload_factory
        self._config: Mapping[str, Any] | None = None

    def __enter__(self) -> ArenaClient:  # noqa: PYI034 - Self is not in typing until Python 3.11
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self.transport.close()

    def config(self, *, refresh: bool = False) -> Mapping[str, Any]:
        if refresh or self._config is None:
            value = self.transport.get_json(CONFIG_PATH)
            if not isinstance(value, Mapping):
                raise ProtocolError("/config did not return a JSON object")
            self._config = value
        return self._config

    def get_models(self, *, refresh: bool = False) -> list[ModelInfo]:
        return _models_from_config(self.config(refresh=refresh))

    def get_endpoint(self, purpose: str = "chat") -> QueueEndpoint:
        if purpose not in {"chat", "battle"}:
            raise ValueError("purpose must be 'chat' or 'battle'")
        explicit = self.chat_fn_index if purpose == "chat" else self.battle_fn_index
        config = None if explicit is not None else self.config()
        return self._selected_endpoint(purpose, config)

    def _queue(
        self,
        fn_index: int,
        data: Sequence[Any],
        timeout: float,
    ) -> Iterator[tuple[str, Any]]:
        if fn_index < 0:
            raise ValueError("fn_index must be non-negative")
        session_hash = _session_hash()
        joined = self.transport.post_json(
            QUEUE_JOIN_PATH,
            {"data": list(data), "fn_index": fn_index, "session_hash": session_hash},
        )
        self._check_join(joined)
        yielded = False
        for event in self.transport.sse(
            QUEUE_DATA_PATH,
            params={"session_hash": session_hash},
            timeout=timeout,
        ):
            yielded = True
            yield event
        if not yielded:
            raise QueueTimeoutError("Queue stream closed without returning any events.")

    def stream_queue(
        self,
        data: Sequence[Any],
        *,
        fn_index: int,
        timeout: float = DEFAULT_QUEUE_TIMEOUT,
    ) -> Iterator[tuple[str, Any]]:
        """Yield raw queue events for a callback with a custom input schema."""
        yield from self._queue(fn_index, data, timeout)

    def stream(
        self,
        prompt: str,
        *,
        model: str | None = None,
        config: GenerationConfig | None = None,
        history: Sequence[Message] = (),
    ) -> Iterator[StreamChunk]:
        generation = config or GenerationConfig(queue_timeout=DEFAULT_QUEUE_TIMEOUT)
        endpoint = self._selected_endpoint(
            "chat", None if self.chat_fn_index is not None else self.config()
        )
        data = self._chat_data(prompt, model, generation, history)
        previous = ""
        for event_name, event in self._queue(
            endpoint.fn_index, data, generation.queue_timeout
        ):
            _check_queue_event(event_name, event)
            update = _assistant_text(event)
            if update is not None:
                full, delta = _merge_text(previous, update)
                previous = full
                if delta:
                    yield StreamChunk(
                        text=full, delta=delta, event=event_name, raw=event
                    )
            if _terminal(event):
                yield StreamChunk(
                    text=previous, delta="", event="completed", finished=True, raw=event
                )
                return
        raise QueueTimeoutError(
            "Queue stream ended before a completion event was received."
        )

    def complete(
        self,
        prompt: str,
        *,
        model: str | None = None,
        config: GenerationConfig | None = None,
    ) -> str:
        return "".join(
            chunk.delta for chunk in self.stream(prompt, model=model, config=config)
        )

    def chat(
        self,
        *,
        model: str | None = None,
        config: GenerationConfig | None = None,
    ) -> ChatSession:
        from .session import ChatSession

        return ChatSession(self, model=model, config=config)

    def stream_battle(
        self,
        prompt: str,
        *,
        left_model: str | None = None,
        right_model: str | None = None,
        config: GenerationConfig | None = None,
    ) -> Iterator[BattleStreamChunk]:
        generation = config or GenerationConfig(queue_timeout=DEFAULT_QUEUE_TIMEOUT)
        endpoint = self._selected_endpoint(
            "battle", None if self.battle_fn_index is not None else self.config()
        )
        data = self._battle_data(prompt, left_model, right_model, generation)
        left = right = ""
        for event_name, event in self._queue(
            endpoint.fn_index, data, generation.queue_timeout
        ):
            _check_queue_event(event_name, event)
            pair = _battle_texts(event)
            if pair is not None:
                new_left, left_delta = _merge_text(left, pair[0])
                new_right, right_delta = _merge_text(right, pair[1])
                left, right = new_left, new_right
                if left_delta or right_delta:
                    yield BattleStreamChunk(
                        left_text=left,
                        right_text=right,
                        left_delta=left_delta,
                        right_delta=right_delta,
                        event=event_name,
                        raw=event,
                    )
            if _terminal(event):
                yield BattleStreamChunk(
                    left, right, event="completed", finished=True, raw=event
                )
                return
        raise QueueTimeoutError(
            "Battle queue ended before a completion event was received."
        )

    def battle(
        self,
        prompt: str,
        *,
        left_model: str | None = None,
        right_model: str | None = None,
        config: GenerationConfig | None = None,
    ) -> BattleResponse:
        chunks = self.stream_battle(
            prompt,
            left_model=left_model,
            right_model=right_model,
            config=config,
        )
        final: BattleStreamChunk | None = None
        for chunk in chunks:
            if chunk.finished:
                final = chunk
        if final is None:
            raise ProtocolError("Battle stream produced no terminal chunk.")
        if not final.left_text or not final.right_text:
            raise ProtocolError(
                "Battle queue completed without two non-empty responses."
            )
        return BattleResponse(
            final.left_text, final.right_text, left_model, right_model
        )


class AsyncArenaClient(_ArenaClientMixin):
    """Async client with parity to :class:`ArenaClient`.

    Supports the same ``session_source="firefox"`` and ``impersonate=`` options
    as :class:`ArenaClient`. The interactive refresh (console message + waiting
    for Enter) runs in a worker thread so the event loop keeps serving other
    tasks while you re-verify in Firefox.
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
        chat_fn_index: int | None = None,
        battle_fn_index: int | None = None,
        chat_payload_factory: ChatPayloadFactory | None = None,
        battle_payload_factory: BattlePayloadFactory | None = None,
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
        self.chat_fn_index = chat_fn_index
        self.battle_fn_index = battle_fn_index
        self.chat_payload_factory = chat_payload_factory
        self.battle_payload_factory = battle_payload_factory
        self._config: Mapping[str, Any] | None = None

    async def __aenter__(self) -> AsyncArenaClient:  # noqa: PYI034 - Self is not in typing until Python 3.11
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self.transport.close()

    async def config(self, *, refresh: bool = False) -> Mapping[str, Any]:
        if refresh or self._config is None:
            value = await self.transport.get_json(CONFIG_PATH)
            if not isinstance(value, Mapping):
                raise ProtocolError("/config did not return a JSON object")
            self._config = value
        return self._config

    async def get_models(self, *, refresh: bool = False) -> list[ModelInfo]:
        return _models_from_config(await self.config(refresh=refresh))

    async def get_endpoint(self, purpose: str = "chat") -> QueueEndpoint:
        if purpose not in {"chat", "battle"}:
            raise ValueError("purpose must be 'chat' or 'battle'")
        explicit = self.chat_fn_index if purpose == "chat" else self.battle_fn_index
        config = None if explicit is not None else await self.config()
        return self._selected_endpoint(purpose, config)

    async def _queue(
        self,
        fn_index: int,
        data: Sequence[Any],
        timeout: float,
    ) -> AsyncIterator[tuple[str, Any]]:
        if fn_index < 0:
            raise ValueError("fn_index must be non-negative")
        session_hash = _session_hash()
        joined = await self.transport.post_json(
            QUEUE_JOIN_PATH,
            {"data": list(data), "fn_index": fn_index, "session_hash": session_hash},
        )
        self._check_join(joined)
        yielded = False
        async for event in self.transport.sse(
            QUEUE_DATA_PATH,
            params={"session_hash": session_hash},
            timeout=timeout,
        ):
            yielded = True
            yield event
        if not yielded:
            raise QueueTimeoutError("Queue stream closed without returning any events.")

    async def stream_queue(
        self,
        data: Sequence[Any],
        *,
        fn_index: int,
        timeout: float = DEFAULT_QUEUE_TIMEOUT,
    ) -> AsyncIterator[tuple[str, Any]]:
        """Yield raw queue events for a callback with a custom input schema."""
        async for event in self._queue(fn_index, data, timeout):
            yield event

    async def astream(
        self,
        prompt: str,
        *,
        model: str | None = None,
        config: GenerationConfig | None = None,
        history: Sequence[Message] = (),
    ) -> AsyncIterator[StreamChunk]:
        generation = config or GenerationConfig(queue_timeout=DEFAULT_QUEUE_TIMEOUT)
        endpoint = self._selected_endpoint(
            "chat", None if self.chat_fn_index is not None else await self.config()
        )
        data = self._chat_data(prompt, model, generation, history)
        previous = ""
        async for event_name, event in self._queue(
            endpoint.fn_index, data, generation.queue_timeout
        ):
            _check_queue_event(event_name, event)
            update = _assistant_text(event)
            if update is not None:
                full, delta = _merge_text(previous, update)
                previous = full
                if delta:
                    yield StreamChunk(
                        text=full, delta=delta, event=event_name, raw=event
                    )
            if _terminal(event):
                yield StreamChunk(
                    text=previous, delta="", event="completed", finished=True, raw=event
                )
                return
        raise QueueTimeoutError(
            "Queue stream ended before a completion event was received."
        )

    async def acomplete(
        self,
        prompt: str,
        *,
        model: str | None = None,
        config: GenerationConfig | None = None,
    ) -> str:
        return "".join(
            [
                chunk.delta
                async for chunk in self.astream(prompt, model=model, config=config)
            ]
        )

    def chat(
        self,
        *,
        model: str | None = None,
        config: GenerationConfig | None = None,
    ) -> AsyncChatSession:
        from .session import AsyncChatSession

        return AsyncChatSession(self, model=model, config=config)

    async def astream_battle(
        self,
        prompt: str,
        *,
        left_model: str | None = None,
        right_model: str | None = None,
        config: GenerationConfig | None = None,
    ) -> AsyncIterator[BattleStreamChunk]:
        generation = config or GenerationConfig(queue_timeout=DEFAULT_QUEUE_TIMEOUT)
        endpoint = self._selected_endpoint(
            "battle", None if self.battle_fn_index is not None else await self.config()
        )
        data = self._battle_data(prompt, left_model, right_model, generation)
        left = right = ""
        async for event_name, event in self._queue(
            endpoint.fn_index, data, generation.queue_timeout
        ):
            _check_queue_event(event_name, event)
            pair = _battle_texts(event)
            if pair is not None:
                new_left, left_delta = _merge_text(left, pair[0])
                new_right, right_delta = _merge_text(right, pair[1])
                left, right = new_left, new_right
                if left_delta or right_delta:
                    yield BattleStreamChunk(
                        left_text=left,
                        right_text=right,
                        left_delta=left_delta,
                        right_delta=right_delta,
                        event=event_name,
                        raw=event,
                    )
            if _terminal(event):
                yield BattleStreamChunk(
                    left, right, event="completed", finished=True, raw=event
                )
                return
        raise QueueTimeoutError(
            "Battle queue ended before a completion event was received."
        )

    async def abattle(
        self,
        prompt: str,
        *,
        left_model: str | None = None,
        right_model: str | None = None,
        config: GenerationConfig | None = None,
    ) -> BattleResponse:
        final: BattleStreamChunk | None = None
        async for chunk in self.astream_battle(
            prompt,
            left_model=left_model,
            right_model=right_model,
            config=config,
        ):
            if chunk.finished:
                final = chunk
        if final is None:
            raise ProtocolError("Battle stream produced no terminal chunk.")
        if not final.left_text or not final.right_text:
            raise ProtocolError(
                "Battle queue completed without two non-empty responses."
            )
        return BattleResponse(
            final.left_text, final.right_text, left_model, right_model
        )

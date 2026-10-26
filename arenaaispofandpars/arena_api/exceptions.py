"""Exceptions exposed by :mod:`arena_api`."""

from __future__ import annotations


class ArenaError(Exception):
    """Base exception for client, transport, and protocol failures."""


class AuthenticationError(ArenaError):
    """The supplied browser session is absent, expired, or rejected."""


class ChallengeRequiredError(AuthenticationError):
    """The service returned a browser verification or anti-bot challenge.

    Refresh or verify the session in a normal browser, then provide the
    resulting credentials through the documented client inputs.
    """


class CaptchaSolveError(ChallengeRequiredError):
    """A configured solver could not clear an interactive challenge.

    Raised only when ``arena_api.auth`` was explicitly given a captcha solver
    (see :mod:`arena_api.auth.captcha`). It subclasses
    :class:`ChallengeRequiredError`, so existing handlers keep working: the
    remediation is still a browser/human-level fix, the message just also
    reports what the solver tried and why it gave up.
    """


class QueueTimeoutError(ArenaError):
    """The queue or stream did not complete before its configured timeout."""


class ModelUnavailableError(ArenaError):
    """A model, callback, or model-list endpoint is not currently available."""


class RateLimitError(ArenaError):
    """The service rejected a request because of a rate limit."""

    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ProtocolError(ArenaError):
    """A response did not match the expected Arena/Gradio protocol."""


class ClientClosedError(ArenaError):
    """A request was attempted through a client that is already closed.

    Leaving a ``with`` block (or calling ``close()``/``aclose()``) shuts the
    underlying ``httpx`` client down. Reusing it used to surface as a bare
    ``RuntimeError`` from ``httpx``, which no ``except ArenaError`` handler
    caught; build a new client instead.
    """

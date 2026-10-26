"""Unofficial, cookie-authenticated sync/async clients for Arena frontends.

The quickest start is :func:`arena_api.auto_client`: it finds the session of the
browser you are already signed in to, matches its fingerprint, verifies it and
keeps it fresh. This package uses caller-provided credentials — or your own
local browser profile (``auto_client()``, ``session_source="firefox"``); nothing
is collected anywhere else. See the project README for protocol caveats.

On a machine with no profile of yours on it, sign in once by hand --
:func:`arena_api.interactive_login` from Python, or ``arena-api --login`` in a
terminal. It opens a real browser window, waits for you, saves the session to
``state/cookies.json`` and verifies it, after which ``auto_client()`` works with
no arguments at all.

``arena_api.auth`` additionally ships E2E/synthetic-monitoring tooling
(Playwright wrapper, pointer kinematics, determinism init scripts, session
lifecycle management and a challenge *detector*); see
``arena_api.auth.environment`` and ``arena_api.auth.challenge``.
"""

from .auth import (
    BrowserEnvironment,
    BrowserEnvironmentOptions,
    BrowserSessionManager,
    CaptchaAttempt,
    CaptchaSolver,
    ChallengeHandler,
    ChallengeKind,
    ChallengeObservation,
    ChallengeWaitSolver,
    CompositeSolver,
    DeterminismOptions,
    FirefoxSessionError,
    FirefoxSessionManager,
    collect_firefox_report,
    firefox_profiles_roots,
    format_firefox_report,
    FormLoginFlow,
    KinematicMouse,
    KinematicMouseSync,
    LoginResult,
    RecaptchaToolkitSolver,
    SessionManager,
    SessionValidation,
    TrajectoryPlanner,
    alogin_and_save,
    build_init_script,
    inspect_page,
    inspect_response,
    login_and_save,
)
from .client import ArenaClient, AsyncArenaClient, resolve_impersonation
from .direct import (
    AsyncDirectArenaClient,
    AsyncDirectChatSession,
    DirectArenaClient,
    DirectChatSession,
)
from .exceptions import (
    ArenaError,
    AuthenticationError,
    CaptchaSolveError,
    ChallengeRequiredError,
    ClientClosedError,
    ModelUnavailableError,
    ProtocolError,
    QueueTimeoutError,
    RateLimitError,
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
from .session import AsyncChatSession, ChatSession
from .transport import (
    IMPERSONATE_EXTRA,
    ArenaTransport,
    AsyncArenaTransport,
    SSEParser,
    impersonation_available,
    normalize_cookies,
    parse_cookie_header,
)

# Imported last: the bootstrap facade builds on the clients above.
from .auto import (  # noqa: E402
    AutoOptions,
    AutoSessionManager,
    DirectVerificationToken,
    DiscoveredSession,
    LoginOutcome,
    ProbeResult,
    auto_async_client,
    auto_async_direct_client,
    auto_client,
    auto_direct_client,
    discover_session,
    explain_impersonation,
    impersonation_profile,
    interactive_login,
    profile_for_source,
)

# Short aliases for applications that do not need to distinguish the backend.
Client = ArenaClient
AsyncClient = AsyncArenaClient

__all__ = [
    "ArenaClient",
    "ArenaError",
    "ArenaTransport",
    "AsyncArenaClient",
    "AsyncArenaTransport",
    "AsyncChatSession",
    "AsyncClient",
    "AsyncDirectArenaClient",
    "AsyncDirectChatSession",
    "AuthenticationError",
    "AutoOptions",
    "AutoSessionManager",
    "BattleResponse",
    "BattleStreamChunk",
    "BrowserEnvironment",
    "BrowserEnvironmentOptions",
    "BrowserSessionManager",
    "CaptchaAttempt",
    "CaptchaSolveError",
    "CaptchaSolver",
    "ChallengeHandler",
    "ChallengeKind",
    "ChallengeObservation",
    "ChallengeWaitSolver",
    "CompositeSolver",
    "ChallengeRequiredError",
    "ChatSession",
    "IMPERSONATE_EXTRA",
    "Client",
    "ClientClosedError",
    "DeterminismOptions",
    "DirectArenaClient",
    "DirectChatSession",
    "DirectVerificationToken",
    "DiscoveredSession",
    "LoginOutcome",
    "FirefoxSessionError",
    "FirefoxSessionManager",
    "collect_firefox_report",
    "firefox_profiles_roots",
    "format_firefox_report",
    "FormLoginFlow",
    "GenerationConfig",
    "KinematicMouse",
    "explain_impersonation",
    "impersonation_available",
    "impersonation_profile",
    "KinematicMouseSync",
    "LoginResult",
    "Message",
    "ModelInfo",
    "ModelUnavailableError",
    "ProbeResult",
    "ProtocolError",
    "profile_for_source",
    "resolve_impersonation",
    "QueueEndpoint",
    "QueueTimeoutError",
    "RateLimitError",
    "RecaptchaToolkitSolver",
    "SSEParser",
    "SessionManager",
    "SessionValidation",
    "StreamChunk",
    "TrajectoryPlanner",
    "auto_async_client",
    "auto_async_direct_client",
    "auto_client",
    "auto_direct_client",
    "alogin_and_save",
    "build_init_script",
    "discover_session",
    "interactive_login",
    "inspect_page",
    "inspect_response",
    "login_and_save",
    "normalize_cookies",
    "parse_cookie_header",
]

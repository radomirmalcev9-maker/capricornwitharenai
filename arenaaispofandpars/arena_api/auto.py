"""Zero-configuration session bootstrap: sign in once, the rest is automatic.

The one manual step
-------------------
You sign in to your account in your own browser. Nothing else is required: no
cookie export, no headers, no callback indices, no refresh loop.

What happens automatically
--------------------------
1. **Find the session.** Sources are tried in order, first hit wins:
   ``cookies=`` (mapping / header / ``cookies.json``), ``ARENA_COOKIE`` /
   ``ARENA_COOKIES_FILE``, a stored ``cookies.json`` (yours, or written by an
   earlier run that had ``storage_path=`` -- the bootstrap never writes cookies
   to disk on its own), then your browser profile -- Firefox natively
   (``rookiepy`` or the built-in lock-safe ``cookies.sqlite`` reader) and other
   browsers through ``rookiepy`` when it is installed.
2. **Match the fingerprint.** Request headers come from the same source as the
   cookies, so the client presents the browser the session actually came from.
3. **Verify.** One probe request classifies the session: accepted, rejected,
   challenged, rate-limited -- or "reachable, not an auth problem", which does
   not block startup.
4. **Heal, cheapest path first.** When a request later fails with 401/403 or a
   challenge, the refresh ladder runs: re-read the browser profile (in
   interactive mode it asks you to refresh the page and press Enter), then a
   real form login if credentials are configured, then -- only if
   ``solve_captchas`` allows it -- clear a verification screen in a browser:
   a reCAPTCHA token when the solver dependencies are installed, otherwise
   waiting out Turnstile/a managed interstitial or handing hCaptcha/DataDome
   to a person (``wait_out_challenges``, on by default).
5. **Retry transparently.** The transport applies the healed cookies and
   replays the original request, streams included.

Nothing here obtains credentials on its own and nothing is solved silently:
challenge solving needs ``solve_captchas`` (default ``"auto"`` -- on when the
dependencies are importable) and a form login needs credentials *you* put in
the environment. Use it only with accounts and deployments you are entitled to
automate.

Command line::

    python -m arena_api --login              # sign in once by hand, save it
    python -m arena_api --status             # what was found, is it accepted
    python -m arena_api --explain            # every source considered and why
    python -m arena_api --models             # model list of the frontend
    python -m arena_api --prompt "Hi"        # one completion

``--login`` is step 1 for a machine with no browser profile of yours on it: it
opens a headed Chromium, waits for you to sign in, writes ``state/cookies.json``
and verifies it -- after which every command above needs no arguments
(:func:`arena_api.auto.interactive_login` is the same thing from Python).

(``python -m arena_api.auto`` works too; ``python -m arena_api`` is the
warning-free spelling, see :mod:`arena_api.__main__`.)
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import os
import queue
import re
import shutil
import sys
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterator, Mapping, Sequence
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field, replace
from importlib.util import find_spec
from pathlib import Path
from typing import Any, Literal, TextIO
from urllib.parse import urlparse

import httpx

from ._direct_page import (
    _AUTH_REJECT_MARKERS,
    _RetryInHeadedBrowser,
    _arena_auth_jwt_expired,
    _build_browser_fetch_stream_js,
    _build_execute_recaptcha_v3_js,
    _build_wait_supabase_refresh_js,
    _click_challenge_checkbox,
    _cookie_source_for_manager,
    _default_recaptcha_site_key,
    _detect_post_submit_challenge,
    _direct_browser_profile_dir,
    _gentle_page_warmup,
    _is_eval_stream_url,
    _reclick_send_button_if_unsent,
    _reconstruct_supabase_cookie,
    _replay_eval_with_v2_token,
    _safe_bring_to_front,
    _seed_direct_context_cookies,
    _seedable_browser_cookies,
    _submit_prompt_via_composer,
    _token_solver,
)
from ._window_cloak import (
    _OFFSCREEN_HEADFUL_SWITCHES,
    _WindowsBrowserCloaker,
    _hide_headed_page_window_cdp,
    _is_missing_browser_error,
    _is_missing_display_error,
    _maybe_reset_headless_poisoned_cookies,
    _prepare_profile_window_placement,
    _recover_cdp_utf8_bytes,
    _recover_cdp_utf8_text,
    _sanitize_headless_page_cdp,
    _windows_installed_channels,
)

from .auth.autosolve import auto_solve_challenge_on_page
from .auth.browser import BrowserEnvironment, BrowserEnvironmentOptions, run_sync
from .auth.captcha import (
    ChallengeWaitSolver,
    CompositeSolver,
    RecaptchaToolkitSolver,
    describe_solver,
)
from .auth.challenge import ChallengeHandler, ChallengeKind, ChallengeObservation
from .auth.environment import HIDE_WEBDRIVER_SCRIPT
from .auth.login import (
    AUTOMATION_BLINK_SWITCH,
    AUTOMATION_DEFAULT_ARGS_TO_DROP,
    DEFAULT_STATE_PATH,
    LoginResult,
    login_and_save,
)
from .auth.diagnostics import (
    collect_firefox_report,
    format_firefox_report,
    report_as_json,
)
from .auth.firefox_session import (
    DEFAULT_COOKIE_DOMAINS,
    FIREFOX_PROFILE_ENV,
    FIREFOX_ROOT_ENV,
    FirefoxSessionError,
    FirefoxSessionManager,
    SessionManager,
)
from .auth.session import BrowserSessionManager, FormLoginFlow, LoginFlow
from .client import ArenaClient, AsyncArenaClient
from .constants import CONFIG_PATH, DEFAULT_BASE_URL, DEFAULT_TIMEOUT
from .direct import (
    DIRECT_PAGE_PATH,
    AsyncDirectArenaClient,
    DirectArenaClient,
    model_chat_score,
)
from .exceptions import (
    ArenaError,
    AuthenticationError,
    ChallengeRequiredError,
    ProtocolError,
    QueueTimeoutError,
    RateLimitError,
)
from .transport import (
    ARENA_PROXY_ENV,
    IMPERSONATE_EXTRA,
    CookieInput,
    ProxyInput,
    _extract_error_detail,
    _is_verification_rejection,
    _looks_like_challenge,
    _raise_for_status,
    impersonation_available,
    normalize_cookies,
    normalize_proxy,
    redact_proxy_url,
    resolve_proxy_url,
)

_DEFAULT_BROWSER_ENVIRONMENT = BrowserEnvironment

__all__ = [
    "AutoOptions",
    "AutoSessionManager",
    "DirectVerificationToken",
    "DiscoveredSession",
    "LoginOutcome",
    "ProbeResult",
    "aprobe",
    "auto_async_client",
    "auto_async_direct_client",
    "auto_client",
    "auto_direct_client",
    "discover_session",
    "explain_login",
    "explain_impersonation",
    "explain_proxy",
    "explain_sources",
    "has_session_cookie",
    "interactive_login",
    "login_flow_from_env",
    "main",
    "probe",
    "impersonation_profile",
    "profile_for_source",
    "resolve_solver",
    "solver_dependencies_available",
]

#: Printed when no session was found anywhere and the user must sign in.
LOGIN_PROMPT_TEMPLATE = (
    "No session found for {site}. Open it in your browser, sign in to your "
    "account, then press Enter to continue..."
)

#: Browsers ``rookiepy`` can read, in the order they are tried after Firefox.
ROOKIEPY_BROWSERS: tuple[str, ...] = (
    "chrome",
    "chromium",
    "edge",
    "brave",
    "vivaldi",
    "opera",
)

#: Environment variables that turn a stored login into an automatic one.
LOGIN_URL_ENV = "ARENA_LOGIN_URL"
USERNAME_ENV = "ARENA_USERNAME"
PASSWORD_ENV = "ARENA_PASSWORD"
USER_SELECTOR_ENV = "ARENA_USER_SELECTOR"
PASS_SELECTOR_ENV = "ARENA_PASS_SELECTOR"
SUBMIT_SELECTOR_ENV = "ARENA_SUBMIT_SELECTOR"
SUCCESS_URL_ENV = "ARENA_SUCCESS_URL"


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DiscoveredSession:
    """A session found by :func:`discover_session`.

    :param source: short label -- ``"cookies"``, ``"env"``, ``"storage"``,
        ``"firefox"`` or ``"browser:<name>"``.
    :param cookies: flat ``{name: value}`` mapping.
    :param headers: browser-consistent headers from the same source.
    :param manager: the source's own manager, used as the cheap first rung of
        the refresh ladder (``None`` for plain cookie exports).
    :param description: human-readable one-liner for logs.
    """

    source: str
    cookies: dict[str, str]
    headers: dict[str, str]
    manager: SessionManager | None = None
    description: str = ""


#: Captcha/challenge markup that must never appear in an API response. Only
#: checked when the body is HTML: a JSON payload cannot be mistaken for one, so
#: a model or endpoint merely *named* "recaptcha" stays a healthy session.
_INTERSTITIAL_MARKERS: tuple[str, ...] = (
    "g-recaptcha",
    "/recaptcha/api2/anchor",
    "/recaptcha/enterprise/anchor",
    "/recaptcha/api.js",
    "hcaptcha",
    "cf-turnstile",
    "cdn-cgi/challenge-platform/h/",
    "just a moment",
    "captcha-delivery",
)


#: Pages that embed reCAPTCHA markup as part of their normal job, so finding it
#: there is not evidence of a challenge. The Direct Chat page is asserted with a
#: v3 token on every load (see :class:`DirectVerificationToken`).
_RECAPTCHA_OK_PATHS: tuple[str, ...] = (DIRECT_PAGE_PATH.split("?")[0],)


def _expects_recaptcha(path: str) -> bool:
    """Whether ``path`` is a page that legitimately contains captcha markup."""
    target = path.split("?")[0].rstrip("/")
    return any(target == ok.rstrip("/") for ok in _RECAPTCHA_OK_PATHS)


def _interstitial_marker(text: str) -> str | None:
    """Name the challenge markup in an HTML body, or ``None`` for a real payload."""
    head = text.lstrip()[:512].lower()
    if not head.startswith(("<!doctype html", "<html")):
        return None
    lowered = text.lower()
    for marker in _INTERSTITIAL_MARKERS:
        if marker in lowered:
            return marker
    return None


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of the one verification request made at bootstrap."""

    ok: bool
    reason: str
    auth_problem: bool = False
    error: ArenaError | None = None

    def describe(self) -> str:
        """One-line summary for logs."""
        return f"{'ok' if self.ok else 'not ok'}: {self.reason}"


# --------------------------------------------------------------------------- #
# Options
# --------------------------------------------------------------------------- #


@dataclass
class AutoOptions:
    """Every knob of the bootstrap, with defaults that need no configuration."""

    base_url: str = DEFAULT_BASE_URL

    #: Explicit cookie export; wins over every discovered source.
    cookies: CookieInput = None

    #: ``cookies.json`` written by an earlier run; also where a browser login
    #: persists its result. Defaults to ``./state/cookies.json`` when present.
    storage_path: str | Path | None = None

    #: Cookie domains; defaults to the ``base_url`` host plus the Arena ones.
    domains: tuple[str, ...] | None = None

    headers: Mapping[str, str] | None = None

    #: Read cookies from browser profiles. ``False`` limits discovery to
    #: explicit exports and the stored file.
    use_browser_profiles: bool = True

    #: Firefox profile pass-throughs (portable installs, a non-default profile,
    #: an explicit ``cookies.sqlite``). ``None`` keeps auto-discovery.
    profiles_root: str | Path | None = None
    profile_name: str | None = None
    cookie_database: str | Path | None = None

    #: Ask for Enter when the session must be refreshed by hand.
    interactive: bool = True
    prompt: Callable[[str], str] = input
    output: TextIO | None = None

    #: Real form login used when the profile re-read is not enough. ``None``
    #: builds one from ``ARENA_*`` environment variables when they are complete.
    login_flow: LoginFlow | None = None
    login_from_env: bool = True

    #: Browser build the ``--login`` window runs in. ``None`` uses Playwright's
    #: bundled Chromium, from which Google refuses to sign an account in ("this
    #: browser or app may not be secure"). ``"chrome"`` (or ``"msedge"`` on
    #: Windows) drives the real, installed browser instead -- the usual fix when
    #: the account signs in *through Google* rather than with a password.
    channel: str | None = None

    #: Drop the automation markers in the ``--login`` window
    #: (``--enable-automation``, ``navigator.webdriver``). Off by default; turn
    #: it on together with ``channel="chrome"`` when the sign-in goes through
    #: Google and it keeps answering "this browser or app may not be secure".
    #: It only affects the interactive sign-in window -- the session the library
    #: then reads is the same either way.
    hide_automation: bool = False

    #: Which browser's TLS/HTTP2 fingerprint the requests should carry, so a
    #: cookie-aware edge does not answer a *correct* session with a challenge
    #: page. ``"auto"`` follows the browser the session was found in
    #: (Firefox -> ``"firefox"``, a Chrome-family profile -> ``"chrome"``) as
    #: soon as the optional ``[impersonate]`` extra is installed; an unknown
    #: source (an explicit ``cookies=``, a stored file) stays as it is, since
    #: guessing the browser would mismatch the headers we send. Pass ``"off"``
    #: to disable, or a profile name (``"firefox147"``) to force one.
    impersonate: str | None = "auto"

    #: ``True``/``False`` force challenge solving on or off; ``"auto"`` (the
    #: default) enables it when the solver dependencies are importable.
    solve_captchas: bool | Literal["auto"] = "auto"
    captcha_backend: str = "audio"
    captcha_solver: Any | None = None

    #: Wait out the challenges that have no token to produce (Turnstile, a
    #: managed Cloudflare interstitial) and give a person a headed window for the
    #: rest (hCaptcha, DataDome, anything unrecognised). Needs no third-party
    #: package, so it is on by default -- set ``False`` for the pure
    #: detect-and-report behaviour.
    wait_out_challenges: bool = True

    #: Seconds :class:`~arena_api.auth.captcha.ChallengeWaitSolver` waits per
    #: round, polling the page, before reporting the challenge as unsolved.
    challenge_wait_timeout: float = 30.0

    #: Path probed to verify the session. Must be an API/JSON endpoint: an HTML
    #: page carrying captcha markup is read as a challenge. (The Direct Chat page
    #: is the documented exception -- it legitimately embeds a v3 assertion.)
    probe_path: str = CONFIG_PATH
    verify: bool = True

    max_auth_refreshes: int = 2
    timeout: float = DEFAULT_TIMEOUT
    http2: bool = True
    verify_tls: bool | str = True
    proxy: ProxyInput = None
    http_transport: Any = None

    #: Where browser artefacts (challenge captures, traces) are written.
    artifacts_dir: str | Path | None = "./artifacts"

    #: Show the Direct Chat verification browser window instead of running
    #: invisibly in New Headless mode (default ``False`` = invisible).
    show_browser: bool = False

    def __post_init__(self) -> None:
        if self.storage_path is not None:
            self.storage_path = Path(self.storage_path)
        if self.artifacts_dir is not None:
            self.artifacts_dir = Path(self.artifacts_dir)
        if self.solve_captchas not in (True, False, "auto"):
            raise ValueError("solve_captchas must be True, False or 'auto'")
        if self.challenge_wait_timeout <= 0:
            raise ValueError("challenge_wait_timeout must be positive")
        normalize_proxy(self.proxy)
        # ``off``/``False``/"" all mean "do not impersonate"; "auto" is kept and
        # resolved later, once the session has been discovered.
        if self.impersonate is False or self.impersonate in ("off", ""):
            self.impersonate = None
        if self.impersonate is not None and not isinstance(self.impersonate, str):
            raise ValueError(
                "impersonate must be 'auto', a curl_cffi profile name, or "
                "None/'off' to disable it"
            )

    @property
    def site(self) -> str:
        """Host of ``base_url``, used in user-facing messages."""
        return urlparse(self.base_url).hostname or self.base_url

    def cookie_domains(self) -> tuple[str, ...]:
        """Domains to read from browser profiles."""
        if self.domains:
            return tuple(self.domains)
        host = self.site
        extras = tuple(domain for domain in DEFAULT_COOKIE_DOMAINS if domain != host)
        return (host, *extras) if host else DEFAULT_COOKIE_DOMAINS


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #


def _emit(options: AutoOptions, message: str) -> None:
    stream = options.output if options.output is not None else sys.stderr
    print(message, file=stream, flush=True)


def _domains_for(options: AutoOptions) -> list[str]:
    return list(options.cookie_domains())


def _from_explicit_cookies(options: AutoOptions) -> DiscoveredSession | None:
    if options.cookies is None:
        return None
    try:
        cookies = normalize_cookies(options.cookies)
    except (ValueError, FileNotFoundError, OSError) as exc:
        raise AuthenticationError(f"cookies= could not be read: {exc}") from exc
    if not cookies:
        return None
    return DiscoveredSession(
        source="cookies",
        cookies=cookies,
        headers={},
        description=f"explicit cookies= ({len(cookies)} names)",
    )


def _from_environment(options: AutoOptions) -> DiscoveredSession | None:
    header = os.environ.get("ARENA_COOKIE")
    path = os.environ.get("ARENA_COOKIES_FILE")
    if not header and not path:
        return None
    try:
        cookies = normalize_cookies(Path(path) if path else header)
    except (ValueError, FileNotFoundError, OSError) as exc:
        raise AuthenticationError(
            f"ARENA_COOKIE{'S_FILE' if path else ''} could not be read: {exc}"
        ) from exc
    if not cookies:
        return None
    return DiscoveredSession(
        source="env",
        cookies=cookies,
        headers={},
        description="ARENA_COOKIES_FILE" if path else "ARENA_COOKIE",
    )


def _default_storage_path(options: AutoOptions) -> Path | None:
    if options.storage_path is not None:
        return Path(options.storage_path)
    candidate = Path("state") / "cookies.json"
    return candidate if candidate.is_file() else None


def _from_storage(options: AutoOptions) -> DiscoveredSession | None:
    path = _default_storage_path(options)
    if path is None or not path.is_file():
        return None
    manager = BrowserSessionManager(
        base_url=options.base_url,
        domains=options.cookie_domains(),
        storage_path=path,
    )
    cookies = manager.load_cookies()
    if not cookies:
        # Not a Playwright ``storage_state`` file: a plain cookie export (a
        # ``{name: value}`` mapping, a ``Cookie:`` header, an extension's
        # record list) is just as good a source.
        try:
            cookies = normalize_cookies(path)
        except (ValueError, OSError) as exc:
            raise AuthenticationError(f"{path} could not be read: {exc}") from exc
        if cookies:
            manager.import_cookies(cookies)
    if not cookies:
        return None
    return DiscoveredSession(
        source="storage",
        cookies=cookies,
        headers=manager.headers(),
        # Re-reading the same file would return the very cookies that were just
        # rejected, so the ladder (login flow / solver) is the refresh path here.
        manager=None,
        description=f"{path} ({len(cookies)} names)",
    )


def _from_firefox(options: AutoOptions) -> DiscoveredSession | None:
    manager = FirefoxSessionManager(
        domains=_domains_for(options),
        profiles_root=options.profiles_root,
        profile_name=options.profile_name,
        cookie_database=options.cookie_database,
        interactive=options.interactive,
        prompt=options.prompt,
        output=options.output,
    )
    try:
        cookies = manager.load_cookies()
    except FirefoxSessionError:
        return None
    if not cookies:
        return None
    return DiscoveredSession(
        source="firefox",
        cookies=cookies,
        headers=manager.firefox_headers(),
        manager=manager,
        description=f"Firefox profile {manager.profile_path()} ({len(cookies)} names)",
    )


def _rookiepy_module() -> Any | None:
    try:
        import rookiepy  # optional dependency; mypy config silences the missing stubs
    except ImportError:
        return None
    return rookiepy


#: Account-level session cookie stems (edge-only cookies like ``cf_clearance``
#: and UI flags like ``sidebar_state`` are excluded so an anonymous landing-page
#: capture does not outrank a signed-in browser profile).
_SESSION_SUBSTRING_HINTS: tuple[str, ...] = (
    "session",
    "token",
    "auth",
    "jwt",
    "login",
    "__secure",
    "__host",
)
_SESSION_TOKEN_HINTS: frozenset[str] = frozenset({"sid", "sess"})
_SESSION_SUFFIX_HINTS: tuple[str, ...] = ("sessid", "sessionid")


def _is_session_cookie_name(name: str) -> bool:
    lowered = name.lower()
    if any(hint in lowered for hint in _SESSION_SUBSTRING_HINTS):
        return True
    if lowered.endswith(_SESSION_SUFFIX_HINTS):
        return True
    tokens = {part for part in re.split(r"[^a-z0-9]+", lowered) if part}
    return bool(tokens & _SESSION_TOKEN_HINTS)


def has_session_cookie(cookies: Mapping[str, str]) -> bool:
    """Whether ``cookies`` includes at least one account-level session token."""
    return any(_is_session_cookie_name(name) for name in cookies)


def _from_other_browsers(options: AutoOptions) -> DiscoveredSession | None:
    """Read a Chromium-family profile through ``rookiepy``, if installed.

    Firefox is handled by :func:`_from_firefox`, which also works without
    ``rookiepy``; this covers the browsers the optional dependency adds.
    """
    rookiepy = _rookiepy_module()
    if rookiepy is None:
        return None
    domains = _domains_for(options)
    fallback: DiscoveredSession | None = None
    for name in ROOKIEPY_BROWSERS:
        reader = getattr(rookiepy, name, None)
        if reader is None:
            continue
        try:
            records = reader(domains=domains)
        except Exception:  # noqa: BLE001 - locked store, missing profile, ...
            continue
        cookies = _flat_records(records)
        if cookies:
            found = DiscoveredSession(
                source=f"browser:{name}",
                cookies=cookies,
                headers={},
                description=f"{name} profile via rookiepy ({len(cookies)} names)",
            )
            if has_session_cookie(cookies):
                return found
            if fallback is None:
                fallback = found
    return fallback


def _flat_records(records: Any) -> dict[str, str]:
    """Flatten a rookiepy record list into ``{name: value}``."""
    from .auth.firefox_session import cookies_from_rookiepy

    try:
        return cookies_from_rookiepy(records)
    except Exception:  # noqa: BLE001 - unexpected record shape
        return {}


def discover_session(options: AutoOptions | None = None) -> DiscoveredSession | None:
    """Return the first usable session, or ``None`` when there is none.

    Order: explicit ``cookies=``, ``ARENA_COOKIE``/``ARENA_COOKIES_FILE``, a
    stored ``cookies.json``, the Firefox profile, then other browsers through
    ``rookiepy``. Among implicit local sources (the default
    ``./state/cookies.json`` and browser profiles), a signed-in session takes
    precedence over an anonymous guest capture that holds no auth cookie.
    """
    options = options or AutoOptions()
    for explicit in (_from_explicit_cookies, _from_environment):
        found = explicit(options)
        if found is not None:
            return found
    if options.storage_path is not None:
        stored = _from_storage(options)
        if stored is not None:
            return stored

    implicit: list[Callable[[AutoOptions], DiscoveredSession | None]] = []
    if options.storage_path is None:
        implicit.append(_from_storage)
    if options.use_browser_profiles:
        implicit.append(_from_firefox)
        implicit.append(_from_other_browsers)

    guest_fallback: DiscoveredSession | None = None
    for candidate in implicit:
        found = candidate(options)
        if found is None:
            continue
        if has_session_cookie(found.cookies):
            return found
        if guest_fallback is None:
            guest_fallback = found
    return guest_fallback


def _report_line(label: str, value: str) -> str:
    """One aligned ``label : value`` line of the discovery report."""
    return f"{label:<20}: {value}"


def explain_sources(options: AutoOptions | None = None) -> list[str]:
    """Describe every source considered, for ``--explain`` and error messages."""
    options = options or AutoOptions()
    report: list[str] = [
        _report_line("cookies=", "set" if options.cookies is not None else "not given"),
        _report_line(
            "ARENA_COOKIE(S_FILE)",
            "set"
            if os.environ.get("ARENA_COOKIE") or os.environ.get("ARENA_COOKIES_FILE")
            else "not set",
        ),
    ]
    path = _default_storage_path(options)
    if path is None:
        report.append(_report_line("stored cookies.json", "not configured"))
    elif not path.is_file():
        report.append(_report_line("stored cookies.json", f"{path} (absent)"))
    else:
        note = "(exists)"
        if options.storage_path is None:
            try:
                stored = _from_storage(options)
            except AuthenticationError:
                stored = None
            if stored is not None and not has_session_cookie(stored.cookies):
                note = "(exists, guest/anonymous -- skipped for signed-in profile)"
        report.append(_report_line("stored cookies.json", f"{path} {note}"))
    if not options.use_browser_profiles:
        report.append(
            _report_line(
                "browser profiles", "disabled by use_browser_profiles=False"
            )
        )
        return report

    report.extend(_explain_firefox(options))
    if _rookiepy_module() is None:
        report.append(
            _report_line(
                "other browsers",
                "rookiepy not installed "
                "(pip install '.[firefox]' to add Chrome/Edge/Brave/...)",
            )
        )
    else:
        report.append(_report_line("other browsers", "rookiepy available"))
    return report


def _explain_firefox(options: AutoOptions) -> list[str]:
    """One report line per Firefox profile, then the one that would be used.

    A machine with several profiles is exactly where "no session found" used to
    come from: the configured default is often not the profile holding the
    cookies, and a single line that named only that default hid the others.
    """
    manager = FirefoxSessionManager(
        domains=_domains_for(options),
        profiles_root=options.profiles_root,
        profile_name=options.profile_name,
        cookie_database=options.cookie_database,
    )
    domains = ", ".join(_domains_for(options))
    lines: list[str] = []
    try:
        candidates = manager.profile_candidates()
    except FirefoxSessionError as exc:
        return [_report_line("Firefox profile", f"unavailable ({exc})")]
    for index, profile in enumerate(candidates[:6], start=1):
        count = manager.profile_cookie_count(profile)
        label = "Firefox profile" if index == 1 else f"Firefox profile {index}"
        lines.append(_report_line(label, f"{profile} ({count} cookies for {domains})"))
    if len(candidates) > 6:
        lines.append(
            _report_line(
                "Firefox profiles",
                f"... and {len(candidates) - 6} more (see --diagnose)",
            )
        )
    try:
        lines.append(_report_line("Firefox selected", manager.selection_reason()))
    except FirefoxSessionError as exc:
        lines.append(_report_line("Firefox selected", f"unavailable ({exc})"))
    return lines


def _firefox_cookie_total(options: AutoOptions) -> int:
    """How many matching cookies all Firefox profiles hold together."""
    manager = FirefoxSessionManager(
        domains=_domains_for(options),
        profiles_root=options.profiles_root,
        profile_name=options.profile_name,
        cookie_database=options.cookie_database,
    )
    try:
        candidates = manager.profile_candidates()
    except FirefoxSessionError:
        return 0
    return sum(manager.profile_cookie_count(profile) for profile in candidates)


def _wait_for_login(options: AutoOptions) -> bool:
    """Ask the user to sign in, then look for a session again."""
    if not options.interactive:
        return False
    message = LOGIN_PROMPT_TEMPLATE.format(site=options.site)
    try:
        # ``input`` prints the message itself; a custom prompt receives it.
        options.prompt(message)
    except (EOFError, KeyboardInterrupt):
        _emit(options, "[arena-api] login wait cancelled")
        return False
    return discover_session(options) is not None


# --------------------------------------------------------------------------- #
# Refresh ladder
# --------------------------------------------------------------------------- #


def _has_spec(name: str) -> bool:
    try:
        return find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def solver_dependencies_available(backend: str = "audio") -> bool:
    """Whether the solver backend's dependencies can be imported.

    Checked with :func:`importlib.util.find_spec` so that deciding costs
    nothing and never imports ``torch``/``playwright`` as a side effect.
    """
    if not _has_spec("playwright"):
        return False
    if str(backend) == "vision_ai":
        return _has_spec("vision_ai_recaptcha_solver")
    return _has_spec("playwright_recaptcha") and _has_spec("playwright_stealth")


def resolve_solver(options: AutoOptions) -> Any | None:
    """Build the captcha solver the options ask for, or ``None``.

    Three ingredients, in order of precedence:

    * an explicit ``options.captcha_solver`` wins outright;
    * ``solve_captchas=False`` switches everything off, waiting included;
    * otherwise a :class:`~arena_api.auth.captcha.RecaptchaToolkitSolver` joins
      when its backend dependencies are importable (or when solving is forced on
      with ``solve_captchas=True``), and a
      :class:`~arena_api.auth.captcha.ChallengeWaitSolver` joins when
      ``wait_out_challenges`` is set.

    A single ingredient is returned bare; several are wrapped in a
    :class:`~arena_api.auth.captcha.CompositeSolver` that dispatches by
    challenge kind. Because waiting needs nothing but Playwright,
    ``solve_captchas="auto"`` is no longer a silent no-op on a machine without
    ``playwright-recaptcha``: reCAPTCHA stays unsolvable there, but a Turnstile
    or an hCaptcha screen is still handled.
    """
    if options.captcha_solver is not None:
        return options.captcha_solver
    if options.solve_captchas is False:
        return None

    solvers: list[Any] = []
    if options.solve_captchas is True or solver_dependencies_available(
        options.captcha_backend
    ):
        solvers.append(RecaptchaToolkitSolver(backend=options.captcha_backend))
    if options.wait_out_challenges:
        solvers.append(
            ChallengeWaitSolver(
                timeout=options.challenge_wait_timeout,
                interactive=options.interactive,
                prompt=options.prompt,
                output=options.output,
            )
        )
    if not solvers:
        return None
    return solvers[0] if len(solvers) == 1 else CompositeSolver(*solvers)


def _solver_needs_headed_window(solver: Any) -> bool:
    """Whether ``solver`` asks a human to act in a visible browser window."""
    if isinstance(solver, ChallengeWaitSolver):
        return bool(solver.interactive)
    members = getattr(solver, "solvers", None)
    if members:
        return any(_solver_needs_headed_window(item) for item in members)
    return False


def login_flow_from_env(options: AutoOptions) -> LoginFlow | None:
    """Build a :class:`FormLoginFlow` from ``ARENA_*`` variables, if complete.

    Credentials alone are not enough: the form's selectors are
    deployment-specific, so a partial configuration is ignored (and reported by
    :func:`explain_login`) rather than guessed at.
    """
    if options.login_flow is not None:
        return options.login_flow
    if not options.login_from_env:
        return None
    required = {
        "credentials": (USERNAME_ENV, PASSWORD_ENV),
        "form": (LOGIN_URL_ENV, USER_SELECTOR_ENV, PASS_SELECTOR_ENV, SUBMIT_SELECTOR_ENV),
    }
    for names in required.values():
        if not all(os.environ.get(name) for name in names):
            return None
    return FormLoginFlow(
        login_url=os.environ[LOGIN_URL_ENV],
        username_selector=os.environ[USER_SELECTOR_ENV],
        password_selector=os.environ[PASS_SELECTOR_ENV],
        submit_selector=os.environ[SUBMIT_SELECTOR_ENV],
        success_url_contains=os.environ.get(SUCCESS_URL_ENV),
        username_env=USERNAME_ENV,
        password_env=PASSWORD_ENV,
    )


def _login_state(options: AutoOptions) -> str:
    """Why the automatic form login is or is not available (value only)."""
    if options.login_flow is not None:
        return "configured explicitly"
    if not options.login_from_env:
        return "disabled by login_from_env=False"
    credentials = [name for name in (USERNAME_ENV, PASSWORD_ENV) if not os.environ.get(name)]
    form = [
        name
        for name in (LOGIN_URL_ENV, USER_SELECTOR_ENV, PASS_SELECTOR_ENV, SUBMIT_SELECTOR_ENV)
        if not os.environ.get(name)
    ]
    if not credentials and not form:
        return "available from the environment"
    missing = ", ".join(credentials + form)
    return f"unavailable, missing {missing}"


def explain_login(options: AutoOptions | None = None) -> str:
    """One-line answer to "can this run sign itself in?"."""
    return f"login flow: {_login_state(options or AutoOptions())}"


# --------------------------------------------------------------------------- #
# Interactive login: the one manual step
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class LoginOutcome:
    """An interactive sign-in, plus the server's verdict on what it produced.

    :ivar login: the browser-side result (cookies, rounds, state file).
    :ivar verification: probe of the freshly saved file, or ``None`` when
        verification was skipped.
    :ivar path: the state file, when one was written.
    """

    login: LoginResult
    verification: ProbeResult | None = None
    path: Path | None = None

    @property
    def ok(self) -> bool:
        """The sign-in produced a usable capture and, when checked, the server
        accepted it.

        Delegates the first half to :attr:`LoginResult.ok`, so an exhausted or
        cancelled wait is never reported as success just because the browser
        happened to hold anonymous cookies.
        """
        return self.login.ok and (self.verification is None or self.verification.ok)

    def describe(self) -> str:
        """Two-line-friendly summary used by the CLI."""
        parts = [f"login: {self.login.describe()}"]
        if self.verification is not None:
            parts.append(f"verification: {self.verification.describe()}")
        return "; ".join(parts)


def interactive_login(
    options: AutoOptions | None = None,
    *,
    path: str | Path | None = None,
    headless: bool = False,
    fresh: bool = False,
    rounds: int = 5,
    verify: bool | None = None,
    login_flow: LoginFlow | None = None,
    **overrides: Any,
) -> LoginOutcome:
    """Open a browser, let a human sign in, save and verify the session.

    This is the "you only have to log in" step, as a function::

        from arena_api import interactive_login

        outcome = interactive_login()
        if outcome.ok:
            print("session saved to", outcome.path)

    Afterwards :func:`auto_client` needs no arguments at all: it finds the state
    file this call wrote.

    :param options: bootstrap options; ``base_url``, ``domains``, ``prompt``,
        ``output``, ``probe_path`` and the captcha settings are taken from it.
    :param path: where to save. Defaults to ``options.storage_path`` and then to
        :data:`~arena_api.auth.login.DEFAULT_STATE_PATH` (``./state/cookies.json``).
    :param headless: hide the window. Almost never what you want here -- you
        have to see the page to sign in to it.
    :param fresh: ignore an existing state file instead of reusing it, e.g. to
        switch accounts.
    :param rounds: how many Enter presses to offer before giving up.
    :param verify: probe the saved session afterwards (defaults to
        ``options.verify``).
    :param login_flow: fill the sign-in form first (``FormLoginFlow``). Without
        it, a complete ``ARENA_*`` configuration is used when present.
    :param overrides: any other :class:`AutoOptions` field -- including
        ``channel`` (e.g. ``"chrome"``) and ``hide_automation``, which together
        are how you sign in to an account that authenticates *through Google*:
        Google rejects Playwright's bundled Chromium, and reads the automation
        markers it leaves behind even in a real one.
    :returns: a :class:`LoginOutcome`; :attr:`LoginOutcome.ok` is ``False`` when
        nothing was captured or the server rejected it.

    .. note::
       Blocking by design: the wait happens on ``input()``. There is no async
       twin, because an interactive sign-in cannot run concurrently with the
       loop that would have to await it.
    """
    options = _merge_options(options, overrides)
    destination = Path(path or options.storage_path or DEFAULT_STATE_PATH)
    flow = login_flow or login_flow_from_env(options)
    solver = resolve_solver(options)

    result = login_and_save(
        base_url=options.base_url,
        path=destination,
        domains=options.cookie_domains(),
        headless=headless,
        channel=options.channel,
        hide_automation=options.hide_automation,
        reuse_existing=not fresh,
        rounds=rounds,
        login_flow=flow,
        captcha_solver=solver,
        prompt=options.prompt,
        output=options.output,
        artifacts_dir=options.artifacts_dir,
    )

    check = options.verify if verify is None else verify
    verification: ProbeResult | None = None
    if check and result.saved:
        verification = _verify_saved_session(options, destination)
        if verification is not None and not verification.ok:
            _emit(
                options,
                f"[arena-api] the saved session did not verify ({verification.reason})",
            )
    elif check:
        _emit(
            options,
            f"[arena-api] nothing saved to {destination}; skipping verification",
        )
    return LoginOutcome(
        login=result,
        verification=verification,
        path=destination if result.saved else None,
    )


def _verify_saved_session(options: AutoOptions, destination: Path) -> ProbeResult | None:
    """Probe exactly the file just written, with no refresh ladder of its own.

    The ladder's own remedy for a rejected session *is* another sign-in, so it
    is switched off here (``interactive=False``, ``verify=False``): this probe
    must report, not act.
    """
    probe_options = replace(
        options,
        cookies=None,
        storage_path=str(destination),
        use_browser_profiles=False,
        login_from_env=False,
        interactive=False,
        solve_captchas=False,
        max_auth_refreshes=0,
        verify=False,
    )
    try:
        with auto_client(probe_options) as client:
            return probe(client, options.probe_path)
    except ArenaError as exc:
        return _classify(exc)


@dataclass
class AutoSessionManager(BrowserSessionManager):
    """Session manager that refreshes through the cheapest path first.

    The ladder is: re-read the source the cookies came from (for a browser
    profile this is the interactive "refresh the page, press Enter" step, and it
    needs no browser of our own), then a real form login, then -- only when a
    solver is configured -- clearing a challenge in a browser. Each rung is
    tried only if the previous one returned nothing.
    """

    #: Manager of the source the cookies were discovered from.
    fallback: SessionManager | None = None
    _from_fallback: bool = field(default=True, repr=False, compare=False)
    #: Serialises the ladder: parallel requests that all fail with 403 must not
    #: each start a browser, solve a captcha, or ask for Enter.
    _refresh_lock: threading.RLock = field(
        default_factory=threading.RLock, repr=False, compare=False
    )

    def firefox_headers(self, *, navigation: bool = False) -> dict[str, str]:
        """Headers of the browser that owns the current cookies.

        A session read from Firefox must be presented as Firefox; once a
        browser login has replaced it, the Chromium headers of that run are the
        consistent ones.
        """
        if self._from_fallback and self.fallback is not None:
            try:
                return self.fallback.firefox_headers(navigation=navigation)
            except Exception:  # noqa: BLE001 - a source without headers
                pass
        return super().firefox_headers(navigation=navigation)

    def proxy_url(
        self, *, scheme: str = "https", host: str | None = None
    ) -> str | None:
        """Manual proxy configured on the underlying browser profile, if any."""
        if self._from_fallback and self.fallback is not None:
            getter = getattr(self.fallback, "proxy_url", None)
            if callable(getter):
                try:
                    value = getter(scheme=scheme, host=host)
                except Exception:  # noqa: BLE001
                    return None
                return value if isinstance(value, str) and value.strip() else None
        return None

    def adopt(self, cookies: Mapping[str, str]) -> None:
        """Replace the stored session with freshly read cookies."""
        self.import_cookies(dict(cookies))
        self._from_fallback = True

    def refresh_session(self, reason: BaseException | None = None) -> dict[str, str] | None:
        """Run the refresh ladder and return fresh cookies, or ``None``.

        Thread-safe: when several requests fail at once, the first one refreshes
        and the others pick up its result instead of repeating the work.
        """
        stale = self.load_cookies()
        with self._refresh_lock:
            current = self.load_cookies()
            if current and current != stale:
                return current
            return self._refresh(reason)

    def _refresh(self, reason: BaseException | None) -> dict[str, str] | None:
        """The ladder itself; called with :attr:`_refresh_lock` held."""
        if self.fallback is not None:
            try:
                cookies = self.fallback.refresh_session(reason)
            except Exception as exc:  # noqa: BLE001 - source-specific failures
                cookies = None
                _emit_note(self, f"source refresh failed: {type(exc).__name__}: {exc}")
            if cookies:
                self.adopt(cookies)
                return cookies
        if self.login_flow is None and self.captcha_solver is None:
            raise AuthenticationError(
                "the session was rejected and no automatic refresh path is left: "
                "sign in again in your browser, or configure one of "
                f"{USERNAME_ENV}/{PASSWORD_ENV} with form selectors "
                f"(see {__name__}.explain_login), or enable challenge solving "
                "(solve_captchas=True, pip install '.[auth-captcha]')"
            )
        self._from_fallback = False
        return super().refresh_session(reason)


def _emit_note(manager: AutoSessionManager, message: str) -> None:
    """Best-effort progress note; the manager has no output stream of its own."""
    print(f"[arena-api] {message}", file=sys.stderr, flush=True)


#: Which curl_cffi profile matches a discovered source. A source is mapped only
#: when both halves of the fingerprint agree: Firefox writes Firefox headers, and
#: every other source is presented with the Chromium headers
#: :meth:`~arena_api.auth.session.BrowserSessionManager.headers` builds (a real
#: Edge profile is presented as Chromium too, so it gets Chromium's wire, not
#: Edge's slightly different one).
_SOURCE_PROFILES: dict[str, str] = {
    "firefox": "firefox",
    "browser:chrome": "chrome",
    "browser:chromium": "chrome",
    "browser:brave": "chrome",
    "browser:vivaldi": "chrome",
    "browser:opera": "chrome",
    "browser:edge": "chrome",
    "cookies": "chrome",
    "env": "chrome",
    "storage": "chrome",
}


def profile_for_source(source: str | None) -> str | None:
    """The curl_cffi profile that matches a discovered session source."""
    if not source:
        return None
    return _SOURCE_PROFILES.get(source)


def impersonation_profile(
    options: AutoOptions, discovered: DiscoveredSession | None = None
) -> str | None:
    """Turn :attr:`AutoOptions.impersonate` into a profile name or ``None``.

    ``"auto"`` is silent by design: when the optional dependency is missing, or
    the browser behind the cookies cannot be identified, it resolves to ``None``
    -- the request goes out exactly as it did before this option existed.
    """
    value = options.impersonate
    if value is None:
        return None
    if value != "auto":
        return value
    if not impersonation_available():
        return None
    return profile_for_source(discovered.source if discovered is not None else None)


def explain_impersonation(options: AutoOptions) -> str:
    """One line for ``--explain``: what the wire will look like, and why."""
    value = options.impersonate
    if value is None:
        return "off"
    if value != "auto":
        if not impersonation_available():
            return (
                f"{value} (requested, but the optional curl_cffi transport is "
                f"missing: {IMPERSONATE_EXTRA})"
            )
        return value
    if not impersonation_available():
        return (
            "auto -> off (the optional curl_cffi transport is not installed; "
            f"{IMPERSONATE_EXTRA} to send the session's own TLS fingerprint)"
        )
    return "auto -> follow the discovered session (firefox / chrome / edge)"


def _firefox_fallback_proxy(options: AutoOptions) -> str | None:
    if not options.use_browser_profiles:
        return None
    parsed = urlparse(options.base_url)
    try:
        manager = FirefoxSessionManager(
            domains=options.cookie_domains(),
            profiles_root=options.profiles_root,
            profile_name=options.profile_name,
            cookie_database=options.cookie_database,
            interactive=False,
        )
        return manager.proxy_url(
            scheme=parsed.scheme or "https", host=parsed.hostname
        )
    except Exception:  # noqa: BLE001
        return None


def explain_proxy(options: AutoOptions) -> str:
    """One line for ``--explain``: how outbound connections will be routed."""
    choice = normalize_proxy(options.proxy)
    if choice is False:
        return "off (direct connection)"
    if isinstance(choice, str):
        return f"{redact_proxy_url(choice)} (explicit)"
    fallback = _firefox_fallback_proxy(options)
    resolved = resolve_proxy_url(options.base_url, None, fallback_proxy=fallback)
    if resolved is None:
        return "auto -> direct"
    return f"auto -> {redact_proxy_url(resolved)}"


def build_session_manager(
    options: AutoOptions, discovered: DiscoveredSession
) -> AutoSessionManager:
    """Wire a discovered session into the manager the clients consume."""
    solver = resolve_solver(options)
    impersonate = impersonation_profile(options, discovered)
    if impersonate:
        _emit(
            options,
            f"[arena-api] requests will impersonate {impersonate} "
            f"(session found in {discovered.source})",
        )
    capture_dir = (
        Path(options.artifacts_dir) / "challenges" if options.artifacts_dir else None
    )
    fallback_proxy = None
    if discovered.manager is not None:
        getter = getattr(discovered.manager, "proxy_url", None)
        if callable(getter):
            parsed_url = urlparse(options.base_url)
            try:
                fallback_proxy = getter(
                    scheme=parsed_url.scheme or "https", host=parsed_url.hostname
                )
            except Exception:  # noqa: BLE001
                fallback_proxy = None
    resolved_proxy = resolve_proxy_url(
        options.base_url, options.proxy, fallback_proxy=fallback_proxy
    )
    manager = AutoSessionManager(
        base_url=options.base_url,
        domains=options.cookie_domains(),
        storage_path=(
            Path(options.storage_path)
            if options.storage_path is not None and discovered.source == "storage"
            else None
        ),
        challenge_handler=ChallengeHandler(
            capture_dir=capture_dir, raise_on_detection=False
        ),
        environment_options=BrowserEnvironmentOptions(
            headless=not _solver_needs_headed_window(solver),
            channel=options.channel,
            proxy=resolved_proxy,
            artifacts_dir=options.artifacts_dir,
        ),
        login_flow=login_flow_from_env(options),
        captcha_solver=solver,
        captcha_url=options.base_url,
        timeout=options.timeout,
        fallback=discovered.manager,
        # Both halves matter: the client derives its wire from this field, and
        # the manager's own session probe uses it too, so the validation request
        # matches the traffic that follows it.
        impersonate=impersonate,
    )
    if discovered.source != "storage":
        manager.adopt(discovered.cookies)
    else:
        if not manager.load_cookies():
            # The file is a plain cookie export rather than a Playwright
            # storage_state, which only the discovery path knows how to read.
            manager.adopt(discovered.cookies)
        manager._from_fallback = False
    return manager


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #


def _classify(exc: ArenaError) -> ProbeResult:
    if isinstance(exc, ChallengeRequiredError):
        return ProbeResult(False, "browser verification challenge", True, exc)
    if isinstance(exc, AuthenticationError):
        return ProbeResult(False, "session rejected or expired", True, exc)
    if isinstance(exc, RateLimitError):
        return ProbeResult(False, "rate limited", False, exc)
    if isinstance(exc.__cause__, httpx.RequestError):
        return ProbeResult(
            False,
            f"network error ({type(exc.__cause__).__name__})",
            False,
            exc,
        )
    # Anything else (redirect, HTTP 404/500, non-JSON body) reached the server
    # and is not a session problem: the frontend may simply not expose the
    # probe path.
    return ProbeResult(True, f"reachable, probe inconclusive ({type(exc).__name__})", False, exc)


def _accepted(path: str, text: str) -> ProbeResult:
    """Classify a response the transport itself did not reject."""
    marker = None if _expects_recaptcha(path) else _interstitial_marker(text)
    if marker is not None:
        return ProbeResult(
            False,
            f"{path} served a challenge page instead of data ({marker})",
            True,
        )
    return ProbeResult(True, "session accepted")


def probe(client: ArenaClient | DirectArenaClient, path: str = CONFIG_PATH) -> ProbeResult:
    """Verify a sync client's session with one request.

    The transport already retries with refreshed cookies, so reaching the
    classifier means every attempt failed; an HTML challenge page served with
    HTTP 200 is caught here because no status code betrays it.
    """
    try:
        text = client.transport.get_text(path)
    except ArenaError as exc:
        return _classify(exc)
    return _accepted(path, text)


async def aprobe(client: Any, path: str = CONFIG_PATH) -> ProbeResult:
    """Verify an async client's session with one request."""
    try:
        text = await client.transport.get_text(path)
    except ArenaError as exc:
        return _classify(exc)
    return _accepted(path, text)


def _heal_sync(
    client: Any,
    manager: AutoSessionManager,
    result: ProbeResult,
    options: AutoOptions,
) -> ProbeResult:
    """Run the refresh ladder once when the probe found an auth problem.

    ``client`` is any of the four clients: all of them own a ``transport`` with
    :meth:`~arena_api.transport.ArenaTransport.apply_session_cookies` and a
    ``close()``.
    """
    _emit(options, f"[arena-api] session needs a refresh ({result.reason})")
    try:
        cookies = manager.refresh_session(result.error)
    except AuthenticationError:
        client.close()
        raise
    if not cookies:
        _emit(options, "[arena-api] refresh produced no cookies; continuing as-is")
        return result
    client.transport.apply_session_cookies(cookies)
    return probe(client, options.probe_path)


async def _heal_async(
    client: Any,
    manager: AutoSessionManager,
    result: ProbeResult,
    options: AutoOptions,
) -> ProbeResult:
    """Async twin of :func:`_heal_sync`; the ladder runs off the event loop."""
    _emit(options, f"[arena-api] session needs a refresh ({result.reason})")
    try:
        cookies = await asyncio.to_thread(manager.refresh_session, result.error)
    except AuthenticationError:
        await client.aclose()
        raise
    if not cookies:
        _emit(options, "[arena-api] refresh produced no cookies; continuing as-is")
        return result
    client.transport.apply_session_cookies(cookies)
    return await aprobe(client, options.probe_path)


def _verified(
    client: Any, manager: AutoSessionManager, options: AutoOptions
) -> Any:
    """Probe a freshly built client and heal it when the session was rejected."""
    if not options.verify:
        return client
    result = probe(client, options.probe_path)
    if result.auth_problem:
        result = _heal_sync(client, manager, result, options)
    _emit(options, f"[arena-api] verification: {result.describe()}")
    return client


async def _averified(
    client: Any, manager: AutoSessionManager, options: AutoOptions
) -> Any:
    """Async twin of :func:`_verified`."""
    if not options.verify:
        return client
    result = await aprobe(client, options.probe_path)
    if result.auth_problem:
        result = await _heal_async(client, manager, result, options)
    _emit(options, f"[arena-api] verification: {result.describe()}")
    return client


# --------------------------------------------------------------------------- #
# Bootstrap
# --------------------------------------------------------------------------- #


def _prepare(
    options: AutoOptions, *, require_session: bool = True
) -> tuple[AutoSessionManager, DiscoveredSession] | None:
    """Discover (or wait for) a session and build its manager."""
    discovered = discover_session(options)
    if discovered is None and require_session:
        if not _wait_for_login(options):
            raise AuthenticationError(
                "no session found for "
                f"{options.site}. Sign in to your account in a browser and run "
                "again, or pass cookies=/set ARENA_COOKIE.\n  "
                + "\n  ".join(explain_sources(options))
            )
        discovered = discover_session(options)
    if discovered is None:
        return None
    _emit(options, f"[arena-api] session: {discovered.description}")
    return build_session_manager(options, discovered), discovered


def auto_client(options: AutoOptions | None = None, **overrides: Any) -> ArenaClient:
    """Return a verified :class:`~arena_api.ArenaClient` for your own session.

    ``**overrides`` are :class:`AutoOptions` fields, so the common case is
    ``auto_client()`` and the tuned case is
    ``auto_client(base_url="https://lmarena.ai", solve_captchas=False)``.
    """
    options = _merge_options(options, overrides)
    prepared = _prepare(options)
    if prepared is None:  # pragma: no cover - require_session is always True here
        raise AuthenticationError("no session found")
    manager, _ = prepared
    client = ArenaClient(
        base_url=options.base_url,
        session_source=manager,
        headers=options.headers,
        timeout=options.timeout,
        http2=options.http2,
        verify=options.verify_tls,
        proxy=options.proxy,
        http_transport=options.http_transport,
        max_auth_refreshes=options.max_auth_refreshes,
    )
    return _verified(client, manager, options)


async def auto_async_client(
    options: AutoOptions | None = None, **overrides: Any
) -> AsyncArenaClient:
    """Async twin of :func:`auto_client`.

    Discovery and a needed refresh run in worker threads, but an interactive
    login wait calls ``prompt`` (``input`` by default) on the calling thread, so
    inside a running server pass ``interactive=False`` or your own non-blocking
    ``prompt``.
    """
    options = _merge_options(options, overrides)
    prepared = _prepare(options)
    if prepared is None:  # pragma: no cover
        raise AuthenticationError("no session found")
    manager, _ = prepared
    client = AsyncArenaClient(
        base_url=options.base_url,
        session_source=manager,
        headers=options.headers,
        timeout=options.timeout,
        http2=options.http2,
        verify=options.verify_tls,
        proxy=options.proxy,
        http_transport=options.http_transport,
        max_auth_refreshes=options.max_auth_refreshes,
    )
    return await _averified(client, manager, options)


def _merge_options(options: AutoOptions | None, overrides: Mapping[str, Any]) -> AutoOptions:
    if not overrides:
        return options or AutoOptions()
    if options is None:
        return AutoOptions(**dict(overrides))
    return replace(options, **dict(overrides))



def _candidate_browser_channels(explicit_channel: str | None) -> list[str | None]:
    if explicit_channel:
        return [explicit_channel]
    if BrowserEnvironment is not _DEFAULT_BROWSER_ENVIRONMENT:
        return [None]
    candidates: list[str | None] = []
    for ch in [*_windows_installed_channels(), "chromium", None]:
        if ch not in candidates:
            candidates.append(ch)
    return candidates


def _can_auto_solve_bframe(solver: Any) -> bool:
    if not isinstance(solver, RecaptchaToolkitSolver):
        return False
    if not solver_dependencies_available(solver.backend):
        return False
    if solver.backend == "audio" and shutil.which("ffmpeg") is None:
        return False
    if solver.backend == "image":
        return False
    return True

class DirectVerificationToken:
    """Callable producing a fresh reCAPTCHA v3 assertion for Direct Chat.

    Strictly opt-in. :mod:`arena_api.direct` never obtains a verification token
    by itself; passing this object as ``verification_token=`` is the caller's
    explicit instruction to do it for them. It opens the Direct Chat page in a
    normalised browser and intercepts the v3 token with
    :class:`~arena_api.auth.captcha.RecaptchaToolkitSolver`, so it needs the
    captcha dependencies and a deployment you may automate.

    A composite solver is unwrapped to its token-producing member
    (:func:`_token_solver`), and a solver that cannot produce a token at all --
    the wait-only default on a machine without ``playwright-recaptcha`` -- is
    rejected with an actionable error instead of returning an empty assertion.
    """

    def __init__(
        self,
        options: AutoOptions | None = None,
        *,
        page_url: str | None = None,
        solver: Any | None = None,
        session_cookies: Mapping[str, str] | None = None,
        session_manager: Any | None = None,
        cookie_source: str | None = None,
    ) -> None:
        self.options = options or AutoOptions()
        self.page_url = page_url or (
            self.options.base_url.rstrip("/") + DIRECT_PAGE_PATH
        )
        self.session_cookies = dict(session_cookies) if session_cookies else None
        self.session_manager = session_manager
        self.cookie_source = cookie_source
        self._explicit_solver = solver is not None
        self._refreshed_cookies: dict[str, str] | None = None
        base = solver or resolve_solver(self.options) or RecaptchaToolkitSolver(
            backend=self.options.captcha_backend
        )
        base = _token_solver(base)
        # The Direct Chat assertion is always a v3 token. A custom solver object
        # decides its own path, so only the toolkit adapter is pinned.
        self.solver = (
            replace(base, version="v3", reload_for_v3=True)
            if isinstance(base, RecaptchaToolkitSolver)
            else base
        )

    def _check_solver_ready(self) -> None:
        self._require_a_token_solver()
        if isinstance(self.solver, RecaptchaToolkitSolver) and not (
            solver_dependencies_available(self.solver.backend)
        ):
            raise AuthenticationError(
                "verification_token='auto' intercepts a reCAPTCHA v3 assertion, "
                "which needs the solver dependencies: pip install "
                "'.[auth-captcha]' and playwright install chromium "
                f"(backend '{self.solver.backend}' reports them missing)."
            )

    def _check_stream_browser_ready(self) -> None:
        if BrowserEnvironment is not _DEFAULT_BROWSER_ENVIRONMENT:
            return
        if solver_dependencies_available(
            getattr(self.solver, "backend", "audio")
        ):
            return
        if not _has_spec("playwright"):
            raise AuthenticationError(
                "Direct Chat browser verification requires Playwright: "
                "pip install playwright && python -m playwright install chromium "
                "(or use --channel chrome / --channel msedge)."
            )

    def _current_cookies(self) -> dict[str, str]:
        merged: dict[str, str] = {}
        if self.session_cookies:
            merged.update(self.session_cookies)
        load = getattr(self.session_manager, "load_cookies", None)
        if callable(load):
            try:
                loaded = load()
            except Exception:  # noqa: BLE001
                loaded = None
            if isinstance(loaded, Mapping) and loaded:
                merged.update({str(k): str(v) for k, v in loaded.items()})
        if self._refreshed_cookies:
            merged.update(self._refreshed_cookies)
        return merged

    async def _mint_token_on_page(self, page: Any) -> str:
        if isinstance(
            self.solver, (RecaptchaToolkitSolver, ChallengeWaitSolver)
        ) and callable(getattr(page, "evaluate", None)):
            js = _build_execute_recaptcha_v3_js(
                _default_recaptcha_site_key(self.page_url)
            )
            try:
                direct_tok = await page.evaluate(js)
            except Exception:  # noqa: BLE001
                direct_tok = None
            if isinstance(direct_tok, str) and direct_tok.strip():
                return direct_tok.strip()
        attempt = await self.solver.asolve(page)
        token = attempt.raise_for_status()
        if not token:
            raise AuthenticationError(
                "the solver cleared the page but produced no assertion "
                f"({attempt.describe()}); Direct Chat needs a v3 token"
            )
        return token

    async def afetch(self) -> str:
        """Fetch a token asynchronously.

        :raises arena_api.exceptions.AuthenticationError: when the configured
            solver cannot produce a token at all, or produced none -- an empty
            assertion must never be sent silently.
        """
        self._check_solver_ready()
        resolved_proxy = resolve_proxy_url(
            self.options.base_url,
            self.options.proxy,
            fallback_proxy=_firefox_fallback_proxy(self.options),
        )
        env_kwargs: dict[str, Any] = {
            "headless": True,
            "artifacts_dir": self.options.artifacts_dir,
            "install_determinism_script": False,
            "reduced_motion": "no-preference",
            "color_scheme": "no-preference",
            "ignore_default_args": AUTOMATION_DEFAULT_ARGS_TO_DROP,
            "launch_args": (AUTOMATION_BLINK_SWITCH,),
            "extra_init_scripts": (HIDE_WEBDRIVER_SCRIPT,),
        }
        if self.options.channel:
            env_kwargs["channel"] = self.options.channel
        if resolved_proxy:
            env_kwargs["proxy"] = resolved_proxy
        options = BrowserEnvironmentOptions.with_captcha_solving(
            self.solver, **env_kwargs
        )
        try:
            async with BrowserEnvironment(options) as environment:
                handler = getattr(environment, "challenge_handler", None)
                if handler is not None:
                    # DirectVerificationToken drives the page imperatively; a
                    # passive response-listener solve would reload the page in
                    # parallel while page.evaluate / solver.asolve is running.
                    handler.solve_on_detection = False
                page = await environment.new_page()
                context = getattr(page, "context", None)
                seed_cookies = (
                    _seedable_browser_cookies(
                        self.session_cookies, cookie_source=self.cookie_source
                    )
                    if self.session_cookies
                    else None
                )
                if (
                    seed_cookies
                    and context is not None
                    and callable(getattr(context, "add_cookies", None))
                ):
                    await context.add_cookies(
                        [
                            {
                                "name": str(name),
                                "value": str(value),
                                "url": self.options.base_url,
                            }
                            for name, value in seed_cookies.items()
                        ]
                    )
                await page.goto(self.page_url, wait_until="domcontentloaded")
                return await self._mint_token_on_page(page)
        except ArenaError:
            raise
        except Exception as exc:  # noqa: BLE001
            detail = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
            if _is_missing_browser_error(exc):
                raise AuthenticationError(
                    f"Direct Chat verification browser could not be started: {detail} "
                    "Install Chromium (`python -m playwright install chromium`) or "
                    "use your installed browser with `--channel msedge` / "
                    "`--channel chrome`."
                ) from exc
            raise

    def _raise_browser_http_error(
        self,
        status: int,
        body: str,
        headers: Mapping[str, str],
    ) -> None:
        mitigated = headers.get("cf-mitigated", "").lower() == "challenge"
        if mitigated or (status in (403, 503) and _looks_like_challenge(body, headers)):
            raise ChallengeRequiredError(
                f"The service requested an interactive browser verification (HTTP {status}). "
                "Refresh or verify the session in a normal browser and retry."
            )
        detail = _extract_error_detail(body)
        suffix = f": {detail}" if detail else ""
        if status in (401, 403):
            if _is_verification_rejection(body):
                raise ProtocolError(
                    f"Arena rejected the request verification token (HTTP {status}){suffix}."
                )
            lowered = (body or "").lower()
            if status == 401 or any(m in lowered for m in _AUTH_REJECT_MARKERS):
                raise AuthenticationError(
                    f"The supplied session was rejected (HTTP {status}){suffix}. "
                    f"Sign in at {self.options.base_url} in your browser "
                    "(or run `python -m arena_api --login`) and retry."
                )
            raise ArenaError(
                f"Arena Direct Chat rejected the request (HTTP {status}){suffix}."
            )
        _raise_for_status(status, body, headers)

    async def _launch_verification_environment(
        self,
        *,
        headless: bool,
        cloaked_headful: bool,
        resolved_proxy: str | None,
        user_data_dir: str | Path | None,
    ) -> tuple[Any, str | None]:
        channels = _candidate_browser_channels(self.options.channel)
        environment: Any = None
        selected_channel: str | None = None
        last_missing_exc: BaseException | None = None
        ignored_default_args = (
            (*AUTOMATION_DEFAULT_ARGS_TO_DROP, "--hide-scrollbars")
            if headless
            else AUTOMATION_DEFAULT_ARGS_TO_DROP
        )
        launch_args: tuple[str, ...]
        if headless:
            launch_args = (AUTOMATION_BLINK_SWITCH, "--window-size=1480,960")
        elif cloaked_headful:
            launch_args = (AUTOMATION_BLINK_SWITCH, *_OFFSCREEN_HEADFUL_SWITCHES)
        else:
            launch_args = (AUTOMATION_BLINK_SWITCH,)

        for channel in channels:
            env_kwargs: dict[str, Any] = {
                "headless": headless,
                "locale": None,
                "timezone_id": None,
                "artifacts_dir": self.options.artifacts_dir,
                "install_determinism_script": False,
                "reduced_motion": "no-preference",
                "color_scheme": "no-preference",
                "ignore_default_args": ignored_default_args,
                "launch_args": launch_args,
                "extra_init_scripts": (HIDE_WEBDRIVER_SCRIPT,),
            }
            if user_data_dir is not None:
                env_kwargs["user_data_dir"] = user_data_dir
            if channel is not None:
                env_kwargs["channel"] = channel
            if resolved_proxy:
                env_kwargs["proxy"] = resolved_proxy
            env_options = BrowserEnvironmentOptions.with_captcha_solving(
                self.solver, **env_kwargs
            )
            candidate_env = BrowserEnvironment(env_options)
            try:
                environment = await candidate_env.__aenter__()
                selected_channel = channel
                break
            except Exception as exc:  # noqa: BLE001
                if _is_missing_browser_error(exc):
                    last_missing_exc = exc
                    continue
                raise

        if environment is None:
            detail = (
                str(last_missing_exc).splitlines()[0]
                if last_missing_exc
                else "no browser executable found"
            )
            raise AuthenticationError(
                f"Direct Chat verification browser could not be started: {detail} "
                "Install Chromium (`python -m playwright install chromium`) or "
                "use your installed browser with `--channel msedge` / "
                "`--channel chrome`."
            ) from last_missing_exc
        return environment, selected_channel

    @asynccontextmanager
    async def _attempt_browser_evaluation(
        self,
        endpoint_path: str,
        body_factory: Callable[[str], Mapping[str, Any]],
        *,
        headless: bool,
        allow_headed_retry: bool,
        timeout: float,
        prompt: str | None = None,
        model_id_override: str | None = None,
        generation_params: Mapping[str, Any] | None = None,
        follow_up: bool = False,
        user_data_dir: str | Path | None = None,
        hide_window: bool = False,
    ) -> AsyncIterator[tuple[str, AsyncIterator[bytes]]]:
        resolved_proxy = resolve_proxy_url(
            self.options.base_url,
            self.options.proxy,
            fallback_proxy=_firefox_fallback_proxy(self.options),
        )
        cloaked_headful = (not headless) and bool(hide_window)
        window_visible = (not headless) and (not hide_window)
        if user_data_dir is not None and not headless:
            _prepare_profile_window_placement(user_data_dir, hidden=cloaked_headful)

        win_cloaker = _WindowsBrowserCloaker(enabled=cloaked_headful)
        win_cloaker.start()
        try:
            environment, selected_channel = (
                await self._launch_verification_environment(
                    headless=headless,
                    cloaked_headful=cloaked_headful,
                    resolved_proxy=resolved_proxy,
                    user_data_dir=user_data_dir,
                )
            )
        except BaseException:
            win_cloaker.stop()
            raise

        registered_listeners: list[tuple[str, Callable[..., Any]]] = []
        response_tasks: set[asyncio.Task[None]] = set()
        page: Any = None
        ua_cdp_session: Any = None
        try:
            handler = getattr(environment, "challenge_handler", None)
            if handler is not None:
                handler.solve_on_detection = False
            page = await environment.new_page()
            context = getattr(page, "context", None)
            if headless:
                ua_cdp_session = await _sanitize_headless_page_cdp(
                    context, page, channel=selected_channel
                )
            elif cloaked_headful:
                await _hide_headed_page_window_cdp(context, page)
                await _maybe_reset_headless_poisoned_cookies(
                    context, user_data_dir
                )
            raw_cookies = self._current_cookies()
            seed_cookies = _seedable_browser_cookies(
                raw_cookies, cookie_source=self.cookie_source
            )
            await _seed_direct_context_cookies(
                context, seed_cookies, self.options.base_url
            )

            async_q: asyncio.Queue[tuple[str, Any]] = asyncio.Queue()
            on_fn = getattr(page, "on", None)
            has_network_events = callable(on_fn)
            in_flight_eval_requests = 0
            eval_request_seen = False
            last_eval_url = ""
            last_eval_post_data = ""

            if has_network_events:
                assert callable(on_fn)

                def _on_request(req: Any) -> None:
                    nonlocal in_flight_eval_requests, eval_request_seen
                    nonlocal last_eval_url, last_eval_post_data
                    method = str(getattr(req, "method", "POST") or "POST").upper()
                    url = str(getattr(req, "url", "") or "")
                    if method == "POST" and _is_eval_stream_url(url):
                        eval_request_seen = True
                        in_flight_eval_requests += 1
                        last_eval_url = url
                        raw_pd = getattr(req, "post_data", None)
                        if isinstance(raw_pd, str) and raw_pd:
                            last_eval_post_data = raw_pd

                def _on_request_failed(req: Any) -> None:
                    nonlocal in_flight_eval_requests
                    method = str(getattr(req, "method", "POST") or "POST").upper()
                    url = str(getattr(req, "url", "") or "")
                    if method == "POST" and _is_eval_stream_url(url):
                        in_flight_eval_requests = max(0, in_flight_eval_requests - 1)

                async def _consume_eval_response(resp: Any) -> None:
                    nonlocal in_flight_eval_requests
                    try:
                        status = int(getattr(resp, "status", 200))
                        raw_hdrs = getattr(resp, "headers", None)
                        hdrs: dict[str, str] = {}
                        if isinstance(raw_hdrs, Mapping):
                            hdrs = {
                                str(k).lower(): str(v) for k, v in raw_hdrs.items()
                            }
                        ct_val = hdrs.get("content-type", "")
                        if status >= 400:
                            err_body = ""
                            text_fn = getattr(resp, "text", None)
                            if callable(text_fn):
                                try:
                                    err_body = _recover_cdp_utf8_text(
                                        str(await text_fn() or ""), ct_val
                                    )
                                except Exception:  # noqa: BLE001
                                    err_body = ""
                            async_q.put_nowait(
                                (
                                    "http_error",
                                    {
                                        "status": status,
                                        "body": err_body,
                                        "contentType": ct_val,
                                        "cfMitigated": hdrs.get("cf-mitigated", ""),
                                    },
                                )
                            )
                            return
                        async_q.put_nowait(("meta", ct_val))
                        body_text = ""
                        text_fn = getattr(resp, "text", None)
                        if callable(text_fn):
                            body_text = str(await text_fn() or "")
                        if body_text:
                            async_q.put_nowait(
                                ("chunk", _recover_cdp_utf8_bytes(body_text, ct_val))
                            )
                        async_q.put_nowait(("eof", None))
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:  # noqa: BLE001
                        async_q.put_nowait(("stream_error", str(exc)))
                    finally:
                        in_flight_eval_requests = max(0, in_flight_eval_requests - 1)

                def _on_response(resp: Any) -> None:
                    req = getattr(resp, "request", None)
                    method = str(
                        getattr(req, "method", "POST") if req is not None else "POST"
                    ).upper()
                    url = str(getattr(resp, "url", "") or "")
                    if method == "POST" and _is_eval_stream_url(url):
                        task = asyncio.create_task(_consume_eval_response(resp))
                        response_tasks.add(task)
                        task.add_done_callback(response_tasks.discard)

                for ev_name, cb in (
                    ("request", _on_request),
                    ("requestfailed", _on_request_failed),
                    ("response", _on_response),
                ):
                    on_fn(ev_name, cb)
                    registered_listeners.append((ev_name, cb))
            else:
                expose_fn = getattr(page, "expose_function", None)
                if callable(expose_fn):
                    await expose_fn(
                        "__arenaDirectMeta",
                        lambda ct: async_q.put_nowait(("meta", str(ct or ""))),
                    )
                    await expose_fn(
                        "__arenaDirectChunk",
                        lambda piece: async_q.put_nowait(
                            ("chunk", str(piece).encode("utf-8"))
                        ),
                    )
                    await expose_fn(
                        "__arenaDirectEof",
                        lambda: async_q.put_nowait(("eof", None)),
                    )
                    await expose_fn(
                        "__arenaDirectHttpError",
                        lambda info: async_q.put_nowait(("http_error", info)),
                    )
                    await expose_fn(
                        "__arenaDirectStreamError",
                        lambda err: async_q.put_nowait(
                            ("stream_error", str(err or ""))
                        ),
                    )

            await page.goto(self.page_url, wait_until="domcontentloaded")
            wait_for_timeout = getattr(page, "wait_for_timeout", None)
            if callable(wait_for_timeout):
                await wait_for_timeout(500)
            page_content_fn = getattr(page, "content", None)
            if callable(page_content_fn):
                try:
                    html = await page_content_fn()
                except Exception:  # noqa: BLE001
                    html = ""
                if isinstance(html, str) and _looks_like_challenge(html, None):
                    if allow_headed_retry:
                        raise _RetryInHeadedBrowser(
                            "Cloudflare challenge in headless mode"
                        )
                    if callable(wait_for_timeout):
                        if window_visible:
                            await _safe_bring_to_front(page)
                        cf_budget = (
                            max(timeout, 120.0) if window_visible else 25.0
                        )
                        wait_deadline = time.monotonic() + cf_budget
                        while time.monotonic() < wait_deadline:
                            obs_cf = await _detect_post_submit_challenge(page)
                            if obs_cf.get("kind") == "turnstile":
                                await _click_challenge_checkbox(page, obs_cf, bring_to_front=window_visible)
                            await wait_for_timeout(600)
                            try:
                                html = await page_content_fn()
                            except Exception:  # noqa: BLE001
                                break
                            if not (
                                isinstance(html, str)
                                and _looks_like_challenge(html, None)
                            ):
                                break
            if _arena_auth_jwt_expired(raw_cookies) and callable(
                getattr(page, "evaluate", None)
            ):
                stale_raw = _reconstruct_supabase_cookie(raw_cookies)
                try:
                    await page.evaluate(_build_wait_supabase_refresh_js(stale_raw))
                except Exception:  # noqa: BLE001
                    pass

            await _gentle_page_warmup(page)

            used_composer = False
            if prompt is not None and not follow_up:
                used_composer = await _submit_prompt_via_composer(
                    page,
                    prompt,
                    model_id_override=model_id_override,
                    generation_params=generation_params,
                    has_submitted=lambda: eval_request_seen,
                    install_legacy_tap_flags=not has_network_events,
                )

            eval_task: asyncio.Task[Any] | None = None
            if not used_composer:
                token = await self._mint_token_on_page(page)
                payload_body = dict(body_factory(token))
                serialized = json.dumps(payload_body, separators=(",", ":"))
                eval_js = _build_browser_fetch_stream_js(endpoint_path, serialized)
                eval_task = asyncio.create_task(page.evaluate(eval_js))
                eval_task.add_done_callback(
                    lambda done_task: async_q.put_nowait(("done", done_task))
                )

            first_kind: str = ""
            first_val: Any = None
            deadline = time.monotonic() + timeout
            pending_verification_err: tuple[int, str, dict[str, str]] | None = None
            grace_until = 0.0
            clicked_checkbox_kinds: set[str] = set()
            auto_solve_attempts = 0
            solved_v2_token: str | None = None
            notified_user = False
            challenge_active = False
            challenge_cleared_at: float | None = None
            retried_send_after_clear = False
            replayed_v2_payload = False

            while True:
                now = time.monotonic()
                if now >= deadline:
                    if pending_verification_err is not None:
                        self._raise_browser_http_error(*pending_verification_err)
                    if eval_task is not None:
                        eval_task.cancel()
                    raise TimeoutError(
                        "Direct Chat browser request timed out waiting for response headers."
                    )

                poll_slice = min(0.5, max(0.05, deadline - now))
                got_event = False
                ev_kind = ""
                ev_val: Any = None
                try:
                    ev_kind, ev_val = await asyncio.wait_for(
                        async_q.get(), timeout=poll_slice
                    )
                    got_event = True
                except asyncio.TimeoutError:
                    got_event = False

                if got_event:
                    if ev_kind != "http_error":
                        first_kind, first_val = ev_kind, ev_val
                        break
                    err_map = ev_val if isinstance(ev_val, Mapping) else {}
                    status = int(err_map.get("status") or 500)
                    err_body = str(err_map.get("body") or "")
                    resp_headers = {
                        "content-type": str(err_map.get("contentType") or ""),
                        "cf-mitigated": str(err_map.get("cfMitigated") or ""),
                    }
                    lowered_err = err_body.lower()
                    if (
                        allow_headed_retry
                        and status in (401, 403)
                        and not any(m in lowered_err for m in _AUTH_REJECT_MARKERS)
                    ):
                        raise _RetryInHeadedBrowser(f"HTTP {status}")
                    if (
                        used_composer
                        and (
                            window_visible
                            or self.options.solve_captchas is not False
                        )
                        and status in (403, 429, 503)
                        and (
                            _is_verification_rejection(err_body)
                            or _looks_like_challenge(err_body, resp_headers)
                        )
                    ):
                        pending_verification_err = (status, err_body, resp_headers)
                        grace_until = max(grace_until, time.monotonic() + 12.0)
                    else:
                        self._raise_browser_http_error(
                            status, err_body, resp_headers
                        )

                if used_composer and (
                    window_visible or self.options.solve_captchas is not False
                ):
                    obs = await _detect_post_submit_challenge(page)
                    obs_kind = obs.get("kind")
                    if isinstance(obs_kind, str) and obs_kind:
                        if not challenge_active:
                            if window_visible:
                                interactive_budget = max(timeout, 300.0)
                                deadline = max(
                                    deadline,
                                    time.monotonic() + interactive_budget,
                                )
                                grace_until = deadline
                            else:
                                deadline = max(deadline, time.monotonic() + 60.0)
                                grace_until = max(
                                    grace_until, time.monotonic() + 60.0
                                )
                        challenge_active = True
                        challenge_cleared_at = None

                        if (
                            obs_kind in ("recaptcha_anchor", "turnstile", "hcaptcha")
                            and obs_kind not in clicked_checkbox_kinds
                        ):
                            clicked_checkbox_kinds.add(obs_kind)
                            await _click_challenge_checkbox(page, obs, bring_to_front=window_visible)
                            if callable(wait_for_timeout):
                                await wait_for_timeout(700)
                            obs = await _detect_post_submit_challenge(page)
                            obs_kind = obs.get("kind")

                        if (
                            obs_kind == "recaptcha_bframe"
                            and (
                                self.options.solve_captchas is not False
                                or self._explicit_solver
                            )
                            and auto_solve_attempts < 2
                        ):
                            auto_solve_attempts += 1
                            solver_opts = getattr(self.solver, "solver", None)
                            cap_key = (
                                getattr(solver_opts, "capsolver_api_key", None)
                                if solver_opts is not None
                                else None
                            )
                            outcome = await auto_solve_challenge_on_page(
                                page,
                                obs,
                                detect_challenge_fn=_detect_post_submit_challenge,
                                proxy=resolved_proxy,
                                capsolver_api_key=cap_key,
                                toolkit_solver=self.solver,
                                status_stream=sys.stderr,
                            )
                            if outcome.token:
                                solved_v2_token = outcome.token
                            if outcome.solved:
                                challenge_active = False
                                challenge_cleared_at = time.monotonic()
                                grace_until = max(
                                    grace_until, challenge_cleared_at + 15.0
                                )
                                continue
                            obs = await _detect_post_submit_challenge(page)
                            obs_kind = obs.get("kind")

                        if isinstance(obs_kind, str) and obs_kind:
                            if not window_visible:
                                bframe_exhausted = obs_kind == "recaptcha_bframe" and (
                                    auto_solve_attempts >= 2
                                    or (
                                        self.options.solve_captchas is False
                                        and not self._explicit_solver
                                    )
                                )
                                if (
                                    bframe_exhausted
                                    and pending_verification_err is not None
                                ):
                                    self._raise_browser_http_error(
                                        *pending_verification_err
                                    )
                            elif not notified_user:
                                notified_user = True
                                await _safe_bring_to_front(page)
                                print(
                                    "[arena-api] после отправки появилась капча — "
                                    "решите её в открытом окне браузера "
                                    "(ожидание до 5 мин)...",
                                    file=sys.stderr,
                                    flush=True,
                                )
                    else:
                        if challenge_active:
                            challenge_active = False
                            challenge_cleared_at = time.monotonic()
                            grace_until = max(
                                grace_until, challenge_cleared_at + 15.0
                            )
                        if (
                            challenge_cleared_at is not None
                            and not retried_send_after_clear
                            and in_flight_eval_requests == 0
                            and (time.monotonic() - challenge_cleared_at) >= 2.0
                        ):
                            if await _reclick_send_button_if_unsent(page):
                                retried_send_after_clear = True
                                grace_until = max(
                                    grace_until, time.monotonic() + 15.0
                                )
                            elif (
                                not replayed_v2_payload
                                and solved_v2_token
                                and last_eval_post_data
                            ):
                                replayed = await _replay_eval_with_v2_token(
                                    page,
                                    last_eval_url or endpoint_path,
                                    last_eval_post_data,
                                    solved_v2_token,
                                )
                                if replayed:
                                    replayed_v2_payload = True
                                    retried_send_after_clear = True
                                    grace_until = max(
                                        grace_until, time.monotonic() + 15.0
                                    )
                        if (
                            pending_verification_err is not None
                            and not challenge_active
                            and in_flight_eval_requests == 0
                            and time.monotonic() >= grace_until
                        ):
                            self._raise_browser_http_error(*pending_verification_err)

            if first_kind == "stream_error":
                raise ArenaError(
                    f"Direct Chat browser stream failed: {first_val}"
                )

            if first_kind == "done":
                result = first_val.result()
                if isinstance(result, Mapping) and not result.get("ok", True):
                    status = int(result.get("status") or 500)
                    err_body = str(result.get("body") or "")
                    resp_headers = {
                        "content-type": str(result.get("contentType") or ""),
                        "cf-mitigated": str(result.get("cfMitigated") or ""),
                    }
                    lowered_err = err_body.lower()
                    if (
                        allow_headed_retry
                        and status in (401, 403)
                        and not any(m in lowered_err for m in _AUTH_REJECT_MARKERS)
                    ):
                        raise _RetryInHeadedBrowser(f"HTTP {status}")
                    self._raise_browser_http_error(status, err_body, resp_headers)
                content_type = (
                    str(result.get("contentType") or "")
                    if isinstance(result, Mapping)
                    else ""
                )

                async def _empty_stream() -> AsyncIterator[bytes]:
                    if False:
                        yield b""

                yield content_type, _empty_stream()
                return

            buffered_first_chunk: bytes | None = None
            if first_kind == "chunk":
                content_type = ""
                buffered_first_chunk = first_val
            elif first_kind == "eof":
                content_type = ""
            else:
                content_type = str(first_val or "")

            async def _iter_chunks() -> AsyncIterator[bytes]:
                try:
                    if first_kind == "eof":
                        return
                    if buffered_first_chunk:
                        yield buffered_first_chunk
                    while True:
                        item_kind, item_val = await asyncio.wait_for(
                            async_q.get(), timeout=timeout
                        )
                        if item_kind == "chunk":
                            if item_val:
                                yield item_val
                        elif item_kind == "eof":
                            break
                        elif item_kind == "stream_error":
                            raise ArenaError(
                                f"Direct Chat browser stream failed: {item_val}"
                            )
                        elif item_kind == "done":
                            await item_val
                            break
                finally:
                    if eval_task is not None and not eval_task.done():
                        eval_task.cancel()
                        try:
                            await eval_task
                        except (asyncio.CancelledError, Exception):  # noqa: BLE001
                            pass

            yield content_type, _iter_chunks()

            cookies_fn = getattr(context, "cookies", None)
            if callable(cookies_fn):
                try:
                    browser_cookies = await cookies_fn([self.options.base_url])
                except Exception:  # noqa: BLE001
                    browser_cookies = None
                if isinstance(browser_cookies, Sequence):
                    updated = {
                        str(c["name"]): str(c["value"])
                        for c in browser_cookies
                        if isinstance(c, Mapping)
                        and isinstance(c.get("name"), str)
                        and c["name"].startswith("arena-auth-")
                        and isinstance(c.get("value"), str)
                    }
                    if updated:
                        self._refreshed_cookies = updated
        finally:
            win_cloaker.stop()
            if ua_cdp_session is not None:
                detach_fn = getattr(ua_cdp_session, "detach", None)
                if callable(detach_fn):
                    try:
                        await detach_fn()
                    except Exception:  # noqa: BLE001
                        pass
            remove_fn = (
                getattr(page, "remove_listener", None) if page is not None else None
            )
            if callable(remove_fn):
                for ev_name, cb in registered_listeners:
                    try:
                        remove_fn(ev_name, cb)
                    except Exception:  # noqa: BLE001
                        pass
            for task in list(response_tasks):
                if not task.done():
                    task.cancel()
            await environment.__aexit__(None, None, None)

    @asynccontextmanager
    async def astream_evaluation(
        self,
        endpoint_path: str,
        body_factory: Callable[[str], Mapping[str, Any]],
        *,
        timeout: float = DEFAULT_TIMEOUT,
        prompt: str | None = None,
        model_id_override: str | None = None,
        generation_params: Mapping[str, Any] | None = None,
        follow_up: bool = False,
    ) -> AsyncIterator[tuple[str, AsyncIterator[bytes]]]:
        """Mint a fresh v3 assertion and stream ``endpoint_path`` inside the same browser tab."""
        self._check_stream_browser_ready()
        allow_headed = bool(self.options.interactive)
        is_live_browser = BrowserEnvironment is _DEFAULT_BROWSER_ENVIRONMENT
        profile_dir = (
            _direct_browser_profile_dir(self.options) if is_live_browser else None
        )
        if is_live_browser:
            hide_live_window = not bool(self.options.show_browser)
            try:
                async with self._attempt_browser_evaluation(
                    endpoint_path,
                    body_factory,
                    headless=False,
                    allow_headed_retry=False,
                    timeout=timeout,
                    prompt=prompt,
                    model_id_override=model_id_override,
                    generation_params=generation_params,
                    follow_up=follow_up,
                    user_data_dir=profile_dir,
                    hide_window=hide_live_window,
                ) as outcome:
                    yield outcome
                    return
            except Exception as exc:  # noqa: BLE001
                if not _is_missing_display_error(exc):
                    raise
            async with self._attempt_browser_evaluation(
                endpoint_path,
                body_factory,
                headless=True,
                allow_headed_retry=False,
                timeout=timeout,
                prompt=prompt,
                model_id_override=model_id_override,
                generation_params=generation_params,
                follow_up=follow_up,
                user_data_dir=profile_dir,
                hide_window=False,
            ) as outcome:
                yield outcome
            return

        try:
            async with self._attempt_browser_evaluation(
                endpoint_path,
                body_factory,
                headless=True,
                allow_headed_retry=allow_headed,
                timeout=timeout,
                prompt=prompt,
                model_id_override=model_id_override,
                generation_params=generation_params,
                follow_up=follow_up,
                user_data_dir=profile_dir,
            ) as outcome:
                yield outcome
                return
        except _RetryInHeadedBrowser as reason:
            print(
                f"[arena-api] headless Direct Chat verification was rejected ({reason}); "
                "retrying in a browser window...",
                file=sys.stderr,
                flush=True,
            )
        async with self._attempt_browser_evaluation(
            endpoint_path,
            body_factory,
            headless=False,
            allow_headed_retry=False,
            timeout=timeout,
            prompt=prompt,
            model_id_override=model_id_override,
            generation_params=generation_params,
            follow_up=follow_up,
            user_data_dir=profile_dir,
        ) as outcome:
            yield outcome

    @contextmanager
    def stream_evaluation(
        self,
        endpoint_path: str,
        body_factory: Callable[[str], Mapping[str, Any]],
        *,
        timeout: float = DEFAULT_TIMEOUT,
        prompt: str | None = None,
        model_id_override: str | None = None,
        generation_params: Mapping[str, Any] | None = None,
        follow_up: bool = False,
    ) -> Iterator[tuple[str, Iterator[bytes]]]:
        """Synchronous streaming bridge over :meth:`astream_evaluation`."""
        sync_q: queue.Queue[tuple[str, Any]] = queue.Queue()
        stop_event = threading.Event()
        sync_wait = (
            max(timeout, 300.0) + 60.0
            if self.options.interactive
            else max(timeout, 60.0) + 30.0
        )

        async def _driver() -> None:
            try:
                async with self.astream_evaluation(
                    endpoint_path,
                    body_factory,
                    timeout=timeout,
                    prompt=prompt,
                    model_id_override=model_id_override,
                    generation_params=generation_params,
                    follow_up=follow_up,
                ) as (content_type, async_chunks):
                    sync_q.put(("meta", content_type))
                    async for wire in async_chunks:
                        if stop_event.is_set():
                            break
                        sync_q.put(("chunk", wire))
                sync_q.put(("eof", None))
            except BaseException as exc:
                sync_q.put(("err", exc))

        worker = threading.Thread(
            target=lambda: asyncio.run(_driver()),
            name="arena-direct-browser-stream",
            daemon=True,
        )
        worker.start()
        try:
            try:
                first_kind, first_payload = sync_q.get(timeout=sync_wait)
            except queue.Empty as exc:
                raise QueueTimeoutError(
                    "Direct Chat browser verification timed out before response headers arrived."
                ) from exc
            if first_kind == "err":
                raise first_payload
            content_type = str(first_payload or "") if first_kind == "meta" else ""

            def _sync_chunks() -> Iterator[bytes]:
                if first_kind == "chunk" and first_payload:
                    yield first_payload
                while True:
                    try:
                        kind, payload = sync_q.get(timeout=timeout + 30.0)
                    except queue.Empty as exc:
                        raise QueueTimeoutError(
                            "Direct Chat browser stream timed out while reading chunks."
                        ) from exc
                    if kind == "chunk":
                        if payload:
                            yield payload
                    elif kind == "eof":
                        break
                    elif kind == "err":
                        raise payload

            yield content_type, _sync_chunks()
        finally:
            stop_event.set()
            worker.join(timeout=5.0)

    def close(self) -> None:
        self._refreshed_cookies = None

    async def aclose(self) -> None:
        self.close()

    def _require_a_token_solver(self) -> None:
        """Refuse a solver that cannot produce a reCAPTCHA token.

        Capability-based on purpose: a custom solver object is fine as long as
        it accepts reCAPTCHA observations, while a wait-only solver (what
        ``resolve_solver`` returns when the toolkit's dependencies are missing)
        would happily report ``cleared=True`` with no token.
        """
        supports = getattr(self.solver, "supports", None)
        if not callable(supports):
            return
        probe = ChallengeObservation(
            url=self.page_url, kind=ChallengeKind.RECAPTCHA, signals=()
        )
        if not supports(probe):
            raise AuthenticationError(
                "verification_token='auto' needs a solver that produces a "
                f"reCAPTCHA token, but {describe_solver(self.solver)} does not "
                "accept reCAPTCHA. Install the token backends with "
                "pip install '.[auth-captcha]' (plus playwright install "
                "chromium), or pass verification_token= your own assertion."
            )

    def __call__(self) -> str:
        """Fetch a token, safe to call from inside a running event loop."""
        return run_sync(self.afetch())


setattr(DirectVerificationToken.afetch, "_is_default_direct_afetch", True)


def auto_direct_client(
    options: AutoOptions | None = None,
    *,
    verification_token: Any = None,
    **overrides: Any,
) -> DirectArenaClient:
    """Return a :class:`~arena_api.DirectArenaClient` for your own session.

    ``verification_token`` accepts everything
    :class:`~arena_api.direct.DirectArenaClient` accepts, plus the string
    ``"auto"``: a :class:`DirectVerificationToken` is then built to intercept a
    v3 assertion with the captcha solver.
    """
    options = _merge_options(options, overrides)
    prepared = _prepare(options)
    if prepared is None:  # pragma: no cover
        raise AuthenticationError("no session found")
    manager, _ = prepared
    if isinstance(verification_token, str) and verification_token.strip().lower() == "auto":
        verification_token = DirectVerificationToken(
            options,
            session_cookies=manager.load_cookies(),
            session_manager=manager,
            cookie_source=_cookie_source_for_manager(manager),
        )
    return _verified(
        DirectArenaClient(
            base_url=options.base_url,
            session_source=manager,
            headers=options.headers,
            timeout=options.timeout,
            http2=options.http2,
            verify=options.verify_tls,
            proxy=options.proxy,
            verification_token=verification_token,
            http_transport=options.http_transport,
            max_auth_refreshes=options.max_auth_refreshes,
        ),
        manager,
        options,
    )


async def auto_async_direct_client(
    options: AutoOptions | None = None,
    *,
    verification_token: Any = None,
    **overrides: Any,
) -> AsyncDirectArenaClient:
    """Async twin of :func:`auto_direct_client`."""
    options = _merge_options(options, overrides)
    prepared = _prepare(options)
    if prepared is None:  # pragma: no cover
        raise AuthenticationError("no session found")
    manager, _ = prepared
    if isinstance(verification_token, str) and verification_token.strip().lower() == "auto":
        verification_token = DirectVerificationToken(
            options,
            session_cookies=manager.load_cookies(),
            session_manager=manager,
            cookie_source=_cookie_source_for_manager(manager),
        )
    return await _averified(
        AsyncDirectArenaClient(
            base_url=options.base_url,
            session_source=manager,
            headers=options.headers,
            timeout=options.timeout,
            http2=options.http2,
            verify=options.verify_tls,
            proxy=options.proxy,
            verification_token=verification_token,
            http_transport=options.http_transport,
            max_auth_refreshes=options.max_auth_refreshes,
        ),
        manager,
        options,
    )


# --------------------------------------------------------------------------- #
# Command line
# --------------------------------------------------------------------------- #


def build_arg_parser() -> argparse.ArgumentParser:
    """CLI parser; ``--help`` documents every flag."""
    parser = argparse.ArgumentParser(
        prog="python -m arena_api",
        description=(
            "Bootstrap an Arena client from your own browser session. The only "
            "manual step is signing in to your account."
        ),
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="frontend to talk to")
    parser.add_argument("--cookies", default=None, help="cookie header or cookies.json path")
    parser.add_argument(
        "--storage",
        default=None,
        help=(
            "cookies.json to read, and where --login saves it "
            "(default ./state/cookies.json)"
        ),
    )
    parser.add_argument(
        "--no-browser-profiles",
        action="store_true",
        help="do not read cookies from local browser profiles",
    )
    parser.add_argument(
        "--non-interactive", action="store_true", help="never wait for Enter"
    )
    parser.add_argument(
        "--solve",
        choices=("auto", "on", "off"),
        default="auto",
        help="challenge solving: auto = on when dependencies are importable",
    )
    parser.add_argument(
        "--backend", default="audio", help="captcha backend: audio, image or vision_ai"
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help=(
            "do not wait out challenges that have no token "
            "(Turnstile, hCaptcha, DataDome); detect and report only"
        ),
    )
    parser.add_argument(
        "--wait-timeout",
        type=float,
        default=30.0,
        help="seconds to wait per challenge round (default 30)",
    )
    parser.add_argument("--probe-path", default=CONFIG_PATH, help="path used to verify")
    parser.add_argument("--no-verify", action="store_true", help="skip the probe request")
    parser.add_argument(
        "--login",
        action="store_true",
        help="open a browser, sign in by hand once, save the session and verify it",
    )
    parser.add_argument(
        "--fresh", action="store_true", help="ignore an existing session file when logging in"
    )
    parser.add_argument(
        "--headless", action="store_true", help="keep the --login window hidden (not recommended)"
    )
    parser.add_argument(
        "--channel",
        default=None,
        help=(
            "browser build for --login: chrome or msedge runs the real installed "
            "browser instead of Playwright's bundled Chromium, which Google "
            "refuses to sign an account in from"
        ),
    )
    parser.add_argument(
        "--impersonate",
        default="auto",
        metavar="PROFILE",
        help=(
            "TLS/HTTP2 fingerprint to send: auto (follow the browser the session "
            "was found in), a curl_cffi profile such as firefox, chrome or "
            "firefox147, or off (httpx's own fingerprint). Needs the "
            "'[impersonate]' extra"
        ),
    )
    parser.add_argument(
        "--proxy",
        default=None,
        metavar="URL",
        help=(
            "HTTP/HTTPS/SOCKS5 proxy URL (e.g. http://127.0.0.1:2080 or "
            "socks5h://127.0.0.1:1080), auto (default: ARENA_PROXY, "
            "HTTPS_PROXY/ALL_PROXY, OS proxy, or Firefox prefs.js), or off"
        ),
    )
    parser.add_argument(
        "--hide-automation",
        action="store_true",
        help=(
            "make the --login window stop advertising that it is driven "
            "(--enable-automation, navigator.webdriver); pair it with --channel "
            "chrome when the sign-in goes through Google"
        ),
    )
    parser.add_argument(
        "--login-rounds",
        type=int,
        default=5,
        help="how many Enter presses --login offers (default 5)",
    )
    parser.add_argument("--status", action="store_true", help="report the session and stop")
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help=(
            "print a redacted report about your Firefox profiles (hosts, names, "
            "expiry, value fingerprints -- never a value) and stop; safe to share"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="with --diagnose: print the report as JSON",
    )
    parser.add_argument(
        "--profile",
        default=None,
        metavar="NAME",
        help=(
            "Firefox profile directory name or absolute path "
            f"(default: the profile holding the cookies; also {FIREFOX_PROFILE_ENV})"
        ),
    )
    parser.add_argument(
        "--profile-root",
        default=None,
        metavar="DIR",
        help=(
            "Firefox profiles directory to search instead of the usual ones "
            f"(also {FIREFOX_ROOT_ENV})"
        ),
    )
    parser.add_argument(
        "--explain", action="store_true", help="list every source considered and why"
    )
    parser.add_argument("--models", action="store_true", help="print the model list")
    parser.add_argument(
        "--model",
        default=None,
        help="model id or display name for --prompt (default: auto-select)",
    )
    parser.add_argument(
        "--verification-token",
        default=None,
        metavar="TOKEN",
        help=(
            "Direct Chat reCAPTCHA v3 assertion, or 'auto' (default when Direct "
            "Chat is used; also ARENA_VERIFICATION_TOKEN)"
        ),
    )
    parser.add_argument(
        "--show-browser",
        action="store_true",
        help="show the Direct Chat browser window instead of running invisibly in the background",
    )
    parser.add_argument("--prompt", default=None, help="send one prompt and print the answer")
    return parser


def _options_from_args(args: argparse.Namespace) -> AutoOptions:
    solve: bool | Literal["auto"] = (
        "auto" if args.solve == "auto" else args.solve == "on"
    )
    return AutoOptions(
        base_url=args.base_url,
        cookies=args.cookies,
        storage_path=args.storage,
        use_browser_profiles=not args.no_browser_profiles,
        interactive=not args.non_interactive,
        solve_captchas=solve,
        captcha_backend=args.backend,
        wait_out_challenges=not args.no_wait,
        challenge_wait_timeout=args.wait_timeout,
        probe_path=args.probe_path,
        verify=not args.no_verify,
        channel=args.channel,
        hide_automation=args.hide_automation,
        impersonate=args.impersonate,
        proxy=args.proxy,
        profiles_root=args.profile_root,
        profile_name=args.profile,
        show_browser=bool(getattr(args, "show_browser", False)),
    )


def _ensure_utf8_stdio() -> None:
    if os.name != "nt":
        return
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            enc = str(getattr(stream, "encoding", "") or "").lower()
            if "utf" not in enc:
                try:
                    stream.reconfigure(encoding="utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    pass


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point of ``python -m arena_api`` (and ``python -m arena_api.auto``).

    Exit codes: ``0`` everything worked, ``1`` no usable session (or another
    library error), ``2`` a session was found but the server rejected it.
    """
    _ensure_utf8_stdio()
    args = build_arg_parser().parse_args(argv)
    try:
        options = _options_from_args(args)
    except ValueError as exc:
        print(f"[arena-api] {exc}", file=sys.stderr)
        return 1

    if args.diagnose:
        report = collect_firefox_report(
            domains=options.cookie_domains(),
            profiles_root=options.profiles_root,
            profile_name=options.profile_name,
            cookie_database=options.cookie_database,
        )
        if args.json:
            print(report_as_json(report))
        else:
            for line in format_firefox_report(report):
                print(line)
        return 0

    if args.explain:
        for line in explain_sources(options):
            print(line)
        print(_report_line("login flow", _login_state(options)))
        print(_report_line("fingerprint", explain_impersonation(options)))
        print(_report_line("proxy", explain_proxy(options)))
        available = solver_dependencies_available(options.captcha_backend)
        detail = (
            f"{options.solve_captchas} (backend {options.captcha_backend}, "
            f"dependencies {'available' if available else 'missing'})"
        )
        solver = resolve_solver(options)
        if solver is not None:
            detail += f" -> {describe_solver(solver)}"
        else:
            detail += " -> off"
        print(_report_line("captcha solving", detail))
        if options.use_browser_profiles and _firefox_cookie_total(options) == 0:
            print(_report_line("no Firefox cookies", "run --diagnose for a redacted report"))
        return 0

    try:
        if args.login:
            destination = Path(args.storage or options.storage_path or DEFAULT_STATE_PATH)
            code = _login(args, options, destination)
            # ``--login --models`` keeps going with the session it just saved.
            if code != 0 or not (args.models or args.prompt):
                return code
            options = replace(
                options,
                cookies=None,
                storage_path=str(destination),
                use_browser_profiles=False,
            )
            return _run(args, options)
        return _run(args, options)
    except ArenaError as exc:
        print(f"[arena-api] {exc}", file=sys.stderr)
        return 1


def _login(
    args: argparse.Namespace, options: AutoOptions, destination: Path
) -> int:
    """``--login``: sign in by hand once, then report what happened."""
    try:
        outcome = interactive_login(
            options,
            path=destination,
            headless=args.headless,
            fresh=args.fresh,
            rounds=args.login_rounds,
        )
    except ArenaError:
        raise
    except Exception as exc:  # noqa: BLE001 - translate into one actionable line
        # The usual cause is a missing browser binary: Playwright answers with
        # its own multi-line error, which reads as a crash rather than as the
        # one-command fix it is.
        detail = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
        if options.channel:
            # With a channel the bundled download would not help: the window
            # needs the real Chrome/Edge the user asked for.
            hint = (
                "Install Google Chrome (or drop --channel to use Playwright's "
                "bundled Chromium: `python -m playwright install chromium`)."
            )
        else:
            hint = "Install it with `python -m playwright install chromium`."
        raise AuthenticationError(
            f"the login browser could not be started: {detail} {hint}"
        ) from exc
    login = outcome.login
    if not login.cookies:
        print(_report_line("login", "no cookies captured"))
        return 1
    print(_report_line("login", login.describe()))
    if not login.saved:
        print(_report_line("hint", "no sign-in detected, so nothing was written"))
        return 1
    if outcome.verification is None:
        return 0
    print(_report_line("verification", outcome.verification.describe()))
    return 0 if outcome.verification.ok else 2


def _direct_client_for_cli(
    client: Any,
    options: AutoOptions,
    *,
    verification_token: Any = None,
) -> Any:
    """Build a :class:`DirectArenaClient` reusing ``client.session_manager``."""
    shared_manager = getattr(client, "session_manager", None)
    if shared_manager is not None:
        tok = verification_token
        if isinstance(tok, str) and tok.strip().lower() == "auto":
            tok = DirectVerificationToken(
                options,
                session_cookies=shared_manager.load_cookies(),
                session_manager=shared_manager,
                cookie_source=_cookie_source_for_manager(shared_manager),
            )
        return DirectArenaClient(
            base_url=options.base_url,
            session_source=shared_manager,
            headers=options.headers,
            timeout=options.timeout,
            http2=options.http2,
            verify=options.verify_tls,
            proxy=options.proxy,
            verification_token=tok,
            http_transport=options.http_transport,
            max_auth_refreshes=options.max_auth_refreshes,
        )
    return auto_direct_client(
        replace(options, verify=False, output=io.StringIO()),
        verification_token=verification_token,
    )


def _safe_stdout_write(text: str) -> None:
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        enc = str(getattr(sys.stdout, "encoding", "") or "utf-8") or "utf-8"
        safe = text.encode(enc, errors="replace").decode(enc, errors="replace")
        sys.stdout.write(safe)
    sys.stdout.flush()


def _stream_to_stdout(stream: Any) -> None:
    stream_iter = iter(stream)
    first = next(stream_iter, None)
    print("answer            : ", end="", flush=True)
    if first is not None:
        _safe_stdout_write(first.delta)
    for chunk in stream_iter:
        _safe_stdout_write(chunk.delta)
    print()


def _run(args: argparse.Namespace, options: AutoOptions) -> int:
    """The part of :func:`main` that needs a session."""
    if args.status and not (args.models or args.prompt):
        discovered = discover_session(options)
        if discovered is None:
            print("session           : none found")
            for line in explain_sources(options):
                print(f"  {line}")
            return 1
        print(f"session           : {discovered.description}")
        print(
            "cookie names      : "
            + (", ".join(sorted(discovered.cookies)) or "none")
        )
        if not options.verify:
            return 0
        status_options = replace(
            options,
            verify=False,
            interactive=False,
            solve_captchas=False,
            login_from_env=False,
            max_auth_refreshes=0,
        )
        with auto_client(status_options) as client:
            active_proxy = getattr(
                getattr(client, "transport", None), "proxy", None
            )
            result = probe(client, options.probe_path)
        if active_proxy:
            print(f"proxy             : {redact_proxy_url(active_proxy)}")
        print(f"verification      : {result.describe()}")
        if not result.ok and result.error is not None:
            print(f"detail            : {result.error}")
            if isinstance(result.error.__cause__, httpx.RequestError):
                if active_proxy:
                    print(
                        "hint              : check that proxy "
                        f"{redact_proxy_url(active_proxy)} is running and can "
                        f"reach {options.base_url}"
                    )
                else:
                    print(
                        "hint              : could not establish a direct "
                        "connection; if your network or split-tunnel VPN only "
                        "routes the browser process, set HTTPS_PROXY / "
                        f"{ARENA_PROXY_ENV} or pass --proxy "
                        "http://127.0.0.1:<port> (or socks5h://127.0.0.1:<port>)"
                    )
        if not result.ok and result.auth_problem:
            if not impersonation_available():
                print(
                    "hint              : TLS fingerprint impersonation is not installed "
                    f'({IMPERSONATE_EXTRA} or pip install -e ".[impersonate]"); '
                    "Cloudflare often challenges browser cookies sent with Python's "
                    "default TLS stack"
                )
            elif discovered.source == "firefox":
                print(
                    "hint              : if cf_clearance in Firefox has expired or was "
                    f"issued for another IP/build, reload {options.base_url} in Firefox "
                    "and run --status again"
                )
        return 0 if result.ok else (2 if result.auth_problem else 1)

    with auto_client(options) as client:
        models: Sequence[Any] | None = None
        if args.models:
            try:
                models = client.get_models()
            except ArenaError as exc:
                if isinstance(exc, AuthenticationError) or isinstance(
                    exc.__cause__, httpx.RequestError
                ):
                    raise
                with _direct_client_for_cli(client, options) as direct:
                    models = sorted(direct.get_models(), key=model_chat_score)
            print(f"models            : {len(models)}")
            for model in models[:25]:
                print(f"  {model.id} — {model.display_name}")
        if args.prompt:
            explicit_vtoken = args.verification_token
            requested_model = args.model
            if (
                isinstance(requested_model, str)
                and requested_model.strip().lower() == "auto"
            ):
                requested_model = None
            stream_kwargs: dict[str, Any] = {}
            if requested_model is not None:
                stream_kwargs["model"] = requested_model
            used_gradio = False
            if explicit_vtoken is None:
                try:
                    _stream_to_stdout(client.stream(args.prompt, **stream_kwargs))
                    used_gradio = True
                except ArenaError as exc:
                    if isinstance(exc, AuthenticationError) or isinstance(
                        exc.__cause__, httpx.RequestError
                    ):
                        raise
            if not used_gradio:
                resolved_vtoken = (
                    explicit_vtoken
                    or os.environ.get("ARENA_VERIFICATION_TOKEN")
                    or "auto"
                )
                with _direct_client_for_cli(
                    client, options, verification_token=resolved_vtoken
                ) as direct:
                    if requested_model is not None:
                        direct_models = (
                            list(models)
                            if models is not None
                            else direct.get_models()
                        )
                        direct._resolve_model(requested_model, direct_models)
                        print(f"model             : {requested_model}")
                    _stream_to_stdout(
                        direct.stream(args.prompt, model=requested_model)
                    )
        if not (args.models or args.prompt):
            print("session           : ready")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())

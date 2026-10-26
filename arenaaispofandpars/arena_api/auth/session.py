"""Session lifecycle management for cookie-authenticated browser sessions.

This is the orchestration layer of ``arena_api.auth``. It answers one question
-- *is the session I have still usable, and how do I get a fresh one when it
is not?* -- across two backends:

* **Fast path (no browser).** :meth:`BrowserSessionManager.validate` issues a
  cheap ``curl_cffi`` probe against a configured endpoint and classifies the
  result: healthy, expired/rejected, rate-limited, or challenged. This is what
  a monitoring tick runs on every iteration, because launching Chromium to
  answer "are we still logged in?" is wasteful.
* **Refresh path (browser).** :meth:`BrowserSessionManager.arefresh_session`
  drives a *real, ordinary sign-in* through Playwright -- the credentials you
  supply, the form selectors you configure -- and persists the resulting
  ``storage_state`` to ``cookies.json``. The same state is exported as a flat
  cookie mapping and as a ready-made ``curl_cffi.requests.Session``.

If a challenge appears during a refresh, the run stops with captured
diagnostics (:class:`~arena_api.exceptions.ChallengeRequiredError` and the
remediation guide in :mod:`arena_api.auth.challenge`).

*Optionally*, a ``captcha_solver`` (see :mod:`arena_api.auth.captcha`) turns
that stop into a solve: a reCAPTCHA met during the login is cleared and the
refresh continues. Configuring a solver without a ``login_flow`` gives a
challenge-only refresh -- open ``captcha_url``, clear the screen, persist the
cookies -- for the case where the session is fine but blocked.

``curl_cffi`` is used here as a fast HTTP client with HTTP/2 and a real TLS
stack. Its ``impersonate=`` knob is exposed as a pass-through because some
servers reject non-browser TLS stacks outright, and it defaults to ``None``.
"""


from __future__ import annotations

import json
import os
import platform
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple, Protocol, runtime_checkable
from urllib.parse import urljoin, urlparse

from ..constants import DEFAULT_BASE_URL
from ..exceptions import AuthenticationError
from .browser import BrowserEnvironment, BrowserEnvironmentOptions
from .challenge import ChallengeHandler, ChallengeObservation, inspect_response
from .kinematics import KinematicMouse

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from .captcha import CaptchaSolver

__all__ = [
    "BrowserSessionManager",
    "CurlCffiProbe",
    "FormLoginFlow",
    "LoginFlow",
    "RawResponse",
    "SessionProbe",
    "SessionValidation",
    "chromium_user_agent",
]

DEFAULT_CHROMIUM_VERSION = "140.0.7339.207"
DEFAULT_VALIDATE_PATHS: tuple[str, ...] = ("/",)
DEFAULT_ACCEPT_STATUSES: tuple[int, ...] = (200, 204, 206, 301, 302, 304)


def _coerce_cookie_records(cookies: Any, host: str) -> list[dict[str, Any]]:
    """Normalise a list of cookie records, backfilling domain/path.

    Records exported by hand often carry only ``name`` and ``value``; without
    a domain they would be filtered out by every domain-scoped lookup, so the
    manager's own host is filled in.
    """
    records: list[dict[str, Any]] = []
    if not isinstance(cookies, (list, tuple)):
        return records
    for item in cookies:
        if not isinstance(item, Mapping):
            continue
        name = item.get("name")
        value = item.get("value")
        if not isinstance(name, str) or not isinstance(value, str) or not name:
            continue
        records.append(
            {
                "name": name,
                "value": value,
                "domain": str(item.get("domain") or host),
                "path": str(item.get("path") or "/"),
                "expires": item.get("expires", -1),
                "secure": bool(item.get("secure", True)),
                "httpOnly": bool(item.get("httpOnly", False)),
                "sameSite": str(item.get("sameSite") or "Lax"),
            }
        )
    return records


def _records_from_cookie_header(header: str, host: str) -> list[dict[str, Any]]:
    """Parse a ``"a=1; b=2"`` Cookie header into cookie records."""
    records: list[dict[str, Any]] = []
    for part in str(header).split(";"):
        name, _, value = part.partition("=")
        name = name.strip()
        if not name:
            continue
        records.append(
            {
                "name": name,
                "value": value.strip(),
                "domain": host,
                "path": "/",
                "expires": -1,
                "secure": True,
                "httpOnly": False,
                "sameSite": "Lax",
            }
        )
    return records


def normalize_state_payload(payload: Any, host: str) -> dict[str, Any]:
    """Accept every cookie-file shape this package documents.

    Supported: a Playwright ``storage_state`` dict, a plain array of cookie
    records (the ``cookies.json`` format shown in the README), and a browser
    export with a ``cookie`` header string. Anything else yields an empty
    state, so callers can fall back to a flat ``{name: value}`` mapping.
    """
    if isinstance(payload, Mapping):
        cookies = payload.get("cookies")
        if isinstance(cookies, (list, tuple)):
            return {
                "cookies": _coerce_cookie_records(cookies, host),
                "origins": payload.get("origins") or [],
            }
        header = payload.get("cookie")
        if isinstance(header, str):
            return {"cookies": _records_from_cookie_header(header, host), "origins": []}
        return {}
    if isinstance(payload, (list, tuple)):
        return {"cookies": _coerce_cookie_records(payload, host), "origins": []}
    return {}


def chromium_user_agent(version: str = DEFAULT_CHROMIUM_VERSION) -> str:
    """Build the User-Agent of a Chromium build on the current platform.

    The result is meant to describe *the browser that actually produced the
    stored session*, so the session's headers match its cookies. Override
    ``version`` (or pass ``user_agent=``) to match your installed build.
    """
    system = platform.system()
    if system == "Darwin":
        token = "Macintosh; Intel Mac OS X 10_15_7"
    elif system == "Windows":
        token = "Windows NT 10.0; Win64; x64"
    else:
        token = "X11; Linux x86_64"
    return (
        f"Mozilla/5.0 ({token}) AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{version} Safari/537.36"
    )


# --------------------------------------------------------------------------- #
# Probes
# --------------------------------------------------------------------------- #


class RawResponse(NamedTuple):
    """Minimal response view needed to validate a session."""

    status: int
    headers: Mapping[str, str]
    body: str


@runtime_checkable
class SessionProbe(Protocol):
    """Callable that performs one validation request."""

    def __call__(
        self,
        url: str,
        *,
        cookies: Mapping[str, str],
        headers: Mapping[str, str],
        timeout: float,
    ) -> RawResponse: ...


@dataclass
class CurlCffiProbe:
    """Default probe backed by ``curl_cffi``.

    ``impersonate=None`` leaves curl_cffi's default TLS/HTTP2 fingerprint in
    place; see the module docstring for why that is the default here.
    """

    impersonate: str | None = None
    verify: bool = True
    proxy: str | None = None
    max_body_chars: int = 200_000
    request_factory: Callable[..., Any] | None = None

    def __call__(
        self,
        url: str,
        *,
        cookies: Mapping[str, str],
        headers: Mapping[str, str],
        timeout: float,
    ) -> RawResponse:
        factory = self.request_factory
        if factory is None:
            try:
                from curl_cffi import requests as curl_requests
            except ImportError as exc:  # pragma: no cover - dependency path
                raise RuntimeError(
                    "curl_cffi is required for session validation; "
                    "install it with `pip install curl_cffi`"
                ) from exc
            request = None
        else:
            request = factory

        options: dict[str, Any] = {
            "cookies": dict(cookies),
            "headers": dict(headers),
            "timeout": timeout,
            "allow_redirects": True,
            "verify": self.verify,
        }
        if self.impersonate:
            options["impersonate"] = self.impersonate
        if request is None:
            from ..transport import resolve_proxy_url

            effective_proxy = resolve_proxy_url(url, self.proxy)
            if effective_proxy:
                options["proxy"] = effective_proxy
            with curl_requests.Session(trust_env=False) as session:
                response = session.get(url, **options)
        else:
            if self.proxy:
                options["proxy"] = self.proxy
            response = request(url, **options)
        return RawResponse(
            status=int(response.status_code),
            headers={
                str(key): str(value)
                for key, value in response.headers.items()
                if value is not None
            },
            body=str(response.text or "")[: self.max_body_chars],
        )


@dataclass(frozen=True)
class SessionValidation:
    """Outcome of one :meth:`BrowserSessionManager.validate` call."""

    ok: bool
    status: int | None
    url: str
    reason: str
    challenge: ChallengeObservation | None = None
    latency: float = 0.0

    def describe(self) -> str:
        """One-line summary for logs."""
        status = "?" if self.status is None else str(self.status)
        return f"{'ok' if self.ok else 'invalid'} [{status}] {self.url}: {self.reason}"

    def raise_for_status(self) -> None:
        """Raise the error that corresponds to this failed validation."""
        if self.ok:
            return None
        if self.challenge is not None and self.challenge.is_challenge:
            handler = ChallengeHandler(raise_on_detection=False)
            handler.raise_for(self.challenge)
        raise AuthenticationError(f"{self.describe()}")


# --------------------------------------------------------------------------- #
# Login flows
# --------------------------------------------------------------------------- #


@runtime_checkable
class LoginFlow(Protocol):
    """An ordinary, credentialed sign-in driven through a Playwright page."""

    async def run(self, page: Any) -> None: ...


@dataclass
class FormLoginFlow:
    """Fill a username/password form and wait for a post-login condition.

    Credentials come from the constructor or, by default, from environment
    variables -- never from the repository.

    Set ``human_input=True`` to drive the form with
    :class:`~arena_api.auth.kinematics.KinematicMouse`; that exercises
    keystroke- and pointer-dependent behaviour (autocomplete dropdowns,
    "show password" toggles, disabled-until-valid submit buttons) at the cost
    of a slower run. The default uses ``locator.fill``, which is faster and
    more robust for a pure session refresh.
    """

    login_url: str
    username_selector: str
    password_selector: str
    submit_selector: str
    success_selector: str | None = None
    success_url_contains: str | None = None
    remember_selector: str | None = None
    username: str | None = None
    password: str | None = None
    username_env: str = "ARENA_USERNAME"
    password_env: str = "ARENA_PASSWORD"
    timeout: float = 30_000.0
    human_input: bool = False
    wait_until: str = "domcontentloaded"

    def credentials(self) -> tuple[str, str]:
        """Resolve credentials, preferring explicit values over the environment."""
        username = self.username if self.username is not None else os.environ.get(self.username_env)
        password = self.password if self.password is not None else os.environ.get(self.password_env)
        missing = [
            name
            for name, value in (
                (self.username_env, username),
                (self.password_env, password),
            )
            if not value
        ]
        if missing:
            raise AuthenticationError(
                "missing login credentials; set "
                + ", ".join(missing)
                + " or pass username=/password= to FormLoginFlow"
            )
        return str(username), str(password)

    async def run(self, page: Any) -> None:
        """Navigate to the login form, submit it, and wait for success."""
        username, password = self.credentials()
        await page.goto(self.login_url, wait_until=self.wait_until, timeout=self.timeout)

        if self.human_input:
            mouse = KinematicMouse(page)
            await mouse.type_text(self.username_selector, username, clear_first=True)
            await mouse.type_text(self.password_selector, password, clear_first=True)
        else:
            await page.fill(self.username_selector, username, timeout=self.timeout)
            await page.fill(self.password_selector, password, timeout=self.timeout)

        if self.remember_selector:
            await page.check(self.remember_selector, timeout=self.timeout)

        if self.human_input:
            await mouse.click(self.submit_selector)
        else:
            await page.click(self.submit_selector, timeout=self.timeout)

        if self.success_selector:
            await page.wait_for_selector(
                self.success_selector, timeout=self.timeout, state="visible"
            )
        elif self.success_url_contains:
            token = self.success_url_contains

            def _matches(url: str) -> bool:
                return token in str(url)

            await page.wait_for_url(_matches, timeout=self.timeout)
        else:
            await page.wait_for_load_state("networkidle", timeout=self.timeout)


# --------------------------------------------------------------------------- #
# Manager
# --------------------------------------------------------------------------- #


@dataclass
class BrowserSessionManager:
    """Validate, persist and refresh a browser-backed session.

    Implements the duck-typed ``SessionManager`` protocol the clients accept as
    ``session_source`` (``load_cookies`` / ``refresh_session`` / headers), so
    it can be dropped in beside
    :class:`~arena_api.auth.firefox_session.FirefoxSessionManager`.
    """

    base_url: str = DEFAULT_BASE_URL
    domains: Sequence[str] | None = None
    storage_path: str | Path | None = None
    probe: SessionProbe | None = None
    impersonate: str | None = None
    validate_paths: Sequence[str] = DEFAULT_VALIDATE_PATHS
    accept_statuses: Sequence[int] = DEFAULT_ACCEPT_STATUSES
    anonymous_markers: Sequence[str] = ()
    detect_anonymous: bool = False
    challenge_handler: ChallengeHandler | None = None
    environment_options: BrowserEnvironmentOptions | None = None
    login_flow: LoginFlow | None = None
    #: Opt-in challenge solver (see :mod:`arena_api.auth.captcha`). When set, a
    #: reCAPTCHA met during a refresh is solved and the login continues instead
    #: of failing the run; with no ``login_flow`` it enables a challenge-only
    #: refresh against ``captcha_url`` (or ``base_url``).
    captcha_solver: "CaptchaSolver | None" = None
    #: URL opened for a challenge-only refresh; defaults to ``base_url``.
    captcha_url: str | None = None
    user_agent: str | None = None
    chromium_version: str = DEFAULT_CHROMIUM_VERSION
    timeout: float = 45.0
    max_refresh_attempts: int = 1
    _state: dict[str, Any] | None = field(default=None, repr=False, compare=False)

    # ------------------------------------------------------------------ #
    # Identity
    # ------------------------------------------------------------------ #

    def __post_init__(self) -> None:
        self.base_url = str(self.base_url).rstrip("/")
        if self.domains is None:
            # Cookie domains never carry a port, so derive them from the
            # hostname. Using netloc here would silently filter out every
            # cookie on any origin with a non-default port (typical staging).
            host = self.host
            self.domains = (host,) if host else ()
        else:
            self.domains = tuple(self.domains)
        if self.storage_path is not None:
            self.storage_path = Path(self.storage_path)
        if self.challenge_handler is None:
            self.challenge_handler = ChallengeHandler(
                capture_dir=self.default_capture_dir(),
                raise_on_detection=False,
            )
        if self.captcha_solver is not None:
            # A solver handed to the manager is a solver the manager uses: fill
            # in the handler it was not given explicitly, and turn solving on.
            if self.challenge_handler.captcha_solver is None:
                self.challenge_handler.captcha_solver = self.captcha_solver
            self.challenge_handler.solve_on_detection = True

    @property
    def host(self) -> str:
        """Hostname of ``base_url``, lower-cased and without a port.

        This is the value a cookie's ``domain`` is matched against, which is
        why the port is dropped.
        """
        return urlparse(self.base_url).hostname or ""

    def default_capture_dir(self) -> Path | None:
        """Directory used for challenge diagnostics when none is configured."""
        if self.storage_path is None:
            return None
        return Path(self.storage_path).parent / "challenges"

    def _resolve_probe(self) -> SessionProbe:
        if self.probe is not None:
            return self.probe
        return CurlCffiProbe(impersonate=self.impersonate)

    # ------------------------------------------------------------------ #
    # Stored state
    # ------------------------------------------------------------------ #

    def _load_state(self) -> dict[str, Any]:
        if self._state is not None:
            return self._state
        if self.storage_path is None:
            return {}
        path = Path(self.storage_path)
        if not path.is_file():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return normalize_state_payload(payload, self.host)

    def cookie_records(self) -> list[dict[str, Any]]:
        """Return every stored cookie as a record with its domain and path."""
        records: list[dict[str, Any]] = []
        for cookie in self._load_state().get("cookies", []) or []:
            if not isinstance(cookie, Mapping):
                continue
            name = cookie.get("name")
            value = cookie.get("value")
            if not isinstance(name, str) or not isinstance(value, str) or not name:
                continue
            records.append(
                {
                    "name": name,
                    "value": value,
                    "domain": str(cookie.get("domain") or ""),
                    "path": str(cookie.get("path") or "/"),
                    "expires": cookie.get("expires", -1),
                    "secure": bool(cookie.get("secure")),
                    "http_only": bool(cookie.get("httpOnly")),
                    "same_site": str(cookie.get("sameSite") or ""),
                }
            )
        return records

    def _domain_matches(self, domain: str, targets: Sequence[str]) -> bool:
        candidate = str(domain).lstrip(".").lower()
        for target in targets:
            wanted = str(target).lstrip(".").lower()
            if candidate == wanted or candidate.endswith("." + wanted):
                return True
        return False

    def load_cookies(self, domains: Sequence[str] | None = None) -> dict[str, str]:
        """Return a flat ``{name: value}`` mapping for the target domains.

        This is the shape accepted by ``curl_cffi.requests.Session`` and by the
        ``cookies=`` argument of the Arena clients.
        """
        targets = tuple(domains) if domains is not None else tuple(self.domains or ())
        cookies: dict[str, str] = {}
        for record in self.cookie_records():
            if targets and not self._domain_matches(record["domain"], targets):
                continue
            cookies[record["name"]] = record["value"]
        return cookies

    def to_curl_cffi(self) -> dict[str, dict[str, str]]:
        """Group cookies by domain for curl_cffi's domain-aware cookie jar."""
        grouped: dict[str, dict[str, str]] = {}
        for record in self.cookie_records():
            jar = grouped.setdefault(record["domain"] or self.host, {})
            jar[record["name"]] = record["value"]
        return grouped

    def to_curl_cffi_session(self, **kwargs: Any) -> Any:
        """Build a ``curl_cffi.requests.Session`` carrying the stored session."""
        try:
            from curl_cffi import requests as curl_requests
        except ImportError as exc:  # pragma: no cover - dependency path
            raise RuntimeError(
                "curl_cffi is required for to_curl_cffi_session(); "
                "install it with `pip install curl_cffi`"
            ) from exc
        session = curl_requests.Session(
            impersonate=self.impersonate, headers=self.headers(), **kwargs
        )
        for name, value in self.load_cookies().items():
            session.cookies.set(name, value, domain=self.host)
        return session

    def export_cookies(self, path: str | Path | None = None) -> Path:
        """Write cookies as a JSON array (the format ``cookies=`` accepts)."""
        target = Path(path) if path is not None else Path(
            self.storage_path or "cookies.json"
        )
        payload = [
            {
                "name": record["name"],
                "value": record["value"],
                "domain": record["domain"] or self.host,
                "path": record["path"],
            }
            for record in self.cookie_records()
        ]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return target

    def import_cookies(
        self,
        cookies: Mapping[str, str] | Sequence[Mapping[str, Any]] | str | Path,
    ) -> None:
        """Seed the in-memory state from a mapping, records, or JSON file."""
        if isinstance(cookies, (str, Path)):
            payload: Any = json.loads(Path(cookies).read_text(encoding="utf-8"))
        else:
            payload = cookies

        state = normalize_state_payload(payload, self.host)
        if state.get("cookies"):
            self._state = state
            return

        # Fall back to a flat {name: value} mapping, or a sparse record list
        # whose entries carried no usable name/value pair.
        if isinstance(payload, Mapping):
            records = [
                self._record(str(name), str(value)) for name, value in payload.items()
            ]
        elif isinstance(payload, Sequence) and not isinstance(payload, (str, bytes)):
            records = _coerce_cookie_records(list(payload), self.host)
        else:
            raise TypeError("cookies must be a mapping, a record list, or a JSON path")
        self._state = {"cookies": records, "origins": []}

    def _record(self, name: str, value: str) -> dict[str, Any]:
        return {
            "name": name,
            "value": value,
            "domain": self.host,
            "path": "/",
            "expires": -1,
            "secure": True,
            "httpOnly": False,
            "sameSite": "Lax",
        }

    # ------------------------------------------------------------------ #
    # Headers
    # ------------------------------------------------------------------ #

    def default_user_agent(self) -> str:
        """User-Agent describing the browser build behind this session."""
        return self.user_agent or chromium_user_agent(self.chromium_version)

    def headers(self, *, navigation: bool = False) -> dict[str, str]:
        """Browser-consistent request headers for the stored session."""
        headers: dict[str, str] = {
            "User-Agent": self.default_user_agent(),
            "Accept-Language": "en-US,en;q=0.9",
        }
        if navigation:
            headers.update(
                {
                    "Accept": (
                        "text/html,application/xhtml+xml,"
                        "application/xml;q=0.9,*/*;q=0.8"
                    ),
                    "Upgrade-Insecure-Requests": "1",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-User": "?1",
                }
            )
        else:
            headers.update(
                {
                    "Accept": "text/event-stream, application/json, text/plain, */*",
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "same-origin",
                }
            )
        return headers

    def firefox_headers(self, *, navigation: bool = False) -> dict[str, str]:
        """Alias of :meth:`headers`.

        The clients check for a ``firefox_headers`` member when accepting a
        duck-typed ``session_source``. The name is historical; this manager
        emits headers for whichever browser build produced the session, which
        is Chromium unless ``user_agent=`` says otherwise.
        """
        return self.headers(navigation=navigation)

    # ------------------------------------------------------------------ #
    # Validation
    # ------------------------------------------------------------------ #

    def validate(self, cookies: Mapping[str, str] | None = None) -> SessionValidation:
        """Probe the target and classify the stored session's health."""
        probe = self._resolve_probe()
        active = dict(cookies) if cookies is not None else self.load_cookies()
        handler = self.challenge_handler or ChallengeHandler(
            raise_on_detection=False
        )
        paths = tuple(self.validate_paths) or DEFAULT_VALIDATE_PATHS
        started = time.perf_counter()
        last: SessionValidation | None = None

        for path in paths:
            url = urljoin(self.base_url + "/", str(path).lstrip("/"))
            try:
                response = probe(
                    url,
                    cookies=active,
                    headers=self.headers(navigation=True),
                    timeout=self.timeout,
                )
            except Exception as exc:
                last = SessionValidation(
                    ok=False,
                    status=None,
                    url=url,
                    reason=f"transport error: {type(exc).__name__}: {exc}",
                    latency=time.perf_counter() - started,
                )
                continue

            observation = inspect_response(
                response.status,
                response.headers,
                response.body,
                url=url,
                extra_text_markers=handler.extra_text_markers,
            )
            latency = time.perf_counter() - started

            if response.status == 429:
                # Rate limiting is its own actionable outcome, not a
                # verification challenge: the fix is a lower cadence, not a
                # different session.
                return SessionValidation(
                    ok=False,
                    status=response.status,
                    url=url,
                    reason="rate limited (HTTP 429)",
                    latency=latency,
                )
            if observation.is_challenge:
                return SessionValidation(
                    ok=False,
                    status=response.status,
                    url=url,
                    reason=f"browser verification challenge ({observation.kind.value})",
                    challenge=observation,
                    latency=latency,
                )
            if response.status in tuple(self.accept_statuses):
                if self.detect_anonymous and self._looks_anonymous(response.body):
                    return SessionValidation(
                        ok=False,
                        status=response.status,
                        url=url,
                        reason="session accepted but the page rendered as signed-out",
                        latency=latency,
                    )
                return SessionValidation(
                    ok=True,
                    status=response.status,
                    url=url,
                    reason="session accepted",
                    latency=latency,
                )
            if response.status in (401, 403):
                last = SessionValidation(
                    ok=False,
                    status=response.status,
                    url=url,
                    reason="session rejected or expired",
                    latency=latency,
                )
                continue
            last = SessionValidation(
                ok=False,
                status=response.status,
                url=url,
                reason=f"unexpected status {response.status}",
                latency=latency,
            )

        if last is None:
            return SessionValidation(
                ok=False,
                status=None,
                url=self.base_url,
                reason="no validation path configured",
            )
        return last

    def _looks_anonymous(self, body: str) -> bool:
        lowered = (body or "").lower()
        return any(marker.lower() in lowered for marker in self.anonymous_markers)

    # ------------------------------------------------------------------ #
    # Refresh
    # ------------------------------------------------------------------ #

    async def arefresh_session(
        self, reason: BaseException | None = None
    ) -> dict[str, str] | None:
        """Re-authenticate in a browser and persist the resulting state.

        Two entry points, in order of preference:

        * ``login_flow`` -- an ordinary credentialed sign-in. A reCAPTCHA met on
          the way is solved first when a ``captcha_solver`` is configured.
        * ``captcha_solver`` alone -- the session is not expired, it is blocked
          by a verification screen, so opening ``captcha_url`` (default
          ``base_url``) and clearing it is enough to continue.
        """
        if self.login_flow is None and self.captcha_solver is None:
            raise AuthenticationError(
                "no login_flow configured; construct BrowserSessionManager with "
                "login_flow=FormLoginFlow(...) so the session can be renewed "
                "from your own credentials"
            )

        options = self.environment_options or BrowserEnvironmentOptions()
        options = replace(options, storage_state=self.storage_path)
        handler = self.challenge_handler or ChallengeHandler(
            capture_dir=self.default_capture_dir(), raise_on_detection=False
        )
        handler.clear()

        async with BrowserEnvironment(options) as environment:
            context = await environment.new_context()
            page = await environment.new_page(context)
            await handler.install(page)
            if self.login_flow is not None:
                await self.login_flow.run(page)
            else:
                await page.goto(
                    self.captcha_url or self.base_url, wait_until="domcontentloaded"
                )
            observation = await handler.check(page)
            if observation.is_challenge:
                handler.raise_for(observation, attempts=handler.solve_attempts)
            await self._persist_state(context)

        cookies = self.load_cookies()
        if not cookies:
            raise AuthenticationError(
                "the login flow completed but no cookies for "
                f"{', '.join(self.domains or ())} were stored"
            )
        return cookies

    async def _persist_state(self, context: Any) -> None:
        """Write the context's cookies/localStorage to ``storage_path`` (or memory)."""
        if self.storage_path is not None:
            Path(self.storage_path).parent.mkdir(parents=True, exist_ok=True)
            self._state = await context.storage_state(path=str(self.storage_path))
        else:
            self._state = await context.storage_state()

    def refresh_session(
        self, reason: BaseException | None = None
    ) -> dict[str, str] | None:
        """Blocking twin of :meth:`arefresh_session`.

        Safe to call from inside a running event loop: the coroutine is then
        executed on a worker thread with its own loop.
        """
        from .browser import run_sync

        return run_sync(self.arefresh_session(reason))

    async def aensure_valid(self) -> dict[str, str]:
        """Validate, refreshing up to ``max_refresh_attempts`` times."""
        result = self.validate()
        attempts = 0
        while not result.ok and attempts < max(0, int(self.max_refresh_attempts)):
            attempts += 1
            if self.login_flow is None and self.captcha_solver is None:
                break
            refreshed = await self.arefresh_session(reason=None)
            if refreshed is None:
                break
            result = self.validate(refreshed)
        if not result.ok:
            if result.challenge is not None and result.challenge.is_challenge:
                handler = self.challenge_handler or ChallengeHandler(
                    raise_on_detection=False
                )
                handler.raise_for(result.challenge, attempts=handler.solve_attempts)
            result.raise_for_status()
        return self.load_cookies()

    def ensure_valid(self) -> dict[str, str]:
        """Blocking twin of :meth:`aensure_valid`."""
        from .browser import run_sync

        return run_sync(self.aensure_valid())

"""Opt-in challenge solving: a token for reCAPTCHA, patience for the rest.

Posture
-------
Everywhere else ``arena_api.auth`` is deliberately *observational*:
:mod:`arena_api.auth.challenge` detects a verification screen, captures
diagnostics and reports it, and :class:`~arena_api.auth.browser.BrowserEnvironment`
announces itself with ``X-Synthetic-Monitor`` instead of camouflaging the run.
This module is the single place where that stance is relaxed, and it is relaxed
only when you ask for it: nothing here is active unless you construct a solver
and hand it to a handler, an environment or a session manager.

Two solvers live here, and they cover the classified kinds between them:

* :class:`RecaptchaToolkitSolver` produces a real ``g-recaptcha-response`` token
  for :data:`~arena_api.auth.challenge.ChallengeKind.RECAPTCHA` through the
  vendored toolkit (audio, image or local-YOLO backend).
* :class:`ChallengeWaitSolver` handles everything that has *no* token to forge:
  Turnstile and a Cloudflare managed interstitial usually pass on their own in a
  real browser, so it re-scans the page until they do; hCaptcha, DataDome and
  anything unrecognised are handed to a person, which a headed browser window
  makes possible (``interactive=True`` announces the wait and lets you extend it).

:class:`CompositeSolver` dispatches between them by kind, and
:func:`arena_api.auto.resolve_solver` builds exactly that pair by default. When
neither can help, the detect-and-report path still applies -- see
:data:`~arena_api.auth.challenge.REMEDIATION_TEMPLATE` for the durable fixes.

No second browser
-----------------
The toolkit's bots are used as a *solver facade* over a page that this package
already opened. ``PlaywrightBot.solve_recaptcha_v2/v3`` accept an external
``page`` and never touch their own context, so the bot is constructed but never
entered: no extra Chromium, no extra ``sync_playwright()``. The one exception is
``SolverBackend.VISION_AI``, whose YOLO solver replicates the widget in a
browser of its own; it therefore needs ``website_key``/``website_url``, which
are read from the live page (and the page's cookies are handed over so the
solver's browser shares the session).

Stealth
-------
Solving a reCAPTCHA while announcing ``navigator.webdriver`` and a synthetic
monitor header is self-defeating, so the solver applies
``playwright-stealth`` to the page before handing it to the audio/image/v3
backend. Set ``apply_stealth=False`` to opt out -- and prefer
:meth:`~arena_api.auth.browser.BrowserEnvironmentOptions.with_captcha_solving`,
which also drops the synthetic-monitor announcement so the two postures do not
contradict each other.

Dependencies stay optional: :mod:`arena_api._vendor.recaptcha_toolkit` is
imported lazily inside the methods that need it, so importing this module (and
therefore ``arena_api``) requires nothing beyond the standard library. The wait
solver needs no third-party package at all -- only the Playwright page it is
given.
"""

from __future__ import annotations

import asyncio
import inspect
import time
import sys
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    ClassVar,
    IO,
    Protocol,
    Sequence,
    runtime_checkable,
)

from ..exceptions import CaptchaSolveError
from .challenge import (
    SOLVABLE_CHALLENGE_KINDS,
    ChallengeKind,
    ChallengeObservation,
    inspect_page,
    inspect_page_sync,
)

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from arena_api._vendor.recaptcha_toolkit import (
        PlaywrightSolverOptions,
        RecaptchaVersion,
        SolverBackend,
        StealthOptions,
        VisionAIOptions,
    )

__all__ = [
    "SOLVABLE_CHALLENGE_KINDS",
    "TOOLKIT_PACKAGE",
    "WAITABLE_CHALLENGE_KINDS",
    "CaptchaAttempt",
    "CaptchaSolver",
    "ChallengeWaitSolver",
    "CompositeSolver",
    "RecaptchaToolkitSolver",
    "detect_recaptcha_version",
    "detect_recaptcha_version_sync",
    "describe_solver",
    "observation_targets_recaptcha",
    "solver_for",
]

#: Distribution that provides the toolkit's own dependencies. The toolkit code
#: itself is vendored, so only its backends ever need installing.
TOOLKIT_PACKAGE = "arena_api._vendor.recaptcha_toolkit"

#: Distinguish a visible v2 checkbox from an invisible/v3 widget.
#:
#: ``data-size="invisible"`` is the documented invisible flow; an ``anchor``
#: iframe with a non-empty box is the v2 checkbox; a zero-sized anchor iframe
#: or a bare ``grecaptcha`` object means the token is produced without a
#: visible challenge, which is what the v3 interception path expects.
_VERSION_DETECT_JS = """
() => {
  const nodes = Array.from(
    document.querySelectorAll(
      '.g-recaptcha, [data-sitekey], [data-recaptcha-widget-id], #recaptcha'
    )
  );
  for (const node of nodes) {
    const size = String(node.getAttribute('data-size') || '').toLowerCase();
    if (size === 'invisible') return 'v3';
  }
  const anchor = document.querySelector(
    "iframe[src*='recaptcha/api2/anchor'], iframe[src*='recaptcha/enterprise/anchor']"
  );
  if (anchor) {
    const box = anchor.getBoundingClientRect();
    return box.width > 1 && box.height > 1 ? 'v2' : 'v3';
  }
  if (typeof window.grecaptcha !== 'undefined') return 'v3';
  return 'v2';
}
"""


def _toolkit() -> Any:
    """Import the vendored toolkit lazily, with an actionable error."""
    try:
        from .._vendor import recaptcha_toolkit
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise CaptchaSolveError(
            "Solving reCAPTCHA needs the vendored toolkit's backends "
            f"({TOOLKIT_PACKAGE} failed to import: {exc}); install them with "
            "`pip install '.[auth-captcha]'` (add `.[vision]` for the local "
            "YOLO backend). Waiting a challenge out needs no extra install: "
            "see ChallengeWaitSolver."
        ) from exc
    return recaptcha_toolkit


def observation_targets_recaptcha(observation: ChallengeObservation) -> bool:
    """Whether an observation carries any reCAPTCHA evidence.

    :func:`~arena_api.auth.challenge.inspect_response` and
    :func:`~arena_api.auth.challenge.inspect_page` classify by priority, so a
    page that embeds a reCAPTCHA *inside* a Cloudflare interstitial is
    reported as ``TURNSTILE``/``CLOUDFLARE_MANAGED`` while still holding a
    reCAPTCHA signal. This helper exposes that distinction; whether it is
    worth acting on is up to :meth:`RecaptchaToolkitSolver.supports`.
    """
    if observation.kind in SOLVABLE_CHALLENGE_KINDS:
        return True
    return any(signal.kind in SOLVABLE_CHALLENGE_KINDS for signal in observation.signals)


@dataclass(frozen=True)
class CaptchaAttempt:
    """Outcome of one solve attempt.

    A failure is *returned*, not raised, so that a caller can retry, count
    attempts and report every reason in one message. :meth:`raise_for_status`
    turns a failed attempt into :class:`~arena_api.exceptions.CaptchaSolveError`
    when you would rather have the exception.
    """

    token: str | None = None
    backend: str = ""
    version: str = ""
    site_key: str | None = None
    attempts: int = 1
    duration: float = 0.0
    error: str | None = None
    stealth_applied: bool = False
    observation: ChallengeObservation | None = None

    #: ``True`` when the challenge disappeared without a token being produced --
    #: what :class:`ChallengeWaitSolver` reports after a Turnstile or a managed
    #: Cloudflare interstitial passes on its own.
    cleared: bool = False

    @property
    def ok(self) -> bool:
        """Whether the attempt achieved something: a token, or a cleared page."""
        return bool(self.token) or self.cleared

    def describe(self) -> str:
        """One-line summary suitable for a CI log."""
        label = f"{self.backend or 'solver'}/{self.version or '?'}"
        if self.cleared and not self.token:
            outcome = f"cleared after {self.attempts} check(s)"
        elif self.ok:
            outcome = "solved"
        else:
            outcome = f"failed ({self.error})"
        return f"{label} in {self.duration:.1f}s: {outcome}"

    def raise_for_status(self) -> str:
        """Return the token (``""`` when the page merely cleared), or raise.

        :raises CaptchaSolveError: when the attempt neither produced a token nor
            cleared the challenge. The hint depends on the backend: a token
            backend usually means missing dependencies, a wait usually means the
            page needs a person.
        """
        if self.ok:
            return str(self.token or "")
        hint = (
            "The challenge did not clear by itself. Open a headed browser "
            "(``headless=False``) and solve it there, raise ``timeout``, or "
            "set ``interactive=True`` so the wait can be extended."
            if self.backend == ChallengeWaitSolver.backend
            else "Check the solver backend, its dependencies (FFmpeg for the "
            "audio backend, CAPSOLVER_API_KEY for the image backend) and that "
            "the page really hosts a reCAPTCHA widget."
        )
        raise CaptchaSolveError(
            f"the challenge was not solved ({self.describe()}). {hint}"
        )


@runtime_checkable
class CaptchaSolver(Protocol):
    """Duck-typed solver accepted by :class:`~arena_api.auth.challenge.ChallengeHandler`.

    Implementations decide for themselves which observations they can act on;
    the handler consults :meth:`supports` before handing over a page.
    """

    def supports(self, observation: ChallengeObservation) -> bool:
        """Whether this solver can act on ``observation``."""
        ...

    async def asolve(
        self, page: Any, observation: ChallengeObservation | None = None
    ) -> CaptchaAttempt:
        """Solve the challenge on an already-open Playwright page (async)."""
        ...

    def solve(
        self, page: Any, observation: ChallengeObservation | None = None
    ) -> CaptchaAttempt:
        """Synchronous twin of :meth:`asolve`."""
        ...


@dataclass
class RecaptchaToolkitSolver:
    """Solve reCAPTCHA on an ``arena_api.auth`` page via the vendored toolkit.

    Parameters
    ----------
    backend:
        :class:`~arena_api._vendor.recaptcha_toolkit.SolverBackend` (or its value):
        ``"audio"`` (Google Speech, needs FFmpeg), ``"image"`` (CapSolver, needs
        ``CAPSOLVER_API_KEY``) or ``"vision_ai"`` (local YOLO, own browser).
    version:
        ``"v2"``/``"v3"`` to force a path; ``None`` (default) inspects the page
        and picks one -- a visible checkbox is v2, an invisible widget is
        handled by the v3 token interception.
    solver:
        :class:`~arena_api._vendor.recaptcha_toolkit.PlaywrightSolverOptions` (attempts,
        CapSolver key).
    vision_ai:
        :class:`~arena_api._vendor.recaptcha_toolkit.VisionAIOptions` for the YOLO backend. Give
        concurrent solvers distinct ``server_port``/``download_dir`` values.
    stealth:
        :class:`~arena_api._vendor.recaptcha_toolkit.StealthOptions` applied to the page before
        solving. ``None`` uses the toolkit defaults.
    apply_stealth:
        Set to ``False`` to solve without masking ``navigator.webdriver`` and
        friends (the audio backend then fails far more often).
    reload_for_v3:
        The v3 listener must be attached *before* the browser requests
        ``/recaptcha/api2/reload``; since the page is already loaded, it is
        reloaded after the listener is installed.
    solve_kinds:
        Challenge kinds this solver accepts. Defaults to reCAPTCHA only.
    allow_mixed_signals:
        Also accept observations whose *classification* is something else (e.g.
        a Cloudflare interstitial) but which contain a reCAPTCHA signal. Off by
        default: solving the widget will not clear a managed challenge.
    share_cookies_with_vision_ai:
        Hand the page's cookies to the YOLO solver's own browser so it works
        inside the same session.
    """

    backend: "SolverBackend | str" = "audio"
    version: "RecaptchaVersion | str | None" = None
    solver: "PlaywrightSolverOptions | None" = None
    vision_ai: "VisionAIOptions | None" = None
    stealth: "StealthOptions | None" = None
    apply_stealth: bool = True
    reload_for_v3: bool = True
    solve_kinds: tuple[ChallengeKind, ...] = tuple(SOLVABLE_CHALLENGE_KINDS)
    allow_mixed_signals: bool = False
    share_cookies_with_vision_ai: bool = True

    def __post_init__(self) -> None:
        if not self.solve_kinds:
            raise ValueError("solve_kinds must contain at least one ChallengeKind")
        unknown = [kind for kind in self.solve_kinds if not isinstance(kind, ChallengeKind)]
        if unknown:
            raise TypeError(f"solve_kinds must be ChallengeKind members, got {unknown!r}")

    # ------------------------------------------------------------------ #
    # Capability
    # ------------------------------------------------------------------ #

    def supports(self, observation: ChallengeObservation) -> bool:
        """Whether this solver will act on ``observation``."""
        if not observation.is_challenge:
            return False
        if observation.kind in self.solve_kinds:
            return True
        return self.allow_mixed_signals and observation_targets_recaptcha(observation)

    def describe(self) -> str:
        """Human-readable backend label for logs."""
        version = "auto" if self.version is None else str(getattr(self.version, "value", self.version))
        stealth = "stealth" if self.apply_stealth else "no-stealth"
        return f"recaptcha-toolkit[{self.backend}/{version}/{stealth}]"

    # ------------------------------------------------------------------ #
    # Async path
    # ------------------------------------------------------------------ #

    async def asolve(
        self, page: Any, observation: ChallengeObservation | None = None
    ) -> CaptchaAttempt:
        """Solve the reCAPTCHA on ``page`` and return the attempt.

        Failures are reported through :attr:`CaptchaAttempt.error` rather than
        raised, so a handler can retry and then explain every attempt.
        """
        toolkit = _toolkit()
        backend = toolkit.SolverBackend(self.backend)
        label = str(getattr(backend, "value", backend))
        started = time.perf_counter()
        version = await detect_recaptcha_version(page, toolkit=toolkit, override=self.version)
        stealth_applied = False
        # Only VisionAI learns the site key; the Playwright backends do not.
        token: str
        site_key: str | None
        try:
            stealth_applied = await self._apply_stealth_async(page, toolkit, backend)
            if backend is toolkit.SolverBackend.VISION_AI:
                token, site_key = await self._asolve_vision_ai(page, toolkit, version)
            else:
                token, site_key = await self._asolve_playwright(page, toolkit, backend, version)
        except Exception as exc:  # noqa: BLE001 - toolkit raises its own types
            return CaptchaAttempt(
                backend=label,
                version=str(getattr(version, "value", version)),
                duration=time.perf_counter() - started,
                error=f"{type(exc).__name__}: {exc}",
                stealth_applied=stealth_applied,
                observation=observation,
            )
        return CaptchaAttempt(
            token=token,
            backend=label,
            version=str(getattr(version, "value", version)),
            site_key=site_key,
            duration=time.perf_counter() - started,
            stealth_applied=stealth_applied,
            observation=observation,
        )

    async def _apply_stealth_async(self, page: Any, toolkit: Any, backend: Any) -> bool:
        """Patch the page with ``playwright-stealth`` before solving."""
        if not self.apply_stealth or backend is toolkit.SolverBackend.VISION_AI:
            # The YOLO solver replicates the widget in its own browser, so
            # patching this page would change nothing; its user agent is
            # forwarded from the stealth options instead.
            return False
        from .._vendor.recaptcha_toolkit.stealth import apply_stealth_async

        await apply_stealth_async(page, self.stealth)
        return True

    def _async_bot(self, toolkit: Any, backend: Any) -> Any:
        """Build an ``AsyncPlaywrightBot`` **without** launching its browser.

        The bot is only a facade here: its ``solve_recaptcha_v2/v3`` accept an
        external page and never touch ``bot.context``, so entering the context
        manager (which would start a second Chromium) is both unnecessary and
        wasteful. Stealth is disabled at bot level because this class applies
        it to the page itself.
        """
        return toolkit.AsyncPlaywrightBot(
            backend=backend,
            stealth=toolkit.StealthOptions(enabled=False),
            solver=self.solver,
            vision_ai=self.vision_ai,
        )

    async def _asolve_playwright(
        self, page: Any, toolkit: Any, backend: Any, version: Any
    ) -> tuple[str, None]:
        bot = self._async_bot(toolkit, backend)
        if version is toolkit.RecaptchaVersion.V3:
            token = await bot.solve_recaptcha_v3(page, reload=self.reload_for_v3)
        else:
            token = await bot.solve_recaptcha_v2(page)
        return str(token), None

    async def _asolve_vision_ai(
        self, page: Any, toolkit: Any, version: Any
    ) -> tuple[str, str]:
        site_key = await toolkit.playwright_bot.detect_site_key_async(page)
        url = str(getattr(page, "url", "") or "")
        if not url:
            raise toolkit.SiteKeyDetectionError(
                "SolverBackend.VISION_AI needs the page URL; the supplied page "
                "has none."
            )
        cookies = await _page_cookies_async(page) if self.share_cookies_with_vision_ai else None
        result = await toolkit.VisionAISolver(self.vision_ai).solve_async(
            website_key=site_key,
            website_url=url,
            is_invisible=version is toolkit.RecaptchaVersion.V3,
            cookies=cookies,
            user_agent=(self.stealth.navigator_user_agent if self.stealth else None),
        )
        return str(result.token), site_key

    # ------------------------------------------------------------------ #
    # Sync path
    # ------------------------------------------------------------------ #

    def solve(
        self, page: Any, observation: ChallengeObservation | None = None
    ) -> CaptchaAttempt:
        """Synchronous twin of :meth:`asolve` for ``playwright.sync_api`` pages."""
        toolkit = _toolkit()
        backend = toolkit.SolverBackend(self.backend)
        label = str(getattr(backend, "value", backend))
        started = time.perf_counter()
        version = detect_recaptcha_version_sync(page, toolkit=toolkit, override=self.version)
        stealth_applied = False
        # Only VisionAI learns the site key; the Playwright backends do not.
        token: str
        site_key: str | None
        try:
            stealth_applied = self._apply_stealth_sync(page, toolkit, backend)
            if backend is toolkit.SolverBackend.VISION_AI:
                token, site_key = self._solve_vision_ai(page, toolkit, version)
            else:
                token, site_key = self._solve_playwright(page, toolkit, backend, version)
        except Exception as exc:  # noqa: BLE001 - toolkit raises its own types
            return CaptchaAttempt(
                backend=label,
                version=str(getattr(version, "value", version)),
                duration=time.perf_counter() - started,
                error=f"{type(exc).__name__}: {exc}",
                stealth_applied=stealth_applied,
                observation=observation,
            )
        return CaptchaAttempt(
            token=token,
            backend=label,
            version=str(getattr(version, "value", version)),
            site_key=site_key,
            duration=time.perf_counter() - started,
            stealth_applied=stealth_applied,
            observation=observation,
        )

    def _apply_stealth_sync(self, page: Any, toolkit: Any, backend: Any) -> bool:
        if not self.apply_stealth or backend is toolkit.SolverBackend.VISION_AI:
            return False
        from .._vendor.recaptcha_toolkit.stealth import apply_stealth_sync

        apply_stealth_sync(page, self.stealth)
        return True

    def _sync_bot(self, toolkit: Any, backend: Any) -> Any:
        """Build a ``PlaywrightBot`` without launching its browser (see :meth:`_async_bot`)."""
        return toolkit.PlaywrightBot(
            backend=backend,
            stealth=toolkit.StealthOptions(enabled=False),
            solver=self.solver,
            vision_ai=self.vision_ai,
        )

    def _solve_playwright(
        self, page: Any, toolkit: Any, backend: Any, version: Any
    ) -> tuple[str, None]:
        bot = self._sync_bot(toolkit, backend)
        if version is toolkit.RecaptchaVersion.V3:
            token = bot.solve_recaptcha_v3(page, reload=self.reload_for_v3)
        else:
            token = bot.solve_recaptcha_v2(page)
        return str(token), None

    def _solve_vision_ai(self, page: Any, toolkit: Any, version: Any) -> tuple[str, str]:
        site_key = toolkit.playwright_bot.detect_site_key(page)
        url = str(getattr(page, "url", "") or "")
        if not url:
            raise toolkit.SiteKeyDetectionError(
                "SolverBackend.VISION_AI needs the page URL; the supplied page has none."
            )
        cookies = _page_cookies_sync(page) if self.share_cookies_with_vision_ai else None
        result = toolkit.VisionAISolver(self.vision_ai).solve_detailed(
            website_key=site_key,
            website_url=url,
            is_invisible=version is toolkit.RecaptchaVersion.V3,
            cookies=cookies,
            user_agent=(self.stealth.navigator_user_agent if self.stealth else None),
        )
        return str(result.token), site_key


# --------------------------------------------------------------------------- #
# Challenges that have no token to produce
# --------------------------------------------------------------------------- #


#: Kinds :class:`ChallengeWaitSolver` acts on: everything a reCAPTCHA token
#: cannot fix. Turnstile and a managed Cloudflare interstitial usually pass on
#: their own once a real browser sits on them for a few seconds; hCaptcha and
#: DataDome need a person, which a headed browser provides. ``RATE_LIMIT`` is
#: deliberately absent -- waiting on a 429 is a retry policy, not a solve.
WAITABLE_CHALLENGE_KINDS: tuple[ChallengeKind, ...] = (
    ChallengeKind.TURNSTILE,
    ChallengeKind.CLOUDFLARE_MANAGED,
    ChallengeKind.HCAPTCHA,
    ChallengeKind.DATADOME,
    ChallengeKind.INTERSTITIAL,
    ChallengeKind.UNKNOWN,
)

#: Announced before an interactive wait, so a headed run is not a silent stall.
CHALLENGE_WAIT_PROMPT = (
    "[arena-api] {kind} challenge at {url}: solve it in the browser window; "
    "waiting up to {timeout:g}s, checking every {poll:g}s"
)

#: Offered when an interactive wait runs out of time.
CHALLENGE_WAIT_MORE = (
    "[arena-api] the {kind} challenge is still up after {timeout:g}s. Finish it "
    "in the browser, then press Enter to keep waiting (Ctrl-C to give up)..."
)

#: Printed when that offer is declined.
CHALLENGE_WAIT_CANCELLED = "[arena-api] challenge wait cancelled"


@dataclass
class ChallengeWaitSolver:
    """Clear a challenge by waiting for it instead of producing a token.

    Half of the classified challenge kinds have no token this library could
    forge, and that is fine: a Cloudflare managed interstitial or a Turnstile
    widget typically passes by itself in a real browser within seconds, and an
    hCaptcha or DataDome box is something a *person* clears in a headed window.
    Both reduce to the same mechanism -- re-scan the page until it stops looking
    like a challenge -- so this solver implements it once:

    * headless: wait up to :attr:`timeout`, polling every :attr:`poll` seconds;
    * ``interactive=True``: announce what is on screen, wait, and when the time
      runs out offer another window in exchange for an Enter press (up to
      :attr:`rounds` windows). The prompt runs in a worker thread, so the event
      loop -- and therefore Playwright -- keeps running while you click.

    The result is a :class:`CaptchaAttempt` with ``cleared=True`` and no token:
    :class:`~arena_api.auth.challenge.ChallengeHandler` decides success from its
    own re-scan, so nothing downstream needs to know that no token existed.

    :ivar timeout: seconds to wait per round before giving up.
    :ivar poll: seconds between re-scans. Kept at 1s: a re-scan evaluates
        JavaScript on the page, so polling faster buys little.
    :ivar interactive: tell a human what to do and let them extend the wait.
    :ivar rounds: how many wait windows an interactive run may use.
    :ivar solve_kinds: kinds accepted; defaults to
        :data:`WAITABLE_CHALLENGE_KINDS`.
    :ivar prompt: called with the "keep waiting?" text (``input`` by default).
    :ivar output: stream for the announcements (``sys.stderr`` by default).
    :ivar recheck: custom ``page -> ChallengeObservation`` callable, sync or
        async. Tests use it; the default re-scans with
        :func:`~arena_api.auth.challenge.inspect_page` (no screenshot -- the
        handler captures its own diagnostics).
    """

    timeout: float = 30.0
    poll: float = 1.0
    interactive: bool = False
    rounds: int = 2
    solve_kinds: tuple[ChallengeKind, ...] = WAITABLE_CHALLENGE_KINDS
    prompt: Callable[[str], Any] = input
    output: IO[str] | None = None
    recheck: Callable[[Any], Any] | None = None

    #: Label used in :attr:`CaptchaAttempt.backend`.
    backend: ClassVar[str] = "wait"

    def __post_init__(self) -> None:
        if not self.solve_kinds:
            raise ValueError("solve_kinds must contain at least one ChallengeKind")
        unknown = [kind for kind in self.solve_kinds if not isinstance(kind, ChallengeKind)]
        if unknown:
            raise TypeError(f"solve_kinds must be ChallengeKind members, got {unknown!r}")
        if ChallengeKind.NONE in self.solve_kinds:
            raise ValueError("ChallengeKind.NONE is never a challenge; drop it from solve_kinds")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if self.poll <= 0:
            raise ValueError("poll must be positive")
        if self.rounds < 1:
            raise ValueError("rounds must be at least 1")

    # ------------------------------------------------------------------ #
    # Capability
    # ------------------------------------------------------------------ #

    def supports(self, observation: ChallengeObservation) -> bool:
        """Whether this solver will wait out ``observation``."""
        return observation.is_challenge and observation.kind in self.solve_kinds

    def describe(self) -> str:
        """Human-readable label for logs."""
        mode = "/interactive" if self.interactive else ""
        return (
            f"wait[{len(self.solve_kinds)} kinds/{self.timeout:g}s"
            f"/{self.poll:g}s poll{mode}]"
        )

    # ------------------------------------------------------------------ #
    # Async path
    # ------------------------------------------------------------------ #

    async def asolve(
        self, page: Any, observation: ChallengeObservation | None = None
    ) -> CaptchaAttempt:
        """Wait for the challenge on ``page`` to clear.

        :param page: an open Playwright page (``playwright.async_api``).
        :param observation: the challenge to wait out; ``None`` scans the page.
        :returns: an attempt with ``cleared=True`` on success, otherwise one
            carrying the reason in :attr:`CaptchaAttempt.error`.
        """
        started = time.monotonic()
        current = observation if observation is not None else await self._ascan(page)
        if not current.is_challenge:
            return self._attempt(current, started=started, checks=0, cleared=True)
        if self.interactive:
            self._announce(current)

        rounds = max(1, int(self.rounds))
        checks = 0
        for index in range(1, rounds + 1):
            cleared, used = await self._await_clearance(page)
            checks += used
            if cleared:
                return self._attempt(current, started=started, checks=checks, cleared=True)
            if not self.interactive or index >= rounds:
                break
            if not await self._offer_more_async(current):
                break
        return self._attempt(current, started=started, checks=checks, cleared=False)

    async def _await_clearance(self, page: Any) -> tuple[bool, int]:
        """Poll until the page stops looking like a challenge, or time runs out."""
        deadline = time.monotonic() + self.timeout
        checks = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False, checks
            await asyncio.sleep(min(self.poll, remaining))
            checks += 1
            observation = await self._ascan(page)
            if not observation.is_challenge:
                return True, checks

    async def _ascan(self, page: Any) -> ChallengeObservation:
        if self.recheck is not None:
            outcome = self.recheck(page)
            if inspect.isawaitable(outcome):
                outcome = await outcome
            return outcome
        return await inspect_page(page, screenshot=False)

    async def _offer_more_async(self, observation: ChallengeObservation) -> bool:
        """Ask for another window; ``False`` ends the wait.

        The prompt runs in a worker thread: blocking the event loop here would
        also block Playwright, and the page could not finish clearing.
        """
        try:
            await asyncio.to_thread(self.prompt, self._more_message(observation))
        except (EOFError, KeyboardInterrupt):
            self._note(CHALLENGE_WAIT_CANCELLED)
            return False
        return True

    # ------------------------------------------------------------------ #
    # Sync path
    # ------------------------------------------------------------------ #

    def solve(
        self, page: Any, observation: ChallengeObservation | None = None
    ) -> CaptchaAttempt:
        """Synchronous twin of :meth:`asolve` for ``playwright.sync_api`` pages."""
        started = time.monotonic()
        current = observation if observation is not None else self._scan_sync(page)
        if not current.is_challenge:
            return self._attempt(current, started=started, checks=0, cleared=True)
        if self.interactive:
            self._announce(current)

        rounds = max(1, int(self.rounds))
        checks = 0
        for index in range(1, rounds + 1):
            cleared, used = self._wait_sync(page)
            checks += used
            if cleared:
                return self._attempt(current, started=started, checks=checks, cleared=True)
            if not self.interactive or index >= rounds:
                break
            if not self._offer_more_sync(current):
                break
        return self._attempt(current, started=started, checks=checks, cleared=False)

    def _wait_sync(self, page: Any) -> tuple[bool, int]:
        deadline = time.monotonic() + self.timeout
        checks = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False, checks
            time.sleep(min(self.poll, remaining))
            checks += 1
            if not self._scan_sync(page).is_challenge:
                return True, checks

    def _scan_sync(self, page: Any) -> ChallengeObservation:
        if self.recheck is not None:
            outcome = self.recheck(page)
            if inspect.isawaitable(outcome):
                raise CaptchaSolveError(
                    "ChallengeWaitSolver.solve() cannot await an async recheck; "
                    "pass a synchronous callable or use asolve()"
                )
            return outcome
        return inspect_page_sync(page, screenshot=False)

    def _offer_more_sync(self, observation: ChallengeObservation) -> bool:
        try:
            self.prompt(self._more_message(observation))
        except (EOFError, KeyboardInterrupt):
            self._note(CHALLENGE_WAIT_CANCELLED)
            return False
        return True

    # ------------------------------------------------------------------ #
    # Reporting
    # ------------------------------------------------------------------ #

    def _attempt(
        self,
        observation: ChallengeObservation,
        *,
        started: float,
        checks: int,
        cleared: bool,
    ) -> CaptchaAttempt:
        duration = time.monotonic() - started
        error = (
            None
            if cleared
            else (
                f"{observation.kind.value} challenge still present after "
                f"{duration:.1f}s and {checks} check(s)"
            )
        )
        return CaptchaAttempt(
            backend=self.backend,
            version=observation.kind.value,
            attempts=max(checks, 1),
            duration=duration,
            error=error,
            cleared=cleared,
            observation=observation,
        )

    def _announce(self, observation: ChallengeObservation) -> None:
        self._note(
            CHALLENGE_WAIT_PROMPT.format(
                kind=observation.kind.value,
                url=observation.url,
                timeout=self.timeout,
                poll=self.poll,
            )
        )

    def _more_message(self, observation: ChallengeObservation) -> str:
        return CHALLENGE_WAIT_MORE.format(
            kind=observation.kind.value, timeout=self.timeout
        )

    def _note(self, message: str) -> None:
        stream = self.output if self.output is not None else sys.stderr
        print(message, file=stream, flush=True)


def _solver_supports(solver: Any, observation: ChallengeObservation) -> bool:
    """``solver.supports(observation)``, with the token-kind default as a fallback."""
    supports = getattr(solver, "supports", None)
    if callable(supports):
        return bool(supports(observation))
    return observation.kind in SOLVABLE_CHALLENGE_KINDS


def solver_for(
    solvers: Sequence[Any], observation: ChallengeObservation
) -> Any | None:
    """The first solver that accepts ``observation``, or ``None``."""
    for solver in solvers:
        if _solver_supports(solver, observation):
            return solver
    return None


def describe_solver(solver: Any) -> str:
    """``solver.describe()`` when it has one, else its class name.

    Solvers are duck-typed (:class:`CaptchaSolver`), so reporting must not
    assume a ``describe`` method exists.
    """
    describe = getattr(solver, "describe", None)
    return str(describe()) if callable(describe) else type(solver).__name__


class CompositeSolver:
    """Route each challenge kind to whichever solver can actually handle it.

    ``CompositeSolver(RecaptchaToolkitSolver(), ChallengeWaitSolver())`` covers
    the whole classified surface: reCAPTCHA gets a token from the vendored
    toolkit, and Turnstile, a managed Cloudflare interstitial, hCaptcha,
    DataDome and anything unrecognised get waited out (or handed to a person in
    a headed browser). Order matters -- the first solver whose
    :meth:`~CaptchaSolver.supports` accepts the observation wins -- so put the
    more specific one first.

    A composite is itself a :class:`CaptchaSolver`, so it can be handed to
    :meth:`~arena_api.auth.browser.BrowserEnvironmentOptions.with_captcha_solving`,
    to :class:`~arena_api.auth.challenge.ChallengeHandler`, or to
    :data:`~arena_api.auto.AutoOptions` as ``captcha_solver=``.
    """

    #: Label used in :attr:`CaptchaAttempt.backend` when nobody accepts.
    backend: ClassVar[str] = "composite"

    def __init__(self, *solvers: Any) -> None:
        if not solvers:
            raise ValueError("CompositeSolver needs at least one solver")
        self.solvers: tuple[Any, ...] = tuple(solvers)

    def supports(self, observation: ChallengeObservation) -> bool:
        """Whether any member solver accepts ``observation``."""
        return self.select(observation) is not None

    def select(self, observation: ChallengeObservation) -> Any | None:
        """The member that will handle ``observation`` (public for reporting)."""
        return solver_for(self.solvers, observation)

    async def asolve(
        self, page: Any, observation: ChallengeObservation | None = None
    ) -> CaptchaAttempt:
        """Hand the page to the first solver that accepts it."""
        current = (
            observation
            if observation is not None
            else await inspect_page(page, screenshot=False)
        )
        solver = self.select(current)
        if solver is None:
            return self._unsupported(current)
        return await solver.asolve(page, current)

    def solve(
        self, page: Any, observation: ChallengeObservation | None = None
    ) -> CaptchaAttempt:
        """Synchronous twin of :meth:`asolve` for ``playwright.sync_api`` pages."""
        current = (
            observation
            if observation is not None
            else inspect_page_sync(page, screenshot=False)
        )
        solver = self.select(current)
        if solver is None:
            return self._unsupported(current)
        return solver.solve(page, current)

    def describe(self) -> str:
        """Every member's label, in dispatch order."""
        return "composite[" + ", ".join(describe_solver(item) for item in self.solvers) + "]"

    def _unsupported(self, observation: ChallengeObservation) -> CaptchaAttempt:
        return CaptchaAttempt(
            backend=self.backend,
            version=observation.kind.value,
            error=(
                f"no solver accepts a {observation.kind.value} challenge "
                f"({self.describe()})"
            ),
            observation=observation,
        )


# --------------------------------------------------------------------------- #
# Version detection
# --------------------------------------------------------------------------- #


def _normalize_version(raw: Any, toolkit: Any, override: Any) -> Any:
    if override is not None:
        return toolkit.RecaptchaVersion(override)
    text = str(raw or "").strip().lower()
    if text in {"v3", "invisible"}:
        return toolkit.RecaptchaVersion.V3
    return toolkit.RecaptchaVersion.V2


async def detect_recaptcha_version(page: Any, *, toolkit: Any = None, override: Any = None) -> Any:
    """Guess whether ``page`` hosts a v2 checkbox or an invisible/v3 widget.

    The heuristic is intentionally conservative: anything it cannot classify is
    treated as v2, because the v2 solver waits for a visible widget and reports
    a clear :class:`~arena_api._vendor.recaptcha_toolkit.RecaptchaNotFoundError` instead of
    silently intercepting nothing.
    """
    toolkit = toolkit or _toolkit()
    if override is not None:
        return _normalize_version(None, toolkit, override)
    try:
        raw = await page.evaluate(_VERSION_DETECT_JS)
    except Exception:  # noqa: BLE001 - closed page, CSP, non-JS context
        raw = None
    return _normalize_version(raw, toolkit, None)


def detect_recaptcha_version_sync(page: Any, *, toolkit: Any = None, override: Any = None) -> Any:
    """Synchronous twin of :func:`detect_recaptcha_version`."""
    toolkit = toolkit or _toolkit()
    if override is not None:
        return _normalize_version(None, toolkit, override)
    try:
        raw = page.evaluate(_VERSION_DETECT_JS)
    except Exception:  # noqa: BLE001
        raw = None
    return _normalize_version(raw, toolkit, None)


async def _page_cookies_async(page: Any) -> list[dict[str, Any]] | None:
    """Read the page context's cookies for the YOLO solver's own browser."""
    context = getattr(page, "context", None)
    if context is None:
        return None
    try:
        cookies = await context.cookies()
    except Exception:  # noqa: BLE001 - context may already be closed
        return None
    return [dict(cookie) for cookie in cookies or []] or None


def _page_cookies_sync(page: Any) -> list[dict[str, Any]] | None:
    context = getattr(page, "context", None)
    if context is None:
        return None
    try:
        cookies = context.cookies()
    except Exception:  # noqa: BLE001
        return None
    return [dict(cookie) for cookie in cookies or []] or None

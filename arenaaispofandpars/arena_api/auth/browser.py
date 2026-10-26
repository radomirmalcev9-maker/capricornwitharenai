"""Async Playwright wrapper with reproducible, CI-ready browser contexts.

This is the browser half of the ``arena_api.auth`` package. It owns three
things and nothing else:

1. **Context normalisation** -- locale, timezone, viewport, colour scheme and
   reduced-motion are Playwright's own supported knobs, and they are the
   correct way to make a headless run match a reference run. Setting them here
   means every test in a suite shares one configuration instead of each test
   inventing its own.
2. **Determinism injection** -- the init script from
   :mod:`arena_api.auth.environment` is installed on every page.
3. **Artefact capture** -- traces, HARs and screenshots land in one directory
   so a CI failure is diagnosable after the runner is gone.

It does **not** install stealth/fingerprint patches. See
:mod:`arena_api.auth.environment` for the reasoning; the short version is that
a synthetic monitor should be identifiable, not camouflaged. The one opt-in
exception is challenge *solving*: ``BrowserEnvironmentOptions.solve_challenges``
plus a ``captcha_solver`` installs a
:class:`~arena_api.auth.challenge.ChallengeHandler` on every page, and
:meth:`BrowserEnvironmentOptions.with_captcha_solving` additionally drops the
synthetic-monitor announcement, since masking automation while announcing it
would be self-contradictory.

Playwright is imported lazily, so importing this module never requires the
package (or a downloaded browser binary) to be present.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version as _distribution_version
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import unquote, urlparse, urlunparse

from .challenge import ChallengeHandler, ChallengeObservation
from .environment import DeterminismOptions, build_init_script
from .kinematics import KinematicMouse, TrajectoryPlanner

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from .captcha import CaptchaSolver

__all__ = [
    "BrowserEnvironment",
    "BrowserEnvironmentOptions",
    "SYNTHETIC_MONITOR_HEADER",
]

#: Header attached when :attr:`BrowserEnvironmentOptions.identify_automation`
#: is enabled, so the site under test can recognise and allowlist the monitor.
SYNTHETIC_MONITOR_HEADER = "X-Synthetic-Monitor"


def _library_version() -> str:
    try:
        return _distribution_version("arena-api")
    except PackageNotFoundError:
        return "0.0.0"


@dataclass
class BrowserEnvironmentOptions:
    """Configuration for :class:`BrowserEnvironment`.

    Defaults are chosen for headless CI: a fixed 1440x900 viewport, UTC,
    reduced motion, deterministic animations, and artefacts on disk.
    """

    headless: bool = True

    #: Chromium channel, e.g. ``"chromium"`` or ``"chrome"``. ``None`` uses
    #: Playwright's bundled build.
    channel: str | None = None

    #: Outbound proxy URL (``http://``, ``https://`` or ``socks5://``) passed to
    #: Playwright's ``browser_type.launch(proxy=...)``.
    proxy: str | None = None

    #: Sets ``navigator.language`` and ``navigator.languages``; ``None`` keeps the host locale.
    locale: str | None = "en-US"

    #: Sets the ``Intl``/``Date`` timezone; ``None`` keeps the host timezone.
    timezone_id: str | None = "UTC"

    #: Viewport in CSS pixels; ``None`` uses the window size.
    viewport: dict[str, int] | None = field(
        default_factory=lambda: {"width": 1440, "height": 900}
    )

    device_scale_factor: float = 1.0

    #: ``None`` keeps Playwright's default UA for the browser build.
    user_agent: str | None = None

    reduced_motion: Literal["reduce", "no-preference", "null"] = "reduce"
    color_scheme: Literal["light", "dark", "no-preference", "null"] = "light"

    #: Emulates ``prefers-reduced-transparency`` / contrast where supported.
    forced_colors: Literal["active", "none", "null"] = "none"

    java_script_enabled: bool = True
    ignore_default_args: tuple[str, ...] = ()
    extra_http_headers: dict[str, str] = field(default_factory=dict)

    #: Maps to Playwright's ``chromium_sandbox``. Disabling it is required in
    #: some container images but weakens the browser sandbox, so it is opt-in.
    no_sandbox: bool = False

    #: Extra Chromium switches; ``--disable-dev-shm-usage`` is added
    #: automatically when ``container_safe`` is set.
    launch_args: tuple[str, ...] = ()
    container_safe: bool = True

    slow_mo: int = 0
    default_timeout: float = 30_000.0
    navigation_timeout: float = 30_000.0

    #: Determinism script options; ``None`` installs the defaults.
    determinism: DeterminismOptions | None = None

    #: Set to ``False`` to skip the init script entirely.
    install_determinism_script: bool = True

    #: Extra ``page.add_init_script`` payloads, installed before any navigation
    #: on every page :meth:`BrowserEnvironment.new_page` returns. The one the
    #: library itself uses is
    #: :data:`~arena_api.auth.environment.HIDE_WEBDRIVER_SCRIPT`, and only in
    #: the sign-in window (see ``hide_automation`` there): reproducibility is
    #: this package's goal, concealment is not.
    extra_init_scripts: tuple[str, ...] = ()

    #: Announce the run as synthetic (header + ``window.__arenaSynthetic``).
    identify_automation: bool = True

    #: Path to a Playwright ``storage_state`` JSON used to seed cookies.
    storage_state: str | Path | None = None

    #: Optional persistent Chromium profile directory. When set,
    #: :class:`BrowserEnvironment` uses ``launch_persistent_context`` so trust
    #: cookies (``_GRECAPTCHA``, ``cf_clearance``) and ``localStorage`` survive
    #: across runs.
    user_data_dir: str | Path | None = None

    #: Directory for traces, HARs and screenshots. ``None`` disables capture.
    artifacts_dir: str | Path | None = None

    record_har: bool = False
    record_trace: bool = False
    screenshot_on_close: bool = False

    #: Resource types dropped before they hit the network (speed, not stealth:
    #: skipping media and fonts removes a large source of timing flake).
    block_resource_types: tuple[str, ...] = ()

    #: Trajectory planner handed to :meth:`BrowserEnvironment.mouse`.
    planner: TrajectoryPlanner | None = None

    #: Opt-in challenge solver (see :mod:`arena_api.auth.captcha`). ``None``
    #: keeps every page observational, which is the default posture.
    captcha_solver: "CaptchaSolver | None" = None

    #: Install a solving :class:`~arena_api.auth.challenge.ChallengeHandler` on
    #: every page created by :meth:`BrowserEnvironment.new_page`. Requires
    #: ``captcha_solver``.
    solve_challenges: bool = False

    #: Use this handler instead of building one from the options above. Its
    #: ``captcha_solver`` is filled in from ``captcha_solver`` when unset.
    challenge_handler: ChallengeHandler | None = None

    @classmethod
    def with_captcha_solving(
        cls,
        captcha_solver: Any,
        *,
        identify_automation: bool = False,
        **overrides: Any,
    ) -> "BrowserEnvironmentOptions":
        """Options preconfigured to solve challenges rather than only report them.

        Masking ``navigator.webdriver`` while announcing the run through
        ``X-Synthetic-Monitor`` and ``window.__arenaSynthetic`` defeats both, so
        the announcements are dropped by default here. Pass
        ``identify_automation=True`` to keep them (for example on a staging host
        that allowlists the monitor by header).

        :param captcha_solver: e.g.
            :class:`~arena_api.auth.captcha.RecaptchaToolkitSolver`.
        :param identify_automation: keep the synthetic-monitor announcements.
        :param overrides: any other :class:`BrowserEnvironmentOptions` field.
        """
        determinism = overrides.pop("determinism", None) or DeterminismOptions()
        if not identify_automation:
            determinism = replace(determinism, identify_automation=False)
        return cls(
            captcha_solver=captcha_solver,
            solve_challenges=True,
            identify_automation=identify_automation,
            determinism=determinism,
            **overrides,
        )

    def context_kwargs(self) -> dict[str, Any]:
        """Render the Playwright ``new_context`` keyword arguments."""
        kwargs: dict[str, Any] = {
            "device_scale_factor": self.device_scale_factor,
            "reduced_motion": self.reduced_motion,
            "color_scheme": self.color_scheme,
            "java_script_enabled": self.java_script_enabled,
        }
        if self.locale is not None:
            kwargs["locale"] = self.locale
        if self.timezone_id is not None:
            kwargs["timezone_id"] = self.timezone_id
        if self.viewport is not None:
            kwargs["viewport"] = dict(self.viewport)
            kwargs["no_viewport"] = False
        else:
            kwargs["no_viewport"] = True
        if self.user_agent:
            kwargs["user_agent"] = self.user_agent
        if self.forced_colors != "none":
            kwargs["forced_colors"] = self.forced_colors
        if self.storage_state:
            kwargs["storage_state"] = str(self.storage_state)
        headers = dict(self.extra_http_headers)
        if self.identify_automation:
            headers.setdefault(
                SYNTHETIC_MONITOR_HEADER, f"arena-api/{_library_version()}"
            )
        if headers:
            kwargs["extra_http_headers"] = headers
        return kwargs

    def launch_kwargs(self) -> dict[str, Any]:
        """Render the Playwright ``launch`` keyword arguments."""
        args: list[str] = list(self.launch_args)
        if self.container_safe:
            args.append("--disable-dev-shm-usage")
        kwargs: dict[str, Any] = {
            "headless": self.headless,
            "slow_mo": self.slow_mo,
            "args": args,
            # Playwright's own switch, rather than a raw --no-sandbox flag.
            "chromium_sandbox": not self.no_sandbox,
        }
        if self.channel:
            kwargs["channel"] = self.channel
        if self.proxy:
            kwargs["proxy"] = _playwright_proxy_settings(self.proxy)
        if self.ignore_default_args:
            kwargs["ignore_default_args"] = list(self.ignore_default_args)
        return kwargs

    def persistent_context_kwargs(self) -> dict[str, Any]:
        """Render the Playwright ``launch_persistent_context`` keyword arguments."""
        kwargs = self.launch_kwargs()
        ctx_kwargs = self.context_kwargs()
        ctx_kwargs.pop("storage_state", None)
        kwargs.update(ctx_kwargs)
        return kwargs


def _is_profile_in_use_error(exc: BaseException) -> bool:
    message = str(exc).lower()
    return any(
        marker in message
        for marker in (
            "processsingleton",
            "singletonlock",
            "already in use",
            "in use by another",
            "profile appears to be in use",
        )
    )


def _playwright_proxy_settings(proxy_url: str) -> dict[str, str]:
    """Convert a URL string into Playwright's ``ProxySettings`` dictionary.

    Chromium resolves hostnames remotely over ``socks5://`` automatically and
    rejects libcurl's ``socks5h://`` scheme, so ``socks5h`` is normalised to
    ``socks5`` here while any embedded credentials are split out.
    """
    raw = proxy_url.strip()
    if "://" not in raw:
        raw = f"http://{raw}"
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    if scheme in ("socks5h", "socks4", "socks4a", "socks"):
        scheme = "socks5"
    host = parsed.hostname or ""
    if scheme not in ("http", "https", "socks5") or not host:
        raise ValueError(f"Unsupported browser proxy URL: {proxy_url!r}")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    settings: dict[str, str] = {
        "server": urlunparse((scheme, netloc, "", "", "", ""))
    }
    if parsed.username is not None:
        settings["username"] = unquote(parsed.username)
    if parsed.password is not None:
        settings["password"] = unquote(parsed.password)
    return settings


class BrowserEnvironment:
    """Owns a Playwright browser and hands out normalised pages.

    Usable as an async context manager::

        async with BrowserEnvironment() as env:
            page = await env.new_page()
            await page.goto("https://example.com")

    Or manually with :meth:`start` / :meth:`close`.
    """

    def __init__(
        self,
        options: BrowserEnvironmentOptions | None = None,
        *,
        artifacts_dir: str | Path | None = None,
    ) -> None:
        self.options = options or BrowserEnvironmentOptions()
        if artifacts_dir is not None:
            self.options.artifacts_dir = artifacts_dir
        if self.options.artifacts_dir is not None:
            self.options.artifacts_dir = Path(self.options.artifacts_dir)
        self._playwright: Any = None
        self._browser: Any = None
        self._persistent_context: Any = None
        self._claimed_initial_page: bool = False
        self._contexts: list[Any] = []
        self._started = False
        self._challenge_handler: ChallengeHandler | None = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    @property
    def started(self) -> bool:
        """Whether :meth:`start` has completed successfully."""
        return self._started

    @property
    def browser(self) -> Any:
        """The underlying Playwright ``Browser``."""
        if self._browser is None:
            raise RuntimeError("BrowserEnvironment is not started; call start() first")
        return self._browser

    @property
    def artifacts_dir(self) -> Path | None:
        """Directory that captured artefacts are written to."""
        directory = self.options.artifacts_dir
        return Path(directory) if directory is not None else None

    @property
    def challenge_handler(self) -> ChallengeHandler | None:
        """Handler installed on new pages, or ``None`` when solving is off.

        Built once, from ``options.challenge_handler`` when supplied, so every
        page of a run shares one observation and attempt history. Diagnostics
        land in ``artifacts_dir/challenges``.
        """
        if self._challenge_handler is not None:
            return self._challenge_handler
        if not self.options.solve_challenges or self.options.captcha_solver is None:
            return None
        handler = self.options.challenge_handler
        if handler is None:
            capture_dir = (
                self.artifacts_dir / "challenges" if self.artifacts_dir else None
            )
            handler = ChallengeHandler(
                capture_dir=capture_dir,
                # A listener runs inside a background task, where raising would
                # be swallowed; solve_challenge() raises explicitly instead.
                raise_on_detection=False,
            )
        if handler.captcha_solver is None:
            handler.captcha_solver = self.options.captcha_solver
        handler.solve_on_detection = True
        self._challenge_handler = handler
        return handler

    async def start(self) -> "BrowserEnvironment":
        """Launch Playwright and the browser."""
        if self._started:
            return self
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        try:
            if self.options.user_data_dir is not None:
                profile_dir = Path(self.options.user_data_dir).expanduser()
                profile_dir.mkdir(parents=True, exist_ok=True)
                p_kwargs = self.options.persistent_context_kwargs()
                if self.options.record_har:
                    p_kwargs["record_har_path"] = str(
                        self._artifact_path("network.har")
                    )
                    p_kwargs.setdefault("record_har_content", "omit")
                try:
                    self._persistent_context = (
                        await self._playwright.chromium.launch_persistent_context(
                            str(profile_dir), **p_kwargs
                        )
                    )
                except Exception as exc:
                    if _is_profile_in_use_error(exc):
                        self._browser = await self._playwright.chromium.launch(
                            **self.options.launch_kwargs()
                        )
                    else:
                        raise
            else:
                self._browser = await self._playwright.chromium.launch(
                    **self.options.launch_kwargs()
                )
        except Exception:
            try:
                await self._playwright.stop()
            except Exception:
                pass
            self._playwright = None
            raise
        self._started = True
        return self

    async def close(self) -> None:
        """Close every context, then the browser and Playwright."""
        if not self._started:
            return
        if (
            self._persistent_context is not None
            and self._persistent_context not in self._contexts
        ):
            self._contexts.append(self._persistent_context)
        for context in list(self._contexts):
            await self._safe_close_context(context)
        self._contexts.clear()
        self._persistent_context = None
        self._claimed_initial_page = False
        if self._browser is not None:
            try:
                await self._browser.close()
            except Exception:
                pass
            self._browser = None
        if self._playwright is not None:
            try:
                await self._playwright.stop()
            except Exception:
                pass
            self._playwright = None
        self._started = False

    async def __aenter__(self) -> "BrowserEnvironment":
        await self.start()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        await self.close()

    async def _safe_close_context(self, context: Any) -> None:
        try:
            if self.options.record_trace:
                await context.tracing.stop(path=str(self._artifact_path("trace.zip")))
        except Exception:
            pass
        try:
            if self.options.screenshot_on_close:
                for index, page in enumerate(context.pages):
                    await self.screenshot(page, name=f"close-page-{index}.png")
        except Exception:
            pass
        try:
            await context.close()
        except Exception:
            pass

    def _artifact_path(self, name: str) -> Path:
        directory = self.artifacts_dir
        if directory is None:
            raise RuntimeError(
                "artifacts_dir is not configured; set BrowserEnvironmentOptions."
                "artifacts_dir to capture traces, HARs or screenshots"
            )
        directory.mkdir(parents=True, exist_ok=True)
        return directory / name

    # ------------------------------------------------------------------ #
    # Contexts and pages
    # ------------------------------------------------------------------ #

    async def new_context(self, **overrides: Any) -> Any:
        """Create a browser context with the configured normalisation."""
        if not self._started:
            await self.start()
        if self._persistent_context is not None and not overrides:
            context = self._persistent_context
            if context not in self._contexts:
                context.set_default_timeout(self.options.default_timeout)
                context.set_default_navigation_timeout(
                    self.options.navigation_timeout
                )
                if self.options.record_trace:
                    await context.tracing.start(
                        screenshots=True, snapshots=True, sources=True
                    )
                self._contexts.append(context)
            return context
        kwargs = self.options.context_kwargs()
        kwargs.update(overrides)
        if self.options.record_har:
            kwargs["record_har_path"] = str(self._artifact_path("network.har"))
            kwargs.setdefault("record_har_content", "omit")
        context = await self.browser.new_context(**kwargs)
        context.set_default_timeout(self.options.default_timeout)
        context.set_default_navigation_timeout(self.options.navigation_timeout)
        if self.options.record_trace:
            await context.tracing.start(
                screenshots=True, snapshots=True, sources=True
            )
        self._contexts.append(context)
        return context

    async def new_page(self, context: Any | None = None, **overrides: Any) -> Any:
        """Create a page with the determinism init script installed.

        A new context is created when ``context`` is not supplied.
        """
        if context is None:
            context = await self.new_context(**overrides)
        existing_pages = (
            getattr(context, "pages", None)
            if context is self._persistent_context and not self._claimed_initial_page
            else None
        )
        if existing_pages:
            self._claimed_initial_page = True
            page = existing_pages[0]
        else:
            page = await context.new_page()
        if self.options.install_determinism_script:
            script = build_init_script(
                self.options.determinism or DeterminismOptions()
            )
            await page.add_init_script(script=script)
        for script in self.options.extra_init_scripts:
            await page.add_init_script(script=script)
        if self.options.block_resource_types:
            blocked = set(self.options.block_resource_types)

            async def _route_handler(route: Any, request: Any) -> None:
                if request.resource_type in blocked:
                    await route.abort()
                else:
                    await route.continue_()

            await page.route("**/*", _route_handler)
        handler = self.challenge_handler
        if handler is not None:
            await handler.install(page)
        return page

    async def solve_challenge(
        self, page: Any, *, url: str | None = None, raise_on_failure: bool = True
    ) -> ChallengeObservation:
        """Solve a challenge on ``page`` explicitly and return the re-scan.

        :meth:`new_page` already solves challenges as they appear when
        ``solve_challenges`` is on; this is the imperative form for a known
        point in a flow (after a navigation, before an assertion).

        :param page: an open Playwright page.
        :param url: URL to report in the observation (defaults to ``page.url``).
        :param raise_on_failure: raise
            :class:`~arena_api.exceptions.CaptchaSolveError` when the challenge
            survives every attempt.
        :returns: the post-solve :class:`ChallengeObservation`.
        """
        handler = self.challenge_handler
        if handler is None:
            raise ValueError(
                "challenge solving is not configured; set "
                "BrowserEnvironmentOptions.solve_challenges and captcha_solver "
                "(or use BrowserEnvironmentOptions.with_captcha_solving)"
            )
        observation = await handler.solve_page(page, url=url)
        if observation.is_challenge and raise_on_failure:
            handler.raise_for(observation, attempts=handler.solve_attempts)
        return observation

    def mouse(self, page: Any, **kwargs: Any) -> KinematicMouse:
        """Return a :class:`KinematicMouse` bound to ``page``."""
        planner = self.options.planner or TrajectoryPlanner()
        return KinematicMouse(page, planner, **kwargs)

    # ------------------------------------------------------------------ #
    # Artefacts and state
    # ------------------------------------------------------------------ #

    async def screenshot(self, page: Any, name: str = "screenshot.png", **kwargs: Any) -> Path:
        """Save a screenshot into the artefacts directory.

        ``animations="disabled"`` and ``caret="hide"`` are Playwright's own
        supported stabilisers and are applied by default, on top of the
        init-script CSS (which also stabilises ``bounding_box()`` timings and
        non-screenshot assertions).
        """
        path = self._artifact_path(name)
        options: dict[str, Any] = {"animations": "disabled", "caret": "hide"}
        options.update(kwargs)
        options.setdefault("full_page", True)
        await page.screenshot(path=str(path), **options)
        return path

    async def save_storage_state(self, context: Any, name: str = "state.json") -> Path:
        """Persist cookies and ``localStorage`` to ``artifacts_dir/name``."""
        path = self._artifact_path(name)
        await context.storage_state(path=str(path))
        return path

    @staticmethod
    def stamp() -> str:
        """UTC timestamp usable as a unique artefact prefix."""
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")


def run_sync(coroutine: Any) -> Any:
    """Run ``coroutine`` from synchronous code.

    Uses ``asyncio.run`` on a thread with no loop, and a dedicated thread with
    a fresh loop when one is already running (so this is safe to call from
    inside an async client that needs a blocking session refresh).
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)

    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coroutine).result()

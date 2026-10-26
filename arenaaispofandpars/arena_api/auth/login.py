"""Sign in once by hand, then let every later run reuse the session.

``arena_api`` can lift cookies out of the browser profile you already use, but
three cases still need a first sign-in: a fresh account, a machine (or
container) without your profile, and a session the site invalidated. This
module covers them with the least machinery possible: it opens a **headed**
Chromium window, you log in the way you always do -- password manager, 2FA app,
"remember this device" -- and the resulting Playwright ``storage_state`` is
written to disk::

    from arena_api.auth import login_and_save

    result = login_and_save()          # ./state/cookies.json
    print(result.describe())

Every later run finds that file on its own (``arena_api.auto_client()`` checks
``storage_path`` and then ``./state/cookies.json``), so the one manual step
stays exactly one.

Two properties matter here and are deliberate:

* **No credentials pass through this library.** Nothing is typed into a form by
  default and nothing is logged; the cookies are whatever your own browser
  ended up with. If you *do* want a form filled in, pass a
  :class:`~arena_api.auth.session.LoginFlow` -- the same object the session
  refresh ladder uses.
* **The saved file is a credential.** It is written with mode ``0600`` (POSIX),
  ``state/`` and ``cookies.json`` are git-ignored, and an anonymous state never
  overwrites a good one: when the sign-in is not detected, the existing file is
  left untouched and :attr:`LoginResult.saved` stays ``False``.

Detecting "signed in" without knowing the site's cookie names is done by
comparison: the cookies present right after the page loads are remembered, and
a round is accepted as soon as new (or changed) cookies appear for the site's
domains. That is a heuristic, so the bootstrap layer
(:func:`arena_api.auto.interactive_login`) follows it with a real ``/config``
probe -- the server has the final say.

Playwright is imported lazily by :class:`~arena_api.auth.browser.
BrowserEnvironment`, so importing this module stays free of heavy
dependencies.
"""

from __future__ import annotations

import inspect
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, IO, Mapping, Sequence
from urllib.parse import urlparse

from ..constants import DEFAULT_BASE_URL
from .browser import BrowserEnvironment, BrowserEnvironmentOptions, run_sync
from .environment import HIDE_WEBDRIVER_SCRIPT

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from .captcha import CaptchaSolver
    from .session import LoginFlow

__all__ = [
    "DEFAULT_STATE_PATH",
    "STATE_FILE_MODE",
    "LoginResult",
    "alogin_and_save",
    "login_and_save",
    "login_environment_options",
]

#: Where a manual sign-in is stored by default. ``arena_api.auto`` looks here
#: when no explicit ``storage_path`` is configured, which is what makes the
#: "log in once" promise work across runs.
DEFAULT_STATE_PATH = Path("state") / "cookies.json"

#: A state file contains live credentials, so it is owner-only on POSIX.
STATE_FILE_MODE = 0o600

#: Printed before the first wait. ``input`` renders the prompt itself.
SIGN_IN_PROMPT = (
    "Sign in to {site} in the browser window that just opened, then press "
    "Enter here to save the session..."
)

#: Printed when a round produced no new cookies.
NO_SESSION_YET = (
    "[arena-api] no session cookie for {site} yet (round {round}/{rounds}): "
    "finish signing in, then press Enter again"
)

#: Printed when the caller gave up (Ctrl-C / closed stdin).
WAIT_CANCELLED = "[arena-api] login wait cancelled; no state file will be written"

#: Playwright's own automation switches, dropped when ``hide_automation`` is on:
#: ``--enable-automation`` also raises Chromium's "controlled by automated
#: software" infobar, which is a loud hint for any sign-in page that looks for
#: one. Passed as ``ignore_default_args``, not as an argument of our own.
AUTOMATION_DEFAULT_ARGS_TO_DROP = ("--enable-automation",)

#: Chrome/Chromium switch that stops the browser from reporting
#: ``navigator.webdriver`` at all (the Blink feature is called
#: ``AutomationControlled``). The init-script mask in
#: :data:`~arena_api.auth.environment.HIDE_WEBDRIVER_SCRIPT` covers the rest.
AUTOMATION_BLINK_SWITCH = "--disable-blink-features=AutomationControlled"


# --------------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class LoginResult:
    """What a manual sign-in produced.

    :ivar cookies: cookie records as Playwright reports them (``name``,
        ``value``, ``domain``, ``path``, ``expires``, ``secure``, ``httpOnly``).
    :ivar path: the state file written, or ``None`` when ``save=False``.
    :ivar saved: whether :attr:`path` was (re)written by this call.
    :ivar accepted: whether a round looked like a completed sign-in.
    :ivar attempts: how many Enter presses were consumed.
    :ivar url: the page URL at the end of the wait -- useful when a site parks
        you on a consent or verification screen.
    :ivar reused: ``True`` when the browser was seeded from an existing state
        file, i.e. you may not have had to log in at all.
    """

    cookies: tuple[Mapping[str, Any], ...] = ()
    path: Path | None = None
    saved: bool = False
    accepted: bool = False
    attempts: int = 0
    url: str = ""
    reused: bool = False
    domains: tuple[str, ...] = field(default_factory=tuple)

    def __bool__(self) -> bool:
        """Truthy when at least one cookie came back."""
        return bool(self.cookies)

    @property
    def ok(self) -> bool:
        """A usable capture: cookies exist and were either saved or accepted.

        ``False`` for an exhausted or cancelled wait -- the browser may still
        hold anonymous cookies, but there is no session to reuse.
        """
        return bool(self.cookies) and (self.saved or self.accepted)

    @property
    def names(self) -> tuple[str, ...]:
        """Cookie names, in the order the browser reported them."""
        return tuple(str(cookie.get("name", "")) for cookie in self.cookies)

    def site_cookies(self) -> dict[str, str]:
        """Cookies for :attr:`domains` as a plain ``{name: value}`` mapping."""
        return {
            str(cookie["name"]): str(cookie.get("value", ""))
            for cookie in self.cookies
            if _domain_matches(str(cookie.get("domain", "")), self.domains)
            and cookie.get("name")
        }

    def cookie_header(self) -> str:
        """Site cookies rendered as a ``Cookie:`` header value."""
        return "; ".join(f"{name}={value}" for name, value in self.site_cookies().items())

    def describe(self) -> str:
        """One human-readable line, e.g. for a CLI report."""
        site = len(self.site_cookies())
        where = str(self.path) if self.path is not None else "not saved"
        state = "saved" if self.saved else "not written"
        return (
            f"{site} cookie(s) for {', '.join(self.domains) or 'the site'}; "
            f"{state} ({where}); {self.attempts} round(s)"
        )


# --------------------------------------------------------------------------- #
# Environment
# --------------------------------------------------------------------------- #


def login_environment_options(
    *,
    headless: bool = False,
    channel: str | None = None,
    storage_state: str | Path | None = None,
    captcha_solver: "CaptchaSolver | None" = None,
    artifacts_dir: str | Path | None = None,
    hide_automation: bool = False,
    **overrides: Any,
) -> BrowserEnvironmentOptions:
    """Options for a browser driven by a person, not by a test.

    Compared with the headless-CI defaults this drops the synthetic-monitor
    announcement and the determinism init script (both would make the window
    behave unlike a normal browser), restores the user's motion and colour
    preferences, and shows the window unless ``headless`` is set.

    :param captcha_solver: opt-in solver for a challenge met on the way to the
        sign-in form. Solving stays off by default: a person can click through
        it, and diagnostics are not worth surprising automation here.
    :param hide_automation: drop the switches and page markers that give the
        window away as a driven browser. Off by default -- the library says what
        it is. Turn it on for the one case where the check is not about you:
        signing in to *your own* account through Google, which refuses an
        account sign-in from anything it reads as automated ("this browser or
        app may not be secure"). It normally needs ``channel="chrome"`` as well:
        a real browser that does not advertise itself, rather than a bundled
        build pretending to be one.
    :param overrides: any other :class:`BrowserEnvironmentOptions` field. An
        explicit ``ignore_default_args``, ``launch_args`` or
        ``extra_init_scripts`` is *merged* with what ``hide_automation`` adds.
    """
    kwargs: dict[str, Any] = {
        "headless": headless,
        "channel": channel,
        "storage_state": storage_state,
        "identify_automation": False,
        "install_determinism_script": False,
        "reduced_motion": "no-preference",
        "color_scheme": "no-preference",
        "artifacts_dir": artifacts_dir,
    }
    kwargs.update(overrides)
    if hide_automation:
        kwargs["ignore_default_args"] = tuple(
            kwargs.get("ignore_default_args", ())
        ) + AUTOMATION_DEFAULT_ARGS_TO_DROP
        kwargs["launch_args"] = tuple(kwargs.get("launch_args", ())) + (
            AUTOMATION_BLINK_SWITCH,
        )
        kwargs["extra_init_scripts"] = tuple(
            kwargs.get("extra_init_scripts", ())
        ) + (HIDE_WEBDRIVER_SCRIPT,)
    options = BrowserEnvironmentOptions(**kwargs)
    if captcha_solver is not None:
        options.captcha_solver = captcha_solver
        options.solve_challenges = True
    return options


# --------------------------------------------------------------------------- #
# The flow
# --------------------------------------------------------------------------- #


async def alogin_and_save(
    *,
    base_url: str = DEFAULT_BASE_URL,
    path: str | Path | None = DEFAULT_STATE_PATH,
    start_url: str | None = None,
    domains: Sequence[str] | None = None,
    headless: bool = False,
    channel: str | None = None,
    hide_automation: bool = False,
    reuse_existing: bool = True,
    save: bool = True,
    rounds: int = 5,
    accept: Callable[..., Any] | None = None,
    login_flow: "LoginFlow | None" = None,
    captcha_solver: "CaptchaSolver | None" = None,
    prompt: Callable[[str], Any] = input,
    output: IO[str] | None = None,
    wait_until: str = "domcontentloaded",
    artifacts_dir: str | Path | None = None,
    environment: BrowserEnvironment | None = None,
    environment_options: BrowserEnvironmentOptions | None = None,
) -> LoginResult:
    """Open a browser, wait for a human sign-in, persist the session.

    :param base_url: the frontend to sign in to; also the default ``start_url``
        and the source of the default cookie domains.
    :param path: where the Playwright ``storage_state`` is written. ``None``
        keeps the session in memory only.
    :param start_url: page to open first (a ``/login`` route, a consent page).
    :param domains: cookie domains to watch; defaults to the host of
        ``base_url``.
    :param headless: ``False`` by default -- you cannot sign in to a window you
        cannot see.
    :param channel: Chromium channel, e.g. ``"chrome"`` to use your installed
        browser instead of Playwright's build.
    :param hide_automation: make the window look like a browser a person drives
        (see :func:`login_environment_options`). Needed when the sign-in goes
        through Google; ignored when ``environment_options`` is supplied, since
        those options are then used as they are.
    :param reuse_existing: seed the context from ``path`` when it already
        exists, so an earlier session does not have to be repeated. Pass
        ``False`` to sign in as somebody else.
    :param save: write the state file at all.
    :param rounds: how many Enter presses to offer. ``0`` never prompts, which
        suits a ``login_flow`` that signs in unattended.
    :param accept: predicate deciding a round succeeded. Called with
        ``(cookies, page, context)`` -- or fewer arguments if it accepts fewer
        -- and may be sync or async. Defaults to "new or changed cookies
        appeared for ``domains``".
    :param login_flow: optional :class:`~arena_api.auth.session.LoginFlow`
        (e.g. ``FormLoginFlow``) run right after the first navigation.
    :param captcha_solver: optional solver installed on the login pages.
    :param prompt: called with the instruction text; ``input`` by default.
    :param output: stream for progress notes (``sys.stderr`` by default).
    :param wait_until: Playwright navigation condition for the first load.
    :param artifacts_dir: keep traces/screenshots of the sign-in (diagnostics).
    :param environment: reuse an already-configured
        :class:`~arena_api.auth.browser.BrowserEnvironment` instead of building
        one; it is **not** started or closed by this function, and
        ``environment_options`` is then ignored.
    :param environment_options: supply your own options instead of
        :func:`login_environment_options`.
    :returns: a :class:`LoginResult`; :attr:`LoginResult.saved` says whether
        the state file was written.
    :raises Exception: a missing browser binary or a failed navigation surfaces
        as Playwright's own error. ``arena-api --login`` translates it into one
        actionable line; from Python, wrap the call if you need that too.
    """
    destination = Path(path) if path is not None else None
    targets = _target_domains(base_url, domains)
    seed = (
        destination
        if destination is not None and reuse_existing and destination.is_file()
        else None
    )

    owned = environment is None
    env = environment or BrowserEnvironment(
        environment_options
        or login_environment_options(
            headless=headless,
            channel=channel,
            storage_state=seed,
            captcha_solver=captcha_solver,
            artifacts_dir=artifacts_dir,
            hide_automation=hide_automation,
        )
    )

    try:
        if owned:
            await env.start()
        context = await env.new_context()
        page = await env.new_page(context)
        await page.goto(start_url or base_url, wait_until=wait_until)
        if login_flow is not None:
            await login_flow.run(page)

        before = _fingerprints(await context.cookies(), targets)
        cookies: list[Mapping[str, Any]] = []
        accepted = False
        attempts = 0

        for round_index in range(1, max(rounds, 0) + 1):
            attempts = round_index
            message = SIGN_IN_PROMPT.format(site=_site_label(base_url))
            try:
                prompt(message)
            except (EOFError, KeyboardInterrupt):
                _note(output, WAIT_CANCELLED)
                attempts = round_index - 1
                # Report what the browser holds anyway: the caller may still
                # want the cookies even though nothing is written to disk.
                cookies = list(await context.cookies())
                break
            cookies = list(await context.cookies())
            accepted = await _round_accepted(accept, cookies, before, targets, page, context)
            if accepted:
                break
            _note(
                output,
                NO_SESSION_YET.format(
                    site=_site_label(base_url), round=round_index, rounds=rounds
                ),
            )

        if not cookies:
            # ``rounds=0`` (an unattended login_flow) never entered the loop.
            cookies = list(await context.cookies())

        # Never trade a working session for an anonymous one: write the file
        # only when a round was accepted, or when the caller asked for no
        # interaction at all (an unattended ``login_flow``).
        writable = accepted or rounds == 0
        saved = False
        if save and destination is not None and cookies and writable:
            await _store(context, destination)
            saved = True
        elif save and destination is not None and not writable:
            _note(
                output,
                f"[arena-api] no sign-in detected; leaving {destination} untouched",
            )

        return LoginResult(
            cookies=tuple(cookies),
            path=destination if saved else None,
            saved=saved,
            accepted=accepted,
            attempts=attempts,
            url=str(getattr(page, "url", "") or ""),
            reused=seed is not None,
            domains=targets,
        )
    finally:
        if owned:
            await env.close()


def login_and_save(**kwargs: Any) -> LoginResult:
    """Synchronous :func:`alogin_and_save`; same keyword arguments.

    Blocks on ``input()`` between rounds, so call it from a script or a CLI.
    Inside a running event loop the wait is moved to its own thread by
    :func:`~arena_api.auth.browser.run_sync`, which keeps the loop responsive
    but still blocks the calling task.
    """
    result: LoginResult = run_sync(alogin_and_save(**kwargs))
    return result


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #


async def _store(context: Any, destination: Path) -> None:
    """Write the state file and tighten its permissions."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    await context.storage_state(path=str(destination))
    _restrict(destination)


def _restrict(destination: Path) -> None:
    """Make the state file owner-only where the platform supports it."""
    if os.name == "nt":  # pragma: no cover - Windows ACLs are out of scope
        return
    try:
        os.chmod(destination, STATE_FILE_MODE)
    except OSError:  # pragma: no cover - read-only filesystems, exotic mounts
        pass


def _target_domains(base_url: str, domains: Sequence[str] | None) -> tuple[str, ...]:
    if domains:
        return tuple(dict.fromkeys(str(item).strip().lstrip(".") for item in domains if item))
    host = urlparse(base_url).hostname or ""
    return (host,) if host else ()


def _site_label(base_url: str) -> str:
    return urlparse(base_url).hostname or base_url


def _domain_matches(domain: str, targets: Sequence[str]) -> bool:
    """Suffix match, the way cookie domains are conventionally compared."""
    if not targets:
        return True
    host = str(domain).lstrip(".").lower()
    for target in targets:
        needle = str(target).lstrip(".").lower()
        if host == needle or host.endswith("." + needle):
            return True
    return False


#: Cookies set asynchronously on an unauthenticated landing page (guest IDs,
#: edge clearance, analytics, UI preferences). Ignoring them in the default
#: ``before != after`` heuristic prevents an incomplete ``--login`` run from
#: saving a guest session that later shadows a signed-in browser profile.
_ANONYMOUS_NOISE_EXACT: frozenset[str] = frozenset(
    {
        "__cf_bm",
        "_cfuvid",
        "_dd_s",
        "_ga",
        "_gat",
        "_gid",
        "arena_build_bucket",
        "arena_visit_id",
        "cf_clearance",
        "cookie-preferences",
        "provisional_user_id",
        "sidebar_state",
        "user_country_code",
    }
)
_ANONYMOUS_NOISE_PREFIXES: tuple[str, ...] = (
    "_ga_",
    "_gat_",
    "_vcrr_",
    "ph_phc_",
)


def _is_anonymous_noise_cookie(name: str) -> bool:
    lowered = name.lower()
    return lowered in _ANONYMOUS_NOISE_EXACT or lowered.startswith(
        _ANONYMOUS_NOISE_PREFIXES
    )


def _fingerprints(cookies: Sequence[Mapping[str, Any]], targets: Sequence[str]) -> set[tuple[str, str]]:
    """``(name, value)`` pairs for the watched domains, for change detection."""
    return {
        (str(cookie.get("name", "")), str(cookie.get("value", "")))
        for cookie in cookies
        if _domain_matches(str(cookie.get("domain", "")), targets)
        and not _is_anonymous_noise_cookie(str(cookie.get("name", "")))
    }


async def _round_accepted(
    accept: Callable[..., Any] | None,
    cookies: Sequence[Mapping[str, Any]],
    before: set[tuple[str, str]],
    targets: Sequence[str],
    page: Any,
    context: Any,
) -> bool:
    """Decide whether the human finished signing in."""
    if accept is None:
        return bool(_fingerprints(cookies, targets) - before)
    outcome = _call_with_supported_arguments(accept, cookies=cookies, page=page, context=context)
    if inspect.isawaitable(outcome):
        outcome = await outcome
    return bool(outcome)


def _call_with_supported_arguments(
    callback: Callable[..., Any], **kwargs: Any
) -> Any:
    """Call ``callback`` with only the keyword arguments it declares.

    Keeps custom predicates short (``lambda cookies: ...``) without forcing
    callers to accept the full signature.
    """
    try:
        signature = inspect.signature(callback)
    except (TypeError, ValueError):  # pragma: no cover - builtins without signature
        return callback(**kwargs)
    parameters = signature.parameters
    if any(item.kind is inspect.Parameter.VAR_KEYWORD for item in parameters.values()):
        return callback(**kwargs)
    wanted = {name: value for name, value in kwargs.items() if name in parameters}
    return callback(**wanted)


def _note(output: IO[str] | None, message: str) -> None:
    import sys

    print(message, file=output if output is not None else sys.stderr, flush=True)

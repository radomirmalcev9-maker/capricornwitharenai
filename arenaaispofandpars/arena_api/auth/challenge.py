"""Detection and diagnostics for browser verification challenges.

What this module does
---------------------
In a synthetic-monitoring or E2E pipeline you need to know, unambiguously and
early, when the site under test served an interactive verification page
instead of the page you meant to test. A challenge that is silently clicked
through is worse than a challenge that fails the build: it hides the fact that
your monitor is being rate-shaped, it hides a misconfigured WAF rule, and it
produces green runs that measure nothing.

So this module answers three questions and stops:

* **Is this a challenge?** -- :func:`inspect_response` for the fast HTTP path
  (``curl_cffi``/``httpx``), :func:`inspect_page` for the Playwright path.
* **What kind, and what gave it away?** -- a :class:`ChallengeObservation`
  carrying every matched signal with its source (header / status / DOM
  selector / frame URL / body text).
* **What do we do about it?** -- :meth:`ChallengeHandler.raise_for` raises
  :class:`~arena_api.exceptions.ChallengeRequiredError` with a remediation
  guide and paths to captured screenshots, HTML and metadata.

The detection logic reads response headers, status codes, frame URLs and
public DOM markers. See :data:`REMEDIATION_TEMPLATE` for the durable
infrastructure-level fixes -- allowlisting, the vendor's published test keys
for CI, an exception rule on a zone you own, or a real service credential
instead of a borrowed browser session.

Opting in to solving
--------------------
:class:`ChallengeHandler` can also *clear* a challenge instead of only
reporting it, but only when you ask for it: pass a ``captcha_solver`` (see
:mod:`arena_api.auth.captcha`) and set ``solve_on_detection=True``. The handler
then solves, re-scans the page, and reports only a challenge that survived --
with every attempt's failure reason attached to the error. Which kinds are in
reach is the *solver's* decision (:meth:`ChallengeHandler.can_solve` asks
``solver.supports(observation)`` first): a token bridge such as
:class:`~arena_api.auth.captcha.RecaptchaToolkitSolver` covers
:data:`SOLVABLE_CHALLENGE_KINDS`, while
:class:`~arena_api.auth.captcha.ChallengeWaitSolver` covers the kinds that have
no token to produce. The fast HTTP path
(:func:`inspect_response`, :meth:`ChallengeHandler.check_response`) has no page
to act on, so it stays observational in all configurations.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterable, Mapping, NamedTuple, Sequence

from ..exceptions import CaptchaSolveError, ChallengeRequiredError

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from .captcha import CaptchaAttempt, CaptchaSolver

__all__ = [
    "CLOUDFLARE_FRAME_HOSTS",
    "DATADOME_FRAME_HOSTS",
    "DATADOME_HEADERS",
    "DATADOME_SELECTORS",
    "ChallengeHandler",
    "ChallengeKind",
    "ChallengeObservation",
    "ChallengeSignal",
    "HCAPTCHA_SELECTORS",
    "RECAPTCHA_SELECTORS",
    "REMEDIATION_TEMPLATE",
    "SOLVABLE_CHALLENGE_KINDS",
    "STATUS_TEXT_MARKERS",
    "TURNSTILE_SELECTORS",
    "inspect_page",
    "inspect_page_sync",
    "inspect_response",
]

TURNSTILE_SELECTORS: tuple[str, ...] = (
    "iframe[src*='challenges.cloudflare.com']",
    "iframe[src*='turnstile']",
    ".cf-turnstile",
    "div[data-sitekey]",
    "[data-cf-turnstile-response]",
)

HCAPTCHA_SELECTORS: tuple[str, ...] = (
    "iframe[src*='hcaptcha.com']",
    "iframe[src*='hcaptcha']",
    ".h-captcha",
    "[data-hcaptcha-widget-id]",
)

RECAPTCHA_SELECTORS: tuple[str, ...] = (
    "iframe[src*='google.com/recaptcha']",
    "iframe[src*='recaptcha']",
    ".g-recaptcha",
    "[data-recaptcha-widget-id]",
)

DATADOME_SELECTORS: tuple[str, ...] = (
    "iframe[src*='captcha-delivery.com']",
    "iframe[src*='datadome']",
    ".datadome-widget",
    "[data-datadome-widget-id]",
)

#: Frame hosts that indicate a Cloudflare interstitial rather than page content.
CLOUDFLARE_FRAME_HOSTS: tuple[str, ...] = (
    "challenges.cloudflare.com",
    "cf-assets.com",
    "cdn-cgi/challenge-platform",
)

#: DataDome serves its captcha from these hosts, and answers a blocked request
#: with ``x-datadome``/``x-datadome-cid`` headers.
DATADOME_FRAME_HOSTS: tuple[str, ...] = (
    "captcha-delivery.com",
    "geo.captcha-delivery.com",
)

#: Response headers that identify a DataDome block page.
DATADOME_HEADERS: tuple[str, ...] = ("x-datadome", "x-datadome-cid")

#: Substrings matched case-insensitively against the visible body text.
STATUS_TEXT_MARKERS: tuple[str, ...] = (
    "just a moment",
    "checking your browser",
    "checking if the site connection is secure",
    "verify you are human",
    "verify that you are human",
    "attention required",
    "enable javascript and cookies to continue",
    "performance & security by cloudflare",
    "performance and security by cloudflare",
    "please complete the security check",
    "one more step",
    "unusual traffic from your",
    "ddos protection by",
)

#: Headers worth keeping verbatim in a captured observation.
_DETAIL_HEADERS: tuple[str, ...] = (
    "cf-mitigated",
    "cf-ray",
    "cf-chl-out",
    "cf-cache-status",
    "server",
    "retry-after",
    "content-type",
    "x-arena-challenge",
    "location",
)

_INTERESTING_HEADER_FRAGMENTS: tuple[str, ...] = ("cf-", "challenge", "turnstile")

#: Status codes that, on their own, are only a hint -- paired with a marker.
_SUSPECT_STATUS: frozenset[int] = frozenset({401, 403, 429, 503})


class ChallengeKind(str, Enum):
    """Classification of a detected verification screen."""

    NONE = "none"
    TURNSTILE = "turnstile"
    CLOUDFLARE_MANAGED = "cloudflare_managed"
    RECAPTCHA = "recaptcha"
    HCAPTCHA = "hcaptcha"
    DATADOME = "datadome"
    INTERSTITIAL = "interstitial"
    RATE_LIMIT = "rate_limit"
    UNKNOWN = "unknown"


#: Kinds solvable **by producing a token** (see :mod:`arena_api.auth.captcha`).
#: The vendored toolkit solves reCAPTCHA only. The other challenge kinds have no
#: token to forge here, but they are not hopeless: :class:`~arena_api.auth.captcha.
#: ChallengeWaitSolver` clears Turnstile and a managed Cloudflare interstitial by
#: waiting them out, and hands hCaptcha/DataDome to a person in a headed browser.
#: Such a solver declares its own reach through ``supports()``, which
#: :meth:`ChallengeHandler.can_solve` prefers over this constant.
SOLVABLE_CHALLENGE_KINDS: frozenset[ChallengeKind] = frozenset({ChallengeKind.RECAPTCHA})


class ChallengeSignal(NamedTuple):
    """A single piece of evidence that a challenge is being served."""

    source: str
    detail: str
    kind: ChallengeKind


@dataclass(frozen=True)
class ChallengeObservation:
    """Result of scanning a page or response for a verification challenge."""

    url: str
    kind: ChallengeKind
    signals: tuple[ChallengeSignal, ...]
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    frame_urls: tuple[str, ...] = ()
    html_path: str | None = None
    screenshot_path: str | None = None
    detected_at: str = ""

    @property
    def is_challenge(self) -> bool:
        """Whether anything was actually detected."""
        return self.kind is not ChallengeKind.NONE

    @property
    def markers(self) -> tuple[str, ...]:
        """Deduplicated human-readable list of what matched."""
        seen: list[str] = []
        for signal in self.signals:
            label = f"{signal.source}: {signal.detail}"
            if label not in seen:
                seen.append(label)
        return tuple(seen)

    def summary(self) -> str:
        """One-line description suitable for a CI log."""
        markers = ", ".join(self.markers) or "no markers"
        status = "?" if self.status is None else str(self.status)
        return f"{self.kind.value} challenge at {self.url} (status {status}; {markers})"

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable form for artefact capture."""
        return {
            "url": self.url,
            "kind": self.kind.value,
            "status": self.status,
            "detected_at": self.detected_at,
            "signals": [
                {"source": s.source, "detail": s.detail, "kind": s.kind.value}
                for s in self.signals
            ],
            "headers": dict(self.headers),
            "frame_urls": list(self.frame_urls),
            "html_path": self.html_path,
            "screenshot_path": self.screenshot_path,
        }


REMEDIATION_TEMPLATE = """\
The service requested an interactive browser verification. Fix it at the \
infrastructure level:

  1. Allowlist the monitor. Add a WAF skip / bot-management exception rule for
     your CI runner's egress IPs or ASN, or match on the \
"{monitor_header}" request header this client already sends when \
identify_automation is enabled.
  2. Use the vendor's own test credentials in CI. Cloudflare publishes Turnstile
     test sitekey/secret pairs that always return a passing token, so a pipeline
     can exercise the real widget path end to end.
  3. Relax the rule on zones you own: disable Bot Fight Mode / managed
     challenges for the staging hostname your suite targets.
  4. Prefer a real credential over a borrowed browser session. For
     machine-to-machine monitoring, an API token or service account is more
     stable than replaying a user's cookies.
  5. If you must exercise production, do it at a human-scale cadence and
     identify the traffic so the operator can tune their rule.

Where you are authorized to complete the check yourself, this package can help: \
Turnstile and a managed Cloudflare interstitial are waited out, hCaptcha and \
DataDome are handed to you in a headed browser (``arena-api --login``, or \
``ChallengeWaitSolver(interactive=True)``), and reCAPTCHA can be solved with \
``RecaptchaToolkitSolver`` -- see :mod:`arena_api.auth.captcha`.
"""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _header_value(headers: Mapping[str, Any], name: str) -> str:
    target = name.lower()
    for key, value in headers.items():
        if str(key).lower() == target:
            return str(value)
    return ""


def _filter_headers(headers: Mapping[str, Any]) -> dict[str, str]:
    kept: dict[str, str] = {}
    for key, value in headers.items():
        lowered = str(key).lower()
        if lowered in _DETAIL_HEADERS or any(
            fragment in lowered for fragment in _INTERESTING_HEADER_FRAGMENTS
        ):
            kept[str(key)] = str(value)
    return kept


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _classify(signals: Sequence[ChallengeSignal]) -> ChallengeKind:
    """Reduce a set of signals to one :class:`ChallengeKind`."""
    if not signals:
        return ChallengeKind.NONE
    # A decisive response header (``cf-mitigated: challenge``) outranks a
    # widget reference found in the body, because managed challenges also
    # embed a challenge iframe.
    priority = (
        ChallengeKind.CLOUDFLARE_MANAGED,
        ChallengeKind.TURNSTILE,
        ChallengeKind.RECAPTCHA,
        ChallengeKind.HCAPTCHA,
        ChallengeKind.DATADOME,
        ChallengeKind.RATE_LIMIT,
        ChallengeKind.INTERSTITIAL,
    )
    kinds = {signal.kind for signal in signals}
    for kind in priority:
        if kind in kinds:
            return kind
    return ChallengeKind.UNKNOWN


def _match_text(body: str, markers: Iterable[str]) -> list[str]:
    lowered = body.lower()
    return [marker for marker in markers if marker in lowered]


# --------------------------------------------------------------------------- #
# Fast path: HTTP response inspection (no browser required)
# --------------------------------------------------------------------------- #


def inspect_response(
    status: int | None,
    headers: Mapping[str, Any] | None,
    body: str,
    *,
    url: str = "",
    extra_text_markers: Sequence[str] = (),
) -> ChallengeObservation:
    """Classify an HTTP response as a challenge or not.

    This is the cheap check that runs before any browser is launched: a
    ``curl_cffi`` probe hits the target and this function decides whether the
    stored session is still usable.

    A status code alone is never sufficient -- ``403`` is also a plain
    authorisation failure. Markers must corroborate.
    """
    headers = headers or {}
    body = body or ""
    signals: list[ChallengeSignal] = []

    if _header_value(headers, "cf-mitigated").lower() == "challenge":
        signals.append(
            ChallengeSignal("header", "cf-mitigated: challenge", ChallengeKind.CLOUDFLARE_MANAGED)
        )

    content_type = _header_value(headers, "content-type").lower()
    looks_html = "html" in content_type or not content_type
    probe_body = body[:200_000] if looks_html else ""

    for marker in _match_text(probe_body, STATUS_TEXT_MARKERS):
        signals.append(
            ChallengeSignal("body-text", f"marker {marker!r}", ChallengeKind.INTERSTITIAL)
        )
    for marker in _match_text(probe_body, extra_text_markers):
        signals.append(
            ChallengeSignal("body-text", f"custom marker {marker!r}", ChallengeKind.UNKNOWN)
        )

    body_lower = probe_body.lower()
    if "challenges.cloudflare.com" in body_lower or "turnstile" in body_lower:
        signals.append(
            ChallengeSignal("body-text", "challenges.cloudflare.com reference", ChallengeKind.TURNSTILE)
        )
    if "cdn-cgi/challenge-platform" in body_lower and (
        "cdn-cgi/challenge-platform/h/" in body_lower
        or "cdn-cgi/challenge-platform/scripts/jsd/" not in body_lower
    ):
        signals.append(
            ChallengeSignal(
                "body-text", "cdn-cgi/challenge-platform", ChallengeKind.CLOUDFLARE_MANAGED
            )
        )
    if any(host in body_lower for host in DATADOME_FRAME_HOSTS):
        signals.append(
            ChallengeSignal("body-text", "captcha-delivery.com reference", ChallengeKind.DATADOME)
        )
    for name in DATADOME_HEADERS:
        if _header_value(headers, name):
            signals.append(
                ChallengeSignal("header", f"{name} present", ChallengeKind.DATADOME)
            )
            break
    if "hcaptcha.com" in body_lower:
        signals.append(ChallengeSignal("body-text", "hcaptcha.com", ChallengeKind.HCAPTCHA))
    if "google.com/recaptcha" in body_lower or "grecaptcha" in body_lower:
        signals.append(ChallengeSignal("body-text", "recaptcha", ChallengeKind.RECAPTCHA))

    if status == 429 or _header_value(headers, "retry-after"):
        signals.append(
            ChallengeSignal("status", f"status {status}", ChallengeKind.RATE_LIMIT)
        )

    server = _header_value(headers, "server").lower()
    if status in _SUSPECT_STATUS and server == "cloudflare" and signals:
        signals.append(
            ChallengeSignal(
                "header", f"cloudflare served status {status}", ChallengeKind.CLOUDFLARE_MANAGED
            )
        )

    return ChallengeObservation(
        url=url,
        kind=_classify(signals),
        signals=tuple(signals),
        status=status,
        headers=_filter_headers(headers),
        detected_at=_utc_now(),
    )


# --------------------------------------------------------------------------- #
# Browser path: page inspection
# --------------------------------------------------------------------------- #

_PAGE_SCAN_JS = """
(pairs) => {
  const result = { selectors: [], frames: [], text: '', title: '' };
  for (const selector of pairs) {
    try {
      if (document.querySelector(selector)) result.selectors.push(selector);
    } catch (error) {
      /* invalid selector for this document; ignore */
    }
  }
  result.frames = Array.from(document.querySelectorAll('iframe'))
    .map((frame) => frame.src || frame.getAttribute('data-src') || '')
    .filter(Boolean)
    .slice(0, 50);
  result.title = document.title || '';
  result.text = ((document.body && document.body.innerText) || '').slice(0, 8000);
  return result;
}
"""


async def inspect_page(
    page: Any,
    *,
    capture_dir: str | Path | None = None,
    screenshot: bool = True,
    extra_selectors: Sequence[str] = (),
    extra_text_markers: Sequence[str] = (),
    url: str | None = None,
) -> ChallengeObservation:
    """Scan a Playwright page for a verification challenge.

    Examines frame URLs, DOM selectors and visible text. When a challenge is
    found and ``capture_dir`` is set, a screenshot, the page HTML and a JSON
    metadata file are written there for post-mortem analysis.

    This only *observes*. It does not locate, focus, or interact with any
    widget inside the challenge frame.
    """
    target_url = _page_url(page, url)
    signals, frame_urls = _frame_signals(page)

    scan = _empty_scan()
    try:
        evaluated = await page.evaluate(
            _PAGE_SCAN_JS, list(_all_selectors(extra_selectors))
        )
        if isinstance(evaluated, dict):
            scan = evaluated
    except Exception:
        scan = _empty_scan()

    extra_signals, frames = _scan_signals(scan, frame_urls, extra_text_markers)
    signals.extend(extra_signals)

    observation = _observation(target_url, signals, frames)
    if observation.is_challenge and capture_dir is not None:
        observation = await _capture(page, observation, capture_dir, screenshot)
    return observation


def inspect_page_sync(
    page: Any,
    *,
    capture_dir: str | Path | None = None,
    screenshot: bool = True,
    extra_selectors: Sequence[str] = (),
    extra_text_markers: Sequence[str] = (),
    url: str | None = None,
) -> ChallengeObservation:
    """Sync twin of :func:`inspect_page` for ``playwright.sync_api`` pages.

    Same signals, same classification, same diagnostics on disk. It exists so
    that a solver driven from synchronous code -- :meth:`arena_api.auth.captcha.
    ChallengeWaitSolver.solve`, for instance -- can re-check a page between
    waits instead of guessing from the initial observation.
    """
    target_url = _page_url(page, url)
    signals, frame_urls = _frame_signals(page)

    scan = _empty_scan()
    try:
        evaluated = page.evaluate(_PAGE_SCAN_JS, list(_all_selectors(extra_selectors)))
        if isinstance(evaluated, dict):
            scan = evaluated
    except Exception:
        scan = _empty_scan()

    extra_signals, frames = _scan_signals(scan, frame_urls, extra_text_markers)
    signals.extend(extra_signals)

    observation = _observation(target_url, signals, frames)
    if observation.is_challenge and capture_dir is not None:
        observation = _capture_sync(page, observation, capture_dir, screenshot)
    return observation


def _page_url(page: Any, url: str | None) -> str:
    return url if url is not None else str(getattr(page, "url", "") or "")


def _empty_scan() -> dict[str, Any]:
    return {"selectors": [], "frames": [], "text": "", "title": ""}


def _frame_signals(page: Any) -> tuple[list[ChallengeSignal], list[str]]:
    """Signals from the frames the page already holds (sync- and async-safe)."""
    signals: list[ChallengeSignal] = []
    frame_urls: list[str] = []

    for frame in getattr(page, "frames", []) or []:
        frame_url = str(getattr(frame, "url", "") or "")
        if frame_url:
            frame_urls.append(frame_url)
        lowered = frame_url.lower()
        for host in CLOUDFLARE_FRAME_HOSTS:
            if host in lowered:
                signals.append(
                    ChallengeSignal("frame", f"{host} in {frame_url}", ChallengeKind.TURNSTILE)
                )
                break
        if "hcaptcha.com" in lowered:
            signals.append(ChallengeSignal("frame", frame_url, ChallengeKind.HCAPTCHA))
        if any(host in lowered for host in DATADOME_FRAME_HOSTS):
            signals.append(ChallengeSignal("frame", frame_url, ChallengeKind.DATADOME))
        if "recaptcha" in lowered:
            signals.append(ChallengeSignal("frame", frame_url, ChallengeKind.RECAPTCHA))

    return signals, frame_urls


def _scan_signals(
    scan: Mapping[str, Any],
    frame_urls: Sequence[str],
    extra_text_markers: Sequence[str],
) -> tuple[list[ChallengeSignal], list[str]]:
    """Signals from a ``_PAGE_SCAN_JS`` result, plus any frames it adds."""
    signals: list[ChallengeSignal] = []
    frames = list(frame_urls)

    for selector in scan.get("selectors", []):
        signals.append(
            ChallengeSignal("dom", f"matched {selector}", _kind_for_selector(selector))
        )
    for frame_url in scan.get("frames", []):
        if frame_url not in frames:
            frames.append(str(frame_url))

    haystack = "\n".join(
        part for part in (scan.get("title", ""), scan.get("text", "")) if part
    )
    for marker in _match_text(haystack, STATUS_TEXT_MARKERS):
        signals.append(
            ChallengeSignal("dom-text", f"marker {marker!r}", ChallengeKind.INTERSTITIAL)
        )
    for marker in _match_text(haystack, extra_text_markers):
        signals.append(
            ChallengeSignal("dom-text", f"custom marker {marker!r}", ChallengeKind.UNKNOWN)
        )

    return signals, frames


def _observation(
    url: str, signals: Sequence[ChallengeSignal], frame_urls: Sequence[str]
) -> ChallengeObservation:
    return ChallengeObservation(
        url=url,
        kind=_classify(signals),
        signals=tuple(signals),
        frame_urls=tuple(frame_urls[:50]),
        detected_at=_utc_now(),
    )


def _all_selectors(extra: Sequence[str]) -> list[str]:
    seen: list[str] = []
    for selector in (
        *TURNSTILE_SELECTORS,
        *RECAPTCHA_SELECTORS,
        *HCAPTCHA_SELECTORS,
        *DATADOME_SELECTORS,
        *extra,
    ):
        if selector not in seen:
            seen.append(selector)
    return seen


def _kind_for_selector(selector: str) -> ChallengeKind:
    """Map a matched selector back to the vendor it belongs to.

    Comparison ignores punctuation, so ``.h-captcha`` and ``.hcaptcha-widget``
    both read as hCaptcha. That matters: ``.h-captcha`` is the documented widget
    class in :data:`HCAPTCHA_SELECTORS`, and a literal ``"hcaptcha"`` substring
    test misses it, which used to downgrade a real hCaptcha page to ``UNKNOWN``.
    """
    compact = re.sub(r"[^a-z0-9]+", "", selector.lower())
    if "turnstile" in compact or "cloudflare" in compact:
        return ChallengeKind.TURNSTILE
    if "hcaptcha" in compact:
        return ChallengeKind.HCAPTCHA
    if "datadome" in compact or "captchadelivery" in compact:
        return ChallengeKind.DATADOME
    if "recaptcha" in compact:
        return ChallengeKind.RECAPTCHA
    return ChallengeKind.UNKNOWN


def _capture_target(
    observation: ChallengeObservation, capture_dir: str | Path
) -> tuple[Path, str]:
    """Directory and artefact prefix for one detected challenge."""
    directory = Path(capture_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    host = re.sub(r"[^a-z0-9]+", "-", observation.url.lower())[:48].strip("-") or "page"
    return directory, f"challenge-{stamp}-{host}"


def _write_html(html: str, directory: Path, base: str) -> str | None:
    if not html:
        return None
    try:
        path = str(directory / f"{base}.html")
        Path(path).write_text(html, encoding="utf-8")
        return path
    except Exception:
        return None


def _finish_capture(
    observation: ChallengeObservation,
    directory: Path,
    base: str,
    html_path: str | None,
    screenshot_path: str | None,
) -> ChallengeObservation:
    """Attach the artefact paths and drop a JSON summary next to them."""
    observation = replace(
        observation, html_path=html_path, screenshot_path=screenshot_path
    )
    try:
        (directory / f"{base}.json").write_text(
            json.dumps(observation.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception:
        pass
    return observation


async def _capture(
    page: Any, observation: ChallengeObservation, capture_dir: str | Path, screenshot: bool
) -> ChallengeObservation:
    """Write screenshot/HTML/metadata for a detected challenge."""
    directory, base = _capture_target(observation, capture_dir)

    try:
        html = await page.content()
    except Exception:
        html = ""
    html_path = _write_html(html, directory, base)

    screenshot_path: str | None = None
    if screenshot:
        try:
            screenshot_path = str(directory / f"{base}.png")
            await page.screenshot(path=screenshot_path, full_page=True)
        except Exception:
            screenshot_path = None

    return _finish_capture(observation, directory, base, html_path, screenshot_path)


def _capture_sync(
    page: Any, observation: ChallengeObservation, capture_dir: str | Path, screenshot: bool
) -> ChallengeObservation:
    """Sync twin of :func:`_capture`."""
    directory, base = _capture_target(observation, capture_dir)

    try:
        html = page.content()
    except Exception:
        html = ""
    html_path = _write_html(html, directory, base)

    screenshot_path: str | None = None
    if screenshot:
        try:
            screenshot_path = str(directory / f"{base}.png")
            page.screenshot(path=screenshot_path, full_page=True)
        except Exception:
            screenshot_path = None

    return _finish_capture(observation, directory, base, html_path, screenshot_path)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


@dataclass
class ChallengeHandler:
    """Detect, capture and report challenges -- and optionally solve reCAPTCHA.

    Attach to a page with :meth:`install` to flag challenges as they appear
    during a flow, and call :meth:`check` at assertion points.

    By default the handler is purely observational. Handing it a
    ``captcha_solver`` (see :mod:`arena_api.auth.captcha`) and setting
    ``solve_on_detection=True`` opts in to solving: a detected challenge is
    passed to the solver, the page is re-scanned afterwards, and only a
    challenge that survives the solve is reported as a failure. Kinds the
    solver cannot act on -- Turnstile, hCaptcha, a managed Cloudflare
    interstitial -- always keep the detect-and-report path.
    """

    capture_dir: str | Path | None = None
    extra_selectors: tuple[str, ...] = ()
    extra_text_markers: tuple[str, ...] = ()
    screenshot: bool = True
    raise_on_detection: bool = True
    on_detection: Callable[[ChallengeObservation], None] | None = None

    #: Opt-in solver bridge, e.g.
    #: :class:`~arena_api.auth.captcha.RecaptchaToolkitSolver`. ``None`` keeps
    #: the handler observational.
    captcha_solver: "CaptchaSolver | None" = None

    #: Whether :meth:`check` and the :meth:`install` listener may attempt a
    #: solve. Has no effect without ``captcha_solver``.
    solve_on_detection: bool = False

    #: Solve attempts per page before the challenge is reported instead. Keeps
    #: a reload-driven flow (the v3 backend reloads the page) from looping.
    max_solve_attempts: int = 1

    _observations: list[ChallengeObservation] = field(default_factory=list, repr=False)
    _solve_attempts: list["CaptchaAttempt"] = field(default_factory=list, repr=False)
    _solving_pages: set[int] = field(default_factory=set, repr=False)
    _page_solve_budget: dict[int, int] = field(default_factory=dict, repr=False)

    @property
    def observations(self) -> tuple[ChallengeObservation, ...]:
        """Every challenge detected so far, oldest first."""
        return tuple(self._observations)

    @property
    def solve_attempts(self) -> tuple["CaptchaAttempt", ...]:
        """Every solve attempt made so far, oldest first."""
        return tuple(self._solve_attempts)

    @property
    def last_attempt(self) -> "CaptchaAttempt | None":
        """Most recent solve attempt, or ``None``."""
        return self._solve_attempts[-1] if self._solve_attempts else None

    @property
    def last(self) -> ChallengeObservation | None:
        """Most recent challenge, or ``None``."""
        return self._observations[-1] if self._observations else None

    def clear(self) -> None:
        """Forget all recorded observations and solve attempts."""
        self._observations.clear()
        self._solve_attempts.clear()
        self._solving_pages.clear()
        self._page_solve_budget.clear()

    def note(self, observation: ChallengeObservation) -> ChallengeObservation:
        """Record an observation and fire ``on_detection``, without raising.

        Used by the passive response listener, which runs as a background task
        where raising would be swallowed; the explicit :meth:`check` at an
        assertion point is what surfaces the failure.
        """
        if observation.is_challenge:
            self._observations.append(observation)
            if self.on_detection is not None:
                self.on_detection(observation)
        return observation

    def record(self, observation: ChallengeObservation) -> ChallengeObservation:
        """Store an observation, fire ``on_detection``, then honour ``raise_on_detection``."""
        self.note(observation)
        if observation.is_challenge and self.raise_on_detection:
            self.raise_for(observation)
        return observation

    def check_response(
        self,
        status: int | None,
        headers: Mapping[str, Any] | None,
        body: str,
        *,
        url: str = "",
    ) -> ChallengeObservation:
        """Classify an HTTP response (fast path) and record it."""
        observation = inspect_response(
            status,
            headers,
            body,
            url=url,
            extra_text_markers=self.extra_text_markers,
        )
        return self.record(observation)

    async def _inspect(self, page: Any, *, url: str | None = None) -> ChallengeObservation:
        """Scan a page with this handler's configuration (no recording)."""
        return await inspect_page(
            page,
            capture_dir=self.capture_dir,
            screenshot=self.screenshot,
            extra_selectors=self.extra_selectors,
            extra_text_markers=self.extra_text_markers,
            url=url,
        )

    def can_solve(self, observation: ChallengeObservation) -> bool:
        """Whether this handler would hand ``observation`` to its solver."""
        if not self.solve_on_detection or self.captcha_solver is None:
            return False
        if not observation.is_challenge:
            return False
        supports = getattr(self.captcha_solver, "supports", None)
        if callable(supports):
            return bool(supports(observation))
        return observation.kind in SOLVABLE_CHALLENGE_KINDS

    async def solve_page(
        self,
        page: Any,
        *,
        observation: ChallengeObservation | None = None,
        url: str | None = None,
        attempts: int | None = None,
    ) -> ChallengeObservation:
        """Solve the challenge on ``page``, then re-scan and record the result.

        Returns the post-solve observation. When the challenge survives every
        attempt, :attr:`raise_on_detection` decides whether it is raised
        (with each attempt's failure reason) or returned for the caller to
        handle -- the same contract :meth:`record` already has.

        :param page: an open Playwright page.
        :param observation: a scan to act on; ``None`` scans the page first and
            returns immediately when it holds no challenge.
        :param url: URL reported in the observation (defaults to ``page.url``).
        :param attempts: solve attempts for this call. ``None`` uses what is
            left of the page's :attr:`max_solve_attempts` budget, which is what
            keeps the passive listener from looping; an explicit number always
            runs that many attempts (and is charged to the same budget).
        """
        solver = self.captcha_solver
        if solver is None:
            raise ValueError(
                "no captcha_solver configured; construct ChallengeHandler with "
                "captcha_solver=RecaptchaToolkitSolver(...) to solve challenges"
            )
        current = observation if observation is not None else await self._inspect(page, url=url)
        if not current.is_challenge:
            return self.record(current)
        # A challenge that is about to be solved is still worth recording: the
        # run should show that it happened, not only that it was cleared.
        self.note(current)

        page_key = id(page)
        if attempts is None:
            budget = max(1, int(self.max_solve_attempts)) - self._page_solve_budget.get(page_key, 0)
        else:
            budget = max(1, int(attempts))
        for _ in range(max(0, budget)):
            self._page_solve_budget[page_key] = self._page_solve_budget.get(page_key, 0) + 1
            self._solve_attempts.append(await solver.asolve(page, current))
            current = await self._inspect(page, url=url)
            self.note(current)
            if not current.is_challenge:
                return current

        if self.raise_on_detection:
            self.raise_for(current, attempts=self.solve_attempts)
        return current

    async def _auto_solve(self, page: Any, *, url: str | None = None) -> None:
        """Solve from the passive listener, one page at a time.

        Guarded twice over: a page that is already being solved is skipped (the
        v3 backend reloads the page, which fires the listener again), and the
        per-page attempt budget caps the total work so a stubborn challenge
        ends in a report rather than a reload loop.
        """
        page_key = id(page)
        if page_key in self._solving_pages:
            return
        if self._page_solve_budget.get(page_key, 0) >= max(1, int(self.max_solve_attempts)):
            return
        self._solving_pages.add(page_key)
        try:
            await self.solve_page(page, url=url)
        finally:
            self._solving_pages.discard(page_key)

    async def check(self, page: Any, *, url: str | None = None) -> ChallengeObservation:
        """Scan a Playwright page, record the result, and solve it if opted in."""
        observation = await self._inspect(page, url=url)
        if self.can_solve(observation):
            return await self.solve_page(page, observation=observation, url=url)
        return self.record(observation)

    async def install(self, page: Any) -> None:
        """Watch a page's responses and frame navigations for challenges.

        Useful for long flows where a challenge may appear mid-run rather than
        on the landing page. Detection is purely observational: the response
        body is read, never modified or replayed. With ``solve_on_detection``
        enabled, a solvable challenge additionally triggers :meth:`solve_page`
        on the page that produced it.
        """

        async def _on_response(response: Any) -> None:
            try:
                if response.status in _SUSPECT_STATUS or response.status == 200:
                    body = await _safe_body(response)
                    if body:
                        observation = inspect_response(
                            response.status,
                            response.headers,
                            body,
                            url=response.url,
                            extra_text_markers=self.extra_text_markers,
                        )
                        if self.can_solve(observation):
                            # Recorded here, then re-scanned from the DOM by
                            # solve_page: a widget reference in a subresource
                            # body is not the same as a challenge on the page.
                            self.note(observation)
                            await self._auto_solve(page, url=response.url)
                            return
                        self.record(observation)
            except ChallengeRequiredError:
                raise
            except Exception:
                pass

        page.on("response", lambda response: _schedule(_on_response(response)))

    def raise_for(
        self,
        observation: ChallengeObservation,
        *,
        attempts: Sequence["CaptchaAttempt"] = (),
    ) -> None:
        """Raise :class:`ChallengeRequiredError` with remediation guidance."""
        artifacts = [
            path
            for path in (observation.screenshot_path, observation.html_path)
            if path
        ]
        detail = "\n".join(
            [
                observation.summary(),
                "",
                REMEDIATION_TEMPLATE.format(monitor_header="X-Synthetic-Monitor"),
            ]
        )
        failed = [attempt for attempt in attempts if not attempt.ok]
        if failed:
            detail += "\nSolver attempts:\n" + "\n".join(
                f"  - {attempt.describe()}" for attempt in failed
            )
        if artifacts:
            detail += "\nCaptured diagnostics:\n" + "\n".join(
                f"  - {path}" for path in artifacts
            )
        error: ChallengeRequiredError = (
            CaptchaSolveError(detail) if failed else ChallengeRequiredError(detail)
        )
        raise error


async def _safe_body(response: Any) -> str:
    """Read a response body as text, tolerating bodies that cannot be read."""
    try:
        content_type = str(response.headers.get("content-type", "")).lower()
        if content_type and "html" not in content_type and "text" not in content_type:
            return ""
        return await response.text()
    except Exception:
        return ""


def _schedule(coroutine: Any) -> Any:
    """Schedule ``coroutine`` on the running loop without awaiting it."""
    import asyncio

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        coroutine.close()
        return None
    return loop.create_task(coroutine)

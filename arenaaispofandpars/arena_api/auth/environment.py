"""Deterministic browser environment for reproducible E2E and visual tests.

What this module is for
-----------------------
Headless Chromium in CI is *non-deterministic* in ways that break tests rather
than protections:

* CSS animations and transitions run at wall-clock speed, so a screenshot or a
  ``bounding_box()`` taken at t+0 ms differs from one taken at t+80 ms;
* the blinking text caret lands in half of all visual-regression diffs;
* ``Math.random()`` re-shuffles A/B buckets, feature-flag rolls and any
  client-side ID, so the same test exercises a different code path each run;
* wall-clock ``Date.now()`` makes "created 2 minutes ago" labels untestable.

:func:`build_init_script` produces a single ``page.add_init_script`` payload
that removes *those* sources of flake.

Identifying the monitor
-----------------------
Set ``identify_automation=True`` and the page exposes ``window.__arenaSynthetic``
so the site under test can branch, and the operator can allowlist the monitor.
See :mod:`arena_api.auth.challenge` for detecting and reporting verification
screens.

Genuinely legitimate needs that people sometimes reach for stealth patches to
solve are already first-class Playwright context options, and
:class:`~arena_api.auth.browser.BrowserEnvironment` wires them up:

* ``locale=`` / ``locale="en-US"`` sets ``navigator.language`` and
  ``navigator.languages``;
* ``timezone_id=`` sets the ``Intl`` and ``Date`` timezone;
* ``user_agent=`` sets the UA;
* ``viewport=`` / ``device_scale_factor=`` set the reported screen geometry;
* ``reduced_motion="reduce"`` honours ``prefers-reduced-motion`` for real.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

__all__ = [
    "ANIMATION_FREEZE_CSS",
    "HIDE_WEBDRIVER_SCRIPT",
    "DeterminismOptions",
    "build_init_script",
]

#: Opt-in init script that drops the ``navigator.webdriver`` marker Playwright
#: leaves on every page.
#:
#: This module's job is reproducibility, not concealment, so the marker is left
#: alone by default -- :func:`build_init_script` never contains this script.
#: The one place it earns its keep is the *sign-in window* a person drives
#: (:func:`arena_api.auth.login.login_and_save` with
#: ``hide_automation=True``): Google refuses to authenticate an account from a
#: browser it reads as automated ("this browser or app may not be secure"), and
#: a human signing in to their own account is not the threat that check is for.
#: Use it there and nowhere else.
HIDE_WEBDRIVER_SCRIPT = """
(function () {
  if (navigator.webdriver === false) {
    return;
  }
  const proto = Object.getPrototypeOf(navigator);
  try {
    delete navigator.webdriver;
  } catch (error) {
    /* A hardened build can refuse the delete; fall through to defineProperty. */
  }
  if ('webdriver' in proto && navigator.webdriver) {
    Object.defineProperty(proto, 'webdriver', {
      get: () => false,
      configurable: true
    });
  }
})();
""".strip()

#: CSS applied to make layout and painting stable for screenshots.
#:
#: Durations are zeroed rather than disabled so that ``transitionend`` and
#: ``animationend`` listeners still fire -- many components (toasts, modals,
#: accordions) only complete their state machine on those events, and dropping
#: them produces tests that hang instead of tests that pass.
ANIMATION_FREEZE_CSS = """
*, *::before, *::after {
  animation-duration: 0.001s !important;
  animation-delay: 0s !important;
  animation-iteration-count: 1 !important;
  transition-duration: 0.001s !important;
  transition-delay: 0s !important;
  scroll-behavior: auto !important;
  caret-color: transparent !important;
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.001s !important;
    transition-duration: 0.001s !important;
  }
}
""".strip()


@dataclass(frozen=True)
class DeterminismOptions:
    """Knobs for the environment normalisation script.

    Every option defaults to the setting that makes a CI run reproducible.
    """

    #: Zero out CSS animation/transition durations and hide the text caret.
    freeze_animations: bool = True

    #: Immediately ``finish()`` any animation created through the Web
    #: Animations API, which CSS alone cannot reach.
    finish_web_animations: bool = True

    #: Replace ``Math.random()`` with a seeded PRNG (mulberry32).
    deterministic_random: bool = True

    #: Seed used for both the page-side PRNG and the telemetry hooks.
    random_seed: int = 1337

    #: Anchor ``Date.now()`` and ``new Date()`` to a fixed instant.
    #: The clock keeps *ticking* from that anchor -- see :meth:`note below
    #: <DeterminismOptions.frozen_time>`.
    anchor_clock: bool = False

    #: ISO-8601 instant used when ``anchor_clock`` is set. ``None`` pins to
    #: the Unix epoch (``1970-01-01T00:00:00.000Z``).
    #:
    #: Time is shifted by a constant offset rather than truly frozen: a frozen
    #: clock also stops ``setTimeout``/``requestAnimationFrame`` scheduling in
    #: many implementations, which breaks every debounced or animated component
    #: under test. Anchoring keeps timers working while making timestamps and
    #: "time ago" labels deterministic.
    frozen_time: str | None = None

    #: Expose ``window.__arenaSynthetic`` and ``window.__arenaTestHooks``.
    identify_automation: bool = True

    #: Namespace for the exposed hooks.
    hook_name: str = "__arenaTestHooks"

    #: Extra entries merged into the hooks object. Values must be JSON-safe.
    extra_hooks: dict[str, Any] = field(default_factory=dict)

    def to_hook_payload(self) -> dict[str, Any]:
        """JSON-safe summary handed to the page for diagnostic assertions."""
        payload = asdict(self)
        payload["extra_hooks"] = dict(self.extra_hooks)
        return payload


def _mulberry32(seed_expression: str) -> str:
    """Return a JS IIFE installing a seeded mulberry32 PRNG."""
    return f"""
(function (seed) {{
  let state = seed >>> 0;
  Math.random = function () {{
    state = (state + 0x6D2B79F5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }};
  Math.random.__seeded = true;
}})({seed_expression});
""".strip()


def _anchor_clock(offset_expression: str) -> str:
    """Return a JS IIFE shifting ``Date.now()`` by a constant offset."""
    return f"""
(function (anchor) {{
  const RealDate = Date;
  const offset = anchor - RealDate.now();
  function PatchedDate(...args) {{
    if (!(this instanceof PatchedDate)) {{
      return new RealDate(RealDate.now() + offset).toString();
    }}
    return args.length === 0
      ? new RealDate(RealDate.now() + offset)
      : new RealDate(...args);
  }}
  PatchedDate.now = function () {{ return RealDate.now() + offset; }};
  PatchedDate.parse = RealDate.parse;
  PatchedDate.UTC = RealDate.UTC;
  PatchedDate.prototype = RealDate.prototype;
  window.Date = PatchedDate;
}})({offset_expression});
""".strip()


def _finish_web_animations() -> str:
    """Return JS collapsing Web Animations API animations to their end state."""
    return """
(function () {
  const original = Element.prototype.animate;
  Element.prototype.animate = function (...args) {
    const animation = original.apply(this, args);
    try { animation.finish(); } catch (error) { /* already settled */ }
    return animation;
  };
  const originalGet = typeof document.getAnimations === 'function'
    ? document.getAnimations.bind(document)
    : null;
  document.getAnimations = function () {
    const animations = originalGet ? originalGet() : [];
    for (const animation of animations) {
      try { animation.finish(); } catch (error) { /* already settled */ }
    }
    return animations;
  };
})();
""".strip()


def _inject_style(css: str) -> str:
    """Return JS inserting ``css`` as the first stylesheet of every document."""
    payload = json.dumps(css)
    return f"""
(function () {{
  const css = {payload};
  const install = () => {{
    const root = document.head || document.documentElement;
    if (!root || root.querySelector('style[data-arena-determinism]')) return;
    const style = document.createElement('style');
    style.setAttribute('data-arena-determinism', 'true');
    style.textContent = css;
    root.insertBefore(style, root.firstChild);
  }};
  if (document.readyState === 'loading') {{
    document.addEventListener('DOMContentLoaded', install, {{ once: true }});
  }}
  install();
}})();
""".strip()


def _identify_automation_block(options: DeterminismOptions) -> str:
    """Return JS marking the page as driven by a synthetic monitor."""
    if not options.identify_automation:
        return ""
    return f"""
  Object.defineProperty(window, '__arenaSynthetic', {{
    value: true,
    enumerable: false,
    configurable: false
  }});
  window.__arenaSyntheticInfo = {{
    library: 'arena-api',
    hook: hookName,
    seed: {options.random_seed}
  }};
""".rstrip()


def _install_hooks(options: DeterminismOptions) -> str:
    """Return JS exposing the honest automation marker and test helpers."""
    hooks = json.dumps(options.to_hook_payload())
    name = json.dumps(options.hook_name)
    extra = json.dumps(dict(options.extra_hooks))
    identity = _identify_automation_block(options)
    return f"""
(function () {{
  const hookName = {name};
  const metadata = {hooks};
  const extra = {extra};
  const settle = (frames) => new Promise((resolve) => {{
    let remaining = Math.max(1, frames | 0);
    const step = () => {{
      remaining -= 1;
      if (remaining <= 0) resolve();
      else requestAnimationFrame(step);
    }};
    requestAnimationFrame(step);
  }});
  const waitForFonts = async () => {{
    if (document.fonts && typeof document.fonts.ready !== 'undefined') {{
      await document.fonts.ready;
    }}
  }};
  const hooks = Object.assign({{
    metadata,
    seededRandom: Boolean(Math.random.__seeded),
    settle,
    waitForFonts,
    drain: async (frames) => {{ await waitForFonts(); await settle(frames || 3); }},
    mark: (label) => performance.mark(String(label)),
    marks: () => performance.getEntriesByType('mark').map((entry) => entry.name)
  }}, extra);
  window[hookName] = hooks;
{identity}
}})();
""".strip()


def build_init_script(options: DeterminismOptions | None = None) -> str:
    """Build the ``page.add_init_script`` payload.

    The result is a single self-contained IIFE-safe script. It is pure text:
    generating it requires no browser, so it can be unit-tested, cached, and
    diffed in code review.
    """
    resolved = options or DeterminismOptions()
    blocks: list[str] = []

    blocks.append("(function () {\n" "  'use strict';\n" "  try {")
    if resolved.freeze_animations:
        blocks.append(_inject_style(ANIMATION_FREEZE_CSS))
    if resolved.finish_web_animations:
        blocks.append(_finish_web_animations())
    if resolved.deterministic_random:
        blocks.append(_mulberry32(str(int(resolved.random_seed))))
    if resolved.anchor_clock:
        if resolved.frozen_time:
            blocks.append(_anchor_clock(f"Date.parse({json.dumps(resolved.frozen_time)})"))
        else:
            blocks.append(_anchor_clock("0"))
    blocks.append(_install_hooks(resolved))
    blocks.append(
        "  } catch (error) {\n"
        "    if (typeof console !== 'undefined' && console.warn) {\n"
        "      console.warn('[arena-api] determinism init failed:', error);\n"
        "    }\n"
        "  }\n"
        "})();"
    )
    return "\n\n".join(blocks)


#: Default payload, generated once at import time.
DEFAULT_INIT_SCRIPT: str = build_init_script(DeterminismOptions())

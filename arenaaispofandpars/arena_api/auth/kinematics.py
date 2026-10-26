"""Deterministic, human-plausible pointer kinematics for Playwright E2E suites.

Why this exists
---------------
Real users do not teleport the cursor. Plenty of UI behaviour under test is
*motion dependent* -- hover menus with open/close hysteresis, drag handles,
tooltips with enter/leave debounce, canvas and signature widgets, sliders,
sortable lists, and anything that samples ``pointermove``. Firing a single
synthetic ``mouse.move(x, y)`` at the destination skips every intermediate
event, which produces both false positives (a menu opens when it should have
stayed closed) and false negatives (a tooltip never appears because no
``mouseenter`` was preceded by movement).

This module synthesises a physically plausible pointer path:

* a cubic Bezier arc between the current position and the target,
* an ease-in/ease-out velocity profile with Fitts's-law stroke timing,
* low-frequency micro-jitter (hand tremor) and occasional overshoot,
* reproducible delays, so a failure can be replayed from its seed.

Everything is deterministic under ``seed=``: identical inputs always produce
an identical trajectory. That is the point -- a flaky hover test is only
debuggable if the motion that broke it can be reproduced exactly.

Scope note
----------
This models human motor behaviour so that *motion-dependent UI* is exercised
realistically. It is not an anti-detection measure: it does not touch
``navigator.webdriver``, plugin lists, WebGL/Canvas fingerprints, permission
APIs or ``window.chrome``, and it is not intended to make an automated client
indistinguishable from a human one. See :mod:`arena_api.auth.environment` for
what this package deliberately does and does not emulate.

Optional dependency
-------------------
``numpy`` accelerates Bezier sampling and noise generation when installed. The
pure-Python fallback is mathematically identical, so the module imports and
runs without it (``scipy`` is not required -- arc-length reparameterisation
here is exact and needs no solver).
"""

from __future__ import annotations

import asyncio
import math
import random
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Callable, NamedTuple

_NP_MODULE: Any = None
_NP_LOOKED_UP = False


def numpy_module() -> Any | None:
    """Return the ``numpy`` module if installed, else ``None`` (cached).

    Loaded lazily so importing this module stays cheap and numpy remains a
    purely optional acceleration.
    """
    global _NP_MODULE, _NP_LOOKED_UP
    if not _NP_LOOKED_UP:
        _NP_LOOKED_UP = True
        module: Any = None
        try:  # pragma: no cover - depends on the environment
            import numpy

            module = numpy
        except ImportError:  # pragma: no cover
            module = None
        _NP_MODULE = module
    return _NP_MODULE

__all__ = [
    "KinematicMouse",
    "KinematicMouseSync",
    "MouseSample",
    "Point",
    "Trajectory",
    "TrajectoryPlanner",
    "cubic_bezier_point",
    "ease_in_out_cubic",
    "ease_in_out_overshoot",
    "ease_out_back",
    "ease_out_cubic",
    "fitts_duration",
    "resolve_element_center",
]

TAU = math.tau


# --------------------------------------------------------------------------- #
# Primitives
# --------------------------------------------------------------------------- #


class Point(NamedTuple):
    """A viewport coordinate in CSS pixels."""

    x: float
    y: float


class MouseSample(NamedTuple):
    """One emitted pointer position.

    ``delay`` is the number of seconds to wait *after* dispatching this move,
    which is what turns a geometric path into a velocity profile.
    """

    x: float
    y: float
    t: float
    delay: float


def clamp(value: float, low: float, high: float) -> float:
    """Constrain ``value`` to ``[low, high]``."""
    if high < low:
        low, high = high, low
    return low if value < low else high if value > high else value


def ease_in_out_cubic(t: float) -> float:
    """Symmetric ease-in/ease-out; zero velocity at both ends."""
    t = clamp(t, 0.0, 1.0)
    return 4.0 * t * t * t if t < 0.5 else 1.0 - ((-2.0 * t + 2.0) ** 3) / 2.0


def ease_out_cubic(t: float) -> float:
    """Fast start, gentle landing."""
    t = clamp(t, 0.0, 1.0)
    return 1.0 - (1.0 - t) ** 3


def ease_out_back(t: float, overshoot: float = 1.15) -> float:
    """Standard ease-out-with-overshoot curve; lands exactly on ``1.0``."""
    t = clamp(t, 0.0, 1.0)
    c3 = overshoot + 1.0
    return 1.0 + c3 * (t - 1.0) ** 3 + overshoot * (t - 1.0) ** 2


def ease_in_out_overshoot(t: float, overshoot: float = 0.05) -> float:
    """Ease-in/ease-out with a small damped overshoot near the end.

    The symmetric velocity profile is preserved -- peak speed still occurs
    mid-stroke, as it does in real pointing movements -- and the overshoot is
    a bump confined to the second half that decays to exactly zero at
    ``t == 1``. That guarantees the stroke lands on the target even though it
    momentarily travels past it.

    ``overshoot`` is a fraction of the total stroke length; ``0.05`` pushes
    roughly 2-3% past the destination before the corrective return.
    """
    t = clamp(t, 0.0, 1.0)
    base = ease_in_out_cubic(t)
    if overshoot <= 0.0:
        return base
    tail = clamp((t - 0.5) / 0.5, 0.0, 1.0)
    return base + overshoot * math.sin(math.pi * tail) ** 2


def fitts_duration(
    distance: float,
    width: float,
    a: float = 0.075,
    b: float = 0.115,
    minimum: float = 0.09,
    maximum: float = 1.35,
) -> float:
    """Stroke time from Fitts's law: ``T = a + b * log2(D / W + 1)``.

    ``a``/``b`` are the standard intercept and slope constants in seconds and
    seconds-per-bit. The result is clamped to ``[minimum, maximum]`` so that a
    3 px nudge does not finish in 0 ms and a 3000 px sweep does not stall a
    test suite for two seconds.
    """
    width = max(float(width), 1.0)
    distance = max(float(distance), 0.0)
    raw = a + b * math.log2(distance / width + 1.0)
    return clamp(raw, minimum, maximum)


def cubic_bezier_point(
    p0: Sequence[float],
    p1: Sequence[float],
    p2: Sequence[float],
    p3: Sequence[float],
    t: float,
) -> Point:
    """Evaluate a cubic Bezier at ``t`` using the Bernstein basis form."""
    t = clamp(t, 0.0, 1.0)
    u = 1.0 - t
    w0 = u * u * u
    w1 = 3.0 * u * u * t
    w2 = 3.0 * u * t * t
    w3 = t * t * t
    return Point(
        w0 * p0[0] + w1 * p1[0] + w2 * p2[0] + w3 * p3[0],
        w0 * p0[1] + w1 * p1[1] + w2 * p2[1] + w3 * p3[1],
    )


def _smooth_noise(count: int, rng: random.Random, octaves: int = 3) -> list[float]:
    """Low-frequency ``[-1, 1]`` noise: a few summed sines with random phase.

    Band-limited on purpose. Per-sample white noise reads as sensor chatter;
    a hand tremor is dominated by frequencies around 8-12 Hz, i.e. a handful
    of cycles across a 200-800 ms stroke.
    """
    if count <= 0:
        return []
    waves: list[tuple[float, float, float]] = []
    total_weight = 0.0
    for index in range(max(1, octaves)):
        frequency = 1.5 * (2.0**index)
        phase = rng.uniform(0.0, TAU)
        weight = 1.0 / (2.0**index)
        total_weight += weight
        waves.append((frequency, phase, weight))
    if total_weight <= 0.0:
        return [0.0] * count
    noise: list[float] = []
    for i in range(count):
        u = i / max(count - 1, 1)
        value = sum(
            weight * math.sin(TAU * frequency * u + phase)
            for frequency, phase, weight in waves
        )
        noise.append(value / total_weight)
    return noise


def _cumulative_lengths(points: Sequence[Point]) -> list[float]:
    """Prefix sums of segment lengths, starting at ``0.0``."""
    lengths = [0.0]
    for index in range(1, len(points)):
        previous = points[index - 1]
        current = points[index]
        lengths.append(
            lengths[-1] + math.hypot(current.x - previous.x, current.y - previous.y)
        )
    return lengths


def _point_at_length(
    points: Sequence[Point], lengths: Sequence[float], distance: float
) -> Point:
    """Interpolate a polyline at a given arc length.

    For ``distance`` beyond the polyline the terminal tangent is extrapolated,
    which is what lets an overshoot easing push past the destination and come
    back along a continuous path instead of snapping.
    """
    if not points:
        raise ValueError("cannot interpolate an empty polyline")
    total = lengths[-1]
    if total <= 0.0:
        return Point(points[-1].x, points[-1].y)
    if distance <= 0.0:
        return Point(points[0].x, points[0].y)
    if distance >= total:
        overshoot = distance - total
        last = points[-1]
        before = points[-2] if len(points) > 1 else points[-1]
        dx, dy = last.x - before.x, last.y - before.y
        norm = math.hypot(dx, dy)
        if norm <= 1e-9:
            return Point(last.x, last.y)
        return Point(last.x + dx / norm * overshoot, last.y + dy / norm * overshoot)
    low, high = 0, len(lengths) - 1
    while low + 1 < high:
        mid = (low + high) // 2
        if lengths[mid] <= distance:
            low = mid
        else:
            high = mid
    segment = lengths[high] - lengths[low]
    fraction = 0.0 if segment <= 0.0 else (distance - lengths[low]) / segment
    start, end = points[low], points[high]
    return Point(
        start.x + (end.x - start.x) * fraction,
        start.y + (end.y - start.y) * fraction,
    )


# --------------------------------------------------------------------------- #
# Trajectory
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Trajectory:
    """A finished, replayable pointer path."""

    samples: tuple[MouseSample, ...]
    start: Point
    end: Point
    duration: float
    distance: float
    seed: int | None

    @property
    def length(self) -> float:
        """Total travelled arc length in pixels."""
        total = 0.0
        previous = self.start
        for sample in self.samples:
            total += math.hypot(sample.x - previous.x, sample.y - previous.y)
            previous = Point(sample.x, sample.y)
        return total

    @property
    def straightness(self) -> float:
        """Arc length over straight-line distance; ``1.0`` is a perfect line."""
        if self.distance <= 0.0:
            return 1.0
        return self.length / self.distance

    @property
    def settle_time(self) -> float:
        """Sum of all inter-sample delays, i.e. wall-clock stroke duration."""
        return sum(sample.delay for sample in self.samples)

    def __len__(self) -> int:
        return len(self.samples)

    def __iter__(self):
        return iter(self.samples)


@dataclass(frozen=True)
class TrajectoryPlanner:
    """Stateless, seedable trajectory synthesiser.

    All tunables are in real units: seconds for time, CSS pixels for distance.
    Ranges are inclusive ``(low, high)`` pairs sampled uniformly per stroke.
    """

    seed: int | None = None
    samples_per_second: float = 110.0
    min_duration: float = 0.09
    max_duration: float = 1.35
    fitts_a: float = 0.075
    fitts_b: float = 0.115
    default_target_width: float = 26.0
    curvature: tuple[float, float] = (0.06, 0.22)
    jitter_amplitude: tuple[float, float] = (0.6, 2.4)
    overshoot_probability: float = 0.18
    overshoot_fraction: tuple[float, float] = (0.03, 0.07)
    timing_jitter: float = 0.18
    coordinate_precision: int = 3

    def plan(
        self,
        start: Sequence[float] | Point,
        end: Sequence[float] | Point,
        *,
        target_width: float | None = None,
        seed: int | None = None,
    ) -> Trajectory:
        """Build a trajectory from ``start`` to ``end``.

        ``target_width`` is the effective width of the destination along the
        movement axis, which Fitts's law uses to set stroke time; pass the
        element's smaller dimension for realistic timing.
        """
        origin = Point(float(start[0]), float(start[1]))
        target = Point(float(end[0]), float(end[1]))
        effective_seed = seed if seed is not None else self.seed
        rng = (
            random.Random(effective_seed)
            if effective_seed is not None
            else random.Random()
        )

        dx, dy = target.x - origin.x, target.y - origin.y
        distance = math.hypot(dx, dy)
        width = max(float(target_width or self.default_target_width), 1.0)
        duration = fitts_duration(
            distance,
            width,
            self.fitts_a,
            self.fitts_b,
            self.min_duration,
            self.max_duration,
        )

        if distance < 0.75:
            # Sub-pixel nudge: no arc, no tremor, just a short settle so that
            # hover debounces still see a discrete event.
            settle = min(duration, 0.05)
            return Trajectory(
                samples=(MouseSample(target.x, target.y, 1.0, settle),),
                start=origin,
                end=target,
                duration=settle,
                distance=distance,
                seed=effective_seed,
            )

        count = max(8, int(round(duration * self.samples_per_second)))
        ux, uy = dx / distance, dy / distance
        nx, ny = -uy, ux

        bend = distance * rng.uniform(*self.curvature)
        if rng.random() < 0.5:
            bend = -bend
        control_1 = Point(
            origin.x + dx * 0.28 + nx * bend,
            origin.y + dy * 0.28 + ny * bend,
        )
        control_2 = Point(
            origin.x + dx * 0.72 + nx * bend * rng.uniform(0.35, 0.95),
            origin.y + dy * 0.72 + ny * bend * rng.uniform(0.35, 0.95),
        )

        dense = max(count * 4, 96)
        np = numpy_module()
        if np is not None:
            curve = _sample_bezier_numpy(np, origin, control_1, control_2, target, dense)
        else:
            curve = [
                cubic_bezier_point(origin, control_1, control_2, target, i / (dense - 1))
                for i in range(dense)
            ]
        lengths = _cumulative_lengths(curve)
        total_length = lengths[-1]

        overshoot = rng.random() < self.overshoot_probability
        easing: Callable[[float], float]
        if overshoot:
            fraction = rng.uniform(*self.overshoot_fraction)

            def easing(t: float, fraction: float = fraction) -> float:
                return ease_in_out_overshoot(t, fraction)

        else:
            easing = ease_in_out_cubic

        amplitude = rng.uniform(*self.jitter_amplitude)
        lateral = _smooth_noise(count, rng)
        longitudinal = _smooth_noise(count, rng, octaves=2)

        coordinates: list[list[float]] = []
        for index in range(count):
            u = index / (count - 1)
            travelled = easing(u) * total_length
            base = _point_at_length(curve, lengths, travelled)
            # Tremor is full-strength through the stroke and fades only in the
            # last few percent, so the cursor lands exactly on the target.
            envelope = amplitude * (1.0 - u**4) * min(1.0, u * 8.0)
            jitter_x = nx * lateral[index] * envelope
            jitter_y = ny * lateral[index] * envelope
            jitter_x += ux * longitudinal[index] * envelope * 0.35
            jitter_y += uy * longitudinal[index] * envelope * 0.35
            coordinates.append([base.x + jitter_x, base.y + jitter_y])

        # Land exactly. Clamping here is what keeps kinematic movement safe for
        # coordinate assertions in tests.
        coordinates[-1] = [target.x, target.y]

        nominal_delay = duration / count
        precision = max(0, int(self.coordinate_precision))
        samples: list[MouseSample] = []
        for index, (x_value, y_value) in enumerate(coordinates):
            progress = index / (count - 1)
            if index == count - 1:
                delay = 0.0
            else:
                delay = nominal_delay * (
                    1.0 + rng.uniform(-self.timing_jitter, self.timing_jitter)
                )
            samples.append(
                MouseSample(
                    round(x_value, precision),
                    round(y_value, precision),
                    round(progress, 6),
                    max(delay, 0.0),
                )
            )

        return Trajectory(
            samples=tuple(samples),
            start=origin,
            end=target,
            duration=duration,
            distance=distance,
            seed=effective_seed,
        )


def _sample_bezier_numpy(
    np: Any, p0: Point, p1: Point, p2: Point, p3: Point, count: int
) -> list[Point]:
    """Vectorised cubic Bezier sampling (used when ``numpy`` is installed)."""
    t_values = np.linspace(0.0, 1.0, count, dtype=np.float64)
    u = 1.0 - t_values
    w0 = u**3
    w1 = 3.0 * u * u * t_values
    w2 = 3.0 * u * t_values * t_values
    w3 = t_values**3
    xs = w0 * p0[0] + w1 * p1[0] + w2 * p2[0] + w3 * p3[0]
    ys = w0 * p0[1] + w1 * p1[1] + w2 * p2[1] + w3 * p3[1]
    return [Point(float(x), float(y)) for x, y in zip(xs, ys, strict=True)]


# --------------------------------------------------------------------------- #
# Element targeting
# --------------------------------------------------------------------------- #


async def resolve_element_center(
    target: Any,
    *,
    page: Any = None,
    timeout: float | None = None,
    scroll_into_view: bool = True,
) -> Point:
    """Resolve a Playwright target to a viewport coordinate in CSS pixels.

    Accepts a ``Point``, an ``(x, y)`` pair, a ``Locator``/``ElementHandle``,
    or a selector string. A selector string has no page of its own, so one
    must be supplied -- either via ``page=`` or by the caller (the mouse
    drivers pass theirs).

    ``bounding_box()`` already returns main-frame viewport CSS pixels and
    already accounts for layout transforms and CSS ``zoom``, so the only
    correction needed is pinch-zoom (``visualViewport.scale``), which is
    non-1 on emulated mobile devices with ``is_mobile=True``.
    """
    owner = page if page is not None else getattr(target, "page", None)
    if owner is None and hasattr(target, "evaluate"):
        owner = target

    if isinstance(target, Point):
        return target
    if isinstance(target, (tuple, list)) and len(target) == 2:
        return Point(float(target[0]), float(target[1]))

    if hasattr(target, "bounding_box"):
        locator = target
    elif owner is not None:
        locator = owner.locator(str(target))
    else:
        raise ValueError(
            f"cannot resolve {target!r}: a selector string needs a page "
            "(pass page=..., or use a Locator)"
        )

    if scroll_into_view:
        await locator.scroll_into_view_if_needed(timeout=timeout)
    box = await locator.bounding_box(timeout=timeout)
    if box is None:
        raise LookupError(f"target has no bounding box and cannot be clicked: {target!r}")
    scale = await _viewport_scale(owner)
    return Point(
        (box["x"] + box["width"] / 2.0) * scale,
        (box["y"] + box["height"] / 2.0) * scale,
    )


def resolve_element_center_sync(
    target: Any,
    *,
    page: Any = None,
    timeout: float | None = None,
    scroll_into_view: bool = True,
) -> Point:
    """Blocking twin of :func:`resolve_element_center`."""
    owner = page if page is not None else getattr(target, "page", None)
    if owner is None and hasattr(target, "evaluate"):
        owner = target

    if isinstance(target, Point):
        return target
    if isinstance(target, (tuple, list)) and len(target) == 2:
        return Point(float(target[0]), float(target[1]))

    if hasattr(target, "bounding_box"):
        locator = target
    elif owner is not None:
        locator = owner.locator(str(target))
    else:
        raise ValueError(
            f"cannot resolve {target!r}: a selector string needs a page "
            "(pass page=..., or use a Locator)"
        )

    if scroll_into_view:
        locator.scroll_into_view_if_needed(timeout=timeout)
    box = locator.bounding_box(timeout=timeout)
    if box is None:
        raise LookupError(f"target has no bounding box and cannot be clicked: {target!r}")
    scale = _viewport_scale_sync(owner)
    return Point(
        (box["x"] + box["width"] / 2.0) * scale,
        (box["y"] + box["height"] / 2.0) * scale,
    )


async def _viewport_scale(page: Any) -> float:
    """Return ``visualViewport.scale`` (pinch-zoom), defaulting to ``1.0``."""
    try:
        value = await page.evaluate(
            "() => (window.visualViewport && window.visualViewport.scale) || 1"
        )
    except Exception:
        return 1.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 1.0


def _viewport_scale_sync(page: Any) -> float:
    try:
        value = page.evaluate(
            "() => (window.visualViewport && window.visualViewport.scale) || 1"
        )
    except Exception:
        return 1.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 1.0


# --------------------------------------------------------------------------- #
# Async driver
# --------------------------------------------------------------------------- #


class KinematicMouse:
    """Async Playwright pointer driver that moves along planned trajectories.

    Tracks its own cursor position so consecutive ``click`` calls chain
    naturally instead of teleporting back to the origin.
    """

    def __init__(
        self,
        page: Any,
        planner: TrajectoryPlanner | None = None,
        *,
        position: Sequence[float] | Point | None = None,
        hover_delay: tuple[float, float] = (0.045, 0.17),
        pre_click_delay: tuple[float, float] = (0.02, 0.09),
        press_duration: tuple[float, float] = (0.02, 0.07),
        post_click_delay: tuple[float, float] = (0.04, 0.13),
        typing_delay: tuple[float, float] = (0.03, 0.15),
        word_pause: tuple[float, float] = (0.08, 0.26),
        seed: int | None = None,
    ) -> None:
        self.page = page
        self.planner = planner or TrajectoryPlanner(seed=seed)
        self.hover_delay = hover_delay
        self.pre_click_delay = pre_click_delay
        self.press_duration = press_duration
        self.post_click_delay = post_click_delay
        self.typing_delay = typing_delay
        self.word_pause = word_pause
        self._rng = random.Random(seed)
        self._position = (
            Point(float(position[0]), float(position[1]))
            if position is not None
            else Point(0.0, 0.0)
        )

    @property
    def position(self) -> Point:
        """Last known cursor position."""
        return self._position

    async def _sleep(self, seconds: float) -> None:
        if seconds > 0:
            await asyncio.sleep(seconds)

    async def move_to(
        self,
        target: Any,
        *,
        target_width: float | None = None,
        seed: int | None = None,
        timeout: float | None = None,
    ) -> Trajectory:
        """Move the cursor to ``target`` and return the trajectory played."""
        destination = await resolve_element_center(
            target, page=self.page, timeout=timeout
        )
        trajectory = self.planner.plan(
            self._position, destination, target_width=target_width, seed=seed
        )
        for sample in trajectory.samples:
            await self.page.mouse.move(sample.x, sample.y)
            await self._sleep(sample.delay)
        self._position = Point(trajectory.end.x, trajectory.end.y)
        return trajectory

    async def hover(
        self,
        target: Any,
        *,
        settle: float | None = None,
        target_width: float | None = None,
        timeout: float | None = None,
    ) -> Trajectory:
        """Move to ``target``, then dwell like a user reading before acting."""
        trajectory = await self.move_to(
            target, target_width=target_width, timeout=timeout
        )
        dwell = settle if settle is not None else self._rng.uniform(*self.hover_delay)
        await self._sleep(dwell)
        return trajectory

    async def click(
        self,
        target: Any,
        *,
        button: str = "left",
        click_count: int = 1,
        target_width: float | None = None,
        timeout: float | None = None,
        settle_before: bool = True,
    ) -> Trajectory:
        """Hover, pause, press, release at ``target``."""
        trajectory = await self.move_to(
            target, target_width=target_width, timeout=timeout
        )
        if settle_before:
            await self._sleep(self._rng.uniform(*self.pre_click_delay))
        for index in range(max(1, click_count)):
            await self.page.mouse.down(button=button)
            await self._sleep(self._rng.uniform(*self.press_duration))
            await self.page.mouse.up(button=button)
            if index + 1 < max(1, click_count):
                await self._sleep(self._rng.uniform(0.04, 0.11))
        await self._sleep(self._rng.uniform(*self.post_click_delay))
        return trajectory

    async def drag_to(
        self,
        source: Any,
        destination: Any,
        *,
        button: str = "left",
        hold_delay: tuple[float, float] = (0.05, 0.14),
        release_delay: tuple[float, float] = (0.04, 0.12),
        timeout: float | None = None,
    ) -> Trajectory:
        """Press at ``source``, travel the arc to ``destination``, release."""
        await self.move_to(source, timeout=timeout)
        await self._sleep(self._rng.uniform(*hold_delay))
        await self.page.mouse.down(button=button)
        trajectory = await self.move_to(destination, timeout=timeout)
        await self._sleep(self._rng.uniform(*release_delay))
        await self.page.mouse.up(button=button)
        return trajectory

    async def type_text(
        self,
        target: Any,
        text: str,
        *,
        clear_first: bool = False,
        press_enter: bool = False,
        timeout: float | None = None,
    ) -> None:
        """Focus ``target`` and type ``text`` with human-plausible key timing."""
        await self.click(target, timeout=timeout)
        if clear_first:
            await self.page.keyboard.press("ControlOrMeta+A")
            await self.page.keyboard.press("Delete")
            await self._sleep(self._rng.uniform(0.03, 0.09))
        for character in text:
            await self.page.keyboard.type(character)
            await self._sleep(self._rng.uniform(*self.typing_delay))
            if character in " \t\n":
                await self._sleep(self._rng.uniform(*self.word_pause))
        if press_enter:
            await self._sleep(self._rng.uniform(0.05, 0.18))
            await self.page.keyboard.press("Enter")

    async def scroll_by(
        self,
        delta_x: float,
        delta_y: float,
        *,
        steps: int | None = None,
    ) -> None:
        """Scroll in increments, because real wheels emit discrete deltas."""
        magnitude = math.hypot(delta_x, delta_y)
        count = steps if steps is not None else max(1, int(magnitude // 100) + 1)
        step_x, step_y = delta_x / count, delta_y / count
        for _ in range(count):
            await self.page.mouse.wheel(step_x, step_y)
            await self._sleep(self._rng.uniform(0.01, 0.045))


# --------------------------------------------------------------------------- #
# Blocking driver
# --------------------------------------------------------------------------- #


class KinematicMouseSync:
    """Blocking twin of :class:`KinematicMouse` for sync Playwright pages."""

    def __init__(
        self,
        page: Any,
        planner: TrajectoryPlanner | None = None,
        *,
        position: Sequence[float] | Point | None = None,
        hover_delay: tuple[float, float] = (0.045, 0.17),
        pre_click_delay: tuple[float, float] = (0.02, 0.09),
        press_duration: tuple[float, float] = (0.02, 0.07),
        post_click_delay: tuple[float, float] = (0.04, 0.13),
        typing_delay: tuple[float, float] = (0.03, 0.15),
        word_pause: tuple[float, float] = (0.08, 0.26),
        seed: int | None = None,
    ) -> None:
        self.page = page
        self.planner = planner or TrajectoryPlanner(seed=seed)
        self.hover_delay = hover_delay
        self.pre_click_delay = pre_click_delay
        self.press_duration = press_duration
        self.post_click_delay = post_click_delay
        self.typing_delay = typing_delay
        self.word_pause = word_pause
        self._rng = random.Random(seed)
        self._position = (
            Point(float(position[0]), float(position[1]))
            if position is not None
            else Point(0.0, 0.0)
        )

    @property
    def position(self) -> Point:
        """Last known cursor position."""
        return self._position

    def _sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)

    def move_to(
        self,
        target: Any,
        *,
        target_width: float | None = None,
        seed: int | None = None,
        timeout: float | None = None,
    ) -> Trajectory:
        """Move the cursor to ``target`` and return the trajectory played."""
        destination = resolve_element_center_sync(
            target, page=self.page, timeout=timeout
        )
        trajectory = self.planner.plan(
            self._position, destination, target_width=target_width, seed=seed
        )
        for sample in trajectory.samples:
            self.page.mouse.move(sample.x, sample.y)
            self._sleep(sample.delay)
        self._position = Point(trajectory.end.x, trajectory.end.y)
        return trajectory

    def hover(
        self,
        target: Any,
        *,
        settle: float | None = None,
        target_width: float | None = None,
        timeout: float | None = None,
    ) -> Trajectory:
        """Move to ``target``, then dwell before acting."""
        trajectory = self.move_to(target, target_width=target_width, timeout=timeout)
        dwell = settle if settle is not None else self._rng.uniform(*self.hover_delay)
        self._sleep(dwell)
        return trajectory

    def click(
        self,
        target: Any,
        *,
        button: str = "left",
        click_count: int = 1,
        target_width: float | None = None,
        timeout: float | None = None,
        settle_before: bool = True,
    ) -> Trajectory:
        """Hover, pause, press, release at ``target``."""
        trajectory = self.move_to(target, target_width=target_width, timeout=timeout)
        if settle_before:
            self._sleep(self._rng.uniform(*self.pre_click_delay))
        for index in range(max(1, click_count)):
            self.page.mouse.down(button=button)
            self._sleep(self._rng.uniform(*self.press_duration))
            self.page.mouse.up(button=button)
            if index + 1 < max(1, click_count):
                self._sleep(self._rng.uniform(0.04, 0.11))
        self._sleep(self._rng.uniform(*self.post_click_delay))
        return trajectory

    def drag_to(
        self,
        source: Any,
        destination: Any,
        *,
        button: str = "left",
        hold_delay: tuple[float, float] = (0.05, 0.14),
        release_delay: tuple[float, float] = (0.04, 0.12),
        timeout: float | None = None,
    ) -> Trajectory:
        """Press at ``source``, travel the arc to ``destination``, release."""
        self.move_to(source, timeout=timeout)
        self._sleep(self._rng.uniform(*hold_delay))
        self.page.mouse.down(button=button)
        trajectory = self.move_to(destination, timeout=timeout)
        self._sleep(self._rng.uniform(*release_delay))
        self.page.mouse.up(button=button)
        return trajectory

    def type_text(
        self,
        target: Any,
        text: str,
        *,
        clear_first: bool = False,
        press_enter: bool = False,
        timeout: float | None = None,
    ) -> None:
        """Focus ``target`` and type ``text`` with human-plausible key timing."""
        self.click(target, timeout=timeout)
        if clear_first:
            self.page.keyboard.press("ControlOrMeta+A")
            self.page.keyboard.press("Delete")
            self._sleep(self._rng.uniform(0.03, 0.09))
        for character in text:
            self.page.keyboard.type(character)
            self._sleep(self._rng.uniform(*self.typing_delay))
            if character in " \t\n":
                self._sleep(self._rng.uniform(*self.word_pause))
        if press_enter:
            self._sleep(self._rng.uniform(0.05, 0.18))
            self.page.keyboard.press("Enter")

    def scroll_by(
        self,
        delta_x: float,
        delta_y: float,
        *,
        steps: int | None = None,
    ) -> None:
        """Scroll in increments, because real wheels emit discrete deltas."""
        magnitude = math.hypot(delta_x, delta_y)
        count = steps if steps is not None else max(1, int(magnitude // 100) + 1)
        step_x, step_y = delta_x / count, delta_y / count
        for _ in range(count):
            self.page.mouse.wheel(step_x, step_y)
            self._sleep(self._rng.uniform(0.01, 0.045))


def iter_samples(trajectory: Trajectory) -> Iterable[MouseSample]:
    """Yield a trajectory's samples (convenience for custom players)."""
    return iter(trajectory.samples)

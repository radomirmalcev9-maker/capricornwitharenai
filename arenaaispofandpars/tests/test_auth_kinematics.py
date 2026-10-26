"""Tests for the pointer-kinematics engine (no browser required)."""

from __future__ import annotations

import asyncio
import math

import pytest

from arena_api.auth.kinematics import (
    KinematicMouse,
    KinematicMouseSync,
    Point,
    TrajectoryPlanner,
    cubic_bezier_point,
    ease_in_out_cubic,
    ease_out_back,
    fitts_duration,
    resolve_element_center,
)

# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


class FakeMouse:
    def __init__(self) -> None:
        self.moves: list[tuple[float, float]] = []
        self.presses: list[str] = []

    async def move(self, x: float, y: float) -> None:
        self.moves.append((x, y))

    async def down(self, button: str = "left") -> None:
        self.presses.append(f"down:{button}")

    async def up(self, button: str = "left") -> None:
        self.presses.append(f"up:{button}")

    async def wheel(self, dx: float, dy: float) -> None:
        self.moves.append((dx, dy))


class SyncMouse:
    def __init__(self) -> None:
        self.moves: list[tuple[float, float]] = []
        self.presses: list[str] = []

    def move(self, x: float, y: float) -> None:
        self.moves.append((x, y))

    def down(self, button: str = "left") -> None:
        self.presses.append(f"down:{button}")

    def up(self, button: str = "left") -> None:
        self.presses.append(f"up:{button}")

    def wheel(self, dx: float, dy: float) -> None:
        self.moves.append((dx, dy))


class FakeKeyboard:
    def __init__(self) -> None:
        self.typed: list[str] = []

    async def type(self, text: str) -> None:
        self.typed.append(text)

    async def press(self, key: str) -> None:
        self.typed.append(f"<{key}>")


class SyncKeyboard:
    def __init__(self) -> None:
        self.typed: list[str] = []

    def type(self, text: str) -> None:
        self.typed.append(text)

    def press(self, key: str) -> None:
        self.typed.append(f"<{key}>")


class FakePage:
    def __init__(self) -> None:
        self.mouse = FakeMouse()
        self.keyboard = FakeKeyboard()
        self.url = "https://example.test/"

    async def evaluate(self, script: str, arg=None):
        return 1


class SyncPage:
    def __init__(self) -> None:
        self.mouse = SyncMouse()
        self.keyboard = SyncKeyboard()
        self.url = "https://example.test/"

    def evaluate(self, script: str, arg=None):
        return 1


class FakeLocator:
    """Minimal Locator stand-in returning a fixed box."""

    def __init__(self, box: dict[str, float], page: object | None = None) -> None:
        self._box = box
        self.page = page if page is not None else FakePage()
        self.scrolled = False

    async def scroll_into_view_if_needed(self, timeout=None) -> None:
        self.scrolled = True

    async def bounding_box(self, timeout=None) -> dict[str, float]:
        return self._box


# --------------------------------------------------------------------------- #
# Easing and geometry
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("t", [0.0, 0.25, 0.5, 0.75, 1.0])
def test_ease_in_out_cubic_endpoints_and_symmetry(t: float) -> None:
    assert ease_in_out_cubic(0.0) == 0.0
    assert ease_in_out_cubic(1.0) == 1.0
    assert math.isclose(ease_in_out_cubic(t), 1.0 - ease_in_out_cubic(1.0 - t), abs_tol=1e-12)


def test_ease_out_back_overshoots_then_lands() -> None:
    assert ease_out_back(1.0) == 1.0
    assert ease_out_back(0.0) == 0.0
    assert max(ease_out_back(i / 100) for i in range(101)) > 1.0


def test_cubic_bezier_endpoints() -> None:
    p0, p1, p2, p3 = (0.0, 0.0), (1.0, 2.0), (3.0, 4.0), (10.0, 0.0)
    start = cubic_bezier_point(p0, p1, p2, p3, 0.0)
    end = cubic_bezier_point(p0, p1, p2, p3, 1.0)
    assert (start.x, start.y) == (0.0, 0.0)
    assert (end.x, end.y) == (10.0, 0.0)


def test_fitts_duration_grows_with_distance_and_is_clamped() -> None:
    near = fitts_duration(10, 26)
    far = fitts_duration(1500, 26)
    assert near < far
    assert fitts_duration(0, 26) >= 0.09
    assert fitts_duration(10**9, 26) <= 1.35


def test_fitts_duration_narrower_target_takes_longer() -> None:
    assert fitts_duration(400, 4) > fitts_duration(400, 200)


# --------------------------------------------------------------------------- #
# Planner
# --------------------------------------------------------------------------- #


def test_plan_is_deterministic_for_a_seed() -> None:
    planner = TrajectoryPlanner(seed=1234)
    first = planner.plan((0, 0), (640, 480))
    second = planner.plan((0, 0), (640, 480))
    assert first.samples == second.samples
    assert first.seed == 1234


def test_different_seeds_produce_different_paths() -> None:
    first = TrajectoryPlanner(seed=1).plan((0, 0), (640, 480))
    second = TrajectoryPlanner(seed=2).plan((0, 0), (640, 480))
    assert first.samples != second.samples


def test_trajectory_lands_exactly_on_target() -> None:
    for seed in range(40):
        trajectory = TrajectoryPlanner(seed=seed).plan((10.5, 12.25), (987.5, 654.25))
        last = trajectory.samples[-1]
        assert (last.x, last.y) == (987.5, 654.25)


def test_trajectory_starts_near_origin_and_is_longer_than_straight_line() -> None:
    trajectory = TrajectoryPlanner(seed=7).plan((0, 0), (600, 0))
    assert math.hypot(trajectory.samples[0].x, trajectory.samples[0].y) < 25
    assert trajectory.straightness >= 1.0
    assert trajectory.length > trajectory.distance


def test_trajectory_has_no_teleports() -> None:
    """Peak per-frame motion must stay inside human motor limits.

    A "teleport" would be one frame covering a large fraction of the whole
    journey. The physical bound is velocity: even a fast flick peaks around
    5-8k CSS px/s, well under the 9k asserted here.
    """
    trajectory = TrajectoryPlanner(seed=11).plan((0, 0), (900, 600))
    previous = trajectory.start
    peak_velocity = 0.0
    for sample in trajectory.samples:
        step = math.hypot(sample.x - previous.x, sample.y - previous.y)
        assert step < 0.10 * trajectory.distance, (
            "one frame covered more than 10% of the journey"
        )
        if sample.delay > 0:
            peak_velocity = max(peak_velocity, step / sample.delay)
        previous = Point(sample.x, sample.y)
    assert peak_velocity < 9_000, f"peak velocity {peak_velocity:.0f} px/s is not human"
    assert trajectory.settle_time > 0


def test_overshoot_settles_back_onto_the_target() -> None:
    """An overshooting stroke must still land exactly on the destination."""
    for seed in range(60):
        trajectory = TrajectoryPlanner(
            seed=seed, overshoot_probability=1.0, overshoot_fraction=(0.07, 0.07)
        ).plan((0, 0), (800, 400))
        assert trajectory.samples[-1].x == 800
        assert trajectory.samples[-1].y == 400
        # ... and it must actually have gone past it at some point.
        assert max(math.hypot(s.x, s.y) for s in trajectory.samples) > math.hypot(
            800, 400
        )


def test_sub_pixel_move_is_a_single_sample() -> None:
    trajectory = TrajectoryPlanner(seed=3).plan((100, 100), (100.2, 100.1))
    assert len(trajectory) == 1
    assert trajectory.samples[0].delay > 0


def test_planner_without_seed_still_produces_valid_paths() -> None:
    trajectory = TrajectoryPlanner().plan((0, 0), (300, 300))
    assert trajectory.seed is None
    assert len(trajectory) > 8
    assert trajectory.samples[-1].x == 300


def test_target_width_affects_stroke_time() -> None:
    planner = TrajectoryPlanner(seed=5)
    small = planner.plan((0, 0), (500, 0), target_width=4)
    large = planner.plan((0, 0), (500, 0), target_width=400)
    assert small.duration > large.duration


# --------------------------------------------------------------------------- #
# Element resolution
# --------------------------------------------------------------------------- #


def test_resolve_element_center_uses_box_centre() -> None:
    locator = FakeLocator({"x": 100.0, "y": 50.0, "width": 200.0, "height": 40.0})
    centre = asyncio.run(resolve_element_center(locator))
    assert centre == Point(200.0, 70.0)
    assert locator.scrolled is True


def test_resolve_element_center_accepts_points_and_pairs() -> None:
    assert asyncio.run(resolve_element_center(Point(3, 4))) == Point(3, 4)
    assert asyncio.run(resolve_element_center((5, 6))) == Point(5.0, 6.0)


def test_resolve_element_center_raises_when_box_is_missing() -> None:
    class Empty:
        page = FakePage()

        async def scroll_into_view_if_needed(self, timeout=None) -> None:
            return None

        async def bounding_box(self, timeout=None):
            return None

    with pytest.raises(LookupError):
        asyncio.run(resolve_element_center(Empty()))


# --------------------------------------------------------------------------- #
# Drivers
# --------------------------------------------------------------------------- #


def test_async_mouse_moves_and_tracks_position() -> None:
    page = FakePage()
    mouse = KinematicMouse(page, TrajectoryPlanner(seed=21), seed=21)

    async def scenario() -> None:
        await mouse.move_to(Point(300, 200))
        assert mouse.position == Point(300, 200)
        await mouse.click(Point(320, 210))

    asyncio.run(scenario())
    assert page.mouse.moves
    assert page.mouse.presses[:2] == ["down:left", "up:left"]
    assert page.mouse.moves[-1] == (320, 210)


def test_async_mouse_hover_emits_moves_without_pressing() -> None:
    page = FakePage()
    mouse = KinematicMouse(page, seed=1)

    async def scenario() -> None:
        await mouse.hover(Point(120, 80), settle=0)

    asyncio.run(scenario())
    assert page.mouse.moves and page.mouse.presses == []


def test_async_mouse_types_with_pauses() -> None:
    page = FakePage()
    mouse = KinematicMouse(page, seed=2)

    async def scenario() -> None:
        await mouse.type_text(Point(10, 10), "ab cd", press_enter=True)

    asyncio.run(scenario())
    assert "".join(c for c in page.keyboard.typed if len(c) == 1) == "ab cd"
    assert page.keyboard.typed[-1] == "<Enter>"


def test_sync_mouse_mirrors_async_behaviour() -> None:
    page = SyncPage()
    mouse = KinematicMouseSync(page, TrajectoryPlanner(seed=9), seed=9)
    mouse.move_to(Point(200, 150))
    assert mouse.position == Point(200, 150)
    mouse.click(Point(210, 160))
    assert page.mouse.presses[:2] == ["down:left", "up:left"]


def test_scroll_by_emits_multiple_wheel_events() -> None:
    page = FakePage()
    mouse = KinematicMouse(page, seed=4)

    async def scenario() -> None:
        await mouse.scroll_by(0, 500, steps=5)

    asyncio.run(scenario())
    assert len(page.mouse.moves) == 5

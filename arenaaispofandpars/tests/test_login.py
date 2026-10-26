"""Tests for the interactive sign-in primitive (``arena_api.auth.login``).

Nothing here launches a browser: a fake environment scripts the cookie
snapshots a real context would report, so the acceptance heuristic, the state
file handling and the prompt loop are all covered offline.
"""

from __future__ import annotations

import asyncio
import json
import os
from io import StringIO
from pathlib import Path
from typing import Any

import pytest

from arena_api.auth import login as login_module
from arena_api.auth.login import (
    DEFAULT_STATE_PATH,
    STATE_FILE_MODE,
    LoginResult,
    alogin_and_save,
    login_and_save,
    login_environment_options,
)
from arena_api.auth.browser import BrowserEnvironmentOptions
from arena_api.auth.environment import HIDE_WEBDRIVER_SCRIPT


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


def cookie(name: str, value: str = "v", domain: str = "arena.ai") -> dict[str, Any]:
    """One Playwright-shaped cookie record."""
    return {
        "name": name,
        "value": value,
        "domain": domain,
        "path": "/",
        "expires": -1,
        "httpOnly": True,
        "secure": True,
        "sameSite": "Lax",
    }


class FakeContext:
    """Returns scripted cookie snapshots, one per ``cookies()`` call."""

    def __init__(self, snapshots: list[list[dict[str, Any]]]) -> None:
        self.snapshots = snapshots
        self.calls = 0
        self.saved_to: list[str] = []

    async def cookies(self) -> list[dict[str, Any]]:
        index = min(self.calls, len(self.snapshots) - 1)
        self.calls += 1
        return [dict(item) for item in self.snapshots[index]]

    async def storage_state(self, path: str | None = None) -> dict[str, Any]:
        assert path is not None, "login always persists to an explicit path"
        self.saved_to.append(str(path))
        payload = {"cookies": self.snapshots[-1], "origins": []}
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(payload), encoding="utf-8")
        return payload


class FakePage:
    def __init__(self, url: str = "https://arena.ai/", final_url: str | None = None) -> None:
        self.url = url
        self.final_url = final_url
        self.visited: list[tuple[str, str]] = []

    async def goto(self, url: str, wait_until: str | None = None) -> None:
        self.visited.append((url, wait_until or ""))
        # ``final_url`` stands in for a redirect the site performs on arrival.
        self.url = self.final_url or url


class FakeEnvironment:
    """Stands in for :class:`~arena_api.auth.browser.BrowserEnvironment`."""

    def __init__(
        self,
        snapshots: list[list[dict[str, Any]]],
        options: Any = None,
        url: str = "https://arena.ai/",
        final_url: str | None = None,
    ) -> None:
        self.options = options
        self.context = FakeContext(snapshots)
        self.page = FakePage(url, final_url=final_url)
        self.started = False
        self.closed = False

    async def start(self) -> "FakeEnvironment":
        self.started = True
        return self

    async def new_context(self, **overrides: Any) -> FakeContext:
        return self.context

    async def new_page(self, context: Any = None, **overrides: Any) -> FakePage:
        return self.page

    async def close(self) -> None:
        self.closed = True


class Prompt:
    """Records instructions; optionally raises like Ctrl-C or a closed stdin."""

    def __init__(self, error: type[BaseException] | None = None) -> None:
        self.messages: list[str] = []
        self.error = error

    def __call__(self, message: str) -> str:
        self.messages.append(message)
        if self.error is not None:
            raise self.error()
        return ""


class RecordingFlow:
    """Stands in for :class:`~arena_api.auth.session.LoginFlow`."""

    def __init__(self) -> None:
        self.pages: list[Any] = []

    async def run(self, page: Any) -> None:
        self.pages.append(page)


class Notes:
    """Collects progress notes written to ``output``."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def write(self, text: str) -> None:
        self.lines.append(text.rstrip("\n"))

    def flush(self) -> None:
        return None

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


def run(coro: Any) -> Any:
    return asyncio.run(coro)


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_login_saves_the_state_file_when_new_cookies_appear(tmp_path: Path) -> None:
    destination = tmp_path / "state" / "cookies.json"
    environment = FakeEnvironment(
        [
            [cookie("cf", "before")],  # snapshot right after navigation
            [cookie("cf", "before"), cookie("session", "abc")],  # round 1
        ]
    )
    prompt = Prompt()

    result = run(
        alogin_and_save(
            path=destination,
            environment=environment,  # type: ignore[arg-type]
            prompt=prompt,
        )
    )

    assert result.accepted is True
    assert result.attempts == 1
    assert result.saved is True
    assert result.path == destination
    assert result.ok is True
    assert destination.is_file()
    assert json.loads(destination.read_text())["cookies"][-1]["name"] == "session"
    assert len(prompt.messages) == 1
    assert "Sign in to arena.ai" in prompt.messages[0]


def test_saved_state_file_is_owner_only(tmp_path: Path) -> None:
    """A state file is a live credential: 0600 where the platform allows it."""
    destination = tmp_path / "cookies.json"
    environment = FakeEnvironment([[], [cookie("session", "abc")]])

    run(
        alogin_and_save(
            path=destination,
            environment=environment,  # type: ignore[arg-type]
            prompt=Prompt(),
        )
    )

    if os.name == "nt":  # pragma: no cover - Windows ACLs are out of scope
        pytest.skip("POSIX permission bits do not apply on Windows")
    assert destination.stat().st_mode & 0o777 == STATE_FILE_MODE


def test_login_reports_what_it_captured(tmp_path: Path) -> None:
    destination = tmp_path / "cookies.json"
    environment = FakeEnvironment(
        [[], [cookie("session", "abc"), cookie("theme", "dark", domain=".arena.ai")]]
    )

    result = run(
        alogin_and_save(
            path=destination,
            environment=environment,  # type: ignore[arg-type]
            prompt=Prompt(),
        )
    )

    assert result.names == ("session", "theme")
    assert result.site_cookies() == {"session": "abc", "theme": "dark"}
    assert result.cookie_header() == "session=abc; theme=dark"
    assert result.domains == ("arena.ai",)
    assert "1 round(s)" in result.describe()
    assert str(destination) in result.describe()
    assert bool(result) is True


def test_sync_wrapper_returns_the_same_result(tmp_path: Path) -> None:
    destination = tmp_path / "cookies.json"
    environment = FakeEnvironment([[], [cookie("session", "abc")]])

    result = login_and_save(
        path=destination,
        environment=environment,
        prompt=Prompt(),
    )

    assert isinstance(result, LoginResult)
    assert result.saved is True
    assert destination.is_file()


def test_navigation_uses_the_requested_start_url(tmp_path: Path) -> None:
    environment = FakeEnvironment([[], [cookie("session", "abc")]])

    run(
        alogin_and_save(
            base_url="https://arena.ai",
            start_url="https://arena.ai/login",
            path=tmp_path / "cookies.json",
            environment=environment,  # type: ignore[arg-type]
            prompt=Prompt(),
        )
    )

    assert environment.page.visited == [("https://arena.ai/login", "domcontentloaded")]


def test_final_url_is_reported(tmp_path: Path) -> None:
    """Where the site parked you is worth reporting (consent screens, 2FA)."""
    environment = FakeEnvironment(
        [[], [cookie("session", "abc")]], final_url="https://arena.ai/app"
    )

    result = run(
        alogin_and_save(
            path=tmp_path / "cookies.json",
            environment=environment,  # type: ignore[arg-type]
            prompt=Prompt(),
        )
    )

    assert result.url == "https://arena.ai/app"


# --------------------------------------------------------------------------- #
# The prompt loop
# --------------------------------------------------------------------------- #


def test_login_keeps_prompting_until_a_round_is_accepted(tmp_path: Path) -> None:
    unchanged = [cookie("cf", "same")]
    environment = FakeEnvironment(
        [unchanged, unchanged, list(unchanged) + [cookie("session", "abc")]]
    )
    prompt = Prompt()

    result = run(
        alogin_and_save(
            path=tmp_path / "cookies.json",
            environment=environment,  # type: ignore[arg-type]
            prompt=prompt,
        )
    )

    assert result.attempts == 2
    assert len(prompt.messages) == 2
    assert result.saved is True


def test_exhausted_rounds_leave_an_existing_session_untouched(tmp_path: Path) -> None:
    """Trading a working session for an anonymous one would be worse than nothing."""
    destination = tmp_path / "cookies.json"
    destination.write_text(json.dumps({"cookies": [cookie("session", "keep")]}), encoding="utf-8")
    before = destination.read_text(encoding="utf-8")
    environment = FakeEnvironment([[cookie("cf", "x")], [cookie("cf", "x")]])
    notes = Notes()

    result = run(
        alogin_and_save(
            path=destination,
            rounds=2,
            environment=environment,  # type: ignore[arg-type]
            prompt=Prompt(),
            output=notes,
        )
    )

    assert result.accepted is False
    assert result.attempts == 2
    assert result.saved is False
    assert result.path is None
    assert result.ok is False
    assert destination.read_text(encoding="utf-8") == before
    assert environment.context.saved_to == []
    assert "no sign-in detected" in notes.text
    assert "round 1/2" in notes.text and "round 2/2" in notes.text


def test_cancellation_keeps_the_cookies_seen_so_far(tmp_path: Path) -> None:
    environment = FakeEnvironment([[cookie("cf", "x")], [cookie("cf", "x")]])
    notes = Notes()

    result = run(
        alogin_and_save(
            path=tmp_path / "cookies.json",
            rounds=3,
            environment=environment,  # type: ignore[arg-type]
            prompt=Prompt(error=KeyboardInterrupt),
            output=notes,
        )
    )

    assert result.attempts == 0
    assert result.saved is False
    assert result.accepted is False
    assert "cancelled" in notes.text
    assert result.cookies  # whatever the browser held is still reported


def test_closed_stdin_is_treated_as_a_cancel(tmp_path: Path) -> None:
    environment = FakeEnvironment([[], []])

    result = run(
        alogin_and_save(
            path=tmp_path / "cookies.json",
            environment=environment,  # type: ignore[arg-type]
            prompt=Prompt(error=EOFError),
        )
    )

    assert result.saved is False


def test_zero_rounds_never_prompts_but_still_saves(tmp_path: Path) -> None:
    """An unattended ``login_flow`` needs no Enter press at all."""
    destination = tmp_path / "cookies.json"
    environment = FakeEnvironment([[cookie("session", "abc")], [cookie("session", "abc")]])
    prompt = Prompt()

    result = run(
        alogin_and_save(
            path=destination,
            rounds=0,
            environment=environment,  # type: ignore[arg-type]
            prompt=prompt,
        )
    )

    assert prompt.messages == []
    assert result.attempts == 0
    assert result.accepted is False
    assert result.saved is True
    assert destination.is_file()


def test_login_flow_runs_before_the_wait(tmp_path: Path) -> None:
    environment = FakeEnvironment([[], [cookie("session", "abc")]])
    flow = RecordingFlow()

    result = run(
        alogin_and_save(
            path=tmp_path / "cookies.json",
            rounds=0,
            login_flow=flow,
            environment=environment,  # type: ignore[arg-type]
            prompt=Prompt(),
        )
    )

    assert flow.pages == [environment.page]
    assert result.saved is True


# --------------------------------------------------------------------------- #
# Acceptance rules
# --------------------------------------------------------------------------- #


def test_a_custom_predicate_may_accept_with_fewer_arguments(tmp_path: Path) -> None:
    environment = FakeEnvironment([[cookie("cf", "x")], [cookie("cf", "x")]])

    result = run(
        alogin_and_save(
            path=tmp_path / "cookies.json",
            rounds=1,
            accept=lambda cookies: any(item["name"] == "cf" for item in cookies),
            environment=environment,  # type: ignore[arg-type]
            prompt=Prompt(),
        )
    )

    assert result.accepted is True
    assert result.saved is True


def test_a_custom_predicate_may_be_async_and_use_the_page(tmp_path: Path) -> None:
    environment = FakeEnvironment([[], []])
    seen: list[Any] = []

    async def accept(cookies: Any, page: Any, context: Any) -> bool:
        seen.append((page, context))
        return True

    result = run(
        alogin_and_save(
            path=tmp_path / "cookies.json",
            rounds=1,
            accept=accept,
            environment=environment,  # type: ignore[arg-type]
            prompt=Prompt(),
        )
    )

    assert result.accepted is True
    assert seen == [(environment.page, environment.context)]


def test_a_rejected_round_keeps_the_loop_going(tmp_path: Path) -> None:
    environment = FakeEnvironment(
        [[], [], [cookie("cf", "x"), cookie("session", "abc")]]
    )
    calls: list[int] = []

    def accept(cookies: Any) -> bool:
        calls.append(len(cookies))
        return len(cookies) > 1

    result = run(
        alogin_and_save(
            path=tmp_path / "cookies.json",
            rounds=2,
            accept=accept,
            environment=environment,  # type: ignore[arg-type]
            prompt=Prompt(),
        )
    )

    assert calls == [0, 2]
    assert result.accepted is True
    assert result.attempts == 2


def test_cookies_of_other_domains_do_not_count(tmp_path: Path) -> None:
    """A third-party cookie appearing is not a sign-in."""
    environment = FakeEnvironment(
        [[cookie("ad", "1", domain="ads.example")], [cookie("ad", "2", domain="ads.example")]]
    )

    result = run(
        alogin_and_save(
            base_url="https://arena.ai",
            path=tmp_path / "cookies.json",
            rounds=1,
            environment=environment,  # type: ignore[arg-type]
            prompt=Prompt(),
        )
    )

    assert result.accepted is False
    assert result.site_cookies() == {}


def test_explicit_domains_override_the_base_url(tmp_path: Path) -> None:
    environment = FakeEnvironment(
        [[], [cookie("session", "abc", domain="lmarena.ai"), cookie("x", "1", domain="arena.ai")]]
    )

    result = run(
        alogin_and_save(
            base_url="https://arena.ai",
            domains=["lmarena.ai", "lmarena.ai", ".sub.lmarena.ai"],
            path=tmp_path / "cookies.json",
            rounds=1,
            environment=environment,  # type: ignore[arg-type]
            prompt=Prompt(),
        )
    )

    assert result.domains == ("lmarena.ai", "sub.lmarena.ai")
    assert result.accepted is True
    assert result.site_cookies() == {"session": "abc"}


def test_domain_matching_is_suffix_based() -> None:
    matches = login_module._domain_matches
    assert matches(".arena.ai", ("arena.ai",)) is True
    assert matches("chat.arena.ai", ("arena.ai",)) is True
    assert matches("notarena.ai", ("arena.ai",)) is False
    assert matches("arena.ai", ()) is True  # no filter means "everything"
    assert matches("ARENA.AI", ("arena.ai",)) is True


def test_domains_are_derived_from_the_base_url() -> None:
    assert login_module._target_domains("https://arena.ai/path", None) == ("arena.ai",)
    assert login_module._target_domains("not-a-url", None) == ()
    assert login_module._site_label("https://arena.ai/path") == "arena.ai"


# --------------------------------------------------------------------------- #
# Saving behaviour
# --------------------------------------------------------------------------- #


def test_save_false_keeps_the_session_in_memory(tmp_path: Path) -> None:
    destination = tmp_path / "cookies.json"
    environment = FakeEnvironment([[], [cookie("session", "abc")]])

    result = run(
        alogin_and_save(
            path=destination,
            save=False,
            environment=environment,  # type: ignore[arg-type]
            prompt=Prompt(),
        )
    )

    assert result.accepted is True
    assert result.saved is False
    assert result.path is None
    assert not destination.exists()
    assert result.site_cookies() == {"session": "abc"}


def test_no_destination_means_no_file(tmp_path: Path) -> None:
    environment = FakeEnvironment([[], [cookie("session", "abc")]])

    result = run(
        alogin_and_save(
            path=None,
            environment=environment,  # type: ignore[arg-type]
            prompt=Prompt(),
        )
    )

    assert result.path is None
    assert result.saved is False
    assert result.cookies


def test_nothing_is_written_when_the_browser_reported_no_cookies(tmp_path: Path) -> None:
    destination = tmp_path / "cookies.json"
    environment = FakeEnvironment([[], []])

    result = run(
        alogin_and_save(
            path=destination,
            rounds=1,
            accept=lambda cookies: True,
            environment=environment,  # type: ignore[arg-type]
            prompt=Prompt(),
        )
    )

    assert result.accepted is True
    assert result.saved is False
    assert not destination.exists()


def test_default_destination_is_the_discoverable_state_file() -> None:
    """``auto_client()`` looks in exactly this place, which is what makes the
    "log in once" promise survive across runs."""
    assert DEFAULT_STATE_PATH == Path("state") / "cookies.json"
    assert str(DEFAULT_STATE_PATH).replace(os.sep, "/") == "state/cookies.json"


def test_an_injected_environment_is_not_closed(tmp_path: Path) -> None:
    environment = FakeEnvironment([[], [cookie("session", "abc")]])

    run(
        alogin_and_save(
            path=tmp_path / "cookies.json",
            environment=environment,  # type: ignore[arg-type]
            prompt=Prompt(),
        )
    )

    assert environment.started is False
    assert environment.closed is False


def patch_environment(
    monkeypatch: pytest.MonkeyPatch, snapshots: list[list[dict[str, Any]]]
) -> tuple[list[Any], list[FakeEnvironment]]:
    """Route ``BrowserEnvironment(...)`` through a fake, recording what was built."""
    options_seen: list[Any] = []
    built: list[FakeEnvironment] = []

    def factory(options: Any) -> FakeEnvironment:
        environment = FakeEnvironment(snapshots, options=options)
        options_seen.append(options)
        built.append(environment)
        return environment

    monkeypatch.setattr(login_module, "BrowserEnvironment", factory)
    return options_seen, built


def test_an_owned_environment_is_started_and_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, built = patch_environment(monkeypatch, [[], [cookie("session", "abc")]])

    result = run(alogin_and_save(path=tmp_path / "cookies.json", prompt=Prompt()))

    assert result.saved is True
    assert built[0].started is True
    assert built[0].closed is True


def test_an_existing_state_file_seeds_the_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Signing in again should not mean starting from scratch."""
    destination = tmp_path / "cookies.json"
    destination.write_text(json.dumps({"cookies": [], "origins": []}), encoding="utf-8")
    options_seen, _ = patch_environment(monkeypatch, [[], [cookie("s", "1")]])

    result = run(alogin_and_save(path=destination, prompt=Prompt()))
    assert options_seen[0].storage_state == destination
    assert result.reused is True

    options_seen.clear()
    run(alogin_and_save(path=destination, reuse_existing=False, prompt=Prompt()))
    assert options_seen[0].storage_state is None


def test_a_missing_state_file_is_not_seeded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    options_seen, _ = patch_environment(monkeypatch, [[], [cookie("s", "1")]])

    result = run(alogin_and_save(path=tmp_path / "cookies.json", prompt=Prompt()))

    assert options_seen[0].storage_state is None
    assert result.reused is False


# --------------------------------------------------------------------------- #
# Environment options
# --------------------------------------------------------------------------- #


def test_login_environment_looks_like_a_person_not_a_test_run() -> None:
    options = login_environment_options()

    assert isinstance(options, BrowserEnvironmentOptions)
    assert options.headless is False
    assert options.identify_automation is False, "a human session is not synthetic monitoring"
    assert options.install_determinism_script is False
    assert options.reduced_motion == "no-preference"
    assert options.color_scheme == "no-preference"
    assert options.captcha_solver is None
    assert options.solve_challenges is False


def test_login_environment_options_pass_everything_through() -> None:
    options = login_environment_options(
        headless=True,
        channel="chrome",
        storage_state="state/cookies.json",
        artifacts_dir="artifacts",
        locale="et-EE",
    )

    assert options.headless is True
    assert options.channel == "chrome"
    assert options.storage_state == "state/cookies.json"
    assert str(options.artifacts_dir) == "artifacts"
    assert options.locale == "et-EE"


def test_a_solver_turns_solving_on_for_the_login_pages() -> None:
    solver = object()

    options = login_environment_options(captcha_solver=solver)  # type: ignore[arg-type]

    assert options.captcha_solver is solver
    assert options.solve_challenges is True


def test_the_solver_reaches_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    options_seen, _ = patch_environment(monkeypatch, [[], [cookie("s", "1")]])
    solver = object()

    run(
        alogin_and_save(
            path=tmp_path / "c.json",
            captcha_solver=solver,  # type: ignore[arg-type]
            prompt=Prompt(),
        )
    )

    assert options_seen[0].captcha_solver is solver
    assert options_seen[0].solve_challenges is True


# --------------------------------------------------------------------------- #
# hide_automation: the sign-in window stops advertising itself
# --------------------------------------------------------------------------- #


def test_a_person_driven_window_is_honest_by_default() -> None:
    options = login_environment_options()

    assert options.ignore_default_args == ()
    assert "--disable-blink-features=AutomationControlled" not in options.launch_args
    assert options.extra_init_scripts == ()


def test_hide_automation_drops_the_markers_google_reads() -> None:
    options = login_environment_options(hide_automation=True)

    launch = options.launch_kwargs()
    assert launch["ignore_default_args"] == ["--enable-automation"]
    # --disable-dev-shm-usage comes from container_safe and is unrelated.
    assert "--disable-blink-features=AutomationControlled" in launch["args"]
    assert options.extra_init_scripts == (HIDE_WEBDRIVER_SCRIPT,)
    # The deterministic init script is a separate, unrelated payload: the login
    # window must not get it, and the mask must not depend on it.
    assert options.install_determinism_script is False


def test_hide_automation_merges_explicit_switches() -> None:
    """An explicit ignore_default_args/launch_args survives the opt-in."""
    options = login_environment_options(
        hide_automation=True,
        ignore_default_args=("--no-first-run",),
        launch_args=("--lang=en-US",),
        extra_init_scripts=("/* mine */",),
    )

    assert options.ignore_default_args == ("--no-first-run", "--enable-automation")
    assert options.launch_args == (
        "--lang=en-US",
        "--disable-blink-features=AutomationControlled",
    )
    assert options.extra_init_scripts == ("/* mine */", HIDE_WEBDRIVER_SCRIPT)


def test_alogin_and_save_forwards_hide_automation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    options_seen, _ = patch_environment(monkeypatch, [[], [cookie("session", "abc")]])

    result = run(
        alogin_and_save(
            path=tmp_path / "cookies.json",
            hide_automation=True,
            prompt=Prompt(),
        )
    )

    assert result.saved is True
    assert options_seen[0].extra_init_scripts == (HIDE_WEBDRIVER_SCRIPT,)
    assert "--enable-automation" in options_seen[0].ignore_default_args
    assert "--disable-blink-features=AutomationControlled" in options_seen[0].launch_args


def test_an_explicit_environment_options_wins_over_hide_automation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Supplying options means they are used as they are, mask included or not."""
    own = BrowserEnvironmentOptions(extra_init_scripts=())
    supplied: list[Any] = []

    def factory(options: Any) -> FakeEnvironment:
        supplied.append(options)
        return FakeEnvironment([[], [cookie("session", "abc")]])

    monkeypatch.setattr(login_module, "BrowserEnvironment", factory)

    run(
        alogin_and_save(
            path=tmp_path / "cookies.json",
            hide_automation=True,
            environment_options=own,
            prompt=Prompt(),
        )
    )

    assert supplied[0] is own
    assert own.extra_init_scripts == ()


# --------------------------------------------------------------------------- #
# Result object
# --------------------------------------------------------------------------- #


def test_an_empty_result_is_falsy_and_describes_itself() -> None:
    result = LoginResult()

    assert result.ok is False
    assert bool(result) is False
    assert result.names == ()
    assert result.site_cookies() == {}
    assert result.cookie_header() == ""
    assert "not saved" in result.describe()
    assert "0 round(s)" in result.describe()


def test_a_saved_result_names_the_file() -> None:
    result = LoginResult(
        cookies=(cookie("session", "abc"),),
        path=Path("state/cookies.json"),
        saved=True,
        accepted=True,
        attempts=1,
        domains=("arena.ai",),
    )

    assert result.ok is True
    # ``describe()`` renders the path as the platform does: on Windows the very
    # same Path stringifies with backslashes, so compare against it, not a
    # POSIX literal.
    assert f"saved ({Path('state/cookies.json')})" in result.describe()
    assert "1 cookie(s) for arena.ai" in result.describe()


def test_guest_and_analytics_cookies_do_not_count_as_completed_login(
    tmp_path: Path,
) -> None:
    """Async guest/telemetry cookies set on landing must not poison state/cookies.json."""
    destination = tmp_path / "state" / "cookies.json"
    guest_only = [
        cookie("__cf_bm", "bm", domain=".arena.ai"),
        cookie("_dd_s", "dd"),
        cookie("_ga", "ga"),
        cookie("_ga_DB32ZN1WHB", "ga2"),
        cookie("_vcrr_ec68a2456e920849", "vc"),
        cookie("arena_build_bucket", "b"),
        cookie("arena_visit_id", "v"),
        cookie("cf_clearance", "cf", domain=".arena.ai"),
        cookie("cookie-preferences", "cp"),
        cookie("ph_phc_abc_posthog", "ph"),
        cookie("provisional_user_id", "guest-uuid"),
        cookie("sidebar_state", "true"),
        cookie("user_country_code", "SE"),
    ]
    signed_in = list(guest_only) + [cookie("arena-auth-prod-v1.0", "jwt-part-0")]
    environment = FakeEnvironment([[], guest_only, signed_in])
    output = StringIO()

    result = asyncio.run(
        alogin_and_save(
            base_url="https://arena.ai",
            path=destination,
            rounds=2,
            prompt=lambda _: "",
            output=output,
            environment=environment,  # type: ignore[arg-type]
        )
    )

    assert result.accepted is True
    assert result.saved is True
    assert result.attempts == 2
    assert "no session cookie" in output.getvalue()
    saved_names = {item["name"] for item in json.loads(destination.read_text())["cookies"]}
    assert "arena-auth-prod-v1.0" in saved_names


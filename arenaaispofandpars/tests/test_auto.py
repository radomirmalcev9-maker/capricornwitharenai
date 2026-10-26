"""Tests for the zero-configuration bootstrap layer (:mod:`arena_api.auto`).

The point of ``arena_api.auto`` is that the only manual step is signing in to an
account in a real browser, so these tests cover: where a session may come from
and in which order, what the probe concludes from each response shape, how a
rejected session is healed at startup, the refresh ladder, and what the
``python -m arena_api.auto`` CLI reports. Nothing here touches the network or
launches a browser.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
import types
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import pytest

from arena_api import ArenaClient, AsyncArenaClient
from arena_api.auth.challenge import ChallengeKind, ChallengeObservation, ChallengeSignal
from arena_api.auth.captcha import (
    CaptchaAttempt,
    ChallengeWaitSolver,
    CompositeSolver,
    RecaptchaToolkitSolver,
)
from arena_api.auth.session import BrowserSessionManager, FormLoginFlow
from arena_api.auth.login import DEFAULT_STATE_PATH, LoginResult
from arena_api.auto import (
    AutoOptions,
    AutoSessionManager,
    DirectVerificationToken,
    DiscoveredSession,
    LoginOutcome,
    ProbeResult,
    _flat_records,
    _merge_options,
    _options_from_args,
    aprobe,
    auto_async_client,
    auto_client,
    auto_direct_client,
    build_arg_parser,
    build_session_manager,
    discover_session,
    explain_login,
    explain_sources,
    interactive_login,
    login_flow_from_env,
    main,
    probe,
    resolve_solver,
    solver_dependencies_available,
)
from arena_api.constants import CONFIG_PATH, DEFAULT_BASE_URL, DIRECT_PAGE_PATH
from arena_api.exceptions import AuthenticationError
from arena_api.models import ModelInfo

import arena_api.auto as auto_module

FUTURE = int(time.time()) + 86_400
ENV_VARS = (
    "ARENA_COOKIE",
    "ARENA_COOKIES_FILE",
    "ARENA_FIREFOX_ROOT",
    "ARENA_FIREFOX_PROFILE",
    "ARENA_LOGIN_URL",
    "ARENA_USERNAME",
    "ARENA_PASSWORD",
    "ARENA_USER_SELECTOR",
    "ARENA_PASS_SELECTOR",
    "ARENA_SUBMIT_SELECTOR",
    "ARENA_SUCCESS_URL",
)
CHALLENGE_HTML = (
    b'<!doctype html><html><head><title>Just a moment...</title></head>'
    b'<body><div id="cf-chl-widget"></div></body></html>'
)
#: Served with HTTP 200 and no marker the transport knows: only the probe's own
#: HTML inspection catches this one.
RECAPTCHA_PAGE = (
    b'<!doctype html><html><head>'
    b'<script src="https://www.google.com/recaptcha/api.js"></script></head>'
    b'<body><div class="g-recaptcha" data-sitekey="6Lc"></div></body></html>'
)
CONFIG_JSON = json.dumps(
    {"dependencies": [{"fn_index": 4, "api_name": "chat", "queue": True}], "components": []}
).encode()


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Keep host-level ``ARENA_*`` configuration out of every test."""
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)


class Recorder:
    """Mock transport that replays canned responses and records requests."""

    def __init__(self, *responses: tuple):
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.responses:
            status, body, content_type = self.responses.pop(0)
        else:
            status, body, content_type = 200, b"{}", "application/json"
        return httpx.Response(
            status,
            request=request,
            headers={"content-type": content_type},
            content=body,
        )

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def cookies(self, index: int = 0) -> str:
        return self.requests[index].headers.get("cookie", "")


def make_firefox_profile(tmp_path: Path, value: str = "from-firefox") -> Path:
    """Build a throwaway Firefox profile tree holding one arena.ai cookie."""
    root = tmp_path / "firefox"
    profile = root / "abcd1234.default-release"
    profile.mkdir(parents=True)
    connection = sqlite3.connect(profile / "cookies.sqlite")
    connection.executescript(
        """
        CREATE TABLE moz_cookies (
            id INTEGER PRIMARY KEY,
            originAttributes TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL,
            value TEXT NOT NULL,
            host TEXT NOT NULL,
            path TEXT NOT NULL DEFAULT '/',
            expiry INTEGER NOT NULL,
            lastAccessed INTEGER NOT NULL,
            creationTime INTEGER NOT NULL,
            isSecure INTEGER NOT NULL,
            isHttpOnly INTEGER NOT NULL,
            inBrowserElement INTEGER NOT NULL DEFAULT 0,
            sameSite INTEGER NOT NULL DEFAULT 0,
            rawSameSite INTEGER NOT NULL DEFAULT 0,
            schemeMap INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    connection.execute(
        "INSERT INTO moz_cookies"
        " (name, value, host, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly)"
        " VALUES (?, ?, ?, '/', ?, 0, 0, 1, 0)",
        ("session", value, ".arena.ai", FUTURE),
    )
    connection.commit()
    connection.close()
    (profile / "compatibility.ini").write_text(
        "[Compatibility]\nLastVersion=156.0_20250101000000\n", encoding="utf-8"
    )
    (root / "profiles.ini").write_text(
        "[Install1234ABCD]\nDefault=abcd1234.default-release\n", encoding="utf-8"
    )
    return root


def isolated_options(tmp_path: Path, **kwargs) -> AutoOptions:
    """Options that cannot pick anything up from the working directory.

    ``profiles_root`` is pinned to a directory that does not exist: without it
    the Firefox rung resolves the *host* profile (``~/.mozilla/firefox`` on
    POSIX, ``%APPDATA%\\Mozilla\\Firefox\\Profiles`` on Windows) and wins the
    ladder on any machine where the developer is signed in to arena.ai, so the
    test would only pass on a machine without such a profile.
    """
    kwargs.setdefault("storage_path", tmp_path / "unused" / "cookies.json")
    kwargs.setdefault("profiles_root", tmp_path / "no-host-profiles")
    kwargs.setdefault("use_browser_profiles", False)
    kwargs.setdefault("solve_captchas", False)
    kwargs.setdefault("artifacts_dir", tmp_path / "artifacts")
    kwargs.setdefault("output", io.StringIO())
    return AutoOptions(**kwargs)


def write_storage(tmp_path: Path, cookies: dict[str, str]) -> Path:
    path = tmp_path / "state" / "cookies.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cookies), encoding="utf-8")
    return path


class StubSource:
    """A browser source standing in for the ladder's cheap first rung."""

    USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:156.0) Gecko/20100101 Firefox/156.0"

    def __init__(self, cookies: dict[str, str] | None = None):
        self.cookies = cookies
        self.refresh_reasons: list = []

    def load_cookies(self, domains=None):
        return dict(self.cookies or {})

    def firefox_headers(self, *, navigation: bool = False):
        return {
            "User-Agent": self.USER_AGENT,
            "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.7,en;q=0.6",
        }

    def refresh_session(self, reason=None):
        self.refresh_reasons.append(reason)
        return dict(self.cookies) if self.cookies else None


class TokenSolver:
    """Custom solver stand-in handing back a fixed token."""

    backend = "stub"

    def __init__(self, token: str = "solved-token"):
        self.token = token
        self.calls: list = []

    def supports(self, kind, observation=None) -> bool:
        return True

    async def asolve(self, page, observation=None) -> CaptchaAttempt:
        self.calls.append(page.url)
        return CaptchaAttempt(token=self.token, backend=self.backend)

    def solve(self, page, observation=None) -> CaptchaAttempt:
        return asyncio.run(self.asolve(page, observation))


class Chunk:
    def __init__(self, delta: str):
        self.delta = delta


class DummyClient:
    """Stand-in for the CLI, so no test needs a reachable service."""

    def __init__(self, models=(), answer="echo"):
        self._models = list(models)
        self.answer = answer
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        self.closed = True

    def get_models(self, **kwargs):
        return self._models

    def stream(self, prompt, **kwargs):
        yield Chunk(f"{self.answer}: {prompt}")


# --------------------------------------------------------------------------- #
# Options
# --------------------------------------------------------------------------- #


def test_defaults_need_no_configuration() -> None:
    options = AutoOptions()
    assert options.base_url == DEFAULT_BASE_URL
    assert options.probe_path == CONFIG_PATH
    assert options.use_browser_profiles is True
    assert options.interactive is True
    assert options.verify is True
    assert options.solve_captchas == "auto"
    assert options.login_from_env is True
    assert options.prompt is input


def test_cookie_domains_cover_the_configured_host() -> None:
    assert AutoOptions(base_url="https://example.test:8443").cookie_domains()[0] == "example.test"
    assert "lmarena.ai" in AutoOptions().cookie_domains()
    assert AutoOptions(domains=("only.test",)).cookie_domains() == ("only.test",)


def test_solve_captchas_accepts_only_three_values() -> None:
    with pytest.raises(ValueError, match="solve_captchas"):
        AutoOptions(solve_captchas="maybe")


def test_merge_options_replaces_fields_of_an_existing_object(tmp_path) -> None:
    options = isolated_options(tmp_path, cookies="session=a")
    merged = _merge_options(options, {"verify": False, "captcha_backend": "image"})
    assert merged is not options
    assert merged.cookies == "session=a"
    assert merged.verify is False
    assert merged.captcha_backend == "image"
    assert _merge_options(None, {}) == AutoOptions()


# --------------------------------------------------------------------------- #
# Discovery: sources and precedence
# --------------------------------------------------------------------------- #


def test_explicit_cookies_win_over_every_other_source(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ARENA_COOKIE", "session=from-env")
    write_storage(tmp_path, {"session": "from-storage"})
    options = AutoOptions(
        cookies={"session": "explicit"},
        storage_path=tmp_path / "state" / "cookies.json",
        profiles_root=make_firefox_profile(tmp_path),
        solve_captchas=False,
        output=io.StringIO(),
    )
    found = discover_session(options)
    assert found is not None
    assert found.source == "cookies"
    assert found.cookies == {"session": "explicit"}


def test_cookie_header_export_is_parsed(tmp_path) -> None:
    found = discover_session(isolated_options(tmp_path, cookies="b=2; a=1; session=S"))
    assert found.cookies == {"session": "S", "a": "1", "b": "2"}
    assert found.source == "cookies"


def test_cookie_file_export_is_read(tmp_path, monkeypatch) -> None:
    export = tmp_path / "export.json"
    export.write_text(json.dumps([{"name": "session", "value": "file"}]), encoding="utf-8")
    monkeypatch.setenv("ARENA_COOKIES_FILE", str(export))
    found = discover_session(isolated_options(tmp_path))
    assert found.source == "env"
    assert found.cookies == {"session": "file"}


def test_unreadable_cookie_export_is_reported(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ARENA_COOKIE", str(tmp_path / "missing.json"))
    with pytest.raises(AuthenticationError, match="could not be read"):
        discover_session(isolated_options(tmp_path))


def test_stored_state_file_is_reused(tmp_path) -> None:
    path = write_storage(tmp_path, {"session": "stored"})
    options = AutoOptions(storage_path=path, solve_captchas=False, output=io.StringIO())
    found = discover_session(options)
    assert found.source == "storage"
    assert found.cookies == {"session": "stored"}
    # Re-reading the same file would return the rejected cookies, so there is no
    # cheap rung: the ladder (login flow / solver) is the refresh path.
    assert found.manager is None


def test_firefox_profile_is_discovered_without_configuration(tmp_path) -> None:
    profiles = make_firefox_profile(tmp_path)
    options = isolated_options(tmp_path, use_browser_profiles=True, profiles_root=profiles)
    found = discover_session(options)
    assert found.source == "firefox"
    assert found.cookies == {"session": "from-firefox"}
    assert "default-release" in found.description


def test_browser_profile_discovery_can_be_turned_off(tmp_path) -> None:
    options = isolated_options(tmp_path, profiles_root=make_firefox_profile(tmp_path))
    assert discover_session(options) is None


def test_isolated_options_never_point_at_a_host_browser_profile(tmp_path) -> None:
    """The ladder tests must not read the developer's own Firefox profile.

    Regression guard: with a real profile holding arena.ai cookies on the
    machine, ``use_browser_profiles=True`` used to resolve it through the
    default ``profiles_root`` and the Firefox rung answered before the rung
    under test, so ``test_other_browsers_are_read_through_rookiepy`` failed
    with ``'firefox' == 'browser:chrome'``.
    """
    options = isolated_options(tmp_path, use_browser_profiles=True)

    root = Path(options.profiles_root)
    assert root.is_relative_to(tmp_path)
    assert not root.exists()
    assert auto_module._from_firefox(options) is None


def test_other_browsers_are_read_through_rookiepy(tmp_path, monkeypatch) -> None:
    seen = []

    def chrome(domains=()):
        seen.append(tuple(domains))
        return [
            {"name": "session", "value": "from-chrome", "domain": ".arena.ai", "expires": FUTURE},
            {"name": "gtoken", "value": "", "domain": ".arena.ai"},  # recaptcha, empty value
            {"name": "pref", "value": "kept", "domain": ".arena.ai", "expires": FUTURE},
        ]

    monkeypatch.setattr(
        auto_module, "_rookiepy_module", lambda: types.SimpleNamespace(chrome=chrome)
    )
    found = discover_session(isolated_options(tmp_path, use_browser_profiles=True))
    assert found.source == "browser:chrome"
    # rookiepy already filtered by domain; empty values are legitimate cookies.
    assert found.cookies == {"session": "from-chrome", "gtoken": "", "pref": "kept"}
    # rookiepy takes bare domains, the same list the Firefox path queries with.
    assert seen[0] == ("arena.ai", "lmarena.ai")


def test_rookiepy_browsers_are_tried_in_a_fixed_order(tmp_path, monkeypatch) -> None:
    calls = []

    def factory(name):
        def reader(domains=()):
            calls.append(name)
            return []

        return reader

    monkeypatch.setattr(
        auto_module,
        "_rookiepy_module",
        lambda: types.SimpleNamespace(**{name: factory(name) for name in auto_module.ROOKIEPY_BROWSERS}),
    )
    options = isolated_options(tmp_path, use_browser_profiles=True, profiles_root=tmp_path / "none")
    assert discover_session(options) is None
    assert calls == list(auto_module.ROOKIEPY_BROWSERS)


def test_flat_record_filtering_drops_junk() -> None:
    expired = int(time.time()) - 10
    assert _flat_records(
        [
            {"name": "a", "value": "1", "domain": ".arena.ai", "expires": FUTURE},
            {"name": "", "value": "x"},
            {"name": "b", "domain": ".arena.ai"},  # no value
            {"name": "c", "value": "3", "expires": expired},  # expired
            {"name": "a", "value": "duplicate"},  # first record of a name wins
            {"name": "d", "value": "4", "domain": "other.test"},
            "not a mapping",
        ]
    ) == {"a": "1", "d": "4"}


def test_flat_records_survives_an_unexpected_shape() -> None:
    assert _flat_records("not a list") == {}
    assert _flat_records(None) == {}


def test_discovery_reports_every_source_it_considered(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(auto_module, "_rookiepy_module", lambda: None)
    options = isolated_options(
        tmp_path, use_browser_profiles=True, profiles_root=make_firefox_profile(tmp_path)
    )
    joined = "\n".join(explain_sources(options))
    assert "cookies=" in joined
    assert "ARENA_COOKIE" in joined
    assert "stored cookies.json" in joined
    assert "Firefox profile" in joined
    assert "default-release" in joined
    assert "other browsers" in joined
    assert "rookiepy not installed" in joined

    monkeypatch.setattr(auto_module, "_rookiepy_module", lambda: object())
    assert "rookiepy available" in "\n".join(explain_sources(options))


def test_discovery_reports_a_firefox_profile_it_cannot_use(tmp_path) -> None:
    options = isolated_options(
        tmp_path, use_browser_profiles=True, profiles_root=tmp_path / "empty"
    )
    lines = explain_sources(options)
    assert any("unavailable" in line for line in lines)


def test_the_discovery_report_is_aligned_and_honest(tmp_path, monkeypatch) -> None:
    """`--explain` is the first thing a stuck user reads: keep it tidy."""
    monkeypatch.chdir(tmp_path)
    lines = explain_sources(AutoOptions(use_browser_profiles=False))
    assert {line.index(":") for line in lines} == {20}, lines
    assert any(line.endswith("not configured") for line in lines)
    assert "None" not in "\n".join(lines)


def test_the_discovery_report_names_a_configured_storage_file(tmp_path) -> None:
    path = write_storage(tmp_path, {"session": "stored"})
    lines = explain_sources(AutoOptions(storage_path=path, use_browser_profiles=False))
    stored = next(line for line in lines if line.startswith("stored cookies.json"))
    assert str(path) in stored and "(exists)" in stored


def test_explain_login_keeps_its_sentence_form(monkeypatch) -> None:
    monkeypatch.setenv("ARENA_USERNAME", "user@example.com")
    assert explain_login(AutoOptions()).startswith("login flow: ")


def test_discovery_explains_disabled_browser_profiles(tmp_path) -> None:
    joined = "\n".join(explain_sources(isolated_options(tmp_path)))
    assert "disabled by use_browser_profiles=False" in joined
    assert "Firefox profile" not in joined


# --------------------------------------------------------------------------- #
# Login flow discovery from the environment
# --------------------------------------------------------------------------- #


def test_complete_environment_builds_a_form_login_flow(monkeypatch) -> None:
    monkeypatch.setenv("ARENA_LOGIN_URL", "https://arena.ai/login")
    monkeypatch.setenv("ARENA_USERNAME", "user@example.com")
    monkeypatch.setenv("ARENA_PASSWORD", "secret")
    monkeypatch.setenv("ARENA_USER_SELECTOR", "#email")
    monkeypatch.setenv("ARENA_PASS_SELECTOR", "#pass")
    monkeypatch.setenv("ARENA_SUBMIT_SELECTOR", "button[type=submit]")
    monkeypatch.setenv("ARENA_SUCCESS_URL", "https://arena.ai/")
    flow = login_flow_from_env(AutoOptions(solve_captchas=False))
    assert isinstance(flow, FormLoginFlow)
    assert flow.login_url == "https://arena.ai/login"
    assert flow.username_selector == "#email"
    assert flow.password_selector == "#pass"
    assert flow.submit_selector == "button[type=submit]"
    assert flow.success_url_contains == "https://arena.ai/"
    assert flow.credentials() == ("user@example.com", "secret")


def test_partial_environment_configuration_is_ignored(monkeypatch) -> None:
    monkeypatch.setenv("ARENA_USERNAME", "user@example.com")
    options = AutoOptions(solve_captchas=False)
    assert login_flow_from_env(options) is None
    explanation = explain_login(options)
    assert "unavailable" in explanation
    assert "ARENA_PASSWORD" in explanation
    assert "ARENA_LOGIN_URL" in explanation


def login_flow() -> FormLoginFlow:
    return FormLoginFlow(
        login_url="https://arena.ai/login",
        username_selector="#email",
        password_selector="#pass",
        submit_selector="#go",
        username="user@example.com",
        password="secret",
    )


def test_explicit_login_flow_is_kept() -> None:
    flow = login_flow()
    options = AutoOptions(login_flow=flow, solve_captchas=False)
    assert login_flow_from_env(options) is flow
    assert explain_login(options) == "login flow: configured explicitly"


def test_environment_login_can_be_disabled(monkeypatch) -> None:
    for name, value in (
        ("ARENA_LOGIN_URL", "https://arena.ai/login"),
        ("ARENA_USERNAME", "user@example.com"),
        ("ARENA_PASSWORD", "secret"),
        ("ARENA_USER_SELECTOR", "#email"),
        ("ARENA_PASS_SELECTOR", "#pass"),
        ("ARENA_SUBMIT_SELECTOR", "#go"),
    ):
        monkeypatch.setenv(name, value)
    options = AutoOptions(login_from_env=False, solve_captchas=False)
    assert login_flow_from_env(options) is None
    assert "disabled" in explain_login(options)


def test_complete_environment_is_announced(monkeypatch) -> None:
    for name, value in (
        ("ARENA_LOGIN_URL", "https://arena.ai/login"),
        ("ARENA_USERNAME", "user@example.com"),
        ("ARENA_PASSWORD", "secret"),
        ("ARENA_USER_SELECTOR", "#email"),
        ("ARENA_PASS_SELECTOR", "#pass"),
        ("ARENA_SUBMIT_SELECTOR", "#go"),
    ):
        monkeypatch.setenv(name, value)
    assert explain_login(AutoOptions()) == "login flow: available from the environment"


# --------------------------------------------------------------------------- #
# Solver resolution
# --------------------------------------------------------------------------- #


def _observation(kind: ChallengeKind) -> ChallengeObservation:
    """A minimal observation of one kind, for solver-capability checks."""
    return ChallengeObservation(
        url="https://arena.ai/config",
        kind=kind,
        signals=(ChallengeSignal("test", "constructed", kind),),
    )


def test_solver_falls_back_to_waiting_when_dependencies_are_missing(monkeypatch) -> None:
    """Waiting needs no third-party package, so "auto" is not a silent no-op."""
    monkeypatch.setattr(auto_module, "_has_spec", lambda name: False)

    solver = resolve_solver(AutoOptions())

    assert isinstance(solver, ChallengeWaitSolver)
    assert solver.timeout == 30.0
    assert solver.interactive is True  # follows options.interactive
    assert ChallengeKind.RECAPTCHA not in solver.solve_kinds
    assert ChallengeKind.TURNSTILE in solver.solve_kinds


def test_solver_is_fully_off_only_when_both_paths_are_disabled(monkeypatch) -> None:
    monkeypatch.setattr(auto_module, "_has_spec", lambda name: False)
    assert resolve_solver(AutoOptions(wait_out_challenges=False)) is None


def test_solver_switches_itself_on_when_dependencies_exist(monkeypatch) -> None:
    monkeypatch.setattr(
        auto_module,
        "_has_spec",
        lambda name: name in {"playwright", "playwright_recaptcha", "playwright_stealth"},
    )
    solver = resolve_solver(AutoOptions())
    assert isinstance(solver, CompositeSolver)
    toolkit, wait = solver.solvers
    assert isinstance(toolkit, RecaptchaToolkitSolver)
    assert toolkit.backend == "audio"
    assert toolkit.apply_stealth is True
    assert isinstance(wait, ChallengeWaitSolver)
    # dispatch order: a token beats patience for reCAPTCHA
    assert solver.select(_observation(ChallengeKind.RECAPTCHA)) is toolkit
    assert solver.select(_observation(ChallengeKind.TURNSTILE)) is wait
    assert "composite[" in solver.describe()


def test_solver_can_be_forced_on(monkeypatch) -> None:
    monkeypatch.setattr(auto_module, "_has_spec", lambda name: False)
    solver = resolve_solver(AutoOptions(solve_captchas=True, captcha_backend="image"))
    assert isinstance(solver, CompositeSolver)
    assert isinstance(solver.solvers[0], RecaptchaToolkitSolver)
    assert solver.solvers[0].backend == "image"


def test_waiting_can_be_disabled_on_its_own(monkeypatch) -> None:
    monkeypatch.setattr(
        auto_module,
        "_has_spec",
        lambda name: name in {"playwright", "playwright_recaptcha", "playwright_stealth"},
    )
    solver = resolve_solver(AutoOptions(wait_out_challenges=False))
    assert isinstance(solver, RecaptchaToolkitSolver)


def test_the_wait_timeout_comes_from_the_options(monkeypatch) -> None:
    monkeypatch.setattr(auto_module, "_has_spec", lambda name: False)
    solver = resolve_solver(
        AutoOptions(challenge_wait_timeout=5.0, interactive=False, output=io.StringIO())
    )
    assert isinstance(solver, ChallengeWaitSolver)
    assert solver.timeout == 5.0
    assert solver.interactive is False


def test_a_non_positive_wait_timeout_is_refused() -> None:
    with pytest.raises(ValueError):
        AutoOptions(challenge_wait_timeout=0)


def test_solver_can_be_forced_off_even_with_dependencies(monkeypatch) -> None:
    monkeypatch.setattr(auto_module, "_has_spec", lambda name: True)
    assert resolve_solver(AutoOptions(solve_captchas=False)) is None


def test_explicit_solver_object_is_used_verbatim() -> None:
    solver = TokenSolver()
    assert resolve_solver(AutoOptions(captcha_solver=solver)) is solver


def test_dependency_probe_understands_both_solvers(monkeypatch) -> None:
    installed: set[str] = set()
    monkeypatch.setattr(auto_module, "_has_spec", lambda name: name in installed)
    assert solver_dependencies_available("audio") is False
    installed.update({"playwright", "playwright_stealth"})
    assert solver_dependencies_available("audio") is False
    installed.add("playwright_recaptcha")
    assert solver_dependencies_available("audio") is True
    installed.discard("playwright_recaptcha")
    assert solver_dependencies_available("vision_ai") is False
    installed.add("vision_ai_recaptcha_solver")
    assert solver_dependencies_available("vision_ai") is True


def test_dependency_probe_never_imports_a_solver(monkeypatch) -> None:
    monkeypatch.setattr(auto_module, "_has_spec", lambda name: name == "playwright")
    assert solver_dependencies_available("audio") is False
    assert "playwright_recaptcha" not in sys.modules


# --------------------------------------------------------------------------- #
# Probe classification
# --------------------------------------------------------------------------- #


def test_probe_accepts_a_200() -> None:
    recorder = Recorder((200, CONFIG_JSON, "application/json"))
    with ArenaClient(http_transport=recorder.transport) as client:
        result = probe(client, "/config")
    assert result.ok and not result.auth_problem
    assert result.reason == "session accepted"
    assert result.describe() == "ok: session accepted"


def test_probe_accepts_json_that_merely_mentions_a_captcha() -> None:
    body = json.dumps({"dependencies": [{"api_name": "g-recaptcha-reset"}]}).encode()
    recorder = Recorder((200, body, "application/json"))
    with ArenaClient(http_transport=recorder.transport) as client:
        result = probe(client, "/config")
    assert result.ok and not result.auth_problem


def test_probe_reads_an_html_page_without_captcha_as_accepted() -> None:
    recorder = Recorder((200, b"<!doctype html><html><body>hi</body></html>", "text/html"))
    with ArenaClient(http_transport=recorder.transport) as client:
        result = probe(client, "/text/direct")
    assert result.ok and not result.auth_problem


def test_probe_reads_a_403_as_an_auth_problem() -> None:
    recorder = Recorder((403, b"denied", "text/plain"))
    with ArenaClient(http_transport=recorder.transport) as client:
        result = probe(client, "/config")
    assert not result.ok and result.auth_problem
    assert "rejected" in result.reason
    assert result.describe() == "not ok: session rejected or expired"


def test_probe_reads_a_cloudflare_challenge_as_an_auth_problem() -> None:
    """The transport itself refuses a known challenge page."""
    recorder = Recorder((200, CHALLENGE_HTML, "text/html"))
    with ArenaClient(http_transport=recorder.transport) as client:
        result = probe(client, "/config")
    assert not result.ok and result.auth_problem
    assert "browser verification challenge" in result.reason
    assert result.error is not None


def test_probe_reads_a_bare_recaptcha_page_as_an_auth_problem() -> None:
    """A captcha interstitial with HTTP 200 and no Cloudflare marker."""
    recorder = Recorder((200, RECAPTCHA_PAGE, "text/html"))
    with ArenaClient(http_transport=recorder.transport) as client:
        result = probe(client, "/config")
    assert not result.ok and result.auth_problem
    assert "challenge page instead of data" in result.reason
    assert "g-recaptcha" in result.reason


def test_probe_reads_a_rate_limit_as_not_an_auth_problem() -> None:
    recorder = Recorder((429, b"slow down", "text/plain"))
    with ArenaClient(http_transport=recorder.transport) as client:
        result = probe(client, "/config")
    assert not result.ok and not result.auth_problem
    assert "rate limit" in result.reason.lower()


def test_probe_treats_a_redirect_as_reachable() -> None:
    recorder = Recorder((302, b"", "text/plain"))
    with ArenaClient(http_transport=recorder.transport) as client:
        result = probe(client, "/config")
    assert result.ok and not result.auth_problem
    assert "inconclusive" in result.reason


def test_async_probe_matches_the_sync_one() -> None:
    recorder = Recorder((403, b"denied", "text/plain"))

    async def run() -> ProbeResult:
        async with AsyncArenaClient(http_transport=recorder.transport) as client:
            return await aprobe(client, "/config")

    result = asyncio.run(run())
    assert result.auth_problem and "rejected" in result.reason


# --------------------------------------------------------------------------- #
# Bootstrap: building a client
# --------------------------------------------------------------------------- #


def test_bootstrap_sends_the_discovered_cookie(tmp_path) -> None:
    recorder = Recorder((200, CONFIG_JSON, "application/json"))
    options = isolated_options(tmp_path, cookies="session=abc", http_transport=recorder.transport)
    with auto_client(options) as client:
        assert client.session_manager is not None
        assert client.session_manager.load_cookies() == {"session": "abc"}
    assert "session=abc" in recorder.cookies(0)


def test_bootstrap_matches_the_fingerprint_of_the_source_browser(tmp_path) -> None:
    recorder = Recorder((200, b"{}", "application/json"))
    options = isolated_options(
        tmp_path,
        use_browser_profiles=True,
        profiles_root=make_firefox_profile(tmp_path),
        http_transport=recorder.transport,
    )
    with auto_client(options):
        pass
    headers = recorder.requests[0].headers
    assert "Firefox/156.0" in headers["user-agent"]
    assert "Gecko/20100101" in headers["user-agent"]
    assert "accept-language" in headers


def test_bootstrap_without_a_browser_source_uses_a_chromium_fingerprint(tmp_path) -> None:
    recorder = Recorder((200, b"{}", "application/json"))
    options = isolated_options(tmp_path, cookies="session=abc", http_transport=recorder.transport)
    with auto_client(options):
        pass
    assert "Chrome/" in recorder.requests[0].headers["user-agent"]


def test_bootstrap_heals_a_rejected_session_during_the_probe(tmp_path, monkeypatch) -> None:
    """The transport asks the ladder for fresh cookies and replays the request."""
    recorder = Recorder(
        (403, b"denied", "text/plain"),
        (200, CONFIG_JSON, "application/json"),
    )

    def heal(self, reason=None):
        self.adopt({"session": "fresh"})
        return {"session": "fresh"}

    monkeypatch.setattr(AutoSessionManager, "refresh_session", heal)
    options = isolated_options(tmp_path, cookies="session=stale", http_transport=recorder.transport)
    output = options.output
    with auto_client(options) as client:
        assert client.session_manager.load_cookies() == {"session": "fresh"}
    assert "session=stale" in recorder.cookies(0)
    assert "session=fresh" in recorder.cookies(1)
    assert "verification: ok" in output.getvalue()


def test_bootstrap_runs_the_ladder_when_the_transport_gives_up(tmp_path, monkeypatch) -> None:
    """Every attempt rejected: the ladder is tried once more, then reported."""
    recorder = Recorder()  # always 403 below

    def handler(request):
        recorder.requests.append(request)
        return httpx.Response(
            403, request=request, headers={"content-type": "text/plain"}, content=b"denied"
        )

    transport = httpx.MockTransport(handler)
    reasons: list = []

    def exhausted(self, reason=None):
        reasons.append(reason)
        return None

    monkeypatch.setattr(AutoSessionManager, "refresh_session", exhausted)
    options = isolated_options(tmp_path, cookies="session=stale", http_transport=transport)
    output = options.output
    with auto_client(options) as client:
        assert client.session_manager.load_cookies() == {"session": "stale"}
    assert reasons and all(isinstance(reason, AuthenticationError) for reason in reasons)
    assert "needs a refresh" in output.getvalue()
    assert "refresh produced no cookies" in output.getvalue()
    assert "verification: not ok" in output.getvalue()


def test_bootstrap_escalates_a_challenge_page_to_the_ladder(tmp_path) -> None:
    """A captcha interstitial is an auth problem, so the ladder is tried."""
    recorder = Recorder((200, RECAPTCHA_PAGE, "text/html"))
    options = isolated_options(tmp_path, cookies="session=abc", http_transport=recorder.transport)
    output = options.output
    with pytest.raises(AuthenticationError, match="no automatic refresh path"):
        auto_client(options)
    assert "needs a refresh" in output.getvalue()


def test_bootstrap_raises_when_a_rejected_session_cannot_be_healed(tmp_path) -> None:
    recorder = Recorder((403, b"denied", "text/plain"))
    options = isolated_options(tmp_path, cookies="session=stale", http_transport=recorder.transport)
    with pytest.raises(AuthenticationError, match="no automatic refresh path"):
        auto_client(options)


def test_bootstrap_without_verification_keeps_the_client(tmp_path) -> None:
    recorder = Recorder((403, b"denied", "text/plain"))
    options = isolated_options(
        tmp_path, cookies="session=abc", http_transport=recorder.transport, verify=False
    )
    with auto_client(options) as client:
        assert client.session_manager.load_cookies() == {"session": "abc"}
    assert recorder.requests == []


def test_bootstrap_asks_the_user_to_sign_in_when_nothing_is_found(tmp_path, monkeypatch) -> None:
    attempts = {"n": 0}
    prompts: list[str] = []

    def discovered_after_login(options):
        attempts["n"] += 1
        if attempts["n"] == 1:
            return None
        return DiscoveredSession(
            source="env",
            cookies={"session": "after-login"},
            headers={},
            description="user signed in",
        )

    monkeypatch.setattr(auto_module, "discover_session", discovered_after_login)
    recorder = Recorder((200, b"{}", "application/json"))
    options = isolated_options(
        tmp_path,
        http_transport=recorder.transport,
        verify=False,
        prompt=lambda message: prompts.append(message) or "",
    )
    with auto_client(options) as client:
        assert client.session_manager.load_cookies() == {"session": "after-login"}
    assert len(prompts) == 1
    assert "sign in to your account" in prompts[0]
    assert "arena.ai" in prompts[0]


def test_bootstrap_gives_up_when_the_login_wait_is_cancelled(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(auto_module, "discover_session", lambda options: None)

    def interrupt(message):
        raise KeyboardInterrupt

    options = isolated_options(tmp_path, prompt=interrupt, interactive=True)
    with pytest.raises(AuthenticationError, match="no session found"):
        auto_client(options)


def test_bootstrap_refuses_to_guess_in_non_interactive_mode(tmp_path) -> None:
    options = isolated_options(tmp_path, interactive=False)
    with pytest.raises(AuthenticationError) as info:
        auto_client(options)
    message = str(info.value)
    assert "no session found" in message
    assert "Sign in to your account" in message
    assert "ARENA_COOKIE" in message
    assert "disabled by use_browser_profiles=False" in message


def test_bootstrap_accepts_cookies_read_from_a_session_manager(tmp_path) -> None:
    recorder = Recorder((200, b"{}", "application/json"))
    manager = BrowserSessionManager(base_url="https://arena.ai", domains=("arena.ai",))
    manager.import_cookies({"session": "injected"})
    options = isolated_options(
        tmp_path, cookies=manager.load_cookies(), http_transport=recorder.transport
    )
    with auto_client(options):
        pass
    assert "session=injected" in recorder.cookies(0)


def test_bootstrap_passes_extra_client_arguments(tmp_path) -> None:
    recorder = Recorder((200, b"{}", "application/json"))
    options = isolated_options(tmp_path, cookies="session=abc", http_transport=recorder.transport)
    client = auto_client(options, verify=False, timeout=7, max_auth_refreshes=5)
    assert client.transport._max_auth_refreshes == 5
    assert client.transport.session.timeout.connect == 7
    client.close()


def test_async_bootstrap_verifies_and_heals(tmp_path, monkeypatch) -> None:
    recorder = Recorder(
        (403, b"denied", "text/plain"),
        (200, CONFIG_JSON, "application/json"),
    )

    def heal(self, reason=None):
        self.adopt({"session": "fresh"})
        return {"session": "fresh"}

    monkeypatch.setattr(AutoSessionManager, "refresh_session", heal)
    options = isolated_options(tmp_path, cookies="session=stale", http_transport=recorder.transport)

    async def run() -> list[str]:
        client = await auto_async_client(options)
        try:
            assert await client.get_models() == []
        finally:
            await client.aclose()
        return [request.headers.get("cookie", "") for request in recorder.requests]

    cookies = asyncio.run(run())
    assert "session=stale" in cookies[0]
    assert any("session=fresh" in value for value in cookies[1:])


# --------------------------------------------------------------------------- #
# The refresh ladder
# --------------------------------------------------------------------------- #


def make_manager(**kwargs) -> AutoSessionManager:
    kwargs.setdefault("base_url", "https://arena.ai")
    kwargs.setdefault("domains", ("arena.ai",))
    return AutoSessionManager(**kwargs)


def test_ladder_adopts_fresh_cookies_from_the_source_browser() -> None:
    source = StubSource({"session": "renewed"})
    manager = make_manager(fallback=source)
    reason = AuthenticationError("rejected (403)")
    assert manager.refresh_session(reason) == {"session": "renewed"}
    assert manager.load_cookies() == {"session": "renewed"}
    assert source.refresh_reasons == [reason]


def test_ladder_survives_a_source_that_fails(monkeypatch) -> None:
    class Exploding:
        def refresh_session(self, reason=None):
            raise RuntimeError("profile is locked")

    async def fake_refresh(self, reason=None):
        return {"session": "browser"}

    monkeypatch.setattr(auto_module.BrowserSessionManager, "arefresh_session", fake_refresh)
    manager = make_manager(fallback=Exploding(), login_flow=login_flow())
    assert manager.refresh_session() == {"session": "browser"}


def test_ladder_falls_through_to_the_browser_path(monkeypatch) -> None:
    source = StubSource(None)
    manager = make_manager(fallback=source, login_flow=login_flow())

    async def fake_refresh(self, reason=None):
        return {"session": "from-browser"}

    monkeypatch.setattr(auto_module.BrowserSessionManager, "arefresh_session", fake_refresh)
    assert manager.refresh_session("expired") == {"session": "from-browser"}
    # The browser owns the session now, so the headers follow it.
    assert manager._from_fallback is False
    assert "Chrome/" in manager.firefox_headers()["User-Agent"]


def test_ladder_explains_itself_when_no_rung_exists() -> None:
    manager = make_manager()
    with pytest.raises(AuthenticationError) as info:
        manager.refresh_session(AuthenticationError("rejected (403)"))
    message = str(info.value)
    assert "no automatic refresh path" in message
    assert "sign in again in your browser" in message
    assert "ARENA_USERNAME" in message
    assert "solve_captchas=True" in message


def test_headers_follow_the_source_that_owns_the_cookies() -> None:
    source = StubSource({"session": "one"})
    manager = make_manager(fallback=source)
    manager.adopt({"session": "one"})
    assert "Firefox/156.0" in manager.firefox_headers()["User-Agent"]
    manager._from_fallback = False
    assert "Chrome/" in manager.firefox_headers()["User-Agent"]


def test_headers_survive_a_source_without_them() -> None:
    class Headerless:
        def load_cookies(self, domains=None):
            return {"session": "x"}

        def firefox_headers(self, *, navigation=False):
            raise RuntimeError("no headers")

        def refresh_session(self, reason=None):
            return None

    manager = make_manager(fallback=Headerless())
    assert "Chrome/" in manager.firefox_headers()["User-Agent"]


def test_parallel_refreshes_do_not_repeat_the_work() -> None:
    """Two requests failing at once must not start two browsers or two prompts."""

    class SlowSource(StubSource):
        def __init__(self):
            super().__init__({"session": "renewed"})
            self.calls = 0

        def refresh_session(self, reason=None):
            self.calls += 1
            time.sleep(0.05)
            return dict(self.cookies)

    source = SlowSource()
    manager = make_manager(fallback=source)
    gate = threading.Barrier(2, timeout=10)

    def refresh(_):
        gate.wait()
        return manager.refresh_session(AuthenticationError("rejected (403)"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(refresh, range(2)))

    assert source.calls == 1
    assert results == [{"session": "renewed"}, {"session": "renewed"}]
    assert manager.load_cookies() == {"session": "renewed"}


def test_a_second_refresh_after_a_failed_one_still_tries() -> None:
    """The short-circuit only applies while another thread already succeeded."""
    source = StubSource(None)
    manager = make_manager(fallback=source)
    with pytest.raises(AuthenticationError, match="no automatic refresh path"):
        manager.refresh_session()
    source.cookies = {"session": "late"}
    assert manager.refresh_session() == {"session": "late"}


def test_adopt_replaces_the_cookie_set() -> None:
    manager = make_manager()
    manager.adopt({"session": "adopted", "other": "value"})
    assert manager.load_cookies() == {"session": "adopted", "other": "value"}


def test_build_session_manager_wires_the_ladder_and_solver(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        auto_module,
        "_has_spec",
        lambda name: name in {"playwright", "playwright_recaptcha", "playwright_stealth"},
    )
    source = StubSource({"session": "one"})
    discovered = DiscoveredSession(
        source="firefox", cookies={"session": "one"}, headers={}, manager=source
    )
    options = isolated_options(tmp_path, login_from_env=False, solve_captchas="auto")
    manager = build_session_manager(options, discovered)
    assert manager.fallback is source
    assert isinstance(manager.captcha_solver, CompositeSolver)
    assert isinstance(manager.captcha_solver.solvers[0], RecaptchaToolkitSolver)
    assert isinstance(manager.captcha_solver.solvers[1], ChallengeWaitSolver)
    assert manager.challenge_handler.solve_on_detection is True
    assert manager.base_url == options.base_url
    assert manager.domains == options.cookie_domains()
    assert manager.load_cookies() == {"session": "one"}


def test_build_session_manager_keeps_the_storage_path_for_stored_state(tmp_path) -> None:
    path = write_storage(tmp_path, {"session": "stored"})
    discovered = DiscoveredSession(source="storage", cookies={"session": "stored"}, headers={})
    options = isolated_options(tmp_path, storage_path=path)
    manager = build_session_manager(options, discovered)
    assert manager.storage_path == path
    assert manager.fallback is None
    assert manager.load_cookies() == {"session": "stored"}
    assert manager._from_fallback is False


def test_build_session_manager_reads_a_playwright_storage_state(tmp_path) -> None:
    path = tmp_path / "state" / "cookies.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "cookies": [
                    {
                        "name": "session",
                        "value": "stored",
                        "domain": "arena.ai",
                        "path": "/",
                        "expires": -1,
                        "httpOnly": True,
                    }
                ],
                "origins": [{"origin": "https://arena.ai", "localStorage": []}],
            }
        ),
        encoding="utf-8",
    )
    options = isolated_options(tmp_path, storage_path=path)
    discovered = discover_session(options)
    assert discovered.source == "storage"
    manager = build_session_manager(options, discovered)
    # The file is understood by the manager itself, so its origins survive.
    assert manager.load_cookies() == {"session": "stored"}
    assert manager._load_state()["origins"][0]["origin"] == "https://arena.ai"


def test_build_session_manager_ignores_the_storage_path_for_other_sources(tmp_path) -> None:
    discovered = DiscoveredSession(source="env", cookies={"session": "env"}, headers={})
    options = isolated_options(tmp_path, storage_path=tmp_path / "state.json")
    manager = build_session_manager(options, discovered)
    assert manager.storage_path is None
    assert manager.load_cookies() == {"session": "env"}


# --------------------------------------------------------------------------- #
# Direct Chat
# --------------------------------------------------------------------------- #


def test_direct_client_uses_the_self_healing_session_source(tmp_path) -> None:
    recorder = Recorder((200, b"<html></html>", "text/html"))
    options = isolated_options(tmp_path, cookies="session=abc", http_transport=recorder.transport)
    client = auto_direct_client(options)
    assert isinstance(client.session_manager, AutoSessionManager)
    assert client.transport._session_refresher is not None
    client.close()


def test_async_direct_client_is_wired_the_same_way(tmp_path) -> None:
    recorder = Recorder((200, b"<html></html>", "text/html"))
    options = isolated_options(tmp_path, cookies="session=abc", http_transport=recorder.transport)

    async def run() -> bool:
        client = await auto_module.auto_async_direct_client(options)
        await client.aclose()
        return client.transport._session_refresher is not None

    assert asyncio.run(run()) is True


def test_direct_client_verifies_the_session_at_startup(tmp_path) -> None:
    recorder = Recorder((200, CONFIG_JSON, "application/json"))
    options = isolated_options(tmp_path, cookies="session=abc", http_transport=recorder.transport)
    output = options.output
    client = auto_direct_client(options)
    assert recorder.requests[0].url.path == "/config"
    assert "verification: ok" in output.getvalue()
    client.close()


def test_direct_client_heals_a_rejected_session(tmp_path, monkeypatch) -> None:
    recorder = Recorder(
        (403, b"denied", "text/plain"),
        (200, CONFIG_JSON, "application/json"),
    )

    def heal(self, reason=None):
        self.adopt({"session": "fresh"})
        return {"session": "fresh"}

    monkeypatch.setattr(AutoSessionManager, "refresh_session", heal)
    options = isolated_options(tmp_path, cookies="session=stale", http_transport=recorder.transport)
    client = auto_direct_client(options)
    assert "session=fresh" in recorder.cookies(1)
    assert "verification: ok" in options.output.getvalue()
    client.close()


def test_direct_client_can_skip_verification(tmp_path) -> None:
    recorder = Recorder((200, CONFIG_JSON, "application/json"))
    options = isolated_options(
        tmp_path, cookies="session=abc", http_transport=recorder.transport, verify=False
    )
    client = auto_direct_client(options)
    assert recorder.requests == []
    client.close()


def test_async_direct_client_verifies_too(tmp_path) -> None:
    recorder = Recorder((200, CONFIG_JSON, "application/json"))
    options = isolated_options(tmp_path, cookies="session=abc", http_transport=recorder.transport)

    async def run() -> str:
        client = await auto_module.auto_async_direct_client(options)
        await client.aclose()
        return options.output.getvalue()

    assert "verification: ok" in asyncio.run(run())
    assert recorder.requests[0].url.path == "/config"


def test_the_direct_chat_page_is_allowed_to_carry_a_captcha() -> None:
    """Direct Chat embeds a v3 assertion on every load: that is not a challenge."""
    page = (
        b'<!doctype html><html><body>'
        b'<div class="g-recaptcha" data-sitekey="6Lc" data-size="invisible"></div>'
        b'</body></html>'
    )
    recorder = Recorder((200, page, "text/html"))
    with ArenaClient(http_transport=recorder.transport) as client:
        assert probe(client, DIRECT_PAGE_PATH).ok
    recorder = Recorder((200, page, "text/html"))
    with ArenaClient(http_transport=recorder.transport) as client:
        result = probe(client, "/some/other/page")
    assert not result.ok and result.auth_problem


def test_direct_token_factory_pins_the_toolkit_solver_to_v3() -> None:
    factory = DirectVerificationToken(
        AutoOptions(captcha_solver=RecaptchaToolkitSolver(version="v2"), solve_captchas=False)
    )
    assert isinstance(factory.solver, RecaptchaToolkitSolver)
    assert factory.solver.version == "v3"
    assert factory.solver.reload_for_v3 is True
    assert factory.page_url.endswith("/text/direct?model_a=max")


def test_direct_token_factory_accepts_a_custom_solver() -> None:
    solver = TokenSolver()
    factory = DirectVerificationToken(AutoOptions(captcha_solver=solver, solve_captchas=False))
    assert factory.solver is solver


def test_direct_token_factory_honours_an_explicit_page_url() -> None:
    factory = DirectVerificationToken(
        AutoOptions(captcha_solver=TokenSolver(), solve_captchas=False),
        page_url="https://example.test/direct",
    )
    assert factory.page_url == "https://example.test/direct"


def test_direct_token_factory_solves_on_the_direct_page(monkeypatch) -> None:
    class FakePage:
        url = "https://arena.ai/text/direct?model_a=max"

        def __init__(self):
            self.visited = []

        async def goto(self, url, **kwargs):
            self.visited.append((url, kwargs.get("wait_until")))

    class FakeEnvironment:
        instances = []

        def __init__(self, options):
            self.options = options
            self.page = FakePage()
            FakeEnvironment.instances.append(self)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def new_page(self):
            return self.page

    monkeypatch.setattr(auto_module, "BrowserEnvironment", FakeEnvironment)
    solver = TokenSolver("direct-token")
    factory = DirectVerificationToken(AutoOptions(captcha_solver=solver, solve_captchas=False))
    assert asyncio.run(factory.afetch()) == "direct-token"
    assert solver.calls == ["https://arena.ai/text/direct?model_a=max"]
    environment = FakeEnvironment.instances[0]
    assert environment.page.visited[0][1] == "domcontentloaded"
    options = environment.options
    assert options.captcha_solver is solver
    assert options.solve_challenges is True
    assert options.headless is True
    assert options.identify_automation is False


def test_direct_token_factory_fails_fast_without_dependencies(monkeypatch) -> None:
    monkeypatch.setattr(auto_module, "_has_spec", lambda name: False)
    factory = DirectVerificationToken(AutoOptions(solve_captchas=False))
    with pytest.raises(AuthenticationError, match="auth-captcha"):
        asyncio.run(factory.afetch())


def test_direct_token_factory_unwraps_a_composite_solver(monkeypatch) -> None:
    """The assertion can only come from the token member of the default pair."""
    monkeypatch.setattr(
        auto_module,
        "_has_spec",
        lambda name: name in {"playwright", "playwright_recaptcha", "playwright_stealth"},
    )

    factory = DirectVerificationToken(AutoOptions())

    assert isinstance(factory.solver, RecaptchaToolkitSolver)
    assert factory.solver.version == "v3"
    assert factory.solver.reload_for_v3 is True


def test_direct_token_factory_refuses_a_wait_only_solver(monkeypatch) -> None:
    """Without the token backends the default solver can only *wait*: it would
    report the page cleared and hand back an empty assertion."""
    monkeypatch.setattr(auto_module, "_has_spec", lambda name: False)

    factory = DirectVerificationToken(AutoOptions())

    assert isinstance(factory.solver, ChallengeWaitSolver)
    with pytest.raises(AuthenticationError, match="does not accept reCAPTCHA"):
        asyncio.run(factory.afetch())


def test_direct_token_factory_refuses_an_empty_assertion(monkeypatch) -> None:
    class ClearedSolver:
        """Accepts reCAPTCHA but clears the page without producing a token."""

        def supports(self, observation):
            return True

        async def asolve(self, page, observation=None):
            return CaptchaAttempt(backend="wait", cleared=True)

    class FakePage:
        url = "https://arena.ai/text/direct?model_a=max"

        async def goto(self, url, **kwargs):
            return None

    class FakeEnvironment:
        def __init__(self, options):
            self.options = options

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def new_page(self):
            return FakePage()

    monkeypatch.setattr(auto_module, "BrowserEnvironment", FakeEnvironment)
    factory = DirectVerificationToken(
        AutoOptions(captcha_solver=ClearedSolver(), solve_captchas=False)
    )

    with pytest.raises(AuthenticationError, match="produced no assertion"):
        asyncio.run(factory.afetch())


def test_direct_token_factory_is_callable_sync_style(monkeypatch) -> None:
    async def fake_fetch(self):
        return "sync-token"

    monkeypatch.setattr(DirectVerificationToken, "afetch", fake_fetch)
    factory = DirectVerificationToken(AutoOptions(captcha_solver=TokenSolver()))
    assert factory() == "sync-token"


def test_verification_token_auto_selects_the_factory(tmp_path) -> None:
    recorder = Recorder((200, b"<html></html>", "text/html"))
    options = isolated_options(tmp_path, cookies="session=abc", http_transport=recorder.transport)
    client = auto_direct_client(options, verification_token="auto")
    assert isinstance(client.verification_token, DirectVerificationToken)
    client.close()


def test_explicit_verification_token_is_kept(tmp_path) -> None:
    recorder = Recorder((200, b"<html></html>", "text/html"))
    options = isolated_options(tmp_path, cookies="session=abc", http_transport=recorder.transport)
    client = auto_direct_client(options, verification_token="03TOKEN")
    assert client.verification_token == "03TOKEN"
    client.close()


def test_options_are_replaceable(tmp_path) -> None:
    options = isolated_options(tmp_path, cookies="session=abc")
    tweaked = replace(options, verify=False)
    assert tweaked.verify is False
    assert tweaked.cookies == "session=abc"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def patch_cli(monkeypatch, client, result: ProbeResult | None = None) -> None:
    monkeypatch.setattr(auto_module, "auto_client", lambda options=None, **kwargs: client)
    monkeypatch.setattr(auto_module, "probe", lambda client, path: result or ProbeResult(True, "session accepted"))


def test_cli_explain_needs_no_session(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(auto_module, "_has_spec", lambda name: False)
    assert main(["--explain"]) == 0
    out = capsys.readouterr().out
    assert "cookies=" in out
    assert "login flow" in out
    assert "captcha solving" in out
    assert "dependencies missing" in out


def test_cli_status_reports_a_missing_session(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["--status", "--no-verify", "--no-browser-profiles"]) == 1
    assert "none found" in capsys.readouterr().out


def test_cli_status_reports_a_found_session_without_verifying(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARENA_COOKIE", "session=abc")
    assert main(["--status", "--no-verify", "--no-browser-profiles"]) == 0
    assert "ARENA_COOKIE" in capsys.readouterr().out


def test_cli_status_verifies_a_found_session(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARENA_COOKIE", "session=abc")
    client = DummyClient()
    patch_cli(monkeypatch, client)
    assert main(["--status", "--no-browser-profiles"]) == 0
    out = capsys.readouterr().out
    assert "ARENA_COOKIE" in out
    assert "verification" in out and "ok" in out
    assert client.closed is True


def test_cli_status_reports_a_rejected_session(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARENA_COOKIE", "session=abc")
    patch_cli(
        monkeypatch,
        DummyClient(),
        ProbeResult(False, "session rejected", auth_problem=True),
    )
    assert main(["--status", "--no-browser-profiles"]) == 2
    assert "not ok: session rejected" in capsys.readouterr().out


def test_cli_lists_models(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARENA_COOKIE", "session=abc")
    patch_cli(monkeypatch, DummyClient([ModelInfo(id="max", display_name="Max")]))
    assert main(["--models", "--no-browser-profiles"]) == 0
    out = capsys.readouterr().out
    assert "models" in out
    assert "max — Max" in out


def test_cli_sends_a_prompt(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARENA_COOKIE", "session=abc")
    patch_cli(monkeypatch, DummyClient())
    assert main(["--prompt", "Hello", "--no-verify", "--no-browser-profiles"]) == 0
    assert "echo: Hello" in capsys.readouterr().out


def test_cli_without_a_task_reports_a_ready_session(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARENA_COOKIE", "session=abc")
    patch_cli(monkeypatch, DummyClient())
    assert main(["--no-verify", "--no-browser-profiles"]) == 0
    assert "ready" in capsys.readouterr().out


def test_cli_reports_a_bootstrap_failure_on_stderr(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)

    def boom(options=None, **kwargs):
        raise AuthenticationError("no session found")

    monkeypatch.setattr(auto_module, "auto_client", boom)
    assert main(["--prompt", "Hello", "--no-browser-profiles"]) == 1
    captured = capsys.readouterr()
    assert "no session found" in captured.err
    assert captured.out == ""


def test_documented_command_runs_without_warnings(tmp_path) -> None:
    """``python -m arena_api --explain`` is the command the README promises."""
    completed = subprocess.run(
        [sys.executable, "-m", "arena_api", "--explain"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "PYTHONWARNINGS": "error::RuntimeWarning"},
    )
    assert completed.returncode == 0, completed.stderr
    assert "cookies=" in completed.stdout
    assert "RuntimeWarning" not in completed.stderr


def test_cli_maps_flags_onto_options(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    options = _options_from_args(
        build_arg_parser().parse_args(
            [
                "--base-url",
                "https://example.test",
                "--cookies",
                "session=abc",
                "--storage",
                "state/cookies.json",
                "--no-browser-profiles",
                "--non-interactive",
                "--solve",
                "on",
                "--backend",
                "image",
                "--probe-path",
                "/queue/status",
                "--no-verify",
            ]
        )
    )
    assert options.base_url == "https://example.test"
    assert options.cookies == "session=abc"
    assert options.storage_path == Path("state/cookies.json")
    assert options.use_browser_profiles is False
    assert options.interactive is False
    assert options.solve_captchas is True
    assert options.captcha_backend == "image"
    assert options.probe_path == "/queue/status"
    assert options.verify is False


def test_cli_solve_off_disables_the_solver(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    options = _options_from_args(build_arg_parser().parse_args(["--solve", "off"]))
    assert options.solve_captchas is False


def test_cli_defaults_to_automatic_solving(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    options = _options_from_args(build_arg_parser().parse_args([]))
    assert options.solve_captchas == "auto"
    assert options.verify is True
    assert options.interactive is True
    assert options.use_browser_profiles is True


# --------------------------------------------------------------------------- #
# interactive_login: sign in once, by hand
# --------------------------------------------------------------------------- #


def stub_login(monkeypatch, result: LoginResult) -> dict:
    """Replace :func:`login_and_save` and record the call."""
    calls: dict = {}

    def fake(**kwargs):
        calls.update(kwargs)
        return result

    monkeypatch.setattr(auto_module, "login_and_save", fake)
    return calls


def saved_result(path: Path) -> LoginResult:
    return LoginResult(
        cookies=({"name": "session", "value": "abc", "domain": "arena.ai"},),
        path=path,
        saved=True,
        accepted=True,
        attempts=1,
        domains=("arena.ai",),
    )


def test_interactive_login_saves_then_verifies_the_saved_file(tmp_path, monkeypatch) -> None:
    destination = tmp_path / "state" / "cookies.json"
    calls = stub_login(monkeypatch, saved_result(destination))
    seen: list = []

    def fake_client(options=None, **kwargs):
        seen.append(options)
        return DummyClient([ModelInfo(id="max", display_name="Max")])

    monkeypatch.setattr(auto_module, "auto_client", fake_client)
    monkeypatch.setattr(
        auto_module, "probe", lambda client, path: ProbeResult(True, f"accepted via {path}")
    )

    outcome = interactive_login(AutoOptions(), path=destination)

    assert isinstance(outcome, LoginOutcome)
    assert outcome.ok is True
    assert outcome.path == destination
    assert outcome.verification is not None and outcome.verification.ok is True
    assert calls["path"] == destination
    # the probe must test exactly what was written, and must not heal itself
    probe_options = seen[0]
    assert probe_options.storage_path == destination  # normalised to a Path
    assert probe_options.cookies is None
    assert probe_options.use_browser_profiles is False
    assert probe_options.interactive is False
    assert probe_options.verify is False
    assert "accepted via /config" in outcome.describe()


def test_interactive_login_verifies_nothing_when_no_session_was_saved(tmp_path, monkeypatch) -> None:
    calls = stub_login(
        monkeypatch,
        LoginResult(cookies=({"name": "cf", "value": "1", "domain": "arena.ai"},), attempts=2),
    )
    output = io.StringIO()

    def boom(options=None, **kwargs):  # pragma: no cover - must not be called
        raise AssertionError("verification should be skipped")

    monkeypatch.setattr(auto_module, "auto_client", boom)
    outcome = interactive_login(AutoOptions(output=output), path=tmp_path / "c.json")

    assert outcome.ok is False
    assert outcome.verification is None
    assert outcome.path is None
    assert calls["rounds"] == 5
    assert "skipping verification" in output.getvalue()


def test_interactive_login_reports_a_rejected_session(tmp_path, monkeypatch) -> None:
    destination = tmp_path / "cookies.json"
    stub_login(monkeypatch, saved_result(destination))
    monkeypatch.setattr(auto_module, "auto_client", lambda options=None, **kwargs: DummyClient())
    monkeypatch.setattr(
        auto_module,
        "probe",
        lambda client, path: ProbeResult(False, "session rejected", auth_problem=True),
    )
    output = io.StringIO()

    outcome = interactive_login(AutoOptions(output=output), path=destination)

    assert outcome.ok is False
    assert outcome.verification is not None and outcome.verification.auth_problem is True
    assert "did not verify" in output.getvalue()


def test_interactive_login_maps_a_bootstrap_error_onto_the_probe_result(tmp_path, monkeypatch) -> None:
    """A broken state file must not escape as an exception from a login call."""
    destination = tmp_path / "cookies.json"
    stub_login(monkeypatch, saved_result(destination))

    def boom(options=None, **kwargs):
        raise AuthenticationError("the stored session could not be read")

    monkeypatch.setattr(auto_module, "auto_client", boom)

    outcome = interactive_login(AutoOptions(), path=destination)

    assert outcome.ok is False
    assert outcome.verification is not None
    assert "rejected or expired" in outcome.verification.reason


def test_interactive_login_can_skip_verification(tmp_path, monkeypatch) -> None:
    destination = tmp_path / "cookies.json"
    stub_login(monkeypatch, saved_result(destination))
    monkeypatch.setattr(auto_module, "auto_client", lambda options=None, **kwargs: DummyClient())
    monkeypatch.setattr(auto_module, "probe", lambda client, path: ProbeResult(True, "unused"))

    outcome = interactive_login(AutoOptions(verify=False), path=destination, verify=None)

    assert outcome.verification is None
    assert outcome.ok is True


def test_interactive_login_forwards_the_solver_and_the_form_flow(tmp_path, monkeypatch) -> None:
    calls = stub_login(monkeypatch, saved_result(tmp_path / "c.json"))
    solver = object()
    flow = FormLoginFlow(
        login_url="https://arena.ai/login",
        username_selector="#u",
        password_selector="#p",
        submit_selector="#s",
    )
    monkeypatch.setattr(auto_module, "resolve_solver", lambda options: solver)
    monkeypatch.setattr(auto_module, "login_flow_from_env", lambda options: flow)

    interactive_login(AutoOptions(base_url="https://arena.ai"), path=tmp_path / "c.json")

    assert calls["captcha_solver"] is solver
    assert calls["login_flow"] is flow
    assert calls["base_url"] == "https://arena.ai"
    assert calls["domains"] == ("arena.ai", "lmarena.ai")
    assert calls["headless"] is False
    assert calls["reuse_existing"] is True


def test_interactive_login_forwards_the_browser_channel(tmp_path, monkeypatch) -> None:
    """Google refuses sign-in from Playwright's Chromium build, not from Chrome."""
    calls = stub_login(monkeypatch, saved_result(tmp_path / "c.json"))

    interactive_login(AutoOptions(), path=tmp_path / "c.json")
    assert calls["channel"] is None  # the bundled build stays the default

    interactive_login(AutoOptions(channel="chrome"), path=tmp_path / "c.json")
    assert calls["channel"] == "chrome"

    # ...and it is reachable as an override too, without touching AutoOptions.
    interactive_login(AutoOptions(), path=tmp_path / "c.json", channel="msedge")
    assert calls["channel"] == "msedge"


def test_interactive_login_forwards_hide_automation(tmp_path, monkeypatch) -> None:
    """Google's check is about the window, not about the session it yields."""
    calls = stub_login(monkeypatch, saved_result(tmp_path / "c.json"))

    interactive_login(AutoOptions(), path=tmp_path / "c.json")
    assert calls["hide_automation"] is False  # honest by default

    interactive_login(AutoOptions(hide_automation=True), path=tmp_path / "c.json")
    assert calls["hide_automation"] is True

    interactive_login(AutoOptions(), path=tmp_path / "c.json", hide_automation=True)
    assert calls["hide_automation"] is True


def test_interactive_login_fresh_start_ignores_the_old_session(tmp_path, monkeypatch) -> None:
    calls = stub_login(monkeypatch, saved_result(tmp_path / "c.json"))

    interactive_login(AutoOptions(), path=tmp_path / "c.json", fresh=True, rounds=2, headless=True)

    assert calls["reuse_existing"] is False
    assert calls["rounds"] == 2
    assert calls["headless"] is True


def test_interactive_login_destination_precedence(tmp_path, monkeypatch) -> None:
    calls = stub_login(monkeypatch, LoginResult())

    interactive_login(AutoOptions())
    assert calls["path"] == DEFAULT_STATE_PATH

    interactive_login(AutoOptions(storage_path=str(tmp_path / "stored.json")))
    assert calls["path"] == tmp_path / "stored.json"

    explicit = tmp_path / "explicit.json"
    interactive_login(AutoOptions(storage_path="ignored.json"), path=explicit)
    assert calls["path"] == explicit


def test_interactive_login_accepts_option_overrides(tmp_path, monkeypatch) -> None:
    calls = stub_login(monkeypatch, saved_result(tmp_path / "c.json"))
    monkeypatch.setattr(auto_module, "auto_client", lambda options=None, **kwargs: DummyClient())
    monkeypatch.setattr(auto_module, "probe", lambda client, path: ProbeResult(True, "ok"))

    interactive_login(AutoOptions(base_url="https://arena.ai"), base_url="https://lmarena.ai")

    assert calls["base_url"] == "https://lmarena.ai"


def test_login_outcome_describe_mentions_both_parts(tmp_path) -> None:
    outcome = LoginOutcome(
        login=saved_result(tmp_path / "c.json"),
        verification=ProbeResult(True, "session accepted"),
        path=tmp_path / "c.json",
    )

    assert "login:" in outcome.describe()
    assert "verification: ok: session accepted" in outcome.describe()
    assert outcome.ok is True


# --------------------------------------------------------------------------- #
# ``arena-api --login``
# --------------------------------------------------------------------------- #


def stub_cli_login(monkeypatch, outcome: LoginOutcome) -> dict:
    calls: dict = {}

    def fake(options=None, **kwargs):
        calls["options"] = options
        calls.update(kwargs)
        return outcome

    monkeypatch.setattr(auto_module, "interactive_login", fake)
    return calls


def test_cli_login_reports_a_saved_and_verified_session(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    destination = tmp_path / "state" / "cookies.json"
    stub_cli_login(
        monkeypatch,
        LoginOutcome(
            login=saved_result(destination),
            verification=ProbeResult(True, "session accepted"),
            path=destination,
        ),
    )

    assert main(["--login"]) == 0

    out = capsys.readouterr().out
    assert out.startswith("login               : ")
    assert "verification" in out
    assert str(destination) in out


def test_cli_login_exits_2_when_the_server_rejects_the_session(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    stub_cli_login(
        monkeypatch,
        LoginOutcome(
            login=saved_result(tmp_path / "c.json"),
            verification=ProbeResult(False, "session rejected", auth_problem=True),
            path=tmp_path / "c.json",
        ),
    )

    assert main(["--login"]) == 2
    assert "not ok: session rejected" in capsys.readouterr().out


def test_cli_login_exits_0_without_verification(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    stub_cli_login(
        monkeypatch, LoginOutcome(login=saved_result(tmp_path / "c.json"), path=tmp_path / "c.json")
    )

    assert main(["--login", "--no-verify"]) == 0
    assert "verification" not in capsys.readouterr().out


def test_cli_login_exits_1_when_no_cookies_came_back(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    stub_cli_login(monkeypatch, LoginOutcome(login=LoginResult()))

    assert main(["--login"]) == 1
    assert "no cookies captured" in capsys.readouterr().out


def test_cli_login_exits_1_when_nothing_was_written(tmp_path, monkeypatch, capsys) -> None:
    """Anonymous cookies are not a session: say so instead of reporting success."""
    monkeypatch.chdir(tmp_path)
    stub_cli_login(
        monkeypatch,
        LoginOutcome(
            login=LoginResult(
                cookies=({"name": "cf", "value": "1", "domain": "arena.ai"},), attempts=5
            )
        ),
    )

    assert main(["--login"]) == 1

    out = capsys.readouterr().out
    assert "not written" in out
    assert "no sign-in detected" in out


def test_cli_login_maps_its_flags(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    calls = stub_cli_login(
        monkeypatch, LoginOutcome(login=saved_result(tmp_path / "saved.json"), path=tmp_path / "saved.json")
    )

    assert main(
        [
            "--login",
            "--storage",
            "saved.json",
            "--fresh",
            "--headless",
            "--login-rounds",
            "2",
            "--channel",
            "chrome",
            "--hide-automation",
        ]
    ) == 0

    assert calls["path"] == Path("saved.json")  # the CLI keeps the path as given
    assert calls["fresh"] is True
    assert calls["headless"] is True
    assert calls["rounds"] == 2
    assert calls["options"].channel == "chrome"  # the window will be real Chrome
    assert calls["options"].hide_automation is True


def test_cli_login_defaults_to_the_discoverable_state_file(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    calls = stub_cli_login(monkeypatch, LoginOutcome(login=LoginResult()))

    assert main(["--login"]) == 1
    assert calls["path"] == DEFAULT_STATE_PATH


def test_cli_login_can_continue_into_a_task(tmp_path, monkeypatch, capsys) -> None:
    """``--login --models``: sign in, then use the session right away."""
    monkeypatch.chdir(tmp_path)
    destination = tmp_path / "state" / "cookies.json"
    stub_cli_login(
        monkeypatch,
        LoginOutcome(
            login=saved_result(destination),
            verification=ProbeResult(True, "session accepted"),
            path=destination,
        ),
    )
    seen: list = []

    def fake_client(options=None, **kwargs):
        seen.append(options)
        return DummyClient([ModelInfo(id="max", display_name="Max")])

    monkeypatch.setattr(auto_module, "auto_client", fake_client)

    assert main(["--login", "--models"]) == 0

    out = capsys.readouterr().out
    assert "login" in out and "max — Max" in out
    assert seen[0].storage_path == DEFAULT_STATE_PATH
    assert seen[0].cookies is None
    assert seen[0].use_browser_profiles is False


def test_cli_login_stops_before_a_task_when_it_failed(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    stub_cli_login(monkeypatch, LoginOutcome(login=LoginResult()))

    def boom(options=None, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("the task should not run after a failed login")

    monkeypatch.setattr(auto_module, "auto_client", boom)

    assert main(["--login", "--models"]) == 1
    assert "no cookies captured" in capsys.readouterr().out


def test_cli_login_reports_a_browser_error_on_stderr(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)

    def boom(options=None, **kwargs):
        raise AuthenticationError("chromium is not installed; run playwright install chromium")

    monkeypatch.setattr(auto_module, "interactive_login", boom)

    assert main(["--login"]) == 1
    captured = capsys.readouterr()
    assert "playwright install chromium" in captured.err
    assert captured.out == ""


def test_cli_help_documents_the_login_flags() -> None:
    text = build_arg_parser().format_help()
    for flag in (
        "--login",
        "--fresh",
        "--headless",
        "--login-rounds",
        "--storage",
        "--channel",
        "--hide-automation",
    ):
        assert flag in text


def test_cli_channel_failure_suggests_the_right_browser(tmp_path, monkeypatch, capsys) -> None:
    """With ``--channel chrome`` the bundled download would not help: say what does."""
    monkeypatch.chdir(tmp_path)

    def boom(options=None, **kwargs):
        raise RuntimeError(
            "BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/x\n"
            "Please run the following command to download new browsers"
        )

    monkeypatch.setattr(auto_module, "interactive_login", boom)

    assert main(["--login", "--channel", "chrome"]) == 1

    captured = capsys.readouterr()
    assert "Google Chrome" in captured.err
    assert "drop --channel" in captured.err
    assert len(captured.err.strip().splitlines()) == 1, "the hint must stay one line"
    assert captured.out == ""


# --------------------------------------------------------------------------- #
# Other challenge kinds: waiting instead of tokens
# --------------------------------------------------------------------------- #


def test_the_wait_solver_covers_every_kind_a_token_cannot() -> None:
    from arena_api.auth.captcha import WAITABLE_CHALLENGE_KINDS

    assert WAITABLE_CHALLENGE_KINDS == (
        ChallengeKind.TURNSTILE,
        ChallengeKind.CLOUDFLARE_MANAGED,
        ChallengeKind.HCAPTCHA,
        ChallengeKind.DATADOME,
        ChallengeKind.INTERSTITIAL,
        ChallengeKind.UNKNOWN,
    )
    solver = ChallengeWaitSolver()
    for kind in WAITABLE_CHALLENGE_KINDS:
        assert solver.supports(_observation(kind)) is True
    assert solver.supports(_observation(ChallengeKind.RECAPTCHA)) is False
    assert solver.supports(_observation(ChallengeKind.RATE_LIMIT)) is False
    assert solver.supports(_observation(ChallengeKind.NONE)) is False


def test_the_composite_solver_leaves_reCAPTCHA_to_the_toolkit(monkeypatch) -> None:
    monkeypatch.setattr(
        auto_module,
        "_has_spec",
        lambda name: name in {"playwright", "playwright_recaptcha", "playwright_stealth"},
    )
    solver = resolve_solver(AutoOptions())

    assert solver.supports(_observation(ChallengeKind.RECAPTCHA)) is True
    assert solver.supports(_observation(ChallengeKind.DATADOME)) is True
    assert solver.supports(_observation(ChallengeKind.NONE)) is False
    assert solver.select(_observation(ChallengeKind.RATE_LIMIT)) is None


def test_cli_explain_reports_the_solver_that_will_actually_run(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(auto_module, "_has_spec", lambda name: False)

    assert main(["--explain"]) == 0
    out = capsys.readouterr().out
    assert "dependencies missing" in out
    assert "-> wait[" in out

    capsys.readouterr()
    assert main(["--explain", "--no-wait"]) == 0
    out = capsys.readouterr().out
    assert "-> off" in out


def test_cli_wait_flags_map_onto_options(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    options = _options_from_args(
        build_arg_parser().parse_args(["--no-wait", "--wait-timeout", "7.5"])
    )
    assert options.wait_out_challenges is False
    assert options.challenge_wait_timeout == 7.5

    options = _options_from_args(build_arg_parser().parse_args([]))
    assert options.wait_out_challenges is True
    assert options.challenge_wait_timeout == 30.0


def test_cli_help_documents_the_wait_flags() -> None:
    text = build_arg_parser().format_help()
    for flag in ("--no-wait", "--wait-timeout"):
        assert flag in text


def test_cli_login_translates_a_browser_failure_into_one_line(tmp_path, monkeypatch, capsys) -> None:
    """A missing browser binary must read as a one-command fix, not a traceback."""
    monkeypatch.chdir(tmp_path)

    def boom(options=None, **kwargs):
        raise RuntimeError(
            "BrowserType.launch: Executable doesn't exist at /root/.cache/ms-playwright/x\n"
            "Looks like Playwright was just installed or updated.\n"
            "Please run the following command to download new browsers"
        )

    monkeypatch.setattr(auto_module, "interactive_login", boom)

    assert main(["--login"]) == 1

    captured = capsys.readouterr()
    assert "Executable doesn't exist" in captured.err
    assert "playwright install chromium" in captured.err
    assert len(captured.err.strip().splitlines()) == 1, "the hint must stay one line"
    assert captured.out == ""


# --------------------------------------------------------------------------- #
# Profiles, --diagnose and the redacted report
# --------------------------------------------------------------------------- #


def make_extra_firefox_profile(profiles: Path, name: str, rows) -> Path:
    """Add one more profile (and its cookie database) to a Firefox tree."""
    profile = profiles / name
    profile.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(profile / "cookies.sqlite")
    connection.executescript(
        """
        CREATE TABLE moz_cookies (
            id INTEGER PRIMARY KEY,
            originAttributes TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL,
            value TEXT NOT NULL,
            host TEXT NOT NULL,
            path TEXT NOT NULL DEFAULT '/',
            expiry INTEGER NOT NULL,
            lastAccessed INTEGER NOT NULL,
            creationTime INTEGER NOT NULL,
            isSecure INTEGER NOT NULL,
            isHttpOnly INTEGER NOT NULL,
            inBrowserElement INTEGER NOT NULL DEFAULT 0,
            sameSite INTEGER NOT NULL DEFAULT 0,
            rawSameSite INTEGER NOT NULL DEFAULT 0,
            schemeMap INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    connection.executemany(
        "INSERT INTO moz_cookies"
        " (name, value, host, path, expiry, lastAccessed, creationTime,"
        " isSecure, isHttpOnly)"
        " VALUES (?, ?, ?, '/', ?, 0, 0, 1, 1)",
        rows,
    )
    connection.commit()
    connection.close()
    (profile / "prefs.js").write_text("", encoding="utf-8")
    return profile


def test_the_reader_uses_the_profile_that_holds_the_session(tmp_path) -> None:
    """Discovery must not stop at the profile ``profiles.ini`` calls default."""
    root = tmp_path / "firefox"
    (root / "Profiles").mkdir(parents=True)
    make_extra_firefox_profile(root / "Profiles", "aaaa.default-release", [])
    make_extra_firefox_profile(
        root / "Profiles", "bbbb.work", [("session", "from-work", ".arena.ai", FUTURE)]
    )
    (root / "profiles.ini").write_text(
        "[Install1234]\nDefault=Profiles/aaaa.default-release\n", encoding="utf-8"
    )
    options = isolated_options(tmp_path, use_browser_profiles=True, profiles_root=root)
    found = discover_session(options)
    assert found is not None
    assert found.source == "firefox"
    assert found.cookies == {"session": "from-work"}
    assert "bbbb.work" in found.description


def test_explain_lists_every_profile_and_the_selected_one(tmp_path) -> None:
    root = tmp_path / "firefox"
    (root / "Profiles").mkdir(parents=True)
    make_extra_firefox_profile(root / "Profiles", "aaaa.default-release", [])
    make_extra_firefox_profile(
        root / "Profiles", "bbbb.work", [("session", "v", ".arena.ai", FUTURE)]
    )
    (root / "profiles.ini").write_text(
        "[Install1234]\nDefault=Profiles/aaaa.default-release\n", encoding="utf-8"
    )
    lines = explain_sources(
        isolated_options(tmp_path, use_browser_profiles=True, profiles_root=root)
    )
    joined = "\n".join(lines)
    assert "Firefox profile     : " in joined and "aaaa.default-release" in joined
    assert "Firefox profile 2   : " in joined and "bbbb.work" in joined
    selected = next(line for line in lines if line.startswith("Firefox selected"))
    assert "bbbb.work" in selected and "holds the session" in selected


def test_status_names_the_cookies_without_their_values(
    tmp_path, capsys, monkeypatch
) -> None:
    root = make_firefox_profile(tmp_path, value="do-not-print-me")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARENA_FIREFOX_ROOT", str(root))
    assert main(["--status", "--no-verify"]) == 0
    printed = capsys.readouterr().out
    assert "cookie names      : session" in printed
    assert "do-not-print-me" not in printed


def test_diagnose_prints_a_redacted_report(tmp_path, capsys, monkeypatch) -> None:
    root = make_firefox_profile(tmp_path, value="ultra-secret-value")
    monkeypatch.setenv("ARENA_FIREFOX_ROOT", str(root))
    assert main(["--diagnose"]) == 0
    printed = capsys.readouterr().out
    assert "ultra-secret-value" not in printed
    assert "cookie domains" in printed
    assert "session" in printed
    assert "roots searched" in printed
    assert str(root) in printed


def test_diagnose_speaks_json(tmp_path, capsys, monkeypatch) -> None:
    root = make_firefox_profile(tmp_path, value="ultra-secret-value")
    monkeypatch.setenv("ARENA_FIREFOX_ROOT", str(root))
    assert main(["--diagnose", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["cookies"]["names"] == ["session"]
    assert "ultra-secret-value" not in json.dumps(payload)


def test_profile_flags_reach_the_options(tmp_path) -> None:
    args = build_arg_parser().parse_args(
        ["--profile", "bbbb.work", "--profile-root", str(tmp_path)]
    )
    options = _options_from_args(args)
    assert options.profile_name == "bbbb.work"
    assert options.profiles_root == str(tmp_path)


def test_no_firefox_cookies_mentions_the_diagnose_command(
    tmp_path, capsys, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARENA_FIREFOX_ROOT", str(tmp_path / "empty-root"))
    assert main(["--explain"]) == 0
    printed = capsys.readouterr().out
    assert "--diagnose" in printed


def test_has_session_cookie_distinguishes_auth_from_ui_and_edge_cookies() -> None:
    from arena_api.auto import has_session_cookie

    assert has_session_cookie({"arena-auth-prod-v1.0": "tok"}) is True
    assert has_session_cookie({"session": "abc"}) is True
    assert has_session_cookie({"connect.sid": "abc"}) is True
    assert has_session_cookie({"PHPSESSID": "abc"}) is True
    assert (
        has_session_cookie(
            {
                "__cf_bm": "1",
                "_dd_s": "2",
                "_ga": "3",
                "_ga_DB32ZN1WHB": "4",
                "_vcrr_ec68a2456e920849": "5",
                "arena_build_bucket": "6",
                "arena_visit_id": "7",
                "cf_clearance": "8",
                "cookie-preferences": "9",
                "provisional_user_id": "10",
                "sidebar_state": "true",
                "user_country_code": "SE",
            }
        )
        is False
    )


def test_signed_in_firefox_wins_over_guest_default_storage(
    tmp_path, monkeypatch
) -> None:
    """An incomplete ``--login`` guest file in ``./state/cookies.json`` must not
    shadow a signed-in Firefox profile."""
    monkeypatch.chdir(tmp_path)
    write_storage(
        tmp_path,
        {
            "__cf_bm": "bm",
            "_dd_s": "dd",
            "_ga": "ga",
            "arena_visit_id": "vid",
            "cf_clearance": "stale-cf",
            "provisional_user_id": "guest-uuid",
            "sidebar_state": "true",
        },
    )
    profiles = make_firefox_profile(tmp_path, value="signed-in-firefox")
    options = AutoOptions(
        use_browser_profiles=True,
        profiles_root=profiles,
        solve_captchas=False,
        output=io.StringIO(),
    )

    found = discover_session(options)
    assert found is not None
    assert found.source == "firefox"
    assert found.cookies == {"session": "signed-in-firefox"}

    explained = "\n".join(explain_sources(options))
    assert "guest/anonymous -- skipped for signed-in profile" in explained


def test_explicit_storage_path_still_wins_without_session_cookie(tmp_path) -> None:
    path = write_storage(tmp_path, {"provisional_user_id": "explicit-guest"})
    profiles = make_firefox_profile(tmp_path, value="signed-in-firefox")
    options = AutoOptions(
        storage_path=path,
        use_browser_profiles=True,
        profiles_root=profiles,
        solve_captchas=False,
        output=io.StringIO(),
    )
    found = discover_session(options)
    assert found is not None
    assert found.source == "storage"
    assert found.cookies == {"provisional_user_id": "explicit-guest"}


def test_interactive_wait_solver_opens_a_headed_browser_window(tmp_path) -> None:
    discovered = DiscoveredSession(
        source="storage",
        cookies={"session": "abc"},
        headers={},
        description="storage",
    )
    headed = build_session_manager(
        AutoOptions(
            interactive=True,
            solve_captchas="auto",
            channel="chrome",
            artifacts_dir=tmp_path / "artifacts",
            output=io.StringIO(),
        ),
        discovered,
    )
    assert headed.environment_options is not None
    assert headed.environment_options.headless is False
    assert headed.environment_options.channel == "chrome"

    headless = build_session_manager(
        AutoOptions(
            interactive=False,
            solve_captchas="auto",
            artifacts_dir=tmp_path / "artifacts",
            output=io.StringIO(),
        ),
        discovered,
    )
    assert headless.environment_options is not None
    assert headless.environment_options.headless is True


def test_cli_status_probes_once_without_launching_refresh_ladder(
    tmp_path, monkeypatch, capsys
) -> None:
    """``--status`` must report a Cloudflare challenge and exit 2 immediately
    instead of launching Playwright to wait out the challenge."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARENA_COOKIE", "session=abc")
    challenge_html = (
        b"<html><head><title>Just a moment...</title></head>"
        b"<body>__cf_chl_rt_tk=123</body></html>"
    )
    recorder = Recorder((403, challenge_html, "text/html"))
    monkeypatch.setattr(auto_module, "impersonation_available", lambda: False)

    real_options_from_args = auto_module._options_from_args

    def with_mock_transport(args):
        opts = real_options_from_args(args)
        return replace(opts, http_transport=recorder.transport)

    monkeypatch.setattr(auto_module, "_options_from_args", with_mock_transport)

    def fail_if_refreshed(*args, **kwargs):  # pragma: no cover
        raise AssertionError("--status must not run AutoSessionManager.refresh_session")

    monkeypatch.setattr(AutoSessionManager, "refresh_session", fail_if_refreshed)

    assert main(["--status", "--no-browser-profiles"]) == 2
    out = capsys.readouterr().out
    assert len(recorder.requests) == 1
    assert "not ok: browser verification challenge" in out
    assert "impersonate" in out


def test_probe_accepts_nextjs_404_with_passive_cloudflare_jsd_beacon() -> None:
    """When ``arena.ai`` (Next.js) answers ``GET /config`` with HTTP 404 plus
    Cloudflare's passive ``jsd/main.js`` beacon, ``probe()`` must report the
    session as reachable rather than a verification challenge."""
    nextjs_404 = (
        b"<!DOCTYPE html><html><head><title>404</title></head><body>"
        b"<script src='/cdn-cgi/challenge-platform/scripts/jsd/main.js'></script>"
        b"</body></html>"
    )
    recorder = Recorder((404, nextjs_404, "text/html"))
    with ArenaClient(http_transport=recorder.transport) as client:
        result = probe(client, "/config")
    assert result.ok is True
    assert result.auth_problem is False


def test_probe_reports_connect_error_as_not_ok_and_preserves_curl_detail() -> None:
    """A TCP/TLS/proxy ``ConnectError`` must not be misreported as reachable."""

    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            "Failed to perform, curl: (7) Could not connect to server. "
            "See https://curl.se/libcurl/c/libcurl-errors.html first for more details.",
            request=request,
        )

    transport = httpx.MockTransport(broken)
    with ArenaClient(http_transport=transport) as client:
        result = probe(client, "/config")
    assert result.ok is False
    assert result.auth_problem is False
    assert result.reason == "network error (ConnectError)"
    assert result.describe() == "not ok: network error (ConnectError)"
    assert result.error is not None
    assert "curl: (7) Could not connect to server." in str(result.error)
    assert "libcurl-errors.html" not in str(result.error)


def test_cli_status_reports_connect_error_with_exit_code_1_and_proxy_hint(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARENA_COOKIE", "arena-auth-prod-v1.0=tok")
    monkeypatch.delenv("ARENA_PROXY", raising=False)
    monkeypatch.setattr("urllib.request.getproxies", dict)

    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("curl: (7) Connection refused", request=request)

    real_from_args = auto_module._options_from_args
    monkeypatch.setattr(
        auto_module,
        "_options_from_args",
        lambda args: replace(
            real_from_args(args), http_transport=httpx.MockTransport(broken)
        ),
    )

    assert main(["--status", "--no-browser-profiles"]) == 1
    out = capsys.readouterr().out
    assert "not ok: network error (ConnectError)" in out
    assert "curl: (7) Connection refused" in out
    assert "--proxy" in out


def test_cli_models_stops_immediately_on_network_error_without_second_attempt(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARENA_COOKIE", "arena-auth-prod-v1.0=tok")
    attempts: list[str] = []

    def broken(request: httpx.Request) -> httpx.Response:
        attempts.append(request.url.path)
        raise httpx.ConnectError("curl: (7) Connection refused", request=request)

    real_from_args = auto_module._options_from_args
    monkeypatch.setattr(
        auto_module,
        "_options_from_args",
        lambda args: replace(
            real_from_args(args), http_transport=httpx.MockTransport(broken)
        ),
    )

    assert main(["--models", "--no-verify", "--no-browser-profiles"]) == 1
    captured = capsys.readouterr()
    assert attempts == ["/config"]
    assert captured.err.count("[arena-api] session:") == 1
    assert "curl: (7) Connection refused" in captured.err


def test_cli_models_direct_fallback_does_not_repeat_session_banner(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARENA_COOKIE", "arena-auth-prod-v1.0=tok")
    direct_markup = (
        '<html><script>self.__next_f.push([1,"{\\"id\\":\\"'
        "11111111-2222-3333-4444-555555555555"
        '\\",\\"publicName\\":\\"gpt-test\\"}"])</script></html>'
    ).encode("utf-8")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/config":
            return httpx.Response(404, text="not found")
        return httpx.Response(200, content=direct_markup, headers={"content-type": "text/html"})

    real_from_args = auto_module._options_from_args
    monkeypatch.setattr(
        auto_module,
        "_options_from_args",
        lambda args: replace(
            real_from_args(args), http_transport=httpx.MockTransport(handler)
        ),
    )

    assert main(["--models", "--no-browser-profiles"]) == 0
    captured = capsys.readouterr()
    assert "gpt-test" in captured.out
    assert captured.err.count("[arena-api] session:") == 1


def test_cli_explain_redacts_proxy_credentials(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.chdir(tmp_path)
    assert (
        main(
            [
                "--explain",
                "--no-browser-profiles",
                "--proxy",
                "http://alice:super-secret@127.0.0.1:2080",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "http://***@127.0.0.1:2080" in out
    assert "super-secret" not in out
    assert "alice" not in out


def test_direct_verification_token_forwards_proxy_channel_cookies_and_fast_js(
    tmp_path, monkeypatch
) -> None:
    seen_env_options: list[object] = []
    added_cookies: list[list[dict[str, str]]] = []
    solver_calls: list[object] = []

    class FakeContext:
        async def add_cookies(self, cookies):
            added_cookies.append(list(cookies))

    class JsPage:
        def __init__(self) -> None:
            self.context = FakeContext()
            self.visited: list[str] = []

        async def goto(self, url: str, **kwargs) -> None:
            self.visited.append(url)

        async def evaluate(self, script: str):
            assert "chat_submit" in script
            assert "recaptcha/enterprise.js?render=" in script
            assert "6LeTGMcsAAAAALuIlkVwIxaAuZA8VledA6d3Nnb0" in script
            return "fast-v3-assertion"

    class FakeHandler:
        def __init__(self) -> None:
            self.solve_on_detection = True

    class CapturingEnv:
        def __init__(self, options) -> None:
            seen_env_options.append(options)
            self.page = JsPage()
            self.challenge_handler = FakeHandler()
            self.solve_flag_at_new_page: bool | None = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc) -> None:
            return None

        async def new_page(self):
            self.solve_flag_at_new_page = self.challenge_handler.solve_on_detection
            return self.page

    envs: list[CapturingEnv] = []
    monkeypatch.setattr(
        auto_module,
        "BrowserEnvironment",
        lambda options: envs.append(CapturingEnv(options)) or envs[-1],
    )
    monkeypatch.setattr(auto_module, "solver_dependencies_available", lambda _: True)
    solver = RecaptchaToolkitSolver()
    monkeypatch.setattr(
        solver,
        "asolve",
        lambda page: solver_calls.append(page),
    )

    factory = DirectVerificationToken(
        isolated_options(
            tmp_path,
            base_url="https://arena.ai",
            proxy="http://127.0.0.1:10809",
            channel="msedge",
        ),
        solver=solver,
        session_cookies={"cf_clearance": "cf1", "arena-auth-prod-v1.0": "jwt"},
    )
    assert factory() == "fast-v3-assertion"
    assert solver_calls == []
    assert len(seen_env_options) == 1
    env_opt = seen_env_options[0]
    assert env_opt.proxy == "http://127.0.0.1:10809"
    assert env_opt.channel == "msedge"
    assert env_opt.install_determinism_script is False
    assert envs[0].solve_flag_at_new_page is False
    assert added_cookies == [
        [
            {"name": "cf_clearance", "value": "cf1", "url": "https://arena.ai"},
            {"name": "arena-auth-prod-v1.0", "value": "jwt", "url": "https://arena.ai"},
        ]
    ]


def test_direct_verification_token_missing_browser_binary_gives_actionable_error(
    tmp_path, monkeypatch
) -> None:
    class MissingBrowserEnv:
        def __init__(self, options) -> None:
            pass

        async def __aenter__(self):
            raise RuntimeError(
                "BrowserType.launch: Executable doesn't exist at C:\\ms-playwright\\chromium.exe"
            )

        async def __aexit__(self, *exc) -> None:
            return None

    monkeypatch.setattr(auto_module, "BrowserEnvironment", MissingBrowserEnv)
    monkeypatch.setattr(auto_module, "solver_dependencies_available", lambda _: True)
    factory = DirectVerificationToken(
        isolated_options(tmp_path),
        solver=RecaptchaToolkitSolver(),
    )
    with pytest.raises(AuthenticationError, match="--channel msedge"):
        factory()


def test_cli_prompt_falls_back_to_direct_chat_and_selects_ranked_text_model(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARENA_COOKIE", "arena-auth-prod-v1.0=tok")
    monkeypatch.setenv("ARENA_VERIFICATION_TOKEN", "env-v3-tok")

    img_id = "11111111-1111-1111-1111-111111111111"
    flash_id = "22222222-2222-2222-2222-222222222222"
    direct_markup = (
        '<html><script id="__NEXT_DATA__" type="application/json">'
        + json.dumps(
            {
                "props": {
                    "pageProps": {
                        "models": [
                            {"id": img_id, "publicName": "flux-1-schnell"},
                            {"id": flash_id, "publicName": "gemini-2.5-flash"},
                        ]
                    }
                }
            }
        )
        + "</script></html>"
    ).encode("utf-8")
    sent_bodies: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/config":
            return httpx.Response(404, text="not found")
        if request.url.path == "/text/direct":
            return httpx.Response(
                200, content=direct_markup, headers={"content-type": "text/html"}
            )
        if request.url.path == "/nextjs-api/stream/create-evaluation":
            sent_bodies.append(json.loads(request.content))
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                content=b'a0:"\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82!"\nad:{"finishReason":"stop"}\n',
            )
        raise AssertionError(request.url)

    real_from_args = auto_module._options_from_args
    monkeypatch.setattr(
        auto_module,
        "_options_from_args",
        lambda args: replace(
            real_from_args(args), http_transport=httpx.MockTransport(handler)
        ),
    )

    assert main(["--prompt", "Hi!", "--no-browser-profiles"]) == 0
    captured = capsys.readouterr()
    assert "model             :" not in captured.out
    assert "answer            : Привет!" in captured.out
    assert captured.err.count("[arena-api] session:") == 1
    assert len(sent_bodies) == 1
    assert sent_bodies[0]["modelAId"] == flash_id
    assert sent_bodies[0]["recaptchaV3Token"] == "env-v3-tok"


def test_cli_prompt_honors_explicit_model_and_verification_token_flags(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARENA_COOKIE", "arena-auth-prod-v1.0=tok")
    custom_id = "33333333-3333-3333-3333-333333333333"
    direct_markup = (
        '<html><script id="__NEXT_DATA__" type="application/json">'
        + json.dumps(
            {
                "props": {
                    "pageProps": {
                        "models": [{"id": custom_id, "publicName": "claude-sonnet-4-6"}]
                    }
                }
            }
        )
        + "</script></html>"
    ).encode("utf-8")
    sent_bodies: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/config":
            return httpx.Response(404, text="not found")
        if request.url.path == "/text/direct":
            return httpx.Response(
                200, content=direct_markup, headers={"content-type": "text/html"}
            )
        if request.url.path == "/nextjs-api/stream/create-evaluation":
            sent_bodies.append(json.loads(request.content))
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                content=b'a0:"4"\nad:{"finishReason":"stop"}\n',
            )
        raise AssertionError(request.url)

    real_from_args = auto_module._options_from_args
    monkeypatch.setattr(
        auto_module,
        "_options_from_args",
        lambda args: replace(
            real_from_args(args), http_transport=httpx.MockTransport(handler)
        ),
    )

    assert (
        main(
            [
                "--no-browser-profiles",
                "--model",
                "claude-sonnet-4-6",
                "--verification-token",
                "cli-v3-tok",
                "--prompt",
                "2+2?",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert "model             : claude-sonnet-4-6" in captured.out
    assert "answer            : 4" in captured.out
    assert sent_bodies[0]["modelAId"] == custom_id
    assert sent_bodies[0]["recaptchaV3Token"] == "cli-v3-tok"


def test_firefox_browser_cookie_filter_and_supabase_jwt_expiry() -> None:
    import base64
    import time

    filtered = auto_module._seedable_browser_cookies(
        {
            "cf_clearance": "ff-bound",
            "__cf_bm": "ff-bm",
            "_cfuvid": "ff-uvid",
            "arena-auth-prod-v1.0": "part0",
            "arena-auth-prod-v1.1": "part1",
        },
        cookie_source="firefox",
    )
    assert filtered == {
        "arena-auth-prod-v1.0": "part0",
        "arena-auth-prod-v1.1": "part1",
    }

    def make_chunked(expires_at: float) -> dict[str, str]:
        raw_json = json.dumps(
            {"access_token": "jwt", "refresh_token": "rt", "expires_at": expires_at}
        ).encode("utf-8")
        full = "base64-" + base64.urlsafe_b64encode(raw_json).decode("ascii").rstrip("=")
        mid = len(full) // 2
        return {
            "arena-auth-prod-v1.0": full[:mid],
            "arena-auth-prod-v1.1": full[mid:],
        }

    assert auto_module._arena_auth_jwt_expired(make_chunked(time.time() - 300)) is True
    assert auto_module._arena_auth_jwt_expired(make_chunked(time.time() + 3600)) is False


def test_direct_verification_token_streams_in_browser_and_retries_headed_on_403(
    tmp_path, monkeypatch
) -> None:
    seen_headless: list[bool] = []
    added_cookie_sets: list[list[dict[str, str]]] = []
    evaluated_scripts: list[str] = []

    class FakeContext:
        async def add_cookies(self, cookies) -> None:
            added_cookie_sets.append(list(cookies))

        async def cookies(self, urls=None):
            return [
                {"name": "arena-auth-prod-v1.0", "value": "rotated-jwt"},
                {"name": "cf_clearance", "value": "chromium-cf"},
            ]

    class FakePage:
        def __init__(self, *, headless: bool) -> None:
            self._headless = headless
            self.context = FakeContext()
            self._exposed: dict[str, object] = {}

        async def goto(self, url: str, **kwargs: object) -> None:
            return None

        async def wait_for_timeout(self, ms: int) -> None:
            return None

        async def content(self) -> str:
            return "<html><body>Direct Chat</body></html>"

        async def expose_function(self, name: str, fn: object) -> None:
            self._exposed[name] = fn

        async def evaluate(self, script: str) -> object:
            evaluated_scripts.append(script)
            if "chat_submit" in script:
                return "headed-v3-tok" if not self._headless else "headless-v3-tok"
            if "window.fetch" in script:
                if self._headless:
                    return {
                        "ok": False,
                        "status": 403,
                        "body": '{"error":"Forbidden"}',
                        "contentType": "application/json",
                        "cfMitigated": "",
                    }
                assert '"headed-v3-tok"' in script or '\\"headed-v3-tok\\"' in script
                meta_fn = self._exposed["__arenaDirectMeta"]
                chunk_fn = self._exposed["__arenaDirectChunk"]
                assert callable(meta_fn) and callable(chunk_fn)
                meta_fn("text/event-stream")
                chunk_fn('a0:"TCP — надёжный, "\n')
                chunk_fn(
                    'a0:"UDP — быстрый."\nad:{"finishReason":"stop"}\n'
                )
                return {
                    "ok": True,
                    "status": 200,
                    "contentType": "text/event-stream",
                }
            return None

    class FakeEnv:
        def __init__(self, options) -> None:
            self.options = options
            self.challenge_handler = type(
                "H", (), {"solve_on_detection": True}
            )()

        async def __aenter__(self):
            seen_headless.append(self.options.headless)
            return self

        async def __aexit__(self, *exc) -> None:
            return None

        async def new_page(self):
            return FakePage(headless=self.options.headless)

    monkeypatch.setattr(auto_module, "BrowserEnvironment", FakeEnv)
    monkeypatch.setattr(auto_module, "solver_dependencies_available", lambda _: True)

    refresh_calls = 0

    class TrackingManager:
        def load_cookies(self, domains=None) -> dict[str, str]:
            return {
                "cf_clearance": "firefox-cf",
                "arena-auth-prod-v1.0": "initial-jwt",
            }

        def firefox_headers(self, *, navigation: bool = False) -> dict[str, str]:
            return {}

        def refresh_session(self, reason=None):
            nonlocal refresh_calls
            refresh_calls += 1
            return self.load_cookies()

    manager = TrackingManager()
    tok = DirectVerificationToken(
        isolated_options(tmp_path, base_url="https://arena.ai", interactive=True),
        solver=RecaptchaToolkitSolver(),
        session_cookies=manager.load_cookies(),
        session_manager=manager,
        cookie_source="firefox",
    )

    from arena_api.models import ModelInfo

    client = auto_module.DirectArenaClient(
        base_url="https://arena.ai",
        session_source=manager,
        verification_token=tok,
    )
    try:
        model_uuid = "22222222-2222-2222-2222-222222222222"
        client._models = [
            ModelInfo(id=model_uuid, display_name="gemini-2.5-flash")
        ]
        answer = client.complete("TCP vs UDP", model="gemini-2.5-flash")
    finally:
        client.close()

    assert answer == "TCP — надёжный, UDP — быстрый."
    assert seen_headless == [True, False]
    assert refresh_calls == 0
    assert added_cookie_sets[0] == [
        {"name": "arena-auth-prod-v1.0", "value": "initial-jwt", "url": "https://arena.ai"}
    ]


def test_direct_verification_token_401_user_not_found_raises_without_headed_retry(
    tmp_path, monkeypatch
) -> None:
    seen_headless: list[bool] = []

    class FakeContext:
        async def add_cookies(self, cookies) -> None:
            return None

    class FakePage:
        def __init__(self) -> None:
            self.context = FakeContext()

        async def goto(self, url: str, **kwargs: object) -> None:
            return None

        async def wait_for_timeout(self, ms: int) -> None:
            return None

        async def content(self) -> str:
            return "<html></html>"

        async def expose_function(self, name: str, fn: object) -> None:
            return None

        async def evaluate(self, script: str) -> object:
            if "chat_submit" in script:
                return "v3-tok"
            return {
                "ok": False,
                "status": 401,
                "body": '{"message":"User not found"}',
                "contentType": "application/json",
                "cfMitigated": "",
            }

    class FakeEnv:
        def __init__(self, options) -> None:
            self.options = options

        async def __aenter__(self):
            seen_headless.append(self.options.headless)
            return self

        async def __aexit__(self, *exc) -> None:
            return None

        async def new_page(self):
            return FakePage()

    monkeypatch.setattr(auto_module, "BrowserEnvironment", FakeEnv)
    monkeypatch.setattr(auto_module, "solver_dependencies_available", lambda _: True)

    tok = DirectVerificationToken(
        isolated_options(tmp_path, base_url="https://arena.ai", interactive=True),
        solver=RecaptchaToolkitSolver(),
    )

    async def run() -> None:
        async with tok.astream_evaluation(
            "/nextjs-api/stream/create-evaluation",
            lambda t: {"recaptchaV3Token": t},
        ):
            pass  # pragma: no cover

    with pytest.raises(AuthenticationError, match="User not found"):
        asyncio.run(run())
    assert seen_headless == [True]


def test_direct_composer_submission_uses_native_ui_without_forcing_model_and_handles_v2_escalation(
    tmp_path, monkeypatch
) -> None:
    seen_env_options: list[object] = []
    typed_texts: list[str] = []
    clicked_selectors: list[str] = []
    arm_scripts: list[str] = []

    class FakeLocator:
        def __init__(self, selector: str, page: "ComposerPage") -> None:
            self.selector = selector
            self._page = page

        @property
        def first(self) -> "FakeLocator":
            return self

        async def click(self) -> None:
            clicked_selectors.append(self.selector)
            if "data-arena-send" in self.selector:
                self._page._trigger_ui_submit()

        async def fill(self, value: str) -> None:
            typed_texts.append(f"fill:{value}")

        async def press(self, key: str) -> None:
            clicked_selectors.append(f"press:{key}")

    class FakeKeyboard:
        async def type(self, text: str, delay: int = 0) -> None:
            typed_texts.append(text)

    class FakeMouse:
        async def move(self, x: float, y: float, steps: int = 1) -> None:
            return None

    class FakeContext:
        async def add_cookies(self, cookies) -> None:
            return None

        async def cookies(self, urls=None):
            return []

    class ComposerPage:
        def __init__(self, *, headless: bool) -> None:
            self._headless = headless
            self.context = FakeContext()
            self.keyboard = FakeKeyboard()
            self.mouse = FakeMouse()
            self._exposed: dict[str, object] = {}
            self._submitted = False

        def locator(self, selector: str) -> FakeLocator:
            return FakeLocator(selector, self)

        async def goto(self, url: str, **kwargs: object) -> None:
            return None

        async def wait_for_timeout(self, ms: int) -> None:
            return None

        async def content(self) -> str:
            return "<html><body><form><textarea></textarea><button type='submit'>Send</button></form></body></html>"

        async def expose_function(self, name: str, fn: object) -> None:
            self._exposed[name] = fn

        def _trigger_ui_submit(self) -> None:
            self._submitted = True
            err_fn = self._exposed["__arenaDirectHttpError"]
            meta_fn = self._exposed["__arenaDirectMeta"]
            chunk_fn = self._exposed["__arenaDirectChunk"]
            eof_fn = self._exposed["__arenaDirectEof"]
            assert (
                callable(err_fn)
                and callable(meta_fn)
                and callable(chunk_fn)
                and callable(eof_fn)
            )
            if self._headless:
                err_fn(
                    {
                        "status": 403,
                        "body": '{"error":"recaptcha validation failed"}',
                        "contentType": "application/json",
                        "cfMitigated": "",
                    }
                )
                return
            # Simulate arena.ai's React UI receiving an initial v3 403 and
            # automatically escalating to invisible v2 on the next fetch.
            err_fn(
                {
                    "status": 403,
                    "body": '{"error":"recaptcha validation failed"}',
                    "contentType": "application/json",
                    "cfMitigated": "",
                }
            )
            meta_fn("text/plain; charset=utf-8")
            chunk_fn('a0:"Ответ из UI"\nad:{"finishReason":"stop"}\n')
            eof_fn()

        async def evaluate(self, script: str) -> object:
            if "__arenaTapArmed" in script:
                arm_scripts.append(script)
                return None
            if "composer_nonempty" in script:
                return not self._submitted
            if "data-arena-composer" in script and "data-arena-send" not in script:
                return {"found": True, "tag": "textarea", "x": 400, "y": 700}
            if "data-arena-send" in script:
                return {"found": True, "x": 650, "y": 700}
            if "bframe" in script:
                return False
            raise AssertionError(f"unexpected evaluate script: {script[:80]}")

    class FakeEnv:
        def __init__(self, options) -> None:
            self.options = options
            seen_env_options.append(options)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc) -> None:
            return None

        async def new_page(self):
            return ComposerPage(headless=self.options.headless)

    monkeypatch.setattr(auto_module, "BrowserEnvironment", FakeEnv)
    monkeypatch.setattr(auto_module, "solver_dependencies_available", lambda _: True)

    tok = DirectVerificationToken(
        isolated_options(tmp_path, base_url="https://arena.ai", interactive=True),
        solver=RecaptchaToolkitSolver(),
        session_cookies={"arena-auth-prod-v1.0": "jwt"},
        cookie_source="firefox",
    )

    client = auto_module.DirectArenaClient(
        base_url="https://arena.ai",
        cookies={"arena-auth-prod-v1.0": "jwt"},
        verification_token=tok,
    )
    monkeypatch.setattr(
        client,
        "get_models",
        lambda *a, **kw: (_ for _ in ()).throw(
            AssertionError("get_models() should not be called when model is None")
        ),
    )
    try:
        answer = client.complete("Объясни TCP и UDP.")
    finally:
        client.close()

    assert answer == "Ответ из UI"
    assert typed_texts == ["Объясни TCP и UDP.", "Объясни TCP и UDP."]
    assert any("window.__arenaBodyPatch = null" in s for s in arm_scripts)
    assert len(seen_env_options) == 2
    assert getattr(seen_env_options[0], "locale") is None
    assert getattr(seen_env_options[0], "timezone_id") is None


def test_post_submit_recaptcha_anchor_checkbox_clicked_without_expose_function(
    tmp_path, monkeypatch
) -> None:
    mouse_clicks: list[tuple[float, float]] = []
    mouse_moves: list[tuple[float, float]] = []

    class FakeRequest:
        def __init__(self, url: str, method: str = "POST") -> None:
            self.url = url
            self.method = method

    class FakeResponse:
        def __init__(self, url: str, status: int, body: str, content_type: str) -> None:
            self.url = url
            self.status = status
            self._body = body
            self.headers = {"content-type": content_type}
            self.request = FakeRequest(url, "POST")

        async def text(self) -> str:
            return self._body

    class FakeLocator:
        def __init__(self, selector: str, page: "NetworkEventPage") -> None:
            self.selector = selector
            self._page = page

        @property
        def first(self) -> "FakeLocator":
            return self

        async def click(self) -> None:
            if "data-arena-send" in self.selector:
                self._page._on_send_clicked()

        async def fill(self, value: str) -> None:
            return None

        async def press(self, key: str) -> None:
            raise AssertionError("Enter must not be pressed on explicit Send button")

    class FakeKeyboard:
        async def type(self, text: str, delay: int = 0) -> None:
            return None

    class FakeMouse:
        def __init__(self, page: "NetworkEventPage") -> None:
            self._page = page

        async def move(self, x: float, y: float, steps: int = 1) -> None:
            mouse_moves.append((x, y))

        async def click(self, x: float, y: float, delay: int = 0) -> None:
            mouse_clicks.append((x, y))
            self._page._on_anchor_checkbox_clicked()

    class FakeContext:
        async def cookies(self, urls=None):
            return [
                {"name": "_GRECAPTCHA", "value": "existing-google-trust"},
                {"name": "arena-auth-prod-v1.0", "value": "refreshed-jwt"},
            ]

        async def add_cookies(self, cookies) -> None:
            return None

    class NetworkEventPage:
        def __init__(self, *, headless: bool) -> None:
            self._headless = headless
            self.context = FakeContext()
            self.keyboard = FakeKeyboard()
            self.mouse = FakeMouse(self)
            self.frames: list[object] = []
            self._listeners: dict[str, list[object]] = {}
            self._anchor_visible = False

        def on(self, event: str, cb: object) -> None:
            self._listeners.setdefault(event, []).append(cb)

        def remove_listener(self, event: str, cb: object) -> None:
            if event in self._listeners and cb in self._listeners[event]:
                self._listeners[event].remove(cb)

        async def expose_function(self, name: str, fn: object) -> None:
            raise AssertionError(
                "expose_function must not be called when page.on('response') is available"
            )

        def _emit(self, event: str, payload: object) -> None:
            for cb in list(self._listeners.get(event, ())):
                assert callable(cb)
                cb(payload)

        def locator(self, selector: str) -> FakeLocator:
            return FakeLocator(selector, self)

        async def goto(self, url: str, **kwargs: object) -> None:
            return None

        async def wait_for_timeout(self, ms: int) -> None:
            return None

        async def content(self) -> str:
            return "<html><body><form><textarea></textarea><button type='submit'>Send</button></form></body></html>"

        def _on_send_clicked(self) -> None:
            url = "https://arena.ai/nextjs-api/stream/create-evaluation"
            self._emit("request", FakeRequest(url))
            self._emit(
                "response",
                FakeResponse(
                    url,
                    403,
                    '{"error":"recaptcha validation failed"}',
                    "application/json",
                ),
            )
            if not self._headless:
                self._anchor_visible = True

        def _on_anchor_checkbox_clicked(self) -> None:
            self._anchor_visible = False
            url = "https://arena.ai/nextjs-api/stream/create-evaluation"
            self._emit("request", FakeRequest(url))
            self._emit(
                "response",
                FakeResponse(
                    url,
                    200,
                    'a0:"Капча пройдена автоматически!"\nad:{"finishReason":"stop"}\n',
                    "text/plain; charset=utf-8",
                ),
            )

        async def evaluate(self, script: str) -> object:
            if "arena_cleanup_marks" in script:
                return None
            if "composer_nonempty" in script:
                return True
            if "data-arena-composer" in script and "data-arena-send" not in script:
                return {"found": True, "tag": "textarea", "x": 400, "y": 700}
            if "data-arena-send" in script:
                return {
                    "found": True,
                    "confidence": "explicit",
                    "x": 650,
                    "y": 700,
                }
            if "recaptcha_anchor" in script:
                if self._anchor_visible:
                    return {
                        "kind": "recaptcha_anchor",
                        "x": 420,
                        "y": 510,
                        "width": 304,
                        "height": 78,
                    }
                return {"kind": None}
            raise AssertionError(f"unexpected evaluate script: {script[:80]}")

    class FakeEnv:
        def __init__(self, options) -> None:
            self.options = options

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc) -> None:
            return None

        async def new_page(self):
            return NetworkEventPage(headless=self.options.headless)

    monkeypatch.setattr(auto_module, "BrowserEnvironment", FakeEnv)
    monkeypatch.setattr(auto_module, "solver_dependencies_available", lambda _: True)

    tok = DirectVerificationToken(
        isolated_options(tmp_path, base_url="https://arena.ai", interactive=True),
        solver=RecaptchaToolkitSolver(),
        session_cookies={"arena-auth-prod-v1.0": "jwt"},
        cookie_source="firefox",
    )

    client = auto_module.DirectArenaClient(
        base_url="https://arena.ai",
        cookies={"arena-auth-prod-v1.0": "jwt"},
        verification_token=tok,
    )
    try:
        answer = client.complete("Привет!")
        assert tok._refreshed_cookies == {"arena-auth-prod-v1.0": "refreshed-jwt"}
    finally:
        client.close()

    assert answer == "Капча пройдена автоматически!"
    assert mouse_clicks == [(420, 510)]
    assert (420, 510) in mouse_moves


def test_post_submit_bframe_skips_audio_without_ffmpeg_and_resends_after_human_solve(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.setattr(auto_module.shutil, "which", lambda cmd: None)
    monkeypatch.setattr(auto_module, "solver_dependencies_available", lambda _: True)
    audio_solver = RecaptchaToolkitSolver(backend="audio")
    assert auto_module._can_auto_solve_bframe(audio_solver) is False

    send_clicks = 0
    brought_to_front = 0

    class FakeRequest:
        def __init__(self, url: str) -> None:
            self.url = url
            self.method = "POST"

    class FakeResponse:
        def __init__(self, url: str, status: int, body: str, content_type: str) -> None:
            self.url = url
            self.status = status
            self._body = body
            self.headers = {"content-type": content_type}
            self.request = FakeRequest(url)

        async def text(self) -> str:
            return self._body

    class FakeLocator:
        def __init__(self, selector: str, page: "BframePage") -> None:
            self.selector = selector
            self._page = page

        @property
        def first(self) -> "FakeLocator":
            return self

        async def click(self) -> None:
            nonlocal send_clicks
            if "data-arena-send" in self.selector:
                send_clicks += 1
                self._page._on_send(send_clicks)

        async def fill(self, value: str) -> None:
            return None

    class FakeKeyboard:
        async def type(self, text: str, delay: int = 0) -> None:
            return None

    class FakeMouse:
        async def move(self, x: float, y: float, steps: int = 1) -> None:
            return None

    class FakeContext:
        async def cookies(self, urls=None):
            return []

        async def add_cookies(self, cookies) -> None:
            return None

    class BframePage:
        def __init__(self) -> None:
            self.context = FakeContext()
            self.keyboard = FakeKeyboard()
            self.mouse = FakeMouse()
            self._listeners: dict[str, list[object]] = {}
            self._bframe_checks = 0
            self._composer_has_text = True

        def on(self, event: str, cb: object) -> None:
            self._listeners.setdefault(event, []).append(cb)

        def remove_listener(self, event: str, cb: object) -> None:
            return None

        async def bring_to_front(self) -> None:
            nonlocal brought_to_front
            brought_to_front += 1

        def _emit(self, event: str, payload: object) -> None:
            for cb in list(self._listeners.get(event, ())):
                assert callable(cb)
                cb(payload)

        def locator(self, selector: str) -> FakeLocator:
            return FakeLocator(selector, self)

        async def goto(self, url: str, **kwargs: object) -> None:
            return None

        async def wait_for_timeout(self, ms: int) -> None:
            return None

        async def content(self) -> str:
            return "<html><body><form><textarea></textarea><button type='submit'>Send</button></form></body></html>"

        def _on_send(self, attempt_no: int) -> None:
            url = "https://arena.ai/nextjs-api/stream/create-evaluation"
            self._emit("request", FakeRequest(url))
            if attempt_no == 1:
                self._emit(
                    "response",
                    FakeResponse(
                        url,
                        403,
                        '{"error":"recaptcha validation failed"}',
                        "application/json",
                    ),
                )
            else:
                self._composer_has_text = False
                self._emit(
                    "response",
                    FakeResponse(
                        url,
                        200,
                        'a0:"Ответ после ручной капчи"\nad:{"finishReason":"stop"}\n',
                        "text/plain; charset=utf-8",
                    ),
                )

        async def evaluate(self, script: str) -> object:
            if "arena_cleanup_marks" in script:
                return None
            if "composer_nonempty" in script:
                return self._composer_has_text
            if "data-arena-composer" in script and "data-arena-send" not in script:
                return {"found": True, "tag": "textarea", "x": 400, "y": 700}
            if "data-arena-send" in script:
                return {
                    "found": True,
                    "confidence": "explicit",
                    "x": 650,
                    "y": 700,
                }
            if "recaptcha_anchor" in script:
                self._bframe_checks += 1
                if self._bframe_checks <= 2:
                    return {
                        "kind": "recaptcha_bframe",
                        "x": 500,
                        "y": 400,
                        "width": 400,
                        "height": 580,
                    }
                return {"kind": None}
            raise AssertionError(f"unexpected evaluate script: {script[:80]}")

    class FakeEnv:
        def __init__(self, options) -> None:
            self.options = options

        async def __aenter__(self):
            if self.options.headless:
                raise auto_module._RetryInHeadedBrowser("skip headless in test")
            return self

        async def __aexit__(self, *exc) -> None:
            return None

        async def new_page(self):
            return BframePage()

    monkeypatch.setattr(auto_module, "BrowserEnvironment", FakeEnv)

    tok = DirectVerificationToken(
        isolated_options(tmp_path, base_url="https://arena.ai", interactive=True),
        solver=audio_solver,
        session_cookies={"arena-auth-prod-v1.0": "jwt"},
    )
    client = auto_module.DirectArenaClient(
        base_url="https://arena.ai",
        cookies={"arena-auth-prod-v1.0": "jwt"},
        verification_token=tok,
        timeout=10.0,
    )
    try:
        answer = client.complete("Тест капчи")
    finally:
        client.close()

    stderr = capsys.readouterr().err
    assert answer == "Ответ после ручной капчи"
    assert "после отправки появилась капча" in stderr
    assert brought_to_front >= 1
    assert send_clicks == 2


def test_seed_direct_context_cookies_preserves_existing_trust_cookies() -> None:
    added_batches: list[list[dict[str, str]]] = []

    class FakeContext:
        async def cookies(self):
            return [
                {"name": "_GRECAPTCHA", "value": "persisted-grecaptcha"},
                {"name": "cf_clearance", "value": "persisted-cf"},
                {"name": "arena-auth-prod-v1.0", "value": "old-jwt"},
            ]

        async def add_cookies(self, cookies: list[dict[str, str]]) -> None:
            added_batches.append(cookies)

    asyncio.run(
        auto_module._seed_direct_context_cookies(
            FakeContext(),
            {
                "_GRECAPTCHA": "new-grecaptcha-should-not-overwrite",
                "cf_clearance": "new-cf-should-not-overwrite",
                "arena-auth-prod-v1.0": "fresh-jwt",
            },
            "https://arena.ai",
        )
    )
    assert added_batches == [
        [
            {
                "name": "arena-auth-prod-v1.0",
                "value": "fresh-jwt",
                "url": "https://arena.ai",
            }
        ]
    ]


def test_live_browser_runs_invisible_by_default_and_honours_show_browser(
    tmp_path, monkeypatch
) -> None:
    seen_calls: list[tuple[bool, bool, bool, object]] = []
    fail_display = False

    monkeypatch.setattr(
        auto_module, "BrowserEnvironment", auto_module._DEFAULT_BROWSER_ENVIRONMENT
    )
    monkeypatch.setattr(auto_module, "solver_dependencies_available", lambda _: True)

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def fake_attempt(
        endpoint_path,
        body_factory,
        *,
        headless,
        allow_headed_retry,
        timeout,
        prompt=None,
        model_id_override=None,
        generation_params=None,
        follow_up=False,
        user_data_dir=None,
        hide_window=False,
    ):
        seen_calls.append((headless, hide_window, allow_headed_retry, user_data_dir))
        if not headless and fail_display:
            raise RuntimeError("Missing X server or $DISPLAY")

        async def _chunks():
            yield b'a0:"ok"\nad:{"finishReason":"stop"}\n'

        yield ("text/plain", _chunks())

    async def _run(tok: DirectVerificationToken) -> bytes:
        out = bytearray()
        async with tok.astream_evaluation(
            "/nextjs-api/stream/create-evaluation",
            lambda t: {"recaptchaV3Token": t},
            prompt="Hi",
        ) as (_, chunks):
            async for part in chunks:
                out.extend(part)
        return bytes(out)

    # 1) Default (show_browser=False) on desktop: cloaked headful (headless=False, hide_window=True).
    tok_invisible = DirectVerificationToken(
        isolated_options(tmp_path, base_url="https://arena.ai", interactive=True),
        solver=RecaptchaToolkitSolver(),
    )
    monkeypatch.setattr(tok_invisible, "_attempt_browser_evaluation", fake_attempt)
    assert b'a0:"ok"' in asyncio.run(_run(tok_invisible))
    expected_profile = auto_module._direct_browser_profile_dir(tok_invisible.options)
    assert seen_calls == [(False, True, False, expected_profile)]

    # 2) Default (show_browser=False) on display-less server: falls back cleanly to headless=True.
    seen_calls.clear()
    fail_display = True
    assert b'a0:"ok"' in asyncio.run(_run(tok_invisible))
    assert seen_calls == [
        (False, True, False, expected_profile),
        (True, False, False, expected_profile),
    ]

    # 3) Explicit --show-browser (show_browser=True): hide_window=False.
    seen_calls.clear()
    fail_display = False
    tok_visible = DirectVerificationToken(
        isolated_options(
            tmp_path,
            base_url="https://arena.ai",
            interactive=True,
            show_browser=True,
        ),
        solver=RecaptchaToolkitSolver(),
    )
    monkeypatch.setattr(tok_visible, "_attempt_browser_evaluation", fake_attempt)
    assert b'a0:"ok"' in asyncio.run(_run(tok_visible))
    assert seen_calls == [(False, False, False, expected_profile)]


def test_post_submit_bframe_autosolves_without_playwright_recaptcha_or_ffmpeg_and_replays_v2_token(
    tmp_path, monkeypatch, capsys
) -> None:
    """Direct Chat auto-solves bframe challenges with only Playwright installed (no ffmpeg / playwright-recaptcha)."""
    from arena_api.auth.autosolve import AutoSolveOutcome

    monkeypatch.setattr(auto_module.shutil, "which", lambda _cmd: None)
    monkeypatch.setattr(
        auto_module,
        "_has_spec",
        lambda name: name == "playwright",
    )

    replayed_payloads: list[dict[str, object]] = []
    autosolve_calls: list[dict[str, object]] = []

    class FakeRequest:
        def __init__(self, url: str, post_data: str = "") -> None:
            self.url = url
            self.method = "POST"
            self.post_data = post_data

    class FakeResponse:
        def __init__(self, url: str, status: int, body: str, content_type: str) -> None:
            self.url = url
            self.status = status
            self._body = body
            self.headers = {"content-type": content_type}
            self.request = FakeRequest(url)

        async def text(self) -> str:
            return self._body

    class FakeLocator:
        def __init__(self, selector: str, page: "AutoSolveBframePage") -> None:
            self.selector = selector
            self._page = page

        @property
        def first(self) -> "FakeLocator":
            return self

        async def click(self) -> None:
            if "data-arena-send" in self.selector:
                self._page._on_initial_send()

        async def fill(self, value: str) -> None:
            return None

    class FakeKeyboard:
        async def type(self, text: str, delay: int = 0) -> None:
            return None

    class FakeMouse:
        async def move(self, x: float, y: float, steps: int = 1) -> None:
            return None

    class FakeContext:
        async def cookies(self, urls=None):
            return []

        async def add_cookies(self, cookies) -> None:
            return None

    class AutoSolveBframePage:
        def __init__(self) -> None:
            self.context = FakeContext()
            self.keyboard = FakeKeyboard()
            self.mouse = FakeMouse()
            self._listeners: dict[str, list[object]] = {}
            self._bframe_open = False

        def on(self, event: str, cb: object) -> None:
            self._listeners.setdefault(event, []).append(cb)

        def remove_listener(self, event: str, cb: object) -> None:
            return None

        def _emit(self, event: str, payload: object) -> None:
            for cb in list(self._listeners.get(event, ())):
                assert callable(cb)
                cb(payload)

        def locator(self, selector: str) -> FakeLocator:
            return FakeLocator(selector, self)

        async def goto(self, url: str, **kwargs: object) -> None:
            return None

        async def wait_for_timeout(self, ms: int) -> None:
            return None

        async def content(self) -> str:
            return "<html><body><form><textarea></textarea><button type='submit'>Send</button></form></body></html>"

        def _on_initial_send(self) -> None:
            url = "https://arena.ai/nextjs-api/stream/create-evaluation"
            initial_body = json.dumps(
                {
                    "id": "eval-1",
                    "mode": "direct",
                    "userMessage": {"content": "Реши сам"},
                    "recaptchaV3Token": "spent-v3",
                }
            )
            self._emit("request", FakeRequest(url, post_data=initial_body))
            self._emit(
                "response",
                FakeResponse(
                    url,
                    403,
                    '{"error":"recaptcha validation failed"}',
                    "application/json",
                ),
            )
            self._bframe_open = True

        async def evaluate(self, script: str) -> object:
            if "arena_cleanup_marks" in script:
                return None
            if "composer_nonempty" in script:
                # Composer was cleared when React submitted, so v2 token replay must fire.
                return False
            if "arena_replay_v2" in script:
                # Extract serialized JSON body passed into window.fetch(...)
                marker = "body: "
                idx = script.index(marker) + len(marker)
                line = script[idx:].splitlines()[0].strip()
                inner_json = json.loads(line)
                replayed_payloads.append(json.loads(inner_json))
                url = "https://arena.ai/nextjs-api/stream/create-evaluation"
                self._emit("request", FakeRequest(url, post_data=inner_json))
                self._emit(
                    "response",
                    FakeResponse(
                        url,
                        200,
                        'a0:"Решено автоматически без ffmpeg!"\nad:{"finishReason":"stop"}\n',
                        "text/plain; charset=utf-8",
                    ),
                )
                return True
            if "data-arena-composer" in script and "data-arena-send" not in script:
                return {"found": True, "tag": "textarea", "x": 400, "y": 700}
            if "data-arena-send" in script:
                return {"found": True, "confidence": "explicit", "x": 650, "y": 700}
            if "recaptcha_anchor" in script:
                if self._bframe_open:
                    return {
                        "kind": "recaptcha_bframe",
                        "x": 500,
                        "y": 400,
                        "width": 400,
                        "height": 580,
                    }
                return {"kind": None}
            raise AssertionError(f"unexpected evaluate script: {script[:80]}")

    async def fake_auto_solve(page, obs, **kwargs) -> AutoSolveOutcome:
        autosolve_calls.append({"obs": dict(obs), "proxy": kwargs.get("proxy")})
        page._bframe_open = False
        return AutoSolveOutcome(
            solved=True,
            method="audio",
            token="03AFcWeA_FRESH_V2_TOKEN",
            rounds=1,
        )

    class FakeEnv:
        def __init__(self, options) -> None:
            self.options = options

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc) -> None:
            return None

        async def new_page(self):
            return AutoSolveBframePage()

    monkeypatch.setattr(auto_module, "BrowserEnvironment", FakeEnv)
    monkeypatch.setattr(auto_module, "auto_solve_challenge_on_page", fake_auto_solve)

    # solve_captchas="auto" mirrors default real CLI options; without playwright-recaptcha
    # installed, tok.solver resolves to ChallengeWaitSolver, yet Direct Chat still auto-solves!
    tok = DirectVerificationToken(
        isolated_options(
            tmp_path,
            base_url="https://arena.ai",
            proxy="127.0.0.1:10809",
            solve_captchas="auto",
            interactive=False,
        ),
        session_cookies={"arena-auth-prod-v1.0": "jwt"},
    )
    assert isinstance(tok.solver, ChallengeWaitSolver)

    client = auto_module.DirectArenaClient(
        base_url="https://arena.ai",
        cookies={"arena-auth-prod-v1.0": "jwt"},
        verification_token=tok,
        timeout=10.0,
    )
    try:
        answer = client.complete("Реши сам")
    finally:
        client.close()

    stderr = capsys.readouterr().err
    assert answer == "Решено автоматически без ffmpeg!"
    assert "решите её в открытом окне браузера" not in stderr
    assert len(autosolve_calls) == 1
    assert autosolve_calls[0]["proxy"] == "http://127.0.0.1:10809"
    assert len(replayed_payloads) == 1
    assert replayed_payloads[0]["recaptchaV2Token"] == "03AFcWeA_FRESH_V2_TOKEN"


def test_cdp_whatwg_windows1252_mojibake_recovered_for_text_plain_without_charset(
    tmp_path, monkeypatch
) -> None:
    """Chromium CDP decodes text/plain (without charset=utf-8) as WHATWG windows-1252; verify lossless UTF-8 recovery."""
    original_answer = (
        "Привет! Спасибо, всё отлично! 😊 Я — искусственный интеллект, "
        "так что у меня всегда «рабочее настроение».\n\n"
        "А у тебя как дела? Чем могу помочь?"
    )
    wire_line = f"a0:{json.dumps(original_answer, ensure_ascii=False)}\nad:{{\"finishReason\":\"stop\"}}\n"
    raw_utf8 = wire_line.encode("utf-8")

    # Simulate Blink TextResourceDecoder WHATWG windows-1252 decoding on text/plain:
    whatwg_table = list(range(256))
    for b in range(0x80, 0xA0):
        try:
            whatwg_table[b] = ord(bytes((b,)).decode("cp1252"))
        except UnicodeDecodeError:
            whatwg_table[b] = b
    corrupted_cdp_text = "".join(chr(whatwg_table[b]) for b in raw_utf8)
    assert "ÐŸÑ€Ð¸Ð²ÐµÑ‚!" in corrupted_cdp_text

    # Also verify charset=utf-8 and standalone non-UTF-8 Latin-1 stay untouched:
    assert (
        auto_module._recover_cdp_utf8_bytes("café", "text/plain; charset=utf-8")
        == "café".encode("utf-8")
    )
    assert (
        auto_module._recover_cdp_utf8_bytes("café", "text/plain")
        == "café".encode("utf-8")
    )

    class FakeRequest:
        def __init__(self, url: str) -> None:
            self.url = url
            self.method = "POST"

    class FakeResponse:
        def __init__(self, url: str) -> None:
            self.url = url
            self.status = 200
            # Notice: no "; charset=utf-8" in content-type, matching live arena.ai!
            self.headers = {"content-type": "text/plain"}
            self.request = FakeRequest(url)

        async def text(self) -> str:
            return corrupted_cdp_text

    class FakeLocator:
        def __init__(self, selector: str, page: "MojibakePage") -> None:
            self.selector = selector
            self._page = page

        @property
        def first(self) -> "FakeLocator":
            return self

        async def click(self) -> None:
            if "data-arena-send" in self.selector:
                url = "https://arena.ai/nextjs-api/stream/create-evaluation"
                self._page._emit("request", FakeRequest(url))
                self._page._emit("response", FakeResponse(url))

        async def fill(self, value: str) -> None:
            return None

    class MojibakePage:
        def __init__(self) -> None:
            self.context = None
            self._listeners: dict[str, list[object]] = {}

        def on(self, event: str, cb: object) -> None:
            self._listeners.setdefault(event, []).append(cb)

        def remove_listener(self, event: str, cb: object) -> None:
            return None

        def _emit(self, event: str, payload: object) -> None:
            for cb in list(self._listeners.get(event, ())):
                assert callable(cb)
                cb(payload)

        def locator(self, selector: str) -> FakeLocator:
            return FakeLocator(selector, self)

        async def goto(self, url: str, **kwargs: object) -> None:
            return None

        async def wait_for_timeout(self, ms: int) -> None:
            return None

        async def content(self) -> str:
            return "<html><body><form><textarea></textarea></form></body></html>"

        async def evaluate(self, script: str) -> object:
            if "arena_cleanup_marks" in script:
                return None
            if "data-arena-composer" in script and "data-arena-send" not in script:
                return {"found": True, "tag": "textarea", "x": 400, "y": 700}
            if "data-arena-send" in script:
                return {"found": True, "confidence": "explicit", "x": 650, "y": 700}
            if "recaptcha_anchor" in script:
                return {"kind": None}
            return None

    class FakeEnv:
        def __init__(self, options) -> None:
            self.options = options

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc) -> None:
            return None

        async def new_page(self):
            return MojibakePage()

    monkeypatch.setattr(auto_module, "BrowserEnvironment", FakeEnv)
    monkeypatch.setattr(auto_module, "solver_dependencies_available", lambda _: True)

    tok = DirectVerificationToken(
        isolated_options(tmp_path, base_url="https://arena.ai", interactive=False),
        solver=RecaptchaToolkitSolver(),
        session_cookies={"arena-auth-prod-v1.0": "jwt"},
    )
    client = auto_module.DirectArenaClient(
        base_url="https://arena.ai",
        cookies={"arena-auth-prod-v1.0": "jwt"},
        verification_token=tok,
    )
    try:
        assert client.complete("Привет! Как дела?") == original_answer
    finally:
        client.close()


def test_safe_stdout_write_handles_legacy_windows_codepage(monkeypatch) -> None:
    raw_buf = io.BytesIO()
    cp1251_stream = io.TextIOWrapper(raw_buf, encoding="cp1251", errors="strict")
    monkeypatch.setattr(auto_module.sys, "stdout", cp1251_stream)
    auto_module._safe_stdout_write("Привет! 😊 Всё отлично!")
    written = raw_buf.getvalue().decode("cp1251")
    assert "Привет!" in written
    assert "Всё отлично!" in written


def test_headless_cdp_sanitizes_headless_chrome_ua_and_client_hints() -> None:
    sent_commands: list[tuple[str, object]] = []
    detached: list[bool] = []

    class FakeCDPSession:
        async def send(self, method: str, params: object = None):
            sent_commands.append((method, params))
            if method == "Browser.getVersion":
                return {
                    "product": "Chrome/145.0.7632.117",
                    "userAgent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "HeadlessChrome/145.0.7632.117 Safari/537.36 Edg/145.0.3179.98"
                    ),
                }
            return {}

        async def detach(self) -> None:
            detached.append(True)

    class FakeContext:
        async def new_cdp_session(self, page):
            return FakeCDPSession()

    async def _run():
        cdp = await auto_module._sanitize_headless_page_cdp(
            FakeContext(), object(), channel="msedge"
        )
        assert cdp is not None
        await cdp.detach()

    asyncio.run(_run())
    assert detached == [True]
    override_calls = [
        params
        for method, params in sent_commands
        if method == "Emulation.setUserAgentOverride"
    ]
    assert len(override_calls) == 1
    override = override_calls[0]
    assert isinstance(override, dict)
    assert "Headless" not in override["userAgent"]
    assert "Chrome/145.0.7632.117" in override["userAgent"]
    meta = override["userAgentMetadata"]
    assert meta["platform"] == "Windows"
    assert any(b["brand"] == "Microsoft Edge" for b in meta["brands"])
    assert all("Headless" not in b["brand"] for b in meta["brands"])


def test_cloaked_headful_profile_placement_and_cookie_reset(tmp_path) -> None:
    profile_dir = tmp_path / "direct_browser_profile"
    auto_module._prepare_profile_window_placement(profile_dir, hidden=True)
    prefs_path = profile_dir / "Default" / "Preferences"
    prefs = json.loads(prefs_path.read_text(encoding="utf-8"))
    assert prefs["browser"]["window_placement"]["left"] == -32000
    assert prefs["browser"]["window_placement"]["maximized"] is False

    auto_module._prepare_profile_window_placement(profile_dir, hidden=False)
    prefs_visible = json.loads(prefs_path.read_text(encoding="utf-8"))
    assert prefs_visible["browser"]["window_placement"]["left"] == 80

    cleared_patterns: list[object] = []

    class FakeContext:
        async def clear_cookies(self, *, name=None, domain=None, path=None):
            cleared_patterns.append(name)

    asyncio.run(
        auto_module._maybe_reset_headless_poisoned_cookies(FakeContext(), profile_dir)
    )
    assert len(cleared_patterns) == 1
    assert (profile_dir / ".headful_cloaked_v1").is_file()
    # Second call is a no-op once migrated:
    asyncio.run(
        auto_module._maybe_reset_headless_poisoned_cookies(FakeContext(), profile_dir)
    )
    assert len(cleared_patterns) == 1


def test_hide_headed_page_window_cdp_moves_bounds_offscreen() -> None:
    sent: list[tuple[str, object]] = []
    detached: list[bool] = []

    class FakeCDPSession:
        async def send(self, method: str, params: object = None):
            sent.append((method, params))
            if method == "Browser.getWindowForTarget":
                return {"windowId": 42}
            return {}

        async def detach(self) -> None:
            detached.append(True)

    class FakeContext:
        async def new_cdp_session(self, page):
            return FakeCDPSession()

    asyncio.run(auto_module._hide_headed_page_window_cdp(FakeContext(), object()))
    assert detached == [True]
    bounds_calls = [p for m, p in sent if m == "Browser.setWindowBounds"]
    assert any(
        isinstance(c, dict)
        and isinstance(c.get("bounds"), dict)
        and c["bounds"].get("left") == -32000
        for c in bounds_calls
    )


def test_windows_descendant_pids_and_cloaker_smoke() -> None:
    from arena_api._window_cloak import _windows_descendant_pids

    pids = _windows_descendant_pids(os.getpid())
    if sys.platform == "win32":
        assert os.getpid() in pids
    else:
        assert pids == set()

    cloaker = auto_module._WindowsBrowserCloaker(enabled=True)
    cloaker.start()
    cloaker._cloak_once()
    cloaker.stop()








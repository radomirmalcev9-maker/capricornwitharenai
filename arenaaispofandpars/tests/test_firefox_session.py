from __future__ import annotations

import io
import os
import sqlite3
import sys
import time
import types
from pathlib import Path

import pytest

from arena_api.auth import firefox_session as firefox_module
from arena_api.auth.firefox_session import (
    DEFAULT_COOKIE_DOMAINS,
    FirefoxSessionError,
    FirefoxSessionManager,
    cookies_from_rookiepy,
    default_profiles_root,
    read_firefox_cookies,
)

FUTURE = int(time.time()) + 86_400
PAST = int(time.time()) - 86_400


def write_cookie_database(profile: Path, rows: list[tuple]) -> Path:
    database = profile / "cookies.sqlite"
    connection = sqlite3.connect(database)
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
        " VALUES (?, ?, ?, '/', ?, 0, 0, ?, ?)",
        rows,
    )
    connection.commit()
    connection.close()
    return database


def make_profile_tree(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Create two profile directories: one default-release, one default."""
    release = tmp_path / "abcd1234.default-release"
    plain = tmp_path / "wxyz9876.default"
    release.mkdir()
    plain.mkdir()
    return tmp_path, release, plain


def use_rookiepy(manager: FirefoxSessionManager, firefox) -> None:
    """Point the manager at a stand-in rookiepy module (instance-local stub)."""
    module = types.SimpleNamespace(firefox=firefox)
    manager._rookiepy_module = lambda: module


def test_default_domains() -> None:
    manager = FirefoxSessionManager(interactive=False)
    assert DEFAULT_COOKIE_DOMAINS == ("arena.ai", "lmarena.ai")
    assert manager.domains == DEFAULT_COOKIE_DOMAINS


def test_domain_normalization() -> None:
    manager = FirefoxSessionManager(
        domains=[".Arena.ai", "arena.ai", "", "lmarena.ai"], interactive=False
    )
    assert manager.domains == ("arena.ai", "lmarena.ai")
    with pytest.raises(ValueError):
        FirefoxSessionManager(domains=["", "."], interactive=False)
    with pytest.raises(ValueError):
        manager.load_cookies(domains=[])


def test_sqlite_fallback_reads_only_requested_domains(tmp_path) -> None:
    root, release, _ = make_profile_tree(tmp_path)
    write_cookie_database(
        release,
        [
            ("session", "s3cret", "arena.ai", FUTURE, 0, 1),
            ("cf_clearance", "cf-value", ".arena.ai", FUTURE, 1, 1),
            ("stale", "expired", ".arena.ai", PAST, 0, 0),
            ("sub_cookie", "v", "chat.arena.ai", FUTURE, 0, 0),
            ("session_cookie", "v", "arena.ai", 0, 0, 0),
            ("unrelated", "v", "notarena.ai", FUTURE, 0, 0),
            ("lookalike", "v", "arena.ai.evil.example", FUTURE, 0, 0),
            ("dash", "v", "evil-arena.ai", FUTURE, 0, 0),
            ("other_site", "v", "lmarena.ai", FUTURE, 0, 0),
        ],
    )
    manager = FirefoxSessionManager(
        profiles_root=root, interactive=False, max_cookie_attempts=1
    )
    manager._rookiepy_module = lambda: None
    assert manager.load_cookies(domains=["arena.ai"]) == {
        "session": "s3cret",
        "cf_clearance": "cf-value",
        "sub_cookie": "v",
        "session_cookie": "v",
    }


def test_sqlite_snapshot_tolerates_wal_sidecars(tmp_path) -> None:
    root, release, _ = make_profile_tree(tmp_path)
    database = write_cookie_database(
        release, [("session", "with-wal", "arena.ai", FUTURE, 0, 1)]
    )
    # A running Firefox keeps a WAL; the snapshot copy must include it.
    (release / "cookies.sqlite-wal").write_bytes(b"")
    (release / "cookies.sqlite-shm").write_bytes(b"")
    assert read_firefox_cookies(database, ["arena.ai"]) == {"session": "with-wal"}


def test_earlier_domain_wins_on_name_collision(tmp_path) -> None:
    root, release, _ = make_profile_tree(tmp_path)
    write_cookie_database(
        release,
        [
            ("session", "arena-value", "arena.ai", FUTURE, 0, 1),
            ("session", "lm-value", "lmarena.ai", FUTURE, 0, 1),
        ],
    )
    manager = FirefoxSessionManager(profiles_root=root, interactive=False)
    manager._rookiepy_module = lambda: None
    assert manager.load_cookies() == {"session": "arena-value"}


def test_rookiepy_records_are_preferred(tmp_path) -> None:
    root, release, _ = make_profile_tree(tmp_path)
    write_cookie_database(release, [("session", "sqlite", "arena.ai", FUTURE, 0, 1)])
    manager = FirefoxSessionManager(profiles_root=root, interactive=False)
    use_rookiepy(
        manager,
        lambda domains: [
            {
                "domain": ".arena.ai",
                "path": "/",
                "secure": True,
                "expires": FUTURE,
                "name": "session",
                "value": "via-rookiepy",
                "http_only": True,
            }
        ]
        if domains == ["arena.ai"]
        else [],
    )
    assert manager.load_cookies(domains=["arena.ai"]) == {"session": "via-rookiepy"}


def test_rookiepy_lock_falls_back_to_sqlite(tmp_path) -> None:
    root, release, _ = make_profile_tree(tmp_path)
    write_cookie_database(
        release, [("session", "unlocked", "arena.ai", FUTURE, 0, 1)]
    )
    manager = FirefoxSessionManager(
        profiles_root=root,
        interactive=False,
        max_cookie_attempts=2,
        lock_retry_delay=0,
    )

    def locked(domains):
        raise RuntimeError("database is locked")

    use_rookiepy(manager, locked)
    assert manager.load_cookies(domains=["arena.ai"]) == {"session": "unlocked"}


def test_rookiepy_lock_retries_then_succeeds() -> None:
    manager = FirefoxSessionManager(
        interactive=False, max_cookie_attempts=2, lock_retry_delay=0
    )
    calls = {"count": 0}

    def flaky(domains):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("database is locked")
        return [
            {
                "domain": "arena.ai",
                "path": "/",
                "secure": False,
                "expires": FUTURE,
                "name": "session",
                "value": "second-try",
                "http_only": False,
            }
        ]

    use_rookiepy(manager, flaky)
    assert manager.load_cookies(domains=["arena.ai"]) == {"session": "second-try"}
    assert calls["count"] == 2


def test_rookiepy_failure_falls_back_to_sqlite(tmp_path) -> None:
    root, release, _ = make_profile_tree(tmp_path)
    write_cookie_database(
        release, [("session", "fallback", "arena.ai", FUTURE, 0, 1)]
    )
    manager = FirefoxSessionManager(
        profiles_root=root, interactive=False, max_cookie_attempts=1
    )

    def broken(domains):
        raise RuntimeError("Can't find cookies file")

    use_rookiepy(manager, broken)
    assert manager.load_cookies(domains=["arena.ai"]) == {"session": "fallback"}


def test_missing_profile_and_database_raise(tmp_path) -> None:
    empty_root = tmp_path / "empty"
    empty_root.mkdir()
    with pytest.raises(FirefoxSessionError, match="profiles directory not found"):
        FirefoxSessionManager(
            profiles_root=tmp_path / "missing", interactive=False
        ).load_cookies()
    manager = FirefoxSessionManager(
        profiles_root=empty_root, interactive=False, max_cookie_attempts=1
    )
    manager._rookiepy_module = lambda: None
    with pytest.raises(FirefoxSessionError, match="No Firefox profile found"):
        manager.load_cookies()

    root, release, _ = make_profile_tree(tmp_path)
    with pytest.raises(FirefoxSessionError, match="cookie database not found"):
        FirefoxSessionManager(
            profiles_root=root, profile_name="abcd1234.default-release"
        ).cookie_database_path()  # no cookies.sqlite written for this profile


def test_profile_discovery_prefers_install_section(tmp_path) -> None:
    root, release, plain = make_profile_tree(tmp_path)
    (root / "profiles.ini").write_text(
        "[Install308B0890AAB1A44]\n"
        "Default=wxyz9876.default\n"
        "Locked=1\n\n"
        "[Profile1]\n"
        "Name=default\n"
        "IsRelative=1\n"
        "Path=abcd1234.default-release\n"
        "Default=1\n",
        encoding="utf-8",
    )
    manager = FirefoxSessionManager(profiles_root=root, interactive=False)
    assert manager.profile_path() == plain


def test_profile_discovery_uses_flagged_default_without_install_section(
    tmp_path,
) -> None:
    root, release, plain = make_profile_tree(tmp_path)
    (root / "profiles.ini").write_text(
        "[Profile0]\n"
        "Name=default-release\n"
        "IsRelative=1\n"
        "Path=abcd1234.default-release\n"
        "Default=1\n",
        encoding="utf-8",
    )
    manager = FirefoxSessionManager(profiles_root=root, interactive=False)
    assert manager.profile_path() == release


def test_profile_discovery_prefers_default_release_hint(tmp_path) -> None:
    root, release, plain = make_profile_tree(tmp_path)
    manager = FirefoxSessionManager(profiles_root=root, interactive=False)
    assert manager.profile_path() == release


def test_profile_discovery_falls_back_to_newest_database(tmp_path) -> None:
    root = tmp_path
    old = root / "aaaa.custom-profile"
    new = root / "bbbb.another-profile"
    old.mkdir()
    new.mkdir()
    write_cookie_database(old, [("a", "1", "arena.ai", FUTURE, 0, 0)])
    write_cookie_database(new, [("b", "2", "arena.ai", FUTURE, 0, 0)])
    stamp = time.time() + 100
    os.utime(new / "cookies.sqlite", (stamp, stamp))
    manager = FirefoxSessionManager(profiles_root=root, interactive=False)
    assert manager.profile_path() == new


def test_profile_name_override(tmp_path) -> None:
    root, release, _ = make_profile_tree(tmp_path)
    manager = FirefoxSessionManager(
        profiles_root=root, profile_name="abcd1234.default-release", interactive=False
    )
    assert manager.profile_path() == release
    with pytest.raises(FirefoxSessionError, match="profile not found"):
        FirefoxSessionManager(
            profiles_root=root, profile_name="missing.profile"
        ).profile_path()


def test_cookie_database_override(tmp_path) -> None:
    root, release, _ = make_profile_tree(tmp_path)
    database = write_cookie_database(
        release, [("session", "direct", "arena.ai", FUTURE, 0, 1)]
    )
    manager = FirefoxSessionManager(
        cookie_database=database, interactive=False, max_cookie_attempts=1
    )
    manager._rookiepy_module = lambda: None
    assert manager.load_cookies(domains=["arena.ai"]) == {"session": "direct"}
    with pytest.raises(FirefoxSessionError, match="cookie database not found"):
        FirefoxSessionManager(
            cookie_database=tmp_path / "elsewhere.sqlite"
        ).cookie_database_path()


def test_user_agent_reads_version_from_profile(tmp_path) -> None:
    root, release, _ = make_profile_tree(tmp_path)
    (release / "compatibility.ini").write_text(
        "[Compatibility]\nLastVersion=148.0.2_20260315123456/20260315123456\n",
        encoding="utf-8",
    )
    manager = FirefoxSessionManager(profiles_root=root, interactive=False)
    agent = manager.user_agent()
    # Firefox >= 120 reports MOZILLA_UAVERSION (<major>.0) in both rv: and Firefox/
    # so cf_clearance's User-Agent binding matches the real browser byte-for-byte.
    assert "Firefox/148.0" in agent
    assert "Firefox/148.0.2" not in agent
    assert "rv:148.0" in agent
    assert agent.startswith("Mozilla/5.0 (")

    esr_115 = FirefoxSessionManager(
        profiles_root=root, firefox_version="115.0", interactive=False
    )
    assert "rv:109.0" in esr_115.user_agent()
    assert "Firefox/115.0" in esr_115.user_agent()

    override = FirefoxSessionManager(
        profiles_root=root, firefox_version="137.0.1", interactive=False
    )
    assert "rv:137.0" in override.user_agent()
    assert "Firefox/137.0.1" in override.user_agent()


def test_firefox_headers_fetch_and_navigation_shapes(tmp_path) -> None:
    root, release, _ = make_profile_tree(tmp_path)
    (release / "compatibility.ini").write_text(
        "[Compatibility]\nLastVersion=141.0/20250825133129\n", encoding="utf-8"
    )
    manager = FirefoxSessionManager(
        profiles_root=root, language="ru-RU", interactive=False
    )
    headers = manager.firefox_headers()
    assert headers["User-Agent"].endswith("Firefox/141.0")
    assert headers["Accept-Language"] == "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3"
    assert headers["Sec-GPC"] == "1"
    assert headers["Sec-Fetch-Dest"] == "empty"
    assert headers["Sec-Fetch-Mode"] == "cors"
    assert headers["Sec-Fetch-Site"] == "same-origin"
    assert "Accept-Encoding" not in headers  # negotiated by the HTTP backend
    assert "Sec-Fetch-User" not in headers

    navigation = manager.firefox_headers(navigation=True)
    assert navigation["Sec-Fetch-Dest"] == "document"
    assert navigation["Sec-Fetch-Mode"] == "navigate"
    assert navigation["Sec-Fetch-Site"] == "none"
    assert navigation["Sec-Fetch-User"] == "?1"
    assert navigation["Upgrade-Insecure-Requests"] == "1"
    assert navigation["Accept"].startswith("text/html")


def test_accept_language_from_prefs_js(tmp_path) -> None:
    root, release, _ = make_profile_tree(tmp_path)
    (release / "prefs.js").write_text(
        'user_pref("intl.accept_languages", "de, en-US, en");\n', encoding="utf-8"
    )
    manager = FirefoxSessionManager(profiles_root=root, interactive=False)
    assert manager.accept_language() == "de, en-US, en"


def test_to_curl_cffi_groups_by_domain(tmp_path) -> None:
    root, release, _ = make_profile_tree(tmp_path)
    write_cookie_database(
        release,
        [
            ("session", "arena-value", "arena.ai", FUTURE, 0, 1),
            ("other", "lm-value", "lmarena.ai", FUTURE, 0, 0),
        ],
    )
    manager = FirefoxSessionManager(profiles_root=root, interactive=False)
    manager._rookiepy_module = lambda: None
    grouped = manager.to_curl_cffi()
    assert grouped == {
        "arena.ai": {"session": "arena-value"},
        "lmarena.ai": {"other": "lm-value"},
    }


def test_refresh_session_prints_guidance_and_reloads(tmp_path) -> None:
    root, release, _ = make_profile_tree(tmp_path)
    write_cookie_database(
        release, [("session", "fresh-value", "arena.ai", FUTURE, 0, 1)]
    )
    output = io.StringIO()
    prompts: list[str] = []
    manager = FirefoxSessionManager(
        profiles_root=root,
        interactive=True,
        prompt=prompts.append,
        output=output,
        max_cookie_attempts=1,
    )
    manager._rookiepy_module = lambda: None
    cookies = manager.refresh_session(RuntimeError("HTTP 403"))
    assert cookies == {"session": "fresh-value"}
    assert prompts == [""]  # waited for Enter
    text = output.getvalue()
    assert "Сессия устарела. Откройте arena.ai в Firefox" in text
    assert "нажмите Enter" in text
    assert "HTTP 403" in text


def test_refresh_session_noninteractive_does_not_prompt(tmp_path) -> None:
    root, release, _ = make_profile_tree(tmp_path)
    write_cookie_database(
        release, [("session", "value", "arena.ai", FUTURE, 0, 1)]
    )
    output = io.StringIO()

    def fail(_: str) -> str:
        raise AssertionError("prompt must not be called")

    manager = FirefoxSessionManager(
        profiles_root=root,
        interactive=False,
        prompt=fail,
        output=output,
        max_cookie_attempts=1,
    )
    manager._rookiepy_module = lambda: None
    assert manager.refresh_session() == {"session": "value"}


def test_refresh_session_returns_none_without_cookies(tmp_path) -> None:
    root, release, _ = make_profile_tree(tmp_path)
    write_cookie_database(
        release, [("session", "gone", "other.example", FUTURE, 0, 0)]
    )
    output = io.StringIO()
    manager = FirefoxSessionManager(
        profiles_root=root,
        interactive=False,
        output=output,
        max_cookie_attempts=1,
    )
    manager._rookiepy_module = lambda: None
    assert manager.refresh_session() is None
    assert "нет cookie" in output.getvalue()


def test_refresh_session_survives_keyboard_interrupt(tmp_path) -> None:
    manager = FirefoxSessionManager(interactive=False)

    def interrupted(_: str) -> str:
        raise KeyboardInterrupt

    manager.interactive = True
    manager._prompt = interrupted
    assert manager.refresh_session() is None


def test_cookies_from_rookiepy_filters_bad_and_expired_records() -> None:
    records = [
        {
            "domain": "arena.ai",
            "path": "/",
            "secure": False,
            "expires": FUTURE,
            "name": "good",
            "value": "1",
            "http_only": False,
        },
        {"name": "no-value", "value": None, "expires": None},
        {"name": "", "value": "x", "expires": None},
        "not-a-mapping",
        {
            "domain": "arena.ai",
            "path": "/",
            "secure": False,
            "expires": PAST,
            "name": "expired",
            "value": "2",
            "http_only": False,
        },
        {
            "domain": "arena.ai",
            "path": "/",
            "secure": False,
            "expires": None,
            "name": "session-cookie",
            "value": "3",
            "http_only": False,
        },
        {
            "domain": "arena.ai",
            "path": "/",
            "secure": False,
            "expires": "not-a-number",
            "name": "weird-expiry",
            "value": "4",
            "http_only": False,
        },
    ]
    assert cookies_from_rookiepy(records) == {
        "good": "1",
        "session-cookie": "3",
        "weird-expiry": "4",
    }
    assert cookies_from_rookiepy(None) == {}
    assert cookies_from_rookiepy("nope") == {}


def test_manager_validates_constructor_arguments() -> None:
    with pytest.raises(ValueError):
        FirefoxSessionManager(max_cookie_attempts=0)
    with pytest.raises(ValueError):
        FirefoxSessionManager(lock_retry_delay=-1)


# --------------------------------------------------------------------------- #
# Platform specifics: this library reads real browser profiles, so the paths it
# guesses have to be right on every OS -- and are testable from any of them.
# --------------------------------------------------------------------------- #


def _fake_home(monkeypatch, tmp_path) -> Path:
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    return tmp_path


def test_profiles_root_on_windows_prefers_appdata(monkeypatch, tmp_path) -> None:
    home = _fake_home(monkeypatch, tmp_path)
    monkeypatch.setattr(sys, "platform", "win32")
    appdata = home / "Roaming-elsewhere"
    monkeypatch.setenv("APPDATA", str(appdata))
    assert default_profiles_root() == appdata / "Mozilla" / "Firefox"


def test_profiles_root_on_windows_without_appdata(monkeypatch, tmp_path) -> None:
    home = _fake_home(monkeypatch, tmp_path)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delenv("APPDATA", raising=False)
    assert default_profiles_root() == home / "AppData" / "Roaming" / "Mozilla" / "Firefox"


def test_profiles_root_on_macos(monkeypatch, tmp_path) -> None:
    home = _fake_home(monkeypatch, tmp_path)
    monkeypatch.setattr(sys, "platform", "darwin")
    assert default_profiles_root() == home / "Library" / "Application Support" / "Firefox"


def test_profiles_root_on_linux(monkeypatch, tmp_path) -> None:
    home = _fake_home(monkeypatch, tmp_path)
    monkeypatch.setattr(sys, "platform", "linux")
    assert default_profiles_root() == home / ".mozilla" / "firefox"


def test_user_agent_platform_token_per_os(monkeypatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    assert firefox_module._platform_token() == "Windows NT 10.0; Win64; x64"
    monkeypatch.setattr(sys, "platform", "darwin")
    assert firefox_module._platform_token() == "Macintosh; Intel Mac OS X 10.15"
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(firefox_module.platform, "machine", lambda: "x86_64")
    assert firefox_module._platform_token() == "X11; Linux x86_64"
    monkeypatch.setattr(firefox_module.platform, "machine", lambda: "aarch64")
    assert firefox_module._platform_token() == "X11; Linux aarch64"
    monkeypatch.setattr(firefox_module.platform, "machine", lambda: "arm64")
    assert firefox_module._platform_token() == "X11; Linux aarch64"


def test_user_agent_matches_the_platform_token(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    manager = FirefoxSessionManager(
        domains=("arena.ai",), profiles_root=tmp_path, cookie_database=tmp_path / "c.sqlite"
    )
    assert firefox_module._platform_token() in manager.user_agent()


def test_windows_crt_locale_names_never_leak_into_accept_language(
    monkeypatch, tmp_path
) -> None:
    """Windows ``locale.getlocale()`` returns ``('Russian_Russia', '1251')`` or
    ``('English_United States', '1252')``; emitting that raw string produces an
    invalid ``Accept-Language`` header that anti-bot edges flag immediately."""
    root, release, _ = make_profile_tree(tmp_path)
    monkeypatch.setattr(firefox_module, "_windows_ui_locale_tag", lambda: None)
    monkeypatch.setattr(
        firefox_module.locale, "getlocale", lambda: ("Russian_Russia", "1251")
    )
    for var in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        monkeypatch.delenv(var, raising=False)

    manager = FirefoxSessionManager(profiles_root=root, interactive=False)
    assert manager.accept_language() == "en-US,en;q=0.5"
    assert "Russian" not in manager.accept_language()

    monkeypatch.setattr(firefox_module, "_windows_ui_locale_tag", lambda: "ru-RU")
    assert manager.accept_language() == "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3"


def test_user_agent_and_locale_overrides_in_prefs_js(tmp_path) -> None:
    root, release, _ = make_profile_tree(tmp_path)
    (release / "prefs.js").write_text(
        'user_pref("general.useragent.override", "CustomFirefox/150.0");\n'
        'user_pref("intl.locale.requested", "sv-SE,en-US");\n',
        encoding="utf-8",
    )
    manager = FirefoxSessionManager(profiles_root=root, interactive=False)
    assert manager.user_agent() == "CustomFirefox/150.0"
    assert manager.accept_language() == "sv-SE,sv;q=0.8,en-US;q=0.5,en;q=0.3"


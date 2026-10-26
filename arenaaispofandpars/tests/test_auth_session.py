"""Tests for the session lifecycle manager (no browser, no network)."""

from __future__ import annotations

import asyncio
import json

import pytest

from arena_api.auth.challenge import ChallengeHandler, ChallengeKind
from arena_api.auth.firefox_session import SessionManager
from arena_api.auth.session import (
    BrowserSessionManager,
    CurlCffiProbe,
    FormLoginFlow,
    RawResponse,
    SessionValidation,
    chromium_user_agent,
    normalize_state_payload,
)
from arena_api.exceptions import AuthenticationError, ChallengeRequiredError

CLEAN_BODY = "<html><body><h1>Dashboard</h1></body></html>"
CHALLENGE_BODY = (
    "<html><head><title>Just a moment...</title></head><body>"
    "Checking if the site connection is secure"
    "<iframe src='https://challenges.cloudflare.com/x'></iframe></body></html>"
)


class FakeProbe:
    """Returns a canned sequence of responses and records every call."""

    def __init__(self, *responses: RawResponse | Exception) -> None:
        self._responses = list(responses)
        self.calls: list[dict] = []

    def __call__(self, url, *, cookies, headers, timeout):
        self.calls.append(
            {"url": url, "cookies": dict(cookies), "headers": dict(headers), "timeout": timeout}
        )
        if not self._responses:
            raise AssertionError("probe called more times than expected")
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def make_manager(**kwargs) -> BrowserSessionManager:
    kwargs.setdefault("base_url", "https://arena.test")
    kwargs.setdefault("storage_path", None)
    return BrowserSessionManager(**kwargs)


# --------------------------------------------------------------------------- #
# Construction and stored state
# --------------------------------------------------------------------------- #


def test_domains_are_derived_from_base_url() -> None:
    manager = make_manager(base_url="https://lmarena.test/")
    assert manager.host == "lmarena.test"
    assert manager.domains == ("lmarena.test",)
    assert manager.base_url == "https://lmarena.test"


def test_explicit_domains_are_kept() -> None:
    manager = make_manager(domains=("arena.test", ".lmarena.test"))
    assert manager.domains == ("arena.test", ".lmarena.test")


def test_import_export_round_trip(tmp_path) -> None:
    manager = make_manager(storage_path=tmp_path / "state.json")
    manager.import_cookies({"session": "s1", "cf_clearance": "c1"})
    target = manager.export_cookies()
    assert json.loads(target.read_text()) == [
        {"name": "session", "value": "s1", "domain": "arena.test", "path": "/"},
        {"name": "cf_clearance", "value": "c1", "domain": "arena.test", "path": "/"},
    ]


def test_load_cookies_filters_by_domain(tmp_path) -> None:
    manager = make_manager(storage_path=tmp_path / "state.json")
    manager.import_cookies(
        [
            {"name": "a", "value": "1", "domain": "arena.test"},
            {"name": "b", "value": "2", "domain": "other.test"},
        ]
    )
    # Default filtering follows the manager's own domains.
    assert manager.load_cookies() == {"a": "1"}
    assert manager.load_cookies(["other.test"]) == {"b": "2"}
    assert manager.load_cookies(["arena.test", "other.test"]) == {"a": "1", "b": "2"}


def test_cookie_records_carry_attributes(tmp_path) -> None:
    manager = make_manager(storage_path=tmp_path / "state.json")
    manager._state = {
        "cookies": [
            {
                "name": "session",
                "value": "v",
                "domain": ".arena.test",
                "path": "/",
                "expires": -1,
                "secure": True,
                "httpOnly": True,
                "sameSite": "Lax",
            }
        ]
    }
    record = manager.cookie_records()[0]
    assert record["http_only"] is True
    assert record["same_site"] == "Lax"


def test_storage_state_json_is_read(tmp_path) -> None:
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps(
            {
                "cookies": [
                    {
                        "name": "session",
                        "value": "abc",
                        "domain": "arena.test",
                        "path": "/",
                        "secure": True,
                        "httpOnly": False,
                    }
                ],
                "origins": [],
            }
        ),
        encoding="utf-8",
    )
    manager = make_manager(storage_path=path)
    assert manager.load_cookies() == {"session": "abc"}


def test_missing_storage_file_yields_no_cookies(tmp_path) -> None:
    manager = make_manager(storage_path=tmp_path / "missing.json")
    assert manager.load_cookies() == {}


def test_to_curl_cffi_groups_by_domain(tmp_path) -> None:
    manager = make_manager(storage_path=tmp_path / "s.json")
    manager.import_cookies(
        [
            {"name": "a", "value": "1", "domain": "arena.test"},
            {"name": "b", "value": "2", "domain": "lmarena.test"},
        ]
    )
    grouped = manager.to_curl_cffi()
    assert grouped == {"arena.test": {"a": "1"}, "lmarena.test": {"b": "2"}}


def test_to_curl_cffi_session_carries_cookies_and_headers(tmp_path) -> None:
    pytest.importorskip("curl_cffi")
    manager = make_manager(storage_path=tmp_path / "s.json")
    manager.import_cookies({"session": "abc"})
    session = manager.to_curl_cffi_session()
    assert dict(session.cookies) == {"session": "abc"}
    assert session.headers["User-Agent"] == manager.default_user_agent()


def test_import_rejects_unsupported_shapes(tmp_path) -> None:
    manager = make_manager(storage_path=tmp_path / "s.json")
    with pytest.raises(TypeError):
        manager.import_cookies(42)


def test_storage_state_accepts_a_plain_cookie_array(tmp_path) -> None:
    """The README's cookies.json format must work as storage_path too."""
    path = tmp_path / "cookies.json"
    path.write_text(
        json.dumps(
            [
                {"name": "session", "value": "abc", "domain": "arena.test"},
                {"name": "cf_clearance", "value": "def", "domain": ".arena.test"},
            ]
        ),
        encoding="utf-8",
    )
    manager = make_manager(storage_path=path)
    assert manager.load_cookies() == {"session": "abc", "cf_clearance": "def"}


def test_storage_state_accepts_a_cookie_header_export(tmp_path) -> None:
    path = tmp_path / "cookies.json"
    path.write_text(
        json.dumps({"cookie": "session=abc; cf_clearance=def"}), encoding="utf-8"
    )
    manager = make_manager(storage_path=path)
    assert manager.load_cookies() == {"session": "abc", "cf_clearance": "def"}


def test_records_without_a_domain_inherit_the_manager_host(tmp_path) -> None:
    """Hand-written exports usually omit the domain; they must not vanish."""
    path = tmp_path / "cookies.json"
    path.write_text(
        json.dumps([{"name": "session", "value": "abc"}]), encoding="utf-8"
    )
    manager = make_manager(storage_path=path)
    assert manager.load_cookies() == {"session": "abc"}
    assert manager.cookie_records()[0]["domain"] == "arena.test"


def test_export_then_reuse_as_storage_path(tmp_path) -> None:
    """Round-trip: export_cookies() output must be loadable as storage_path."""
    first = make_manager(storage_path=tmp_path / "a.json")
    first.import_cookies({"session": "abc"})
    exported = first.export_cookies(tmp_path / "b.json")

    second = make_manager(storage_path=exported)
    assert second.load_cookies() == {"session": "abc"}


def test_unrecognised_state_file_yields_no_cookies(tmp_path) -> None:
    path = tmp_path / "cookies.json"
    path.write_text(json.dumps({"unexpected": "shape"}), encoding="utf-8")
    assert make_manager(storage_path=path).load_cookies() == {}


def test_normalize_state_payload_helper() -> None:
    assert normalize_state_payload([{"name": "a", "value": "1"}], "h")["cookies"][0][
        "domain"
    ] == "h"
    assert normalize_state_payload({"cookie": "a=1"}, "h")["cookies"][0]["name"] == "a"
    assert normalize_state_payload({"cookies": []}, "h") == {"cookies": [], "origins": []}
    assert normalize_state_payload("nope", "h") == {}


# --------------------------------------------------------------------------- #
# Headers
# --------------------------------------------------------------------------- #


def test_headers_describe_the_browser_that_owns_the_session() -> None:
    manager = make_manager()
    headers = manager.headers(navigation=True)
    assert headers["User-Agent"].startswith("Mozilla/5.0 (")
    assert "Chrome/" in headers["User-Agent"]
    assert headers["Sec-Fetch-Mode"] == "navigate"


def test_fetch_headers_differ_from_navigation_headers() -> None:
    manager = make_manager()
    assert manager.headers()["Sec-Fetch-Dest"] == "empty"
    assert manager.headers(navigation=True)["Sec-Fetch-Dest"] == "document"


def test_user_agent_can_be_overridden() -> None:
    manager = make_manager(user_agent="my-monitor/2.0")
    assert manager.headers()["User-Agent"] == "my-monitor/2.0"


def test_chromium_user_agent_tracks_the_platform() -> None:
    assert "Chrome/140" in chromium_user_agent()
    assert "Chrome/1.2.3" in chromium_user_agent("1.2.3")


def test_firefox_headers_alias_keeps_the_client_protocol_working() -> None:
    manager = make_manager()
    assert manager.firefox_headers() == manager.headers()
    assert isinstance(manager, SessionManager)


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def test_validate_accepts_a_healthy_session() -> None:
    probe = FakeProbe(RawResponse(200, {"content-type": "text/html"}, CLEAN_BODY))
    manager = make_manager(probe=probe)
    manager.import_cookies({"session": "abc"})
    result = manager.validate()
    assert result.ok is True
    assert result.status == 200
    assert result.reason == "session accepted"
    assert probe.calls[0]["cookies"] == {"session": "abc"}
    assert probe.calls[0]["url"] == "https://arena.test/"


def test_validate_detects_rejection() -> None:
    probe = FakeProbe(RawResponse(403, {"content-type": "text/html"}, CLEAN_BODY))
    manager = make_manager(probe=probe)
    result = manager.validate()
    assert result.ok is False
    assert "expired" in result.reason
    assert result.status == 403


def test_validate_detects_rate_limiting() -> None:
    probe = FakeProbe(RawResponse(429, {"content-type": "text/html"}, CLEAN_BODY))
    result = make_manager(probe=probe).validate()
    assert result.ok is False
    assert "rate limited" in result.reason


def test_validate_detects_a_challenge_and_records_it() -> None:
    probe = FakeProbe(
        RawResponse(
            403,
            {"content-type": "text/html", "cf-mitigated": "challenge", "server": "cloudflare"},
            CHALLENGE_BODY,
        )
    )
    manager = make_manager(probe=probe)
    result = manager.validate()
    assert result.ok is False
    assert result.challenge is not None
    assert result.challenge.kind is not ChallengeKind.NONE
    assert "challenge" in result.reason


def test_validate_reports_transport_errors() -> None:
    probe = FakeProbe(ConnectionError("dns failure"))
    result = make_manager(probe=probe).validate()
    assert result.ok is False
    assert "transport error" in result.reason
    assert result.status is None


def test_validate_tries_every_configured_path() -> None:
    probe = FakeProbe(
        RawResponse(403, {"content-type": "text/html"}, CLEAN_BODY),
        RawResponse(200, {"content-type": "text/html"}, CLEAN_BODY),
    )
    manager = make_manager(probe=probe, validate_paths=("/a", "/b"))
    assert manager.validate().ok is True
    assert [call["url"] for call in probe.calls] == [
        "https://arena.test/a",
        "https://arena.test/b",
    ]


def test_validate_can_detect_a_signed_out_render() -> None:
    probe = FakeProbe(
        RawResponse(200, {"content-type": "text/html"}, "<html>Sign in to continue</html>")
    )
    manager = make_manager(
        probe=probe, detect_anonymous=True, anonymous_markers=("sign in",)
    )
    result = manager.validate()
    assert result.ok is False
    assert "signed-out" in result.reason


def test_anonymous_detection_is_off_by_default() -> None:
    probe = FakeProbe(
        RawResponse(200, {"content-type": "text/html"}, "<html>Sign in to continue</html>")
    )
    manager = make_manager(probe=probe, anonymous_markers=("sign in",))
    assert manager.validate().ok is True


def test_validation_failure_raises_the_matching_error() -> None:
    result = SessionValidation(False, 403, "https://arena.test/", "session rejected")
    with pytest.raises(AuthenticationError):
        result.raise_for_status()


def test_validation_success_does_not_raise() -> None:
    SessionValidation(True, 200, "https://arena.test/", "ok").raise_for_status()


def test_validation_with_challenge_raises_challenge_error() -> None:
    handler = ChallengeHandler(raise_on_detection=False)
    observation = handler.check_response(
        403, {"cf-mitigated": "challenge", "content-type": "text/html"}, CHALLENGE_BODY
    )
    result = SessionValidation(
        False, 403, "https://arena.test/", "challenge", challenge=observation
    )
    with pytest.raises(ChallengeRequiredError):
        result.raise_for_status()


def test_describe_is_log_friendly() -> None:
    text = SessionValidation(False, 403, "https://arena.test/", "nope").describe()
    assert text == "invalid [403] https://arena.test/: nope"


# --------------------------------------------------------------------------- #
# curl_cffi probe
# --------------------------------------------------------------------------- #


def test_curl_cffi_probe_uses_an_injected_factory() -> None:
    class FakeCurlResponse:
        status_code = 204
        headers = {"content-type": "text/html"}
        text = ""

    probe = CurlCffiProbe(request_factory=lambda *args, **kwargs: FakeCurlResponse())
    response = probe("https://arena.test/", cookies={}, headers={}, timeout=1.0)
    assert response.status == 204


def test_curl_cffi_probe_truncates_large_bodies() -> None:
    class Big:
        status_code = 200
        headers = {}
        text = "x" * 1000

    probe = CurlCffiProbe(max_body_chars=10, request_factory=lambda *a, **k: Big())
    assert len(probe("https://x/", cookies={}, headers={}, timeout=1.0).body) == 10


# --------------------------------------------------------------------------- #
# Login flow and refresh
# --------------------------------------------------------------------------- #


def test_form_login_flow_reads_credentials_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("ARENA_USERNAME", "user")
    monkeypatch.setenv("ARENA_PASSWORD", "secret")
    flow = FormLoginFlow(
        login_url="https://arena.test/login",
        username_selector="#email",
        password_selector="#password",
        submit_selector="button[type=submit]",
    )
    assert flow.credentials() == ("user", "secret")


def test_form_login_flow_reports_missing_credentials(monkeypatch) -> None:
    monkeypatch.delenv("ARENA_USERNAME", raising=False)
    monkeypatch.delenv("ARENA_PASSWORD", raising=False)
    flow = FormLoginFlow(
        login_url="https://arena.test/login",
        username_selector="#email",
        password_selector="#password",
        submit_selector="button[type=submit]",
    )
    with pytest.raises(AuthenticationError):
        flow.credentials()


def test_refresh_without_a_login_flow_explains_itself() -> None:
    manager = make_manager()
    with pytest.raises(AuthenticationError) as caught:
        asyncio.run(manager.arefresh_session())
    assert "login_flow" in str(caught.value)


def test_ensure_valid_gives_up_cleanly_without_a_login_flow() -> None:
    probe = FakeProbe(RawResponse(403, {"content-type": "text/html"}, CLEAN_BODY))
    manager = make_manager(probe=probe)
    with pytest.raises(AuthenticationError):
        asyncio.run(manager.aensure_valid())


def test_ensure_valid_returns_cookies_when_already_valid() -> None:
    probe = FakeProbe(RawResponse(200, {"content-type": "text/html"}, CLEAN_BODY))
    manager = make_manager(probe=probe)
    manager.import_cookies({"session": "abc"})
    assert asyncio.run(manager.aensure_valid()) == {"session": "abc"}


def test_ensure_valid_surfaces_a_challenge() -> None:
    probe = FakeProbe(
        RawResponse(
            403,
            {"content-type": "text/html", "cf-mitigated": "challenge"},
            CHALLENGE_BODY,
        )
    )
    manager = make_manager(probe=probe)
    with pytest.raises(ChallengeRequiredError):
        asyncio.run(manager.aensure_valid())


def test_validate_uses_explicitly_supplied_cookies() -> None:
    """A post-refresh re-validation must probe with the *new* cookies."""
    probe = FakeProbe(RawResponse(200, {"content-type": "text/html"}, CLEAN_BODY))
    manager = make_manager(probe=probe)
    manager.import_cookies({"session": "stale"})
    result = manager.validate({"session": "fresh"})
    assert result.ok is True
    assert probe.calls[0]["cookies"] == {"session": "fresh"}
    # Stored state is untouched until the refresh is persisted.
    assert manager.load_cookies() == {"session": "stale"}


def test_ensure_valid_fails_fast_without_a_refresh_path() -> None:
    """No login flow means no retry loop -- and no surprise browser launch."""
    probe = FakeProbe(
        RawResponse(403, {"content-type": "text/html"}, CLEAN_BODY),
        RawResponse(403, {"content-type": "text/html"}, CLEAN_BODY),
        RawResponse(403, {"content-type": "text/html"}, CLEAN_BODY),
    )
    manager = make_manager(probe=probe, max_refresh_attempts=3)
    with pytest.raises(AuthenticationError):
        asyncio.run(manager.aensure_valid())
    assert len(probe.calls) == 1, "validation must not be retried without a login flow"

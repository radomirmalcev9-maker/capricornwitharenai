"""Redacted, read-only reports about the local Firefox profile.

Why this exists
---------------
A cookie *value* is a bearer credential: pasting one into a chat, an issue or a
log hands over the account. So when the reader finds nothing it is impossible to
tell from the outside whether the profile is empty, whether the browser was
never signed in, whether the site is served from a different domain, or whether
the library looked in the wrong place.

This module answers those questions without ever printing a value: it reports
hosts, names, paths, flags, expiry dates, the value *length* and a truncated
SHA-256 fingerprint. That is enough to diagnose a real setup -- and little
enough to share safely::

    python -m arena_api --diagnose          # human-readable
    python -m arena_api --diagnose --json   # same data, machine-readable

Nothing here writes to the profile: the cookie database is copied to a private
temporary directory first (Firefox keeps it in WAL mode and may hold it open),
so a running browser is never disturbed.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import io
import json
import os
import platform
import re
import shutil
import sqlite3
import sys
import tempfile
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .firefox_session import (
    DEFAULT_COOKIE_DOMAINS,
    FIREFOX_PROFILE_ENV,
    FIREFOX_ROOT_ENV,
    FirefoxSessionError,
    FirefoxSessionManager,
    _domain_matches,
    _expiry_seconds,
    _sessionstore_cookie_rows,
)

__all__ = [
    "MAX_REPORTED_COOKIES",
    "CookieFingerprint",
    "collect_firefox_report",
    "format_firefox_report",
    "report_as_json",
    "report_for_options",
]

#: Cookies detailed per profile. Enough for a real session (a frontend sets a
#: handful) and short enough to stay readable in a bug report.
MAX_REPORTED_COOKIES = 25

#: Pure-Python UTC epoch arithmetic avoids Windows UCRT ``_gmtime64_s`` failing
#: with ``OSError: [Errno 22]`` on far-future timestamps (> year 3000).
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MAX_DISPLAY_EPOCH = 253_402_300_799  # 9999-12-31T23:59:59Z


def _utc_from_epoch(seconds: int | float) -> datetime:
    clamped = min(max(float(seconds), 0.0), float(_MAX_DISPLAY_EPOCH))
    return _EPOCH + timedelta(seconds=clamped)

#: Cookie names that usually carry the session itself, used only to point a
#: reader at the interesting rows -- never to decide whether a session is valid.
#: Short stems like ``sid`` and ``sess`` are matched on token boundaries so UI
#: cookies such as ``sidebar_state`` are not mislabelled as credentials.
_AUTH_SUBSTRING_HINTS: tuple[str, ...] = (
    "session",
    "token",
    "auth",
    "jwt",
    "login",
    "csrf",
    "clearance",
    "__secure",
    "__host",
)
_AUTH_TOKEN_HINTS: frozenset[str] = frozenset({"sid", "sess"})
_AUTH_SUFFIX_HINTS: tuple[str, ...] = ("sessid", "sessionid")

_SAME_SITE: dict[int, str] = {0: "none", 1: "lax", 2: "strict"}

#: Environment variables reported as set/not set (values are never printed).
_REPORTED_ENV: tuple[str, ...] = (
    FIREFOX_ROOT_ENV,
    FIREFOX_PROFILE_ENV,
    "ARENA_COOKIE",
    "ARENA_COOKIES_FILE",
    "ARENA_COOKIES",
)


@dataclass(frozen=True)
class CookieFingerprint:
    """One cookie, described without its value."""

    host: str
    name: str
    path: str
    expires: int
    secure: bool
    http_only: bool
    same_site: str
    container: str
    value_length: int
    value_sha256: str
    shape: str
    looks_like_auth: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "name": self.name,
            "path": self.path,
            "expires": (
                _utc_from_epoch(self.expires)
                .isoformat()
                .replace("+00:00", "Z")
                if self.expires
                else "session"
            ),
            "secure": self.secure,
            "http_only": self.http_only,
            "same_site": self.same_site,
            "container": self.container,
            "value_length": self.value_length,
            "value_sha256": self.value_sha256,
            "shape": self.shape,
            "looks_like_auth": self.looks_like_auth,
        }

    def describe(self) -> str:
        flags = "".join(
            (
                "S" if self.secure else "-",
                "H" if self.http_only else "-",
            )
        )
        expiry = (
            _utc_from_epoch(self.expires).strftime("%Y-%m-%d")
            if self.expires
            else "session"
        )
        marker = "*" if self.looks_like_auth else " "
        return (
            f"{marker} {self.host:<22} {self.name:<24} {flags} "
            f"{self.same_site:<6} len={self.value_length:<4} "
            f"sha256={self.value_sha256 or '--------'} "
            f"expiry={expiry} shape={self.shape}"
        )


# --------------------------------------------------------------------------- #
# Value shape (never the value)
# --------------------------------------------------------------------------- #


def _fingerprint_value(value: str) -> tuple[int, str, str]:
    """Return ``(length, sha256 prefix, shape)`` for a cookie value."""

    text = str(value or "")
    if not text:
        return 0, "", "empty"
    digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:8]
    return len(text), digest, _value_shape(text)


def _value_shape(value: str) -> str:
    if value.count(".") == 2 and all(part for part in value.split(".")):
        return "jwt"
    if len(value) == 36 and value.count("-") == 4:
        return "uuid"
    if value.isdigit():
        return "numeric"
    lowered = value.lower()
    if len(lowered) >= 16 and all(ch in "0123456789abcdef" for ch in lowered):
        return "hex"
    if value.startswith("{") and value.endswith("}"):
        return "json"
    if any(ch in value for ch in "+/="):
        return "base64"
    if all(ch.isalnum() or ch in "-_" for ch in value):
        return "base64url-ish" if len(value) >= 16 else "short"
    return "opaque"


def _looks_like_auth(name: str) -> bool:
    lowered = name.lower()
    if any(hint in lowered for hint in _AUTH_SUBSTRING_HINTS):
        return True
    if lowered.endswith(_AUTH_SUFFIX_HINTS):
        return True
    tokens = {part for part in re.split(r"[^a-z0-9]+", lowered) if part}
    return bool(tokens & _AUTH_TOKEN_HINTS)


# --------------------------------------------------------------------------- #
# Reading one profile
# --------------------------------------------------------------------------- #


@contextmanager
def _snapshot(database: Path) -> Iterator[Path]:
    """Copy ``cookies.sqlite`` and its sidecars so a live Firefox is untouched."""
    with tempfile.TemporaryDirectory(prefix="arena-api-report-") as temporary:
        target = Path(temporary) / database.name
        shutil.copy2(database, target)
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = database.with_name(database.name + suffix)
            if sidecar.is_file():
                shutil.copy2(sidecar, target.with_name(target.name + suffix))
        yield target


def _columns(connection: sqlite3.Connection) -> list[str]:
    return [
        str(row[1])
        for row in connection.execute("PRAGMA table_info(moz_cookies)").fetchall()
    ]


def _journal_mode(connection: sqlite3.Connection) -> str:
    try:
        row = connection.execute("PRAGMA journal_mode").fetchone()
    except sqlite3.DatabaseError:
        return "unknown"
    return str(row[0]) if row else "unknown"


def _database_overview(database: Path) -> dict[str, Any]:
    """Size, journal mode, row count and schema of one cookie database."""
    overview: dict[str, Any] = {
        "path": str(database),
        "exists": database.is_file(),
        "size": 0,
        "wal_size": 0,
        "modified": None,
        "journal_mode": None,
        "rows": 0,
        "columns": [],
        "error": None,
    }
    if not database.is_file():
        return overview
    try:
        stat = database.stat()
        overview["size"] = stat.st_size
        mtime = stat.st_mtime
        wal = database.with_name(database.name + "-wal")
        if wal.is_file():
            wal_stat = wal.stat()
            overview["wal_size"] = wal_stat.st_size
            mtime = max(mtime, wal_stat.st_mtime)
        overview["modified"] = (
            _utc_from_epoch(mtime).isoformat().replace("+00:00", "Z")
        )
    except OSError as exc:  # pragma: no cover - permission edge
        overview["error"] = f"{type(exc).__name__}: {exc}"
        return overview
    try:
        with _snapshot(database) as snapshot:
            connection = sqlite3.connect(str(snapshot))
            try:
                connection.row_factory = sqlite3.Row
                overview["journal_mode"] = _journal_mode(connection)
                overview["columns"] = _columns(connection)
                overview["rows"] = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM moz_cookies"
                    ).fetchone()[0]
                )
            finally:
                connection.close()
    except (sqlite3.DatabaseError, OSError) as exc:
        overview["error"] = f"{type(exc).__name__}: {exc}"
    return overview


def _raw_rows(database: Path) -> list[sqlite3.Row]:
    """Every row of the cookie store, whatever columns this version has."""
    with _snapshot(database) as snapshot:
        connection = sqlite3.connect(str(snapshot))
        try:
            connection.row_factory = sqlite3.Row
            available = set(_columns(connection))
            wanted = [
                "host",
                "name",
                "value",
                "path",
                "expiry",
                "isSecure",
                "isHttpOnly",
                "sameSite",
                "originAttributes",
            ]
            selected = [column for column in wanted if column in available]
            rows = connection.execute(
                "SELECT " + ", ".join(selected) + " FROM moz_cookies"
            ).fetchall()
            return list(rows)
        finally:
            connection.close()


def _row(record: Any, key: str, default: Any = None) -> Any:
    """Read one column of a :class:`sqlite3.Row` or mapping."""
    if isinstance(record, Mapping):
        return record.get(key, default)
    return record[key] if key in record.keys() else default


def _fingerprints(
    database: Path, targets: Sequence[str]
) -> tuple[
    list[CookieFingerprint], int, list[str], list[str], int, str | None, int
]:
    """Fingerprints for the matching cookies, plus what else is worth knowing.

    Reads both ``cookies.sqlite`` (persistent cookies) and Firefox's
    ``sessionstore`` (``recovery.jsonlz4`` / ``sessionstore.jsonlz4`` /
    ``sessionstore.js`` -- session cookies without ``Expires``/``Max-Age``).
    Returns ``(matching, expired_matching, other_hosts, subdomain_hosts,
    total_rows, sessionstore_source, sessionstore_matching)``.
    ``subdomain_hosts`` matters because a cookie stored for ``beta.arena.ai``
    is *not* sent to ``arena.ai`` by any browser: if the whole session lives
    there, the base URL is the thing to change, not the reader.
    """
    matching: list[CookieFingerprint] = []
    expired = 0
    others: set[str] = set()
    subdomains: set[str] = set()
    sqlite_rows: list[Any] = _raw_rows(database) if database.is_file() else []
    sessionstore_source, sessionstore_rows = _sessionstore_cookie_rows(
        database.parent
    )
    seen_keys: set[tuple[str, str, str, str]] = set()
    sessionstore_matching = 0
    now = time.time()

    for from_sessionstore, batch in (
        (False, sqlite_rows),
        (True, sessionstore_rows),
    ):
        for row in batch:
            host = str(_row(row, "host", "") or "")
            name = str(_row(row, "name", "") or "")
            value = _row(row, "value", "") or ""
            path = str(_row(row, "path", "/") or "/")
            container = str(_row(row, "originAttributes", "") or "")
            if not _domain_matches(host, targets):
                if "arena" in host.lower():
                    others.add(host)
                continue
            key = (host, name, path, container)
            if key in seen_keys:
                continue
            host_only = host.lstrip(".").lower()
            if any(
                host_only != str(target).lstrip(".").lower()
                and host_only.endswith("." + str(target).lstrip(".").lower())
                for target in targets
            ):
                subdomains.add(host)
            moment = _expiry_seconds(_row(row, "expiry"))
            if moment is not None and moment < now:
                expired += 1
                continue
            seen_keys.add(key)
            if from_sessionstore:
                sessionstore_matching += 1
            length, digest, shape = _fingerprint_value(str(value))
            same_site = _row(row, "sameSite", 0)
            matching.append(
                CookieFingerprint(
                    host=host,
                    name=name,
                    path=path,
                    expires=int(moment) if moment is not None else 0,
                    secure=bool(_row(row, "isSecure", 0)),
                    http_only=bool(_row(row, "isHttpOnly", 0)),
                    same_site=_SAME_SITE.get(
                        int(same_site) if isinstance(same_site, int) else 0,
                        "unset",
                    ),
                    container=container,
                    value_length=length,
                    value_sha256=digest,
                    shape=shape,
                    looks_like_auth=_looks_like_auth(name),
                )
            )
    matching.sort(key=lambda item: (not item.looks_like_auth, item.name))
    return (
        matching,
        expired,
        sorted(others),
        sorted(subdomains),
        len(sqlite_rows),
        sessionstore_source,
        sessionstore_matching,
    )


# --------------------------------------------------------------------------- #
# The report
# --------------------------------------------------------------------------- #


def _version() -> str:
    try:
        from importlib.metadata import PackageNotFoundError, version
    except ImportError:  # pragma: no cover - Python 3.10+
        return "unknown"
    for name in ("arena-api", "arena_api"):
        try:
            return version(name)
        except PackageNotFoundError:
            continue
        except Exception:  # pragma: no cover - defensive
            break
    return "unknown"


def _rookiepy_state() -> str:
    """Whether the optional accelerator is importable (it reads only defaults)."""
    try:
        importlib.import_module("rookiepy")
    except ImportError:
        return "not installed"
    except Exception as exc:  # pragma: no cover - broken install
        return f"import failed ({type(exc).__name__})"
    return "installed"


def _pkg_version(dist_name: str) -> str | None:
    try:
        from importlib.metadata import PackageNotFoundError, version

        return version(dist_name)
    except (ImportError, PackageNotFoundError):
        return None
    except Exception:  # pragma: no cover - defensive
        return None


def _impersonation_state() -> str:
    """Whether browser TLS fingerprint impersonation is available."""
    has_curl = importlib.util.find_spec("curl_cffi") is not None
    has_transport = importlib.util.find_spec("httpx_curl_cffi") is not None
    if has_curl and has_transport:
        curl_ver = _pkg_version("curl-cffi") or _pkg_version("curl_cffi")
        tr_ver = _pkg_version("httpx-curl-cffi") or _pkg_version("httpx_curl_cffi")
        curl_label = f"curl_cffi {curl_ver}" if curl_ver else "curl_cffi"
        tr_label = (
            f"httpx_curl_cffi {tr_ver}" if tr_ver else "httpx_curl_cffi"
        )
        return f"installed ({curl_label} + {tr_label})"
    return 'not installed (pip install -e ".[impersonate]")'


def collect_firefox_report(
    *,
    domains: Sequence[str] | None = None,
    profiles_root: str | Path | None = None,
    profile_name: str | None = None,
    cookie_database: str | Path | None = None,
) -> dict[str, Any]:
    """Gather a redacted description of what the reader can see.

    The structure is stable enough to paste into an issue: ``profiles`` holds one
    entry per profile considered (with its cookie fingerprints), ``selected``
    says which one discovery would use and why, and ``warnings`` spells out the
    likely causes when nothing was found.
    """
    targets = tuple(domains) if domains else DEFAULT_COOKIE_DOMAINS
    notes = io.StringIO()
    manager = FirefoxSessionManager(
        domains=targets,
        profiles_root=profiles_root,
        profile_name=profile_name,
        cookie_database=cookie_database,
        interactive=False,
        output=notes,
    )
    roots = manager.profiles_roots()
    report: dict[str, Any] = {
        "generated_at": datetime.now(tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "arena_api": _version(),
        "python": sys.version.split()[0],
        "system": {
            "platform": sys.platform,
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "domains": list(targets),
        "environment": {
            name: "set" for name in _REPORTED_ENV if os.environ.get(name, "").strip()
        },
        "rookiepy": _rookiepy_state(),
        "impersonation": _impersonation_state(),
        "roots": [
            {
                "path": str(root),
                "exists": root.is_dir(),
                "profiles_ini": (root / "profiles.ini").is_file(),
            }
            for root in roots
        ],
        "profiles": [],
        "selected": {"profile": None, "reason": None, "error": None},
        "cookies": {"count": 0, "names": [], "values": "hidden", "error": None},
        "warnings": [],
    }

    candidates: list[Path] = []
    if cookie_database is not None:
        database = Path(cookie_database).expanduser()
        candidates = [database.parent]
    else:
        try:
            candidates = manager.profile_candidates()
        except FirefoxSessionError as exc:
            report["selected"]["error"] = str(exc)
    if len(candidates) > 8:
        report["warnings"].append(
            f"only the first 8 of {len(candidates)} profiles are detailed"
        )
    for profile in candidates[:8]:
        database = (
            Path(cookie_database).expanduser()
            if cookie_database is not None
            else profile / "cookies.sqlite"
        )
        entry: dict[str, Any] = {
            "profile": str(profile),
            "cookies_sqlite": _database_overview(database),
            "sessionstore": {"source": None, "matching": 0},
            "matching": 0,
            "expired_matching": 0,
            "other_arena_hosts": [],
            "subdomain_hosts": [],
            "cookies": [],
        }
        try:
            (
                matching,
                expired,
                others,
                subdomains,
                _,
                sessionstore_source,
                sessionstore_matching,
            ) = _fingerprints(database, targets)
        except (sqlite3.DatabaseError, OSError) as exc:
            entry["error"] = f"{type(exc).__name__}: {exc}"
        else:
            entry["sessionstore"] = {
                "source": sessionstore_source,
                "matching": sessionstore_matching,
            }
            entry["matching"] = len(matching)
            entry["expired_matching"] = expired
            entry["other_arena_hosts"] = others
            entry["subdomain_hosts"] = subdomains
            entry["cookies"] = [
                item.as_dict() for item in matching[:MAX_REPORTED_COOKIES]
            ]
            if len(matching) > MAX_REPORTED_COOKIES:
                entry["omitted"] = len(matching) - MAX_REPORTED_COOKIES
            if database.is_file() or sessionstore_source is not None:
                report["warnings"].extend(
                    _profile_warnings(
                        profile, matching, expired, others, subdomains, targets
                    )
                )
        report["profiles"].append(entry)

    try:
        selected = manager.profile_path()
    except FirefoxSessionError as exc:
        report["selected"]["error"] = str(exc)
    else:
        report["selected"]["profile"] = str(selected)
        report["selected"]["reason"] = manager.selection_reason()
        report["selected"]["user_agent"] = manager.user_agent()
        report["selected"]["accept_language"] = manager.accept_language()

    try:
        cookies = manager.load_cookies()
    except FirefoxSessionError as exc:
        report["cookies"]["error"] = str(exc)
    except Exception as exc:  # noqa: BLE001 - a report must never explode
        report["cookies"]["error"] = f"{type(exc).__name__}: {exc}"
    else:
        report["cookies"]["count"] = len(cookies)
        report["cookies"]["names"] = sorted(cookies)
        report["cookies"]["fingerprints"] = {
            name: _fingerprint_value(value)[1] for name, value in cookies.items()
        }

    captured = notes.getvalue().strip()
    if captured:
        report["notes"] = [
            line for line in captured.splitlines() if line.strip()
        ]
    report["warnings"].extend(_report_warnings(report, targets))
    # A warning can be produced by several profiles; keep it once.
    seen: set[str] = set()
    unique: list[str] = []
    for warning in report["warnings"]:
        if warning and warning not in seen:
            seen.add(warning)
            unique.append(warning)
    report["warnings"] = unique
    return report


def _profile_warnings(
    profile: Path,
    matching: Sequence[CookieFingerprint],
    expired: int,
    others: Sequence[str],
    subdomains: Sequence[str],
    targets: Sequence[str],
) -> list[str]:
    warnings: list[str] = []
    name = profile.name
    if expired and not any(item.looks_like_auth for item in matching):
        warnings.append(
            f"{name}: {expired} cookie(s) for {', '.join(targets)} are expired "
            "and were skipped -- the browser needs to renew the session"
        )
    if others:
        warnings.append(
            f"{name}: cookies exist for other Arena hosts ({', '.join(others)}) "
            f"but not for {', '.join(targets)} -- is the site served from a "
            "different domain? use --base-url to match it"
        )
    if subdomains:
        readable = subdomains[0].lstrip(".")
        warnings.append(
            f"{name}: cookies are stored for the subdomain {', '.join(subdomains)}; "
            f"a browser would not send them to {', '.join(targets)}. If the site "
            f"is served from there, pass --base-url https://{readable}"
        )
    if matching and not any(item.looks_like_auth for item in matching):
        warnings.append(
            f"{name}: {len(matching)} cookie(s) match, but none of their names "
            "looks like a session token -- the sign-in may have expired"
        )
    empty = [item.name for item in matching if item.shape == "empty"]
    if empty:
        warnings.append(
            f"{name}: cookie(s) with an empty value: {', '.join(sorted(set(empty)))}"
        )
    return warnings


def _report_warnings(
    report: Mapping[str, Any], targets: Sequence[str]
) -> list[str]:
    warnings: list[str] = []
    roots = list(report.get("roots") or [])
    if roots and not any(root.get("exists") for root in roots):
        warnings.append(
            "no Firefox profiles directory exists: looked in "
            + ", ".join(str(root["path"]) for root in roots)
        )
    profiles = list(report.get("profiles") or [])
    if profiles and not any(entry.get("matching") for entry in profiles):
        warnings.append(
            f"none of the {len(profiles)} profile(s) holds a cookie for "
            f"{', '.join(targets)}"
        )
        hosts = sorted(
            {
                host
                for entry in profiles
                for host in entry.get("other_arena_hosts") or []
            }
        )
        if hosts:
            warnings.append(
                "closest hosts seen in those profiles: " + ", ".join(hosts)
            )
    cookies = report.get("cookies") or {}
    if cookies.get("error"):
        warnings.append(f"reading the session failed: {cookies['error']}")
    return warnings


def format_firefox_report(report: Mapping[str, Any]) -> list[str]:
    """Render :func:`collect_firefox_report` as readable lines."""
    lines: list[str] = []

    def line(label: str, value: Any) -> None:
        lines.append(f"{label:<20}: {value}")

    def section(title: str) -> None:
        lines.append("")
        lines.append(f"-- {title} " + "-" * max(0, 60 - len(title)))

    line("arena-api", report.get("arena_api", "unknown"))
    system = report.get("system") or {}
    line(
        "system",
        f"{system.get('platform', '?')} {system.get('release', '')} "
        f"({system.get('machine', '?')}), python {report.get('python', '?')}",
    )
    line("cookie domains", ", ".join(report.get("domains") or []))
    line("rookiepy", report.get("rookiepy", "unknown"))
    if "impersonation" in report:
        line("impersonation", report.get("impersonation"))
    environment = report.get("environment") or {}
    line(
        "env overrides",
        ", ".join(sorted(environment)) if environment else "none",
    )

    section("profiles")
    roots = report.get("roots") or []
    line("roots searched", len(roots))
    for root in roots:
        flags = []
        if root.get("exists"):
            flags.append("exists")
        if root.get("profiles_ini"):
            flags.append("profiles.ini")
        line("  root", f"{root.get('path')} [{' '.join(flags) or 'missing'}]")

    profiles = report.get("profiles") or []
    selected = (report.get("selected") or {}).get("profile")
    for index, entry in enumerate(profiles, start=1):
        marker = " (selected)" if str(entry.get("profile")) == str(selected) else ""
        line(f"profile {index}", f"{entry.get('profile')}{marker}")
        database = entry.get("cookies_sqlite") or {}
        sessionstore = entry.get("sessionstore") or {}
        if not database.get("exists"):
            line("  cookies.sqlite", "missing")
            if not sessionstore.get("source"):
                continue
        else:
            wal_note = (
                f" (+{database['wal_size']} bytes wal)"
                if database.get("wal_size")
                else ""
            )
            line(
                "  cookies.sqlite",
                f"{database.get('size', 0)} bytes{wal_note}, "
                f"journal {database.get('journal_mode')}, "
                f"{database.get('rows', 0)} row(s), "
                f"modified {database.get('modified')}",
            )
            if database.get("error"):
                line("  read error", database["error"])
        if sessionstore.get("matching"):
            line(
                "  sessionstore",
                f"{sessionstore.get('source')} "
                f"({sessionstore.get('matching')} session cookie(s))",
            )
        line(
            "  matching cookies",
            f"{entry.get('matching', 0)} "
            f"({entry.get('expired_matching', 0)} expired skipped)",
        )
        for cookie in entry.get("cookies") or []:
            lines.append(
                "    "
                + f"{'*' if cookie.get('looks_like_auth') else ' '} "
                + f"{cookie.get('host', ''):<22} {cookie.get('name', ''):<24} "
                + f"len={cookie.get('value_length', 0):<5} "
                + f"sha256={cookie.get('value_sha256') or '--------'} "
                + f"expiry={cookie.get('expires')} "
                + f"{'secure' if cookie.get('secure') else 'plain'}"
                + f"{' httpOnly' if cookie.get('http_only') else ''}"
            )
        if entry.get("omitted"):
            lines.append(f"    ... and {entry['omitted']} more")
        if entry.get("other_arena_hosts"):
            line("  other hosts", ", ".join(entry["other_arena_hosts"]))
        if entry.get("subdomain_hosts"):
            line("  subdomain hosts", ", ".join(entry["subdomain_hosts"]))

    section("session the library would use")
    selected_info = report.get("selected") or {}
    line("profile", selected or "-")
    line("selection", selected_info.get("reason") or "-")
    if selected_info.get("user_agent"):
        line("user-agent", selected_info.get("user_agent"))
    if selected_info.get("accept_language"):
        line("accept-language", selected_info.get("accept_language"))
    cookies = report.get("cookies") or {}
    if cookies.get("error"):
        line("cookies", f"ERROR {cookies['error']}")
    else:
        line(
            "cookies",
            f"{cookies.get('count', 0)} name(s): "
            + (", ".join(cookies.get("names") or []) or "-"),
        )
        line("values", "always hidden (a cookie is a credential)")

    notes = report.get("notes") or []
    if notes:
        section("notes")
        lines.extend(f"  {note}" for note in notes)

    section("warnings")
    warnings = report.get("warnings") or []
    if warnings:
        lines.extend(f"  ! {warning}" for warning in warnings)
    else:
        lines.append("  none -- the session was found and read")
    return lines


def report_as_json(report: Mapping[str, Any]) -> str:
    """Serialize a report for a machine-readable paste."""
    return json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True)


def report_for_options(options: Any) -> dict[str, Any]:
    """Collect a report from an :class:`arena_api.auto.AutoOptions`.

    Kept here rather than in :mod:`arena_api.auto` so the CLI stays a thin
    wrapper and the report is usable from a script of your own.
    """
    return collect_firefox_report(
        domains=options.cookie_domains(),
        profiles_root=options.profiles_root,
        profile_name=options.profile_name,
        cookie_database=options.cookie_database,
    )

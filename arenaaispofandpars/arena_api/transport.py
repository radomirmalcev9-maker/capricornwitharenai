"""HTTP and incremental SSE primitives shared by both client variants.

Only credentials explicitly provided by the caller are used. Browser challenges
are reported as :class:`ChallengeRequiredError`. When a ``session_refresher``
hook is installed (see the ``session_source`` option of the clients), an
authentication failure first asks that hook for fresh cookies — e.g. after the
user re-verified in their browser — and transparently retries the request.

A browser session is more than its cookies: an anti-bot edge (Cloudflare, and
the ``cf_clearance`` cookie it hands out) also looks at the *dialect* the client
speaks — the TLS ClientHello and the HTTP/2 settings frame. ``httpx`` has
Python's dialect, so a session copied out of Firefox can be challenged even
though every cookie is correct. ``impersonate="firefox"`` swaps the wire for
``curl_cffi``'s, which reproduces that dialect; the httpx API, the SSE
machinery and the callers stay exactly as they are.
"""

from __future__ import annotations

import asyncio
import codecs
import hashlib
import importlib.util
import inspect
import json
import math
import os
import shutil
import ssl
import sys
import tempfile
import time
import urllib.request
from collections.abc import (
    AsyncIterator,
    Callable,
    Iterator,
    Mapping,
    Sequence,
)
from contextlib import (
    AbstractAsyncContextManager,
    AbstractContextManager,
    asynccontextmanager,
    contextmanager,
)
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, TypeAlias
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

from .constants import DEFAULT_HEADERS, DEFAULT_TIMEOUT
from .exceptions import (
    ArenaError,
    AuthenticationError,
    ChallengeRequiredError,
    ClientClosedError,
    ProtocolError,
    QueueTimeoutError,
    RateLimitError,
)

CookieInput: TypeAlias = (
    Mapping[str, Any] | str | Path | Sequence[Mapping[str, Any]] | None
)
#: ``None``/``"auto"`` auto-detects from ``ARENA_PROXY``, ``HTTPS_PROXY`` /
#: ``ALL_PROXY``, the OS proxy settings, or Firefox ``prefs.js``; ``False`` /
#: ``"off"`` forces a direct connection; any URL string uses that proxy.
ProxyInput: TypeAlias = str | bool | None
# Optional hook consulted when a request fails with an auth error (HTTP 401/403
# or a browser challenge). It returns fresh cookies to apply before retrying,
# or None to surface the original error to the caller.
SessionRefresher: TypeAlias = Callable[[ArenaError], Mapping[str, str] | None]

#: Environment variable taking precedence over generic HTTP(S)/system proxies.
ARENA_PROXY_ENV = "ARENA_PROXY"
_SUPPORTED_PROXY_SCHEMES = frozenset({"http", "https", "socks5", "socks5h"})
_CURL_ERROR_URL_SUFFIX = (
    " See https://curl.se/libcurl/c/libcurl-errors.html first for more details."
)


_CHALLENGE_MARKERS = (
    "cf-chl-",
    "__cf_chl_",
    "_cf_chl_opt",
    "cdn-cgi/challenge-platform/h/",
    "cf-turnstile",
    "captcha-delivery",
    "just a moment...",
    "cf-error-details",
)

#: HTTP status codes that anti-bot edges use for challenge screens; a plain
#: origin 404 (e.g. Next.js answering ``GET /config``) must not be mistaken for
#: a challenge just because Cloudflare appended its passive ``jsd`` beacon.
_CHALLENGE_STATUS_CODES = frozenset({401, 403, 429, 503})

#: How to get the optional curl_cffi transport. Named in the error message, so
#: a caller who asked for impersonation but never installed it gets one command
#: instead of a traceback from an import inside a constructor.
IMPERSONATE_EXTRA = "pip install 'arena-api[impersonate]'"

_IMPERSONATION_PACKAGES = ("curl_cffi", "httpx_curl_cffi")


def impersonation_available() -> bool:
    """Whether the curl_cffi transport can be built on this machine.

    Never imports anything: callers use it to decide *silently* whether the
    derived (``impersonate=None``) path is possible. An explicit
    ``impersonate=`` does not consult it -- it either works or explains itself.
    """
    return all(
        importlib.util.find_spec(name) is not None for name in _IMPERSONATION_PACKAGES
    )


def validate_impersonate(value: Any) -> str:
    """Coerce and check an ``impersonate`` value, with an actionable message."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            "impersonate must be a curl_cffi browser profile name such as "
            "'firefox', 'chrome' or 'firefox133'"
        )
    return value.strip()


def normalize_proxy(proxy: ProxyInput) -> str | bool | None:
    """Normalize a ``proxy=`` setting into ``None`` (auto), ``False`` (off), or a URL.

    Windows ``Internet Settings`` registry entries returned by
    :func:`urllib.request.getproxies` label unprefixed SOCKS proxies as
    ``socks4://``, which modern local proxy clients implement as SOCKS5 and
    which ``httpx.Proxy`` rejects unless upgraded to ``socks5://``.
    """
    if proxy is None or proxy is True:
        return None
    if proxy is False:
        return False
    if not isinstance(proxy, str):
        raise ValueError(
            "proxy must be a URL string (e.g. 'http://127.0.0.1:2080' or "
            "'socks5h://127.0.0.1:1080'), False/'off', or None"
        )
    text = proxy.strip()
    lowered = text.lower()
    if lowered in ("", "auto"):
        return None
    if lowered in ("off", "false", "none", "direct"):
        return False
    if "://" not in text:
        text = f"http://{text}"
        lowered = text.lower()
    for legacy_prefix in ("socks4a://", "socks4://", "socks://"):
        if lowered.startswith(legacy_prefix):
            scheme_replacement = (
                "socks5h://" if legacy_prefix == "socks4a://" else "socks5://"
            )
            text = scheme_replacement + text[len(legacy_prefix) :]
            break
    parsed = urlparse(text)
    scheme = parsed.scheme.lower()
    if scheme not in _SUPPORTED_PROXY_SCHEMES or not parsed.netloc:
        raise ValueError(
            f"Unsupported proxy URL {proxy!r}; expected http://, https://, "
            "socks5:// or socks5h://"
        )
    return urlunparse(parsed._replace(scheme=scheme))


def _is_loopback_host(host: str) -> bool:
    cleaned = host.strip().strip("[]").lower()
    return (
        cleaned in ("localhost", "::1")
        or cleaned.startswith("127.")
        or cleaned.endswith(".localhost")
    )


def _proxy_bypassed(host: str, port: int | None) -> bool:
    try:
        if urllib.request.proxy_bypass(host):
            return True
        if port is not None and urllib.request.proxy_bypass(f"{host}:{port}"):
            return True
    except Exception:  # noqa: BLE001 - malformed NO_PROXY or registry entries
        return False
    return False


def resolve_proxy_url(
    base_url: str,
    proxy: ProxyInput = None,
    *,
    fallback_proxy: str | None = None,
) -> str | None:
    """Resolve the effective proxy URL for ``base_url``, or ``None`` for direct.

    Precedence when ``proxy`` is ``None`` (auto):

    1. ``ARENA_PROXY`` environment variable (``off``/``direct`` disables all proxies);
    2. ``HTTPS_PROXY`` / ``HTTP_PROXY`` / ``ALL_PROXY`` and OS system proxy
       settings via :func:`urllib.request.getproxies` (including Windows
       ``Internet Settings``), honouring ``NO_PROXY`` and skipping loopback;
    3. ``fallback_proxy`` (e.g. manual proxy settings from Firefox ``prefs.js``).
    """
    choice = normalize_proxy(proxy)
    if choice is False:
        return None
    if isinstance(choice, str):
        return choice

    env_raw = os.environ.get(ARENA_PROXY_ENV)
    env_choice = normalize_proxy(env_raw) if env_raw is not None else None
    if env_choice is False:
        return None

    parsed = urlparse(base_url)
    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "").lower()
    if not host or _is_loopback_host(host):
        return None
    if isinstance(env_choice, str):
        return env_choice
    if _proxy_bypassed(host, parsed.port):
        return None

    try:
        system_proxies = urllib.request.getproxies()
    except Exception:  # noqa: BLE001 - defensive on broken OS proxy stores
        system_proxies = {}
    candidate = (
        system_proxies.get(scheme)
        or system_proxies.get("all")
        or (system_proxies.get("http") if scheme == "https" else None)
    )
    if candidate:
        try:
            normalized = normalize_proxy(candidate)
        except ValueError:
            normalized = None
        if isinstance(normalized, str):
            return normalized

    if fallback_proxy:
        try:
            normalized_fb = normalize_proxy(fallback_proxy)
        except ValueError:
            normalized_fb = None
        if isinstance(normalized_fb, str):
            return normalized_fb
    return None


def redact_proxy_url(proxy_url: str | None) -> str:
    """Format a proxy URL for logs/diagnostics with credentials removed."""
    if not proxy_url:
        return "direct"
    parsed = urlparse(proxy_url)
    if parsed.username is None and parsed.password is None:
        return proxy_url
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = f"***@{host}" + (f":{parsed.port}" if parsed.port else "")
    return urlunparse(parsed._replace(netloc=netloc))


def _httpx_supports_proxy(proxy_url: str) -> bool:
    scheme = urlparse(proxy_url).scheme.lower()
    if scheme in ("http", "https"):
        return True
    return importlib.util.find_spec("socksio") is not None


def _env_proxies_supported_by_httpx() -> bool:
    for key in (
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ):
        raw = os.environ.get(key, "").strip()
        if raw and not _httpx_supports_proxy(raw if "://" in raw else f"http://{raw}"):
            return False
    return True


def _windows_short_ascii_path(path: str) -> str | None:
    """Return the Windows 8.3 short path when it is pure ASCII and exists."""
    try:
        import ctypes

        windll = getattr(ctypes, "windll", None)
        if windll is None:
            return None
        get_short = windll.kernel32.GetShortPathNameW
        needed = int(get_short(path, None, 0))
        if needed <= 0:
            return None
        buf = ctypes.create_unicode_buffer(needed + 1)
        written = int(get_short(path, buf, needed + 1))
        if written <= 0:
            return None
        short = buf.value
        if short and short.isascii() and os.path.isfile(short):
            return short
    except Exception:  # noqa: BLE001 - non-Windows or restricted API
        return None
    return None


def _windows_ascii_ca_bundle(ca_path: str) -> str | None:
    """Ensure libcurl receives an ASCII-only CA bundle path on Windows.

    ``curl_cffi`` encodes ``CURLOPT_CAINFO`` with ``locale.getpreferredencoding``
    while BoringSSL opens the file with narrow C ``fopen()``; when a Windows
    account directory contains non-ASCII characters (e.g. Cyrillic) and UTF-8
    mode or a mismatched codepage is active, TLS handshakes fail with
    ``CURLE_SSL_CACERT_BADFILE`` / ``ConnectError``.
    """
    if ca_path.isascii() or not os.path.isfile(ca_path):
        return ca_path if ca_path.isascii() else None
    short = _windows_short_ascii_path(ca_path)
    if short:
        return short
    digest = hashlib.sha256(ca_path.encode("utf-8", "replace")).hexdigest()[:12]
    filename = f"arena-api-cacert-{digest}.pem"
    candidate_dirs = [
        tempfile.gettempdir(),
        os.environ.get("PUBLIC", ""),
        str(Path(ca_path).anchor) + "Temp" if Path(ca_path).anchor else "",
    ]
    try:
        source_size = os.path.getsize(ca_path)
    except OSError:
        return None
    for raw_dir in candidate_dirs:
        if not raw_dir or not raw_dir.isascii():
            continue
        target_dir = Path(raw_dir)
        if not target_dir.is_dir():
            continue
        target = target_dir / filename
        try:
            if not target.is_file() or target.stat().st_size != source_size:
                shutil.copyfile(ca_path, target)
            return str(target)
        except OSError:
            continue
    return None


def _adapt_verify(verify: bool | str) -> bool | str:
    """Translate httpx's ``verify=`` into what curl accepts.

    ``httpx`` also allows an ``ssl.SSLContext``; curl has its own TLS stack and
    cannot take one, so that combination fails loudly instead of quietly
    verifying against the system store.
    """
    if isinstance(verify, ssl.SSLContext):
        raise ArenaError(
            "impersonate= uses curl's own TLS stack, which cannot take an "
            "ssl.SSLContext; pass the CA bundle path as verify='path/to/ca.pem'"
        )
    if isinstance(verify, Path):  # pragma: no cover - defensive, httpx types say str
        verify = str(verify)
    if not isinstance(verify, (bool, str)):
        raise ArenaError(
            f"verify must be a bool or a CA bundle path when impersonating, got "
            f"{type(verify).__name__}"
        )
    if sys.platform.startswith("win"):
        if isinstance(verify, str) and not verify.isascii():
            staged = _windows_ascii_ca_bundle(verify)
            if staged:
                return staged
        elif verify is True:
            try:
                import certifi

                ca_file = certifi.where()
            except Exception:  # noqa: BLE001
                ca_file = ""
            if ca_file and not ca_file.isascii():
                staged = _windows_ascii_ca_bundle(ca_file)
                if staged:
                    return staged
    return verify


def build_impersonation_transport(
    impersonate: str,
    *,
    verify: bool | str = True,
    proxy: ProxyInput = None,
    asynchronous: bool = False,
) -> Any:
    """Return a curl_cffi-backed ``httpx`` transport for one browser profile.

    :param impersonate: curl_cffi profile, e.g. ``"firefox"`` (the newest
        supported Firefox), ``"firefox147"`` (an exact build) or ``"chrome"``.
    :param verify: TLS verification, following ``httpx.Client(verify=...)``.
    :param proxy: proxy URL, ``False``/``"off"`` for direct, or ``None`` (auto).
    :param asynchronous: build the ``AsyncCurlTransport`` instead of the sync one.
    :raises ArenaError: the optional dependency is not installed.
    """
    profile = validate_impersonate(impersonate)
    proxy_choice = normalize_proxy(proxy)
    try:
        from httpx_curl_cffi import AsyncCurlTransport, CurlTransport
    except ImportError as exc:  # pragma: no cover - dependency path
        raise ArenaError(
            f"impersonate={profile!r} needs the optional curl_cffi transport, "
            f"which is not installed ({IMPERSONATE_EXTRA}, or drop impersonate= "
            "to send the request with httpx's own TLS fingerprint)"
        ) from exc
    options: dict[str, Any] = {"impersonate": profile, "verify": _adapt_verify(verify)}
    if isinstance(proxy_choice, str):
        options["proxy"] = proxy_choice
    transport = (
        AsyncCurlTransport(**options) if asynchronous else CurlTransport(**options)
    )
    # ``httpx_curl_cffi`` hardcodes ``trust_env=False`` on its internal
    # ``curl_cffi`` session; since ``curl-cffi 0.17.0``, ``trust_env=False``
    # actively sets ``CURLOPT_PROXY=""`` and disables ``HTTPS_PROXY`` /
    # ``ALL_PROXY`` unless re-enabled or given an explicit ``proxy=``.
    if proxy_choice is not False and "proxy" not in options:
        session = getattr(transport, "_session", None)
        if session is not None and hasattr(session, "trust_env"):
            session.trust_env = True
    return transport


def parse_cookie_header(value: str) -> dict[str, str]:
    """Parse a DevTools ``Cookie`` request header.

    Cookie values are split at the first equals sign only, so values containing
    ``=`` (common in signed session cookies) are preserved.
    """
    result: dict[str, str] = {}
    for piece in value.split(";"):
        key, separator, cookie_value = piece.strip().partition("=")
        if key and separator:
            result[key] = cookie_value.strip()
    return result


def _cookies_from_json_value(value: Any) -> dict[str, str]:
    if isinstance(value, Mapping):
        nested = value.get("cookies")
        if isinstance(nested, (list, tuple)):
            return _cookies_from_json_value(nested)
        browser_cookie = value.get("cookie")
        if isinstance(browser_cookie, str):
            return parse_cookie_header(browser_cookie)
        if "name" in value and "value" in value:
            return {str(value["name"]): str(value["value"])}
        return {str(key): str(item) for key, item in value.items() if item is not None}
    if isinstance(value, (list, tuple)):
        result: dict[str, str] = {}
        for item in value:
            if (
                not isinstance(item, Mapping)
                or "name" not in item
                or "value" not in item
            ):
                continue
            result[str(item["name"])] = str(item["value"])
        return result
    raise ValueError("cookies.json must contain an object or a cookie array")


def normalize_cookies(cookies: CookieInput) -> dict[str, str]:
    """Normalize a cookie mapping, Cookie header, or JSON export.

    Supported forms include ``{"session": "..."}``, a DevTools request
    header (``"session=...; cf_clearance=..."``), a path to a JSON export, a
    browser export with a top-level ``cookie`` field, and the standard
    ``[{"name": ..., "value": ...}]`` cookie array.
    """
    if cookies is None:
        return {}
    if isinstance(cookies, Path):
        path = cookies.expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"Cookie file not found: {path}")
        try:
            return _cookies_from_json_value(
                json.loads(path.read_text(encoding="utf-8"))
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(
                "Cookie file must contain a JSON cookie array or object"
            ) from exc
    if isinstance(cookies, str):
        path = Path(cookies).expanduser()
        if path.is_file():
            return normalize_cookies(path)
        if "=" not in cookies and path.suffix.lower() == ".json":
            raise FileNotFoundError(f"Cookie file not found: {path}")
        return parse_cookie_header(cookies)
    return _cookies_from_json_value(cookies)


def _header_value(headers: Mapping[str, Any] | None, name: str) -> str:
    if not headers:
        return ""
    target = name.lower()
    for key, value in headers.items():
        if str(key).lower() == target:
            return str(value)
    return ""


def _looks_like_challenge(body: str, headers: Mapping[str, Any] | None = None) -> bool:
    if _header_value(headers, "cf-mitigated").lower() == "challenge":
        return True
    lowered = body.lower()
    return any(marker in lowered for marker in _CHALLENGE_MARKERS)


def _retry_after(headers: Mapping[str, Any] | None) -> float | None:
    value = _header_value(headers, "retry-after").strip()
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return max(0.0, (parsed - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return None


_VERIFICATION_REJECTION_MARKERS: tuple[str, ...] = (
    "recaptcha",
    "turnstile",
    "captcha",
    "botid",
    "verification token",
    "human verification",
)


def _extract_error_detail(body: str) -> str:
    """Extract a concise, single-line diagnostic summary from a non-HTML error body."""
    stripped = (body or "").strip()
    if not stripped or stripped.startswith("<"):
        return ""
    text = stripped
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, Mapping):
            for key in ("error", "message", "detail", "reason"):
                val = parsed.get(key)
                if isinstance(val, str) and val.strip():
                    text = val.strip()
                    break
                if isinstance(val, Mapping):
                    nested = val.get("message") or val.get("detail") or val.get("code")
                    if isinstance(nested, str) and nested.strip():
                        text = nested.strip()
                        break
    collapsed = " ".join(text.split())
    if len(collapsed) > 240:
        return collapsed[:237] + "..."
    return collapsed


def _is_verification_rejection(body: str) -> bool:
    """Return True when a 401/403 body indicates bot/reCAPTCHA token rejection rather than stale cookies."""
    stripped = (body or "").strip()
    if not stripped or stripped.startswith("<"):
        return False
    lowered = stripped.lower()
    return any(marker in lowered for marker in _VERIFICATION_REJECTION_MARKERS)


def _raise_for_status(
    status: int,
    body: str = "",
    headers: Mapping[str, Any] | None = None,
) -> None:
    """Map HTTP status codes to the public exception hierarchy."""
    if 300 <= status < 400:
        raise ProtocolError(
            f"Arena redirected the request (HTTP {status}); set base_url to the canonical frontend URL."
        )
    if status < 400:
        return
    mitigated = _header_value(headers, "cf-mitigated").lower() == "challenge"
    if mitigated or (
        status in _CHALLENGE_STATUS_CODES and _looks_like_challenge(body, headers)
    ):
        raise ChallengeRequiredError(
            f"The service requested an interactive browser verification (HTTP {status}). "
            "Refresh or verify the session in a normal browser and retry."
        )
    detail = _extract_error_detail(body)
    suffix = f": {detail}" if detail else ""
    if status in (401, 403):
        if _is_verification_rejection(body):
            raise ProtocolError(
                f"Arena rejected the request verification token (HTTP {status}){suffix}."
            )
        raise AuthenticationError(
            f"The supplied session was rejected (HTTP {status}){suffix}."
        )
    if status == 429:
        raise RateLimitError(
            "Arena rate limit reached.", retry_after=_retry_after(headers)
        )
    raise ArenaError(f"Arena returned HTTP {status}{suffix}.")


def _raise_if_challenge_page(
    body: str, headers: Mapping[str, Any] | None = None
) -> None:
    """Detect challenge HTML served with a successful status code."""
    if _looks_like_challenge(body, headers):
        raise ChallengeRequiredError(
            "The service returned a browser verification page. "
            "Complete it in a normal browser and provide a refreshed session."
        )


def _normalize_base_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("base_url must be an absolute http:// or https:// URL")
    if parsed.query or parsed.fragment:
        raise ValueError("base_url must not contain a query string or fragment")
    return base_url.rstrip("/") + "/"


def _network_error(exc: httpx.RequestError, *, streaming: bool) -> ArenaError:
    if streaming and isinstance(exc, httpx.TimeoutException):
        return QueueTimeoutError("The Arena stream timed out before completing.")
    if isinstance(exc, httpx.TimeoutException):
        return ArenaError("The Arena HTTP request timed out.")
    raw = str(exc).strip()
    detail = raw.splitlines()[0].strip() if raw else ""
    if detail.endswith(_CURL_ERROR_URL_SUFFIX):
        detail = detail[: -len(_CURL_ERROR_URL_SUFFIX)].strip()
    if detail:
        return ArenaError(
            f"Arena network request failed ({type(exc).__name__}): {detail}"
        )
    return ArenaError(f"Arena network request failed ({type(exc).__name__}).")


def _merged_default_headers(
    headers: Mapping[str, str] | None,
) -> dict[str, str]:
    """Overlay caller headers on the defaults, case-insensitively.

    Without this, passing ``User-Agent`` alongside the default lowercase
    ``user-agent`` would make httpx send a comma-joined value.
    """
    merged = dict(DEFAULT_HEADERS)
    if headers:
        overridden = {str(key).lower() for key in headers}
        for key in list(merged):
            if str(key).lower() in overridden:
                del merged[key]
        merged.update(headers)
    return merged


def _impersonation_wire_headers(
    profile: str, base_url: str, headers: Mapping[str, str]
) -> dict[str, str]:
    """Add browser wire headers natively supported by ``curl_cffi`` / libcurl.

    ``httpx`` advertises ``Accept-Encoding: gzip, deflate`` unless Python brotli
    and zstd packages are installed, whereas libcurl inside ``curl_cffi`` decodes
    ``gzip, deflate, br, zstd`` natively and real Firefox/Chrome always send all
    four over HTTPS. Caller-supplied headers always win case-insensitively.
    """
    existing = {str(key).lower(): str(value) for key, value in headers.items()}
    defaults: dict[str, str] = {
        "Accept-Encoding": "gzip, deflate, br, zstd",
    }
    if existing.get("sec-fetch-site", "").lower() == "same-origin":
        defaults["Referer"] = base_url
    if profile.lower().startswith("firefox"):
        defaults["Te"] = "trailers"
        if existing.get("sec-fetch-mode", "").lower() == "navigate":
            defaults["Priority"] = "u=0, i"
        else:
            defaults["Priority"] = "u=4"
    result = dict(headers)
    for key, value in defaults.items():
        if key.lower() not in existing:
            result[key] = value
    return result


def _validate_max_auth_refreshes(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("max_auth_refreshes must be a non-negative integer")


class _SyncStream:
    """An already entered httpx stream context awaiting consumption."""

    __slots__ = ("_context", "response")

    def __init__(
        self,
        context: AbstractContextManager[httpx.Response],
        response: httpx.Response,
    ) -> None:
        self._context = context
        self.response = response

    def close(self) -> None:
        self._context.__exit__(None, None, None)


class _AsyncStream:
    """Async counterpart of :class:`_SyncStream`."""

    __slots__ = ("_context", "response")

    def __init__(
        self,
        context: AbstractAsyncContextManager[httpx.Response],
        response: httpx.Response,
    ) -> None:
        self._context = context
        self.response = response

    async def close(self) -> None:
        await self._context.__aexit__(None, None, None)


class SSEParser:
    """Incremental SSE decoder that tolerates arbitrary byte boundaries.

    Handles UTF-8 code points split across reads, LF/CRLF/CR delimiters,
    comments, multiple ``data:`` fields, and an unterminated final event.
    """

    def __init__(self) -> None:
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._buffer = ""
        self._event = "message"
        self._data: list[str] = []
        self._closed = False

    def feed(self, data: bytes | str) -> list[tuple[str, str]]:
        if self._closed:
            raise RuntimeError("cannot feed a closed SSEParser")
        if isinstance(data, bytes):
            self._buffer += self._decoder.decode(data, final=False)
        else:
            self._buffer += data
        return self._parse(final=False)

    def _parse(self, *, final: bool) -> list[tuple[str, str]]:
        events: list[tuple[str, str]] = []
        while self._buffer:
            line_end = len(self._buffer)
            delimiter_size = 0
            for delimiter in ("\r", "\n"):
                position = self._buffer.find(delimiter)
                if position >= 0 and position < line_end:
                    line_end = position
                    delimiter_size = 1
            if not delimiter_size:
                break
            # A CR at the end of a chunk may be the first half of CRLF.
            if (
                self._buffer[line_end] == "\r"
                and line_end + 1 == len(self._buffer)
                and not final
            ):
                break
            if self._buffer.startswith("\r\n", line_end):
                delimiter_size = 2
            line = self._buffer[:line_end]
            self._buffer = self._buffer[line_end + delimiter_size :]
            self._consume_line(line, events)
        if final and self._buffer:
            self._consume_line(self._buffer, events)
            self._buffer = ""
        return events

    def _consume_line(self, line: str, events: list[tuple[str, str]]) -> None:
        if not line:
            if self._data:
                events.append((self._event, "\n".join(self._data)))
            self._event, self._data = "message", []
            return
        if line.startswith(":"):
            return
        field, separator, value = line.partition(":")
        if not separator:
            value = ""
        elif value.startswith(" "):
            value = value[1:]
        if field == "event":
            self._event = value
        elif field == "data":
            self._data.append(value)
        # id/retry and unknown fields are intentionally ignored.

    def close(self) -> list[tuple[str, str]]:
        if self._closed:
            return []
        self._buffer += self._decoder.decode(b"", final=True)
        events = self._parse(final=True)
        if self._data:
            events.append((self._event, "\n".join(self._data)))
        self._event, self._data = "message", []
        self._closed = True
        return events


class ArenaTransport:
    """Synchronous HTTP/2-capable transport backed by ``httpx``.

    ``session_cookies`` holds the browser-session cookie set (it overlays
    ``cookies``); ``session_refresher`` is consulted on auth failures to
    refresh that set before a transparent retry.

    ``impersonate`` sends the request through curl_cffi with that browser's TLS
    and HTTP/2 fingerprint (see the module docstring); it needs the optional
    ``[impersonate]`` extra and is mutually exclusive with ``http_transport``.
    """

    #: curl_cffi profile in use, or ``None`` for httpx's own fingerprint.
    impersonate: str | None
    #: Resolved proxy URL in use, or ``None`` for a direct connection.
    proxy: str | None

    def __init__(
        self,
        base_url: str,
        *,
        cookies: CookieInput = None,
        session_cookies: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        http2: bool = True,
        verify: bool | str = True,
        proxy: ProxyInput = None,
        fallback_proxy: str | None = None,
        http_transport: httpx.BaseTransport | None = None,
        impersonate: str | None = None,
        session_refresher: SessionRefresher | None = None,
        max_auth_refreshes: int = 2,
    ) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite, positive number")
        _validate_max_auth_refreshes(max_auth_refreshes)
        if impersonate is not None and http_transport is not None:
            raise ValueError(
                "pass either http_transport= or impersonate=, not both: "
                "impersonation *is* a transport"
            )
        proxy_choice = normalize_proxy(proxy)
        self.base_url = _normalize_base_url(base_url)
        self.proxy = resolve_proxy_url(
            self.base_url, proxy, fallback_proxy=fallback_proxy
        )
        merged_headers = _merged_default_headers(headers)
        self._base_cookies = normalize_cookies(cookies)
        self._session_cookies: dict[str, str] = dict(session_cookies or {})
        self._session_refresher = session_refresher
        self._max_auth_refreshes = max_auth_refreshes
        self._custom_http_transport: bool = http_transport is not None
        self.impersonate = (
            validate_impersonate(impersonate) if impersonate is not None else None
        )
        if self.impersonate is not None:
            http_transport = build_impersonation_transport(
                self.impersonate,
                verify=verify,
                proxy=self.proxy if self.proxy is not None else False,
            )
            merged_headers = _impersonation_wire_headers(
                self.impersonate, self.base_url, merged_headers
            )
        client_kwargs: dict[str, Any] = {}
        if http_transport is not None:
            client_kwargs["trust_env"] = False
        else:
            if (
                proxy_choice is False
                or self.proxy is not None
                or _is_loopback_host(urlparse(self.base_url).hostname or "")
                or not _env_proxies_supported_by_httpx()
            ):
                client_kwargs["trust_env"] = False
            if self.proxy is not None and _httpx_supports_proxy(self.proxy):
                client_kwargs["proxy"] = self.proxy
        self.session = httpx.Client(
            headers=merged_headers,
            cookies=self._effective_cookies(),
            timeout=httpx.Timeout(timeout),
            http2=http2,
            verify=verify,
            follow_redirects=False,
            transport=http_transport,
            **client_kwargs,
        )
        self._closed = False

    def url(self, path: str) -> str:
        return urljoin(self.base_url, path.lstrip("/"))

    def _effective_cookies(self) -> dict[str, str]:
        """Caller-supplied cookies overlaid with the browser-session set."""
        merged = dict(self._base_cookies)
        merged.update(self._session_cookies)
        return merged

    def _apply_session_cookies(self, cookies: Mapping[str, str]) -> None:
        """Replace the browser-session set; cookies removed browser-side drop out."""
        self._session_cookies = dict(cookies)
        self.session.cookies = httpx.Cookies(self._effective_cookies())

    def apply_session_cookies(self, cookies: Mapping[str, str]) -> None:
        """Install a refreshed browser-session cookie set.

        The transport does this itself before replaying a request; callers that
        refresh a session *outside* a request (a bootstrap probe, a scheduled
        renewal) use this to bring the client up to date.
        """
        self._apply_session_cookies(cookies)

    def _refresh_after_auth_error(self, error: AuthenticationError) -> bool:
        """Ask the session source for fresh cookies; report whether to retry."""
        if self._session_refresher is None:
            return False
        fresh = self._session_refresher(error)
        if not isinstance(fresh, Mapping) or not fresh:
            return False
        self._apply_session_cookies(fresh)
        return True

    def _ensure_open(self) -> None:
        """Reject requests after :meth:`close` with a library-level error."""
        if self._closed:
            raise ClientClosedError(
                "this client has been closed; build a new one "
                "(leaving a `with` block closes it)"
            )

    def _send(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Perform one request attempt, mapping transport-level failures."""
        self._ensure_open()
        try:
            response = self.session.request(method, self.url(path), **kwargs)
        except httpx.RequestError as exc:
            raise _network_error(exc, streaming=False) from exc
        _check_sync_response(response)
        _raise_if_challenge_page(response.text, response.headers)
        return response

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        attempts = self._max_auth_refreshes + 1
        for attempt in range(attempts):
            try:
                return self._send(method, path, **kwargs)
            except AuthenticationError as error:
                if (
                    attempt + 1 >= attempts
                    or not self._refresh_after_auth_error(error)
                ):
                    raise
        raise AssertionError("retry loop must return or raise")  # pragma: no cover

    def get_json(self, path: str, **kwargs: Any) -> Any:
        response = self._request("GET", path, **kwargs)
        try:
            return response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            content_type = response.headers.get("content-type", "unknown")
            hint = (
                " This URL appears to be a web page rather than a JSON endpoint."
                if "html" in content_type.lower()
                else ""
            )
            raise ProtocolError(
                f"Expected JSON from {path} (HTTP {response.status_code}, content-type {content_type}).{hint}"
            ) from exc

    def get_text(self, path: str, **kwargs: Any) -> str:
        response = self._request("GET", path, **kwargs)
        return response.text

    def post_json(self, path: str, payload: Mapping[str, Any], **kwargs: Any) -> Any:
        response = self._request("POST", path, json=dict(payload), **kwargs)
        try:
            return response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise ProtocolError(f"Expected JSON from {path}.") from exc

    @contextmanager
    def stream_request(
        self,
        method: str,
        path: str,
        *,
        streaming_timeout: bool = True,
        **kwargs: Any,
    ) -> Iterator[httpx.Response]:
        stream: _SyncStream | None = None
        try:
            stream = self._acquire_stream(method, path, kwargs)
            yield stream.response
        except httpx.RequestError as exc:
            raise _network_error(exc, streaming=streaming_timeout) from exc
        finally:
            if stream is not None:
                stream.close()

    def _acquire_stream(
        self, method: str, path: str, kwargs: dict[str, Any]
    ) -> _SyncStream:
        """Open a stream response, refreshing the session on auth errors.

        Status and content-type validation happens before the response is
        yielded, so a 401/403 or a challenge page can still be retried with
        refreshed cookies without the consumer noticing.
        """
        self._ensure_open()
        request_kwargs = dict(kwargs)
        content_factory = request_kwargs.pop("content_factory", None)
        attempts = self._max_auth_refreshes + 1
        for attempt in range(attempts):
            attempt_kwargs = dict(request_kwargs)
            if callable(content_factory):
                attempt_kwargs["content"] = content_factory()
            context = self.session.stream(method, self.url(path), **attempt_kwargs)
            response = context.__enter__()
            try:
                _check_sync_response(response, streaming=True)
                content_type = response.headers.get("content-type", "").lower()
                if "text/html" in content_type:
                    body = response.read().decode("utf-8", "replace")
                    _raise_if_challenge_page(body, response.headers)
                    raise ProtocolError(
                        f"Expected a streaming response from {path}, received HTML."
                    )
            except AuthenticationError as error:
                context.__exit__(AuthenticationError, error, error.__traceback__)
                if (
                    attempt + 1 < attempts
                    and self._refresh_after_auth_error(error)
                ):
                    continue
                raise
            except BaseException as error:
                context.__exit__(type(error), error, error.__traceback__)
                raise
            return _SyncStream(context, response)
        raise AssertionError("retry loop must return or raise")  # pragma: no cover

    def sse(
        self,
        path: str,
        *,
        params: Mapping[str, Any],
        timeout: float,
    ) -> Iterator[tuple[str, Any]]:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite, positive number")
        parser = SSEParser()
        deadline = time.monotonic() + timeout
        with self.stream_request(
            "GET",
            path,
            params=dict(params),
            headers={"accept": "text/event-stream"},
            timeout=httpx.Timeout(timeout),
        ) as response:
            first_chunk = True
            for wire_chunk in response.iter_bytes():
                if time.monotonic() >= deadline:
                    raise QueueTimeoutError(
                        "Queue event stream exceeded its configured timeout."
                    )
                if first_chunk:
                    _check_stream_prefix(wire_chunk, response.headers, path)
                    first_chunk = False
                for event, data in parser.feed(wire_chunk):
                    yield event, self._decode_data(data)
            for event, data in parser.close():
                yield event, self._decode_data(data)

    @staticmethod
    def _decode_data(data: str) -> Any:
        if data.strip() == "[DONE]":
            return {"msg": "process_completed"}
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return data

    def close(self) -> None:
        if not self._closed:
            self.session.close()
            self._closed = True

    def __enter__(self) -> ArenaTransport:  # noqa: PYI034 - Self is not in typing until Python 3.11
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class AsyncArenaTransport:
    """Asynchronous HTTP/2-capable transport backed by ``httpx``.

    Accepts the same session refresh options as :class:`ArenaTransport`; the
    (potentially blocking, console-interactive) refresher runs in a worker
    thread so the event loop stays responsive.
    """

    #: curl_cffi profile in use, or ``None`` for httpx's own fingerprint.
    impersonate: str | None
    #: Resolved proxy URL in use, or ``None`` for a direct connection.
    proxy: str | None

    def __init__(
        self,
        base_url: str,
        *,
        cookies: CookieInput = None,
        session_cookies: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        http2: bool = True,
        verify: bool | str = True,
        proxy: ProxyInput = None,
        fallback_proxy: str | None = None,
        http_transport: httpx.AsyncBaseTransport | None = None,
        impersonate: str | None = None,
        session_refresher: SessionRefresher | None = None,
        max_auth_refreshes: int = 2,
    ) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite, positive number")
        _validate_max_auth_refreshes(max_auth_refreshes)
        if impersonate is not None and http_transport is not None:
            raise ValueError(
                "pass either http_transport= or impersonate=, not both: "
                "impersonation *is* a transport"
            )
        proxy_choice = normalize_proxy(proxy)
        self.base_url = _normalize_base_url(base_url)
        self.proxy = resolve_proxy_url(
            self.base_url, proxy, fallback_proxy=fallback_proxy
        )
        merged_headers = _merged_default_headers(headers)
        self._base_cookies = normalize_cookies(cookies)
        self._session_cookies: dict[str, str] = dict(session_cookies or {})
        self._session_refresher = session_refresher
        self._max_auth_refreshes = max_auth_refreshes
        self._custom_http_transport: bool = http_transport is not None
        self.impersonate = (
            validate_impersonate(impersonate) if impersonate is not None else None
        )
        if self.impersonate is not None:
            http_transport = build_impersonation_transport(
                self.impersonate,
                verify=verify,
                proxy=self.proxy if self.proxy is not None else False,
                asynchronous=True,
            )
            merged_headers = _impersonation_wire_headers(
                self.impersonate, self.base_url, merged_headers
            )
        client_kwargs: dict[str, Any] = {}
        if http_transport is not None:
            client_kwargs["trust_env"] = False
        else:
            if (
                proxy_choice is False
                or self.proxy is not None
                or _is_loopback_host(urlparse(self.base_url).hostname or "")
                or not _env_proxies_supported_by_httpx()
            ):
                client_kwargs["trust_env"] = False
            if self.proxy is not None and _httpx_supports_proxy(self.proxy):
                client_kwargs["proxy"] = self.proxy
        self.session = httpx.AsyncClient(
            headers=merged_headers,
            cookies=self._effective_cookies(),
            timeout=httpx.Timeout(timeout),
            http2=http2,
            verify=verify,
            follow_redirects=False,
            transport=http_transport,
            **client_kwargs,
        )
        self._closed = False

    def url(self, path: str) -> str:
        return urljoin(self.base_url, path.lstrip("/"))

    def _effective_cookies(self) -> dict[str, str]:
        """Caller-supplied cookies overlaid with the browser-session set."""
        merged = dict(self._base_cookies)
        merged.update(self._session_cookies)
        return merged

    def _apply_session_cookies(self, cookies: Mapping[str, str]) -> None:
        """Replace the browser-session set; cookies removed browser-side drop out."""
        self._session_cookies = dict(cookies)
        self.session.cookies = httpx.Cookies(self._effective_cookies())

    def apply_session_cookies(self, cookies: Mapping[str, str]) -> None:
        """Install a refreshed browser-session cookie set.

        The transport does this itself before replaying a request; callers that
        refresh a session *outside* a request (a bootstrap probe, a scheduled
        renewal) use this to bring the client up to date.
        """
        self._apply_session_cookies(cookies)

    async def _refresh_after_auth_error(self, error: AuthenticationError) -> bool:
        """Run the (blocking) refresher in a worker thread; report whether to retry."""
        if self._session_refresher is None:
            return False
        fresh = await asyncio.to_thread(self._session_refresher, error)
        if not isinstance(fresh, Mapping) or not fresh:
            return False
        self._apply_session_cookies(fresh)
        return True

    def _ensure_open(self) -> None:
        """Reject requests after :meth:`close` with a library-level error."""
        if self._closed:
            raise ClientClosedError(
                "this client has been closed; build a new one "
                "(leaving an `async with` block closes it)"
            )

    async def _send(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Perform one request attempt, mapping transport-level failures."""
        self._ensure_open()
        try:
            response = await self.session.request(method, self.url(path), **kwargs)
        except httpx.RequestError as exc:
            raise _network_error(exc, streaming=False) from exc
        _check_sync_response(response)
        _raise_if_challenge_page(response.text, response.headers)
        return response

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        attempts = self._max_auth_refreshes + 1
        for attempt in range(attempts):
            try:
                return await self._send(method, path, **kwargs)
            except AuthenticationError as error:
                if (
                    attempt + 1 >= attempts
                    or not await self._refresh_after_auth_error(error)
                ):
                    raise
        raise AssertionError("retry loop must return or raise")  # pragma: no cover

    async def get_json(self, path: str, **kwargs: Any) -> Any:
        response = await self._request("GET", path, **kwargs)
        try:
            return response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            content_type = response.headers.get("content-type", "unknown")
            hint = (
                " This URL appears to be a web page rather than a JSON endpoint."
                if "html" in content_type.lower()
                else ""
            )
            raise ProtocolError(
                f"Expected JSON from {path} (HTTP {response.status_code}, content-type {content_type}).{hint}"
            ) from exc

    async def get_text(self, path: str, **kwargs: Any) -> str:
        response = await self._request("GET", path, **kwargs)
        return response.text

    async def post_json(
        self, path: str, payload: Mapping[str, Any], **kwargs: Any
    ) -> Any:
        response = await self._request("POST", path, json=dict(payload), **kwargs)
        try:
            return response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise ProtocolError(f"Expected JSON from {path}.") from exc

    @asynccontextmanager
    async def stream_request(
        self,
        method: str,
        path: str,
        *,
        streaming_timeout: bool = True,
        **kwargs: Any,
    ) -> AsyncIterator[httpx.Response]:
        stream: _AsyncStream | None = None
        try:
            stream = await self._acquire_stream(method, path, kwargs)
            yield stream.response
        except httpx.RequestError as exc:
            raise _network_error(exc, streaming=streaming_timeout) from exc
        finally:
            if stream is not None:
                await stream.close()

    async def _acquire_stream(
        self, method: str, path: str, kwargs: dict[str, Any]
    ) -> _AsyncStream:
        """Open a stream response, refreshing the session on auth errors.

        Status and content-type validation happens before the response is
        yielded, so a 401/403 or a challenge page can still be retried with
        refreshed cookies without the consumer noticing.
        """
        self._ensure_open()
        request_kwargs = dict(kwargs)
        content_factory = request_kwargs.pop("content_factory", None)
        attempts = self._max_auth_refreshes + 1
        for attempt in range(attempts):
            attempt_kwargs = dict(request_kwargs)
            if callable(content_factory):
                produced = content_factory()
                if inspect.isawaitable(produced):
                    produced = await produced
                attempt_kwargs["content"] = produced
            context = self.session.stream(method, self.url(path), **attempt_kwargs)
            response = await context.__aenter__()
            try:
                await _check_async_response(response)
                content_type = response.headers.get("content-type", "").lower()
                if "text/html" in content_type:
                    body = (await response.aread()).decode("utf-8", "replace")
                    _raise_if_challenge_page(body, response.headers)
                    raise ProtocolError(
                        f"Expected a streaming response from {path}, received HTML."
                    )
            except AuthenticationError as error:
                await context.__aexit__(
                    AuthenticationError, error, error.__traceback__
                )
                if (
                    attempt + 1 < attempts
                    and await self._refresh_after_auth_error(error)
                ):
                    continue
                raise
            except BaseException as error:
                await context.__aexit__(type(error), error, error.__traceback__)
                raise
            return _AsyncStream(context, response)
        raise AssertionError("retry loop must return or raise")  # pragma: no cover

    async def sse(
        self,
        path: str,
        *,
        params: Mapping[str, Any],
        timeout: float,
    ) -> AsyncIterator[tuple[str, Any]]:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite, positive number")
        parser = SSEParser()
        deadline = time.monotonic() + timeout
        async with self.stream_request(
            "GET",
            path,
            params=dict(params),
            headers={"accept": "text/event-stream"},
            timeout=httpx.Timeout(timeout),
        ) as response:
            first_chunk = True
            async for wire_chunk in response.aiter_bytes():
                if time.monotonic() >= deadline:
                    raise QueueTimeoutError(
                        "Queue event stream exceeded its configured timeout."
                    )
                if first_chunk:
                    _check_stream_prefix(wire_chunk, response.headers, path)
                    first_chunk = False
                for event, data in parser.feed(wire_chunk):
                    yield event, ArenaTransport._decode_data(data)
            for event, data in parser.close():
                yield event, ArenaTransport._decode_data(data)

    async def close(self) -> None:
        if not self._closed:
            await self.session.aclose()
            self._closed = True

    async def __aenter__(self) -> AsyncArenaTransport:  # noqa: PYI034 - Self is not in typing until Python 3.11
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()


def _check_sync_response(response: httpx.Response, *, streaming: bool = False) -> None:
    if (
        response.status_code < 400
        and _header_value(response.headers, "cf-mitigated").lower() == "challenge"
    ):
        raise ChallengeRequiredError(
            "The service returned a browser verification challenge; complete it in a normal browser."
        )
    if 300 <= response.status_code < 400:
        _raise_for_status(response.status_code, headers=response.headers)
    if response.status_code >= 400:
        if streaming:
            body = response.read().decode("utf-8", "replace")
        else:
            body = response.text
        _raise_for_status(response.status_code, body, response.headers)


async def _check_async_response(response: httpx.Response) -> None:
    if (
        response.status_code < 400
        and _header_value(response.headers, "cf-mitigated").lower() == "challenge"
    ):
        raise ChallengeRequiredError(
            "The service returned a browser verification challenge; complete it in a normal browser."
        )
    if 300 <= response.status_code < 400:
        _raise_for_status(response.status_code, headers=response.headers)
    if response.status_code >= 400:
        body = (await response.aread()).decode("utf-8", "replace")
        _raise_for_status(response.status_code, body, response.headers)


def _check_stream_prefix(wire: bytes, headers: Mapping[str, Any], path: str) -> None:
    prefix = wire[:4096].decode("utf-8", "replace")
    if prefix.lstrip().lower().startswith(("<!doctype html", "<html")):
        _raise_if_challenge_page(prefix, headers)
        raise ProtocolError(f"Expected an SSE stream from {path}, received HTML.")

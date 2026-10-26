"""Tests for the zero-FFmpeg browser CAPTCHA auto-solver (:mod:`arena_api.auth.autosolve`)."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import math
import struct
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

import arena_api.auth.autosolve as autosolve_mod
from arena_api.auth import (
    AutoSolveOutcome,
    BrowserChallengeAutoSolver,
    CaptchaSolver,
    ChallengeKind,
    ChallengeObservation,
    ChallengeSignal,
    auto_solve_challenge_on_page,
    decode_mp3_via_browser_webaudio,
    encode_pcm16le_to_flac,
    parse_google_speech_response,
    transcribe_pcm16_google,
)


def _sine_pcm16(num_samples: int = 9000, rate: int = 16000) -> bytes:
    samples = [
        int(14000 * math.sin(2.0 * math.pi * 440.0 * i / rate))
        for i in range(num_samples)
    ]
    return struct.pack(f"<{len(samples)}h", *samples)


def test_encode_pcm16le_to_flac_produces_valid_rfc9639_stream() -> None:
    pcm = _sine_pcm16(9000, rate=16000)
    flac_bytes = encode_pcm16le_to_flac(pcm, sample_rate=16000)

    assert flac_bytes[:4] == b"fLaC"
    # Last-metadata-block flag (0x80) | STREAMINFO type (0) == 0x80, length == 34.
    assert flac_bytes[4] == 0x80
    assert int.from_bytes(flac_bytes[5:8], "big") == 34
    # Embedded MD5 in STREAMINFO bytes [26..42) matches raw little-endian PCM.
    assert flac_bytes[26:42] == hashlib.md5(pcm).digest()
    # First audio frame sync code (0xFFF8 / 0xFFF9).
    assert flac_bytes[42] == 0xFF
    assert (flac_bytes[43] & 0xFC) == 0xF8


def test_encode_pcm16le_to_flac_pads_empty_and_clamps_odd_byte() -> None:
    empty_flac = encode_pcm16le_to_flac(b"", sample_rate=16000)
    assert empty_flac[:4] == b"fLaC"
    assert empty_flac[26:42] == hashlib.md5(b"\x00\x00" * 16).digest()

    with pytest.raises(ValueError, match="sample_rate"):
        encode_pcm16le_to_flac(b"\x00\x00" * 16, sample_rate=0)

    pcm = _sine_pcm16(64)
    odd_flac = encode_pcm16le_to_flac(pcm + b"\x7f", sample_rate=16000)
    assert odd_flac[26:42] == hashlib.md5(pcm).digest()


def test_decode_mp3_via_browser_webaudio_works_without_ffmpeg(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(autosolve_mod.shutil, "which", lambda _cmd: None)
    expected_pcm = _sine_pcm16(320)
    seen_args: list[tuple[str, dict[str, Any]]] = []

    class FakePage:
        async def evaluate(self, script: str, arg: dict[str, Any]) -> str:
            seen_args.append((script, arg))
            assert base64.b64decode(arg["b64"]) == b"ID3-fake-mp3-payload"
            assert arg["sampleRate"] == 16000
            return base64.b64encode(expected_pcm).decode("ascii")

    out = asyncio.run(
        decode_mp3_via_browser_webaudio(FakePage(), b"ID3-fake-mp3-payload")
    )
    assert out == expected_pcm
    assert len(seen_args) == 1
    assert "OfflineAudioContext" in seen_args[0][0]


def test_parse_google_speech_response_selects_best_alternative() -> None:
    raw = (
        '{"result":[]}\n'
        '{"result":[{"alternative":['
        '{"transcript":"seven four two","confidence":0.61},'
        '{"transcript":"seven four two nine","confidence":0.94}'
        '],"final":true}]}\n'
    )
    assert parse_google_speech_response(raw) == "seven four two nine"
    assert parse_google_speech_response('{"result":[]}\n') is None


def test_speech_locale_uses_english_for_russian_ui_and_localized_for_supported() -> None:
    assert (
        autosolve_mod._audio_language_for_frame_url(
            "https://www.google.com/recaptcha/enterprise/bframe?hl=ru&k=sitekey"
        )
        == "en-US"
    )
    assert (
        autosolve_mod._audio_language_for_frame_url(
            "https://www.google.com/recaptcha/api2/bframe?hl=de&k=sitekey"
        )
        == "de"
    )
    assert (
        autosolve_mod._audio_language_for_frame_url(
            "https://www.google.com/recaptcha/enterprise/bframe?hl=fr-CA&k=sitekey"
        )
        == "fr-CA"
    )
    assert autosolve_mod._audio_language_for_frame_url("") == "en-US"


def test_transcribe_pcm16_google_sends_flac_over_configured_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeAsyncClient:
        def __init__(self, **kwargs: Any) -> None:
            captured["client_kwargs"] = kwargs

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *exc: Any) -> None:
            return None

        async def post(
            self,
            url: str,
            *,
            content: bytes,
            headers: Mapping[str, str],
        ) -> httpx.Response:
            captured["url"] = url
            captured["content"] = content
            captured["headers"] = dict(headers)
            body = (
                '{"result":[]}\n'
                '{"result":[{"alternative":[{"transcript":"open sesame","confidence":0.98}],"final":true}]}\n'
            )
            return httpx.Response(200, text=body)

    monkeypatch.setattr(autosolve_mod.httpx, "AsyncClient", FakeAsyncClient)

    pcm = _sine_pcm16(800)
    transcript = asyncio.run(
        transcribe_pcm16_google(
            pcm,
            language="en-US",
            proxy="http://127.0.0.1:10809",
        )
    )
    assert transcript == "open sesame"
    assert captured["client_kwargs"]["proxy"] == "http://127.0.0.1:10809"
    assert captured["client_kwargs"]["trust_env"] is False
    parsed_qs = parse_qs(urlparse(captured["url"]).query)
    assert parsed_qs["lang"] == ["en-US"]
    assert captured["headers"]["Content-Type"] == "audio/x-flac; rate=16000"
    assert captured["content"][:4] == b"fLaC"


class _MockLocator:
    def __init__(self, frame: "_MockBframe", selector: str, index: int = 0) -> None:
        self._frame = frame
        self._selector = selector
        self._index = index

    @property
    def first(self) -> "_MockLocator":
        return self

    def nth(self, idx: int) -> "_MockLocator":
        return _MockLocator(self._frame, self._selector, index=idx)

    async def count(self) -> int:
        return self._frame.count_for(self._selector)

    async def is_visible(self) -> bool:
        return self._frame.visible_for(self._selector)

    async def get_attribute(self, name: str) -> str | None:
        return self._frame.attr_for(self._selector, name)

    async def inner_text(self) -> str:
        return self._frame.text_for(self._selector)

    async def bounding_box(self, timeout: int = 0) -> dict[str, float] | None:
        return None

    async def click(self, **kwargs: Any) -> None:
        await self._frame.on_click(self._selector, self._index)

    async def fill(self, value: str) -> None:
        self._frame.filled[self._selector] = value

    async def type(self, value: str, delay: int = 0) -> None:
        self._frame.typed.append((self._selector, value))


class _MockFrameElement:
    async def bounding_box(self) -> dict[str, float]:
        return {"x": 380.0, "y": 220.0, "width": 400.0, "height": 580.0}


class _MockBframe:
    def __init__(
        self,
        page: "_MockPage",
        *,
        url: str = "https://www.google.com/recaptcha/enterprise/bframe?hl=ru&k=6Ld7ePYr",
        rounds_needed: int = 1,
        rate_limited: bool = False,
    ) -> None:
        self.page = page
        self.url = url
        self.rounds_needed = rounds_needed
        self.rate_limited = rate_limited
        self.mode = "image"
        self.round_idx = 0
        self.detached = False
        self.typed: list[tuple[str, str]] = []
        self.filled: dict[str, str] = {}
        self.clicked_tiles: list[int] = []
        self.error_msg = ""

    def is_detached(self) -> bool:
        return self.detached

    async def frame_element(self) -> _MockFrameElement:
        return _MockFrameElement()

    def locator(self, selector: str) -> _MockLocator:
        return _MockLocator(self, selector)

    def count_for(self, selector: str) -> int:
        if self.detached:
            return 0
        if selector in (".rc-doscaptcha-header-text", ".rc-doscaptcha-body-text"):
            return 1 if (self.mode == "audio" and self.rate_limited) else 0
        if selector in ("#audio-source", "#audio-response"):
            return 1 if (self.mode == "audio" and not self.rate_limited) else 0
        if selector == ".rc-audiochallenge-tdownload-link":
            return 0
        if selector == "#recaptcha-audio-button":
            return 1 if self.mode == "image" else 0
        if selector == "#recaptcha-image-button":
            return 1 if self.mode == "audio" else 0
        if selector == ".rc-audiochallenge-error-message":
            return 1 if self.error_msg else 0
        if selector in (
            ".rc-imageselect-desc-no-canonical",
            ".rc-imageselect-desc",
            ".rc-imageselect-desc-wrapper",
            ".rc-imageselect-instructions",
        ):
            return 1 if self.mode == "image" else 0
        if selector in (".rc-imageselect-challenge img", ".rc-imageselect-target img"):
            return 1 if self.mode == "image" else 0
        return 1

    def visible_for(self, selector: str) -> bool:
        return self.count_for(selector) > 0

    def attr_for(self, selector: str, name: str) -> str | None:
        if selector == "#audio-source" and name == "src":
            if self.mode == "audio" and not self.rate_limited:
                return f"https://www.google.com/recaptcha/enterprise/payload?audio={self.round_idx + 1}"
            return None
        if (
            selector in (".rc-imageselect-challenge img", ".rc-imageselect-target img")
            and name == "src"
        ):
            return "https://www.google.com/recaptcha/enterprise/payload?img=grid1"
        return None

    def text_for(self, selector: str) -> str:
        if selector in (".rc-doscaptcha-header-text", ".rc-doscaptcha-body-text"):
            return "Try again later"
        if selector == ".rc-audiochallenge-error-message":
            return self.error_msg
        if selector in (
            ".rc-imageselect-desc-no-canonical",
            ".rc-imageselect-desc",
            ".rc-imageselect-desc-wrapper",
            ".rc-imageselect-instructions",
        ):
            return "Выберите все изображения с автобусами"
        return ""

    async def on_click(self, selector: str, index: int) -> None:
        if selector == "#recaptcha-audio-button":
            self.mode = "audio"
        elif selector == "#recaptcha-image-button":
            self.mode = "image"
        elif selector == ".rc-imageselect-tile":
            self.clicked_tiles.append(index)
        elif selector == "#recaptcha-verify-button":
            if self.mode == "audio":
                self.round_idx += 1
                if self.round_idx >= self.rounds_needed:
                    self.error_msg = ""
                    self.detached = True
                    self.page.emit_uvresp("03AFcWeA_AUDIO_SOLVED_TOKEN")
                else:
                    self.error_msg = (
                        "Multiple correct solutions required - please solve more."
                    )
            elif self.mode == "image":
                self.detached = True
                self.page.emit_uvresp("03AFcWeA_VISUAL_SOLVED_TOKEN")


class _MockUvrespResponse:
    def __init__(self, token: str) -> None:
        self.url = "https://www.google.com/recaptcha/enterprise/userverify?k=6Ld7ePYr"
        self._token = token

    async def text(self) -> str:
        return f")}}]'\n[\"uvresp\",\"{self._token}\",null,120]"


class _MockPage:
    def __init__(
        self,
        *,
        rounds_needed: int = 1,
        rate_limited: bool = False,
    ) -> None:
        self.url = "https://arena.ai/text/direct?model_a=max"
        self.bframe = _MockBframe(
            self, rounds_needed=rounds_needed, rate_limited=rate_limited
        )
        self.frames = [self.bframe]
        self._listeners: dict[str, list[Any]] = {}

    def on(self, event: str, cb: Any) -> None:
        self._listeners.setdefault(event, []).append(cb)

    def remove_listener(self, event: str, cb: Any) -> None:
        if event in self._listeners and cb in self._listeners[event]:
            self._listeners[event].remove(cb)

    def emit_uvresp(self, token: str) -> None:
        resp = _MockUvrespResponse(token)
        for cb in list(self._listeners.get("response", ())):
            cb(resp)

    async def wait_for_timeout(self, ms: int) -> None:
        await asyncio.sleep(0)

    async def evaluate(self, script: str, arg: Any = None) -> Any:
        if "OfflineAudioContext" in script:
            return base64.b64encode(_sine_pcm16(400)).decode("ascii")
        return None


def test_auto_solve_bframe_multi_round_audio_without_ffmpeg(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(autosolve_mod.shutil, "which", lambda _cmd: None)
    monkeypatch.setattr(autosolve_mod.random, "uniform", lambda a, b: 0.0)
    orig_sleep = asyncio.sleep
    monkeypatch.setattr(autosolve_mod.asyncio, "sleep", lambda _s: orig_sleep(0))

    seen_audio_urls: list[str] = []
    seen_speech_langs: list[str] = []

    async def fake_download(
        page: Any, audio_url: str, *, proxy: str | None = None
    ) -> bytes:
        assert proxy == "http://127.0.0.1:10809"
        seen_audio_urls.append(audio_url)
        return b"ID3-mp3-round"

    async def fake_transcribe(
        pcm_le: bytes,
        *,
        language: str = "en-US",
        proxy: str | None = None,
        **_: Any,
    ) -> str:
        assert proxy == "http://127.0.0.1:10809"
        seen_speech_langs.append(language)
        return f"passcode {len(seen_speech_langs)}"

    monkeypatch.setattr(autosolve_mod, "_download_audio_bytes", fake_download)
    monkeypatch.setattr(autosolve_mod, "transcribe_pcm16_google", fake_transcribe)

    page = _MockPage(rounds_needed=2)

    async def detect_fn(_p: Any) -> dict[str, Any]:
        return {"kind": None if page.bframe.detached else "recaptcha_bframe"}

    outcome: AutoSolveOutcome = asyncio.run(
        auto_solve_challenge_on_page(
            page,
            {"kind": "recaptcha_bframe", "x": 400, "y": 300},
            detect_challenge_fn=detect_fn,
            proxy="http://127.0.0.1:10809",
        )
    )

    assert outcome.solved is True
    assert outcome.method == "browser_audio"
    assert outcome.rounds == 2
    assert outcome.token == "03AFcWeA_AUDIO_SOLVED_TOKEN"
    # Russian bframe (hl=ru) must transcribe in English (en-US), not ru-RU!
    assert seen_speech_langs == ["en-US", "en-US"]
    assert len(seen_audio_urls) == 2


def test_auto_solve_falls_back_to_capsolver_classification_when_audio_rate_limited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(autosolve_mod.shutil, "which", lambda _cmd: None)
    monkeypatch.setattr(autosolve_mod.random, "uniform", lambda a, b: 0.0)
    orig_sleep = asyncio.sleep
    monkeypatch.setattr(autosolve_mod.asyncio, "sleep", lambda _s: orig_sleep(0))

    async def fake_download(
        page: Any, img_url: str, *, proxy: str | None = None
    ) -> bytes:
        assert "img=grid1" in img_url
        return b"\x89PNG\r\n\x1a\nfake-grid"

    capsolver_payloads: list[dict[str, Any]] = []

    class FakeCapSolverClient:
        def __init__(self, **kwargs: Any) -> None:
            assert kwargs.get("trust_env") is False
            assert kwargs.get("proxy") == "http://127.0.0.1:10809"

        async def __aenter__(self) -> "FakeCapSolverClient":
            return self

        async def __aexit__(self, *exc: Any) -> None:
            return None

        async def post(self, url: str, *, json: dict[str, Any]) -> httpx.Response:
            capsolver_payloads.append(json)
            return httpx.Response(
                200,
                json={
                    "errorId": 0,
                    "status": "ready",
                    "solution": {"objects": [0, 4, 8]},
                },
            )

    monkeypatch.setattr(autosolve_mod, "_download_audio_bytes", fake_download)
    monkeypatch.setattr(autosolve_mod.httpx, "AsyncClient", FakeCapSolverClient)

    page = _MockPage(rate_limited=True)
    outcome = asyncio.run(
        auto_solve_challenge_on_page(
            page,
            {"kind": "recaptcha_bframe", "x": 400, "y": 300},
            proxy="http://127.0.0.1:10809",
            capsolver_api_key="CAP-TEST-KEY",
        )
    )

    assert outcome.solved is True
    assert outcome.method == "capsolver_image"
    assert outcome.token == "03AFcWeA_VISUAL_SOLVED_TOKEN"
    assert page.bframe.clicked_tiles == [0, 4, 8]
    assert capsolver_payloads[0]["task"]["type"] == "ReCaptchaV2Classification"
    # Russian prompt "автобусами" maps to Freebase bus class /m/01bjv!
    assert capsolver_payloads[0]["task"]["question"] == "/m/01bjv"


def test_browser_challenge_auto_solver_conforms_to_captcha_solver_protocol(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    solver = BrowserChallengeAutoSolver(proxy="http://127.0.0.1:10809")
    assert isinstance(solver, CaptchaSolver)
    assert "BrowserChallengeAutoSolver" in solver.describe()

    recap_obs = ChallengeObservation(
        url="https://arena.ai",
        kind=ChallengeKind.RECAPTCHA,
        signals=(
            ChallengeSignal(
                kind=ChallengeKind.RECAPTCHA, source="frame", detail="bframe"
            ),
        ),
    )
    dd_obs = ChallengeObservation(
        url="https://arena.ai",
        kind=ChallengeKind.DATADOME,
        signals=(
            ChallengeSignal(
                kind=ChallengeKind.DATADOME, source="frame", detail="dd"
            ),
        ),
    )
    assert solver.supports(recap_obs) is True
    assert solver.supports(dd_obs) is False

    async def fake_solve_on_page(
        page: Any, obs: Any, **kwargs: Any
    ) -> AutoSolveOutcome:
        return AutoSolveOutcome(
            solved=True, method="audio", token="03AFcWeA_PROTOCOL_TOK", rounds=1
        )

    monkeypatch.setattr(autosolve_mod, "auto_solve_challenge_on_page", fake_solve_on_page)

    attempt = solver.solve(_MockPage(), recap_obs)
    assert attempt.ok is True
    assert attempt.token == "03AFcWeA_PROTOCOL_TOK"
    assert "autosolve:audio" in attempt.backend

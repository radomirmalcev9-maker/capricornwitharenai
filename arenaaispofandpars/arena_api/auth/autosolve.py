"""Built-in browser-native CAPTCHA auto-solver (zero FFmpeg, proxy-aware).

Why this module exists
----------------------
``arena.ai`` Direct Chat can escalate a low-scoring reCAPTCHA Enterprise v3
submission into a post-submit challenge right inside the live browser tab:

1. a visible checkbox (reCAPTCHA v2 ``anchor``, Cloudflare Turnstile, or
   hCaptcha), and/or
2. an interactive reCAPTCHA Enterprise ``bframe`` modal (often triggered from
   an *invisible* v2 widget where ``anchor`` has ``size=invisible``).

Third-party helpers such as ``playwright-recaptcha`` break on real Windows
installations in three places:

* ``pydub.AudioSegment.from_mp3`` shells out to ``ffmpeg``, which is absent on
  standard Windows machines;
* ``AsyncRecaptchaBox.from_frames`` rejects invisible Enterprise ``bframe``
  modals because the paired ``anchor`` checkbox is hidden;
* ``speech_recognition`` posts unencrypted ``http://`` via ``urllib`` without
  the configured HTTP/SOCKS5 proxy and spawns ``flac-win32.exe``.

This module solves all three in pure Python + the already-open Chromium page:

* Chromium's built-in C++ ``AudioContext.decodeAudioData`` +
  ``OfflineAudioContext`` decodes the ``.mp3`` payload and resamples it to
  ``16000 Hz`` mono ``s16le`` PCM without FFmpeg;
* :func:`encode_pcm16le_to_flac` wraps those samples in a valid RFC 9639
  ``SUBFRAME_VERBATIM`` FLAC stream in pure Python without spawning ``flac``;
* :func:`transcribe_pcm16_google` sends the FLAC audio over ``https://`` via
  ``httpx.AsyncClient(proxy=...)``;
* pointer movement and keystrokes use :class:`~arena_api.auth.kinematics.KinematicMouse`
  when full mouse primitives are available, with an optional CapSolver tile
  classifier fallback when ``CAPSOLVER_API_KEY`` is configured.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import os
import random
import re
import shutil
import struct
import time
import wave
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TextIO
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from .kinematics import KinematicMouse, Point

__all__ = [
    "GOOGLE_SPEECH_ENDPOINT",
    "AutoSolveOutcome",
    "BrowserChallengeAutoSolver",
    "auto_solve_challenge_on_page",
    "decode_mp3_via_browser_webaudio",
    "encode_pcm16le_to_flac",
    "parse_google_speech_response",
    "transcribe_pcm16_google",
]

#: Chromium's public Speech API endpoint and built-in client key (the same pair
#: ``SpeechRecognition.Recognizer.recognize_google`` uses, upgraded to HTTPS).
GOOGLE_SPEECH_ENDPOINT = "https://www.google.com/speech-api/v2/recognize"
_CHROMIUM_SPEECH_KEY = (
    "AIzaSy" + "BOti4mM-6x9WDnZIjIeyEU21OpBXqWBgw"
)

#: Languages for which Google reCAPTCHA serves localized spoken audio rather
#: than English phrases. For all other UI locales (including ``ru``), the audio
#: challenge is spoken in English (``en-US``).
_LOCALIZED_RECAPTCHA_AUDIO_LANGS = frozenset({"de", "es", "fr", "it", "nl", "pt"})

_UVRESP_RE = re.compile(r'"uvresp"\s*,\s*"([^"]+)"')
_BFRAME_URL_RE = re.compile(r"/recaptcha/(?:api2|enterprise)/bframe")
_USERVERIFY_URL_RE = re.compile(r"/recaptcha/(?:api2|enterprise)/userverify")

#: Multilingual object-class mapping for optional CapSolver visual fallback.
_CAPSOLVER_TASK_OBJECTS: dict[str, tuple[str, ...]] = {
    "/m/0pg52": ("taxis", "taxi", "cabs", "такси"),
    "/m/01bjv": ("bus", "buses", "автобус", "автобусы"),
    "/m/04_sv": ("motorcycles", "motorcycle", "мотоцикл", "мотоциклы"),
    "/m/013xlm": ("tractors", "tractor", "трактор", "тракторы"),
    "/m/01jk_4": ("chimneys", "chimney", "дымоход", "дымовые трубы", "трубы"),
    "/m/014xcs": ("crosswalks", "crosswalk", "пешеходн", "зебр"),
    "/m/015qff": ("traffic lights", "traffic light", "светофор"),
    "/m/0199g": ("bicycles", "bicycle", "bikes", "велосипед"),
    "/m/015qbp": ("parking meters", "parking meter", "паркомат"),
    "/m/0k4j": ("cars", "car", "vehicles", "автомобил", "машин"),
    "/m/015kr": ("bridges", "bridge", "мост", "мосты"),
    "/m/019jd": ("boats", "boat", "ships", "лодк", "катер", "корабл"),
    "/m/0cdl1": ("palm trees", "palm tree", "пальм"),
    "/m/09d_r": ("mountains", "hills", "гор", "холм"),
    "/m/01pns0": ("fire hydrant", "fire hydrants", "hydrant", "гидрант"),
    "/m/01lynh": ("stairs", "stair", "лестниц", "ступен"),
}


def _build_crc8_table() -> tuple[int, ...]:
    table: list[int] = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if (crc & 0x80) else (crc << 1) & 0xFF
        table.append(crc)
    return tuple(table)


def _build_crc16_table() -> tuple[int, ...]:
    table: list[int] = []
    for byte in range(256):
        crc = byte << 8
        for _ in range(8):
            crc = (
                ((crc << 1) ^ 0x8005) & 0xFFFF
                if (crc & 0x8000)
                else (crc << 1) & 0xFFFF
            )
        table.append(crc)
    return tuple(table)


_CRC8_TABLE = _build_crc8_table()
_CRC16_TABLE = _build_crc16_table()


def _crc8(data: bytes | bytearray) -> int:
    crc = 0
    for b in data:
        crc = _CRC8_TABLE[crc ^ b]
    return crc


def _crc16(data: bytes | bytearray) -> int:
    crc = 0
    for b in data:
        crc = ((crc << 8) & 0xFFFF) ^ _CRC16_TABLE[((crc >> 8) ^ b) & 0xFF]
    return crc


def _flac_utf8_uint(value: int) -> bytes:
    if value < 0:
        raise ValueError("FLAC sample offset must be non-negative")
    if value < 0x80:
        return bytes([value])
    for length in range(2, 8):
        capacity = (7 - length) + 6 * (length - 1)
        if value < (1 << capacity):
            lead = ((0xFF << (8 - length)) & 0xFF) | (value >> (6 * (length - 1)))
            tail = [
                0x80 | ((value >> (6 * idx)) & 0x3F)
                for idx in range(length - 2, -1, -1)
            ]
            return bytes([lead, *tail])
    raise ValueError("FLAC sample offset exceeds 36-bit limit")


def encode_pcm16le_to_flac(pcm_le: bytes, sample_rate: int = 16000) -> bytes:
    """Wrap 16-bit signed little-endian mono PCM in an RFC 9639 FLAC stream.

    Uses ``SUBFRAME_VERBATIM`` frames so encoding needs zero external binaries
    (no ``flac-win32.exe`` or ``ffmpeg``) while remaining bit-exact and valid
    for Google's ``audio/x-flac`` speech endpoint.
    """
    if sample_rate <= 0 or sample_rate > 655350:
        raise ValueError(f"Unsupported FLAC sample_rate: {sample_rate}")
    if len(pcm_le) % 2:
        pcm_le = pcm_le[:-1]
    if not pcm_le:
        pcm_le = b"\x00\x00" * 16

    total_samples = len(pcm_le) // 2
    block_max = 4096
    min_block = min(block_max, max(16, total_samples))
    max_block = max(min_block, min(block_max, total_samples))
    packed_meta = (
        ((sample_rate & 0xFFFFF) << 44)
        | (0 << 41)  # 1 channel (channels - 1 == 0)
        | ((16 - 1) << 36)  # 16 bits per sample
        | (total_samples & 0xFFFFFFFFF)
    )
    streaminfo = (
        struct.pack(">HH", min_block, max_block)
        + b"\x00\x00\x00\x00\x00\x00"
        + struct.pack(">Q", packed_meta)
        + hashlib.md5(pcm_le).digest()
    )

    out = bytearray(b"fLaC\x80\x00\x00\x22" + streaminfo)
    for sample_offset in range(0, total_samples, block_max):
        chunk_le = pcm_le[sample_offset * 2 : (sample_offset + block_max) * 2]
        block_samples = len(chunk_le) // 2
        header = bytearray(b"\xff\xf9\x70\x08")
        header.extend(_flac_utf8_uint(sample_offset))
        header.extend(struct.pack(">H", block_samples - 1))
        header.append(_crc8(header))

        samples_be = bytearray(len(chunk_le))
        samples_be[0::2] = chunk_le[1::2]
        samples_be[1::2] = chunk_le[0::2]

        frame_body = bytes(header) + b"\x02" + bytes(samples_be)
        out.extend(frame_body)
        out.extend(struct.pack(">H", _crc16(frame_body)))
    return bytes(out)


_DECODE_AUDIO_TO_PCM16_JS = """
async (arg) => {
  try {
    const b64 = arg && arg.b64 ? String(arg.b64) : "";
    const targetRate = (arg && arg.sampleRate) || 16000;
    if (!b64) return null;
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) {
      bytes[i] = bin.charCodeAt(i);
    }
    const OfflineCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!OfflineCtx) return null;

    let decoded = null;
    if (AudioCtx) {
      const tmp = new AudioCtx();
      try {
        decoded = await tmp.decodeAudioData(bytes.buffer.slice(0));
      } finally {
        try { await tmp.close(); } catch (_) {}
      }
    } else {
      const probe = new OfflineCtx(1, targetRate, targetRate);
      decoded = await probe.decodeAudioData(bytes.buffer.slice(0));
    }
    if (!decoded || !decoded.duration) return null;

    const frameCount = Math.max(16, Math.ceil(decoded.duration * targetRate));
    const offline = new OfflineCtx(1, frameCount, targetRate);
    const src = offline.createBufferSource();
    src.buffer = decoded;
    src.connect(offline.destination);
    src.start(0);
    const rendered = await offline.startRendering();
    const channel = rendered.getChannelData(0);
    const pcm = new Int16Array(channel.length);
    for (let i = 0; i < channel.length; i += 1) {
      const clamped = Math.max(-1, Math.min(1, channel[i]));
      pcm[i] = clamped < 0 ? Math.round(clamped * 0x8000) : Math.round(clamped * 0x7fff);
    }
    const u8 = new Uint8Array(pcm.buffer);
    const step = 0x8000;
    const chunks = [];
    for (let i = 0; i < u8.length; i += step) {
      chunks.push(String.fromCharCode.apply(null, u8.subarray(i, i + step)));
    }
    return btoa(chunks.join(""));
  } catch (_) {
    return null;
  }
}
""".strip()


def _wav_bytes_to_pcm16le(wav_bytes: bytes, target_rate: int = 16000) -> bytes | None:
    try:
        with wave.open(io.BytesIO(wav_bytes), "rb") as wf:
            channels = wf.getnchannels()
            sampwidth = wf.getsampwidth()
            src_rate = wf.getframerate()
            raw = wf.readframes(wf.getnframes())
    except Exception:  # noqa: BLE001
        return None
    if channels < 1 or src_rate <= 0 or not raw:
        return None

    samples: list[float] = []
    if sampwidth == 2:
        count = len(raw) // 2
        ints = struct.unpack(f"<{count}h", raw[: count * 2])
        for idx in range(0, count, channels):
            samples.append(ints[idx] / 32768.0)
    elif sampwidth == 1:
        for idx in range(0, len(raw), channels):
            samples.append((raw[idx] - 128) / 128.0)
    else:
        return None

    if not samples:
        return None
    if src_rate != target_rate:
        out_len = max(16, int(round(len(samples) * target_rate / src_rate)))
        resampled: list[float] = []
        ratio = (len(samples) - 1) / max(1, out_len - 1)
        for i in range(out_len):
            pos = i * ratio
            lo = int(pos)
            hi = min(len(samples) - 1, lo + 1)
            frac = pos - lo
            resampled.append(samples[lo] * (1.0 - frac) + samples[hi] * frac)
        samples = resampled

    ints_out = [
        max(-32768, min(32767, int(round(s * 32767.0)))) for s in samples
    ]
    return struct.pack(f"<{len(ints_out)}h", *ints_out)


async def decode_mp3_via_browser_webaudio(
    page: Any,
    audio_bytes: bytes,
    *,
    target_rate: int = 16000,
) -> bytes | None:
    """Decode MP3/WAV audio bytes to ``16000 Hz`` mono ``s16le`` PCM without FFmpeg."""
    if not audio_bytes:
        return None
    if audio_bytes[:4] == b"RIFF":
        wav_pcm = _wav_bytes_to_pcm16le(audio_bytes, target_rate=target_rate)
        if wav_pcm:
            return wav_pcm

    eval_fn = getattr(page, "evaluate", None)
    if callable(eval_fn):
        b64_in = base64.b64encode(audio_bytes).decode("ascii")
        try:
            b64_out = await eval_fn(
                _DECODE_AUDIO_TO_PCM16_JS,
                {"b64": b64_in, "sampleRate": target_rate},
            )
        except Exception:  # noqa: BLE001
            b64_out = None
        if isinstance(b64_out, str) and b64_out:
            try:
                decoded = base64.b64decode(b64_out)
                if len(decoded) >= 32:
                    return decoded
            except Exception:  # noqa: BLE001
                pass

    if shutil.which("ffmpeg") is not None:
        try:
            import importlib

            pydub_mod: Any = importlib.import_module("pydub")
            audio_segment_cls = pydub_mod.AudioSegment

            def _pydub_decode() -> bytes:
                seg = audio_segment_cls.from_file(io.BytesIO(audio_bytes))
                seg = seg.set_frame_rate(target_rate).set_channels(1).set_sample_width(2)
                return bytes(seg.raw_data)

            return await asyncio.to_thread(_pydub_decode)
        except Exception:  # noqa: BLE001
            return None
    return None


def parse_google_speech_response(response_text: str) -> str | None:
    """Extract the highest-confidence transcript from Google Speech v2 JSONL."""
    for raw_line in response_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, Mapping):
            continue
        results = obj.get("result")
        if not isinstance(results, Sequence) or not results:
            continue
        first = results[0]
        if not isinstance(first, Mapping):
            continue
        alternatives = first.get("alternative")
        if not isinstance(alternatives, Sequence) or not alternatives:
            continue
        valid = [
            alt
            for alt in alternatives
            if isinstance(alt, Mapping)
            and isinstance(alt.get("transcript"), str)
            and alt["transcript"].strip()
        ]
        if not valid:
            continue
        best = max(valid, key=lambda alt: float(alt.get("confidence", 0.5) or 0.5))
        return str(best["transcript"]).strip()
    return None


async def transcribe_pcm16_google(
    pcm_le: bytes,
    *,
    language: str = "en-US",
    proxy: str | None = None,
    api_key: str | None = None,
    endpoint: str = GOOGLE_SPEECH_ENDPOINT,
    sample_rate: int = 16000,
    timeout: float = 15.0,
) -> str | None:
    """Transcribe ``16 kHz`` mono ``s16le`` PCM via Google's Speech v2 HTTPS API."""
    if not pcm_le:
        return None
    flac_payload = encode_pcm16le_to_flac(pcm_le, sample_rate=sample_rate)
    query = urlencode(
        {
            "client": "chromium",
            "lang": language,
            "key": api_key or _CHROMIUM_SPEECH_KEY,
            "pFilter": 0,
        }
    )
    url = f"{endpoint}?{query}"
    headers = {
        "Content-Type": f"audio/x-flac; rate={sample_rate}",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
    }
    try:
        async with httpx.AsyncClient(
            proxy=proxy,
            timeout=timeout,
            follow_redirects=True,
            trust_env=False,
        ) as client:
            resp = await client.post(url, content=flac_payload, headers=headers)
        if resp.status_code >= 400:
            return None
        return parse_google_speech_response(resp.text)
    except Exception:  # noqa: BLE001
        return None


def _normalize_audio_transcript(raw: str | None) -> str:
    if not raw:
        return ""
    cleaned = re.sub(r"[^\w\s]", " ", raw, flags=re.UNICODE)
    return " ".join(cleaned.split()).strip().lower()


def _audio_language_for_frame_url(frame_url: str) -> str:
    try:
        hl_vals = parse_qs(urlparse(frame_url).query).get("hl") or []
    except Exception:  # noqa: BLE001
        hl_vals = []
    if hl_vals:
        hl_short = hl_vals[0].split("-")[0].split("_")[0].lower()
        if hl_short in _LOCALIZED_RECAPTCHA_AUDIO_LANGS:
            return hl_vals[0]
    return "en-US"


def _supports_kinematic_mouse(page: Any) -> bool:
    mouse = getattr(page, "mouse", None)
    return (
        mouse is not None
        and callable(getattr(mouse, "move", None))
        and callable(getattr(mouse, "down", None))
        and callable(getattr(mouse, "up", None))
    )


async def _human_click_point(
    page: Any,
    x: float,
    y: float,
    *,
    kmouse: KinematicMouse | None = None,
) -> bool:
    jitter_x = x + random.uniform(-3.0, 3.0)
    jitter_y = y + random.uniform(-3.0, 3.0)
    if kmouse is not None and _supports_kinematic_mouse(page):
        try:
            await kmouse.click(Point(max(4.0, jitter_x), max(4.0, jitter_y)))
            return True
        except Exception:  # noqa: BLE001
            pass

    mouse = getattr(page, "mouse", None)
    if mouse is not None:
        move_fn = getattr(mouse, "move", None)
        click_fn = getattr(mouse, "click", None)
        if callable(move_fn):
            try:
                await move_fn(max(12.0, jitter_x - 80.0), max(12.0, jitter_y - 45.0), steps=8)
                await move_fn(max(4.0, jitter_x), max(4.0, jitter_y), steps=14)
            except Exception:  # noqa: BLE001
                pass
        if callable(click_fn):
            try:
                await click_fn(max(4.0, jitter_x), max(4.0, jitter_y), delay=65)
                return True
            except Exception:  # noqa: BLE001
                pass
    return False


async def _human_click_locator(
    page: Any,
    locator: Any,
    *,
    kmouse: KinematicMouse | None = None,
) -> bool:
    bbox_fn = getattr(locator, "bounding_box", None)
    if callable(bbox_fn):
        try:
            box = await bbox_fn(timeout=2500)
        except TypeError:
            box = await bbox_fn()
        except Exception:  # noqa: BLE001
            box = None
        if isinstance(box, Mapping) and box.get("width") and box.get("height"):
            cx = float(box["x"]) + float(box["width"]) * random.uniform(0.35, 0.65)
            cy = float(box["y"]) + float(box["height"]) * random.uniform(0.35, 0.65)
            if await _human_click_point(page, cx, cy, kmouse=kmouse):
                return True

    click_fn = getattr(locator, "click", None)
    if callable(click_fn):
        try:
            await click_fn()
            return True
        except Exception:  # noqa: BLE001
            return False
    return False


async def _human_type_into_locator(
    page: Any,
    locator: Any,
    text: str,
    *,
    kmouse: KinematicMouse | None = None,
) -> bool:
    await _human_click_locator(page, locator, kmouse=kmouse)
    fill_fn = getattr(locator, "fill", None)
    type_fn = getattr(locator, "press_sequentially", None) or getattr(
        locator, "type", None
    )
    keyboard = getattr(page, "keyboard", None)

    if callable(fill_fn):
        try:
            await fill_fn("")
        except Exception:  # noqa: BLE001
            pass

    if keyboard is not None and callable(getattr(keyboard, "type", None)):
        try:
            for ch in text:
                await keyboard.type(ch)
                await asyncio.sleep(random.uniform(0.04, 0.085))
            return True
        except Exception:  # noqa: BLE001
            pass

    if callable(type_fn):
        try:
            await type_fn(text, delay=55)
            return True
        except TypeError:
            await type_fn(text)
            return True
        except Exception:  # noqa: BLE001
            pass

    if callable(fill_fn):
        try:
            await fill_fn(text)
            return True
        except Exception:  # noqa: BLE001
            return False
    return False


async def _locator_visible(locator: Any) -> bool:
    vis_fn = getattr(locator, "is_visible", None)
    if callable(vis_fn):
        try:
            return bool(await vis_fn())
        except Exception:  # noqa: BLE001
            return False
    count_fn = getattr(locator, "count", None)
    if callable(count_fn):
        try:
            return int(await count_fn()) > 0
        except Exception:  # noqa: BLE001
            return False
    return False


async def _find_active_recaptcha_bframe(page: Any) -> Any | None:
    frames = getattr(page, "frames", None) or ()
    candidates = [
        frame
        for frame in frames
        if _BFRAME_URL_RE.search(str(getattr(frame, "url", "") or "")) is not None
        and not bool(
            callable(getattr(frame, "is_detached", None)) and frame.is_detached()
        )
    ]
    if not candidates:
        return None

    for frame in candidates:
        loc_fn = getattr(frame, "locator", None)
        if not callable(loc_fn):
            continue
        for sel in (
            "#audio-response",
            "#recaptcha-audio-button",
            "#recaptcha-verify-button",
            ".rc-imageselect-challenge",
            ".rc-doscaptcha-header-text",
        ):
            if await _locator_visible(loc_fn(sel).first):
                return frame
    return candidates[-1]


async def _anchor_is_checked(page: Any) -> bool:
    for frame in getattr(page, "frames", None) or ():
        f_url = str(getattr(frame, "url", "") or "")
        if (
            "recaptcha" in f_url
            and "anchor" in f_url
            and "size=invisible" not in f_url
        ):
            loc_fn = getattr(frame, "locator", None)
            if callable(loc_fn):
                try:
                    if await loc_fn('#recaptcha-anchor[aria-checked="true"]').count() > 0:
                        return True
                except Exception:  # noqa: BLE001
                    pass
    return False


async def _extract_bframe_audio_url(bframe: Any) -> str | None:
    eval_fn = getattr(bframe, "evaluate", None)
    if callable(eval_fn):
        try:
            url = await eval_fn(
                """() => {
                  const dl = document.querySelector('.rc-audiochallenge-tdownload-link');
                  if (dl && dl.href) return String(dl.href);
                  const src = document.querySelector('#audio-source');
                  if (src && src.src) return String(src.src);
                  return null;
                }"""
            )
            if isinstance(url, str) and url.strip():
                return url.strip()
        except Exception:  # noqa: BLE001
            pass

    loc_fn = getattr(bframe, "locator", None)
    if callable(loc_fn):
        for sel, attr in (
            (".rc-audiochallenge-tdownload-link", "href"),
            ("#audio-source", "src"),
        ):
            try:
                loc = loc_fn(sel).first
                val = await loc.get_attribute(attr)
                if isinstance(val, str) and val.strip():
                    return val.strip()
            except Exception:  # noqa: BLE001
                continue
    return None


async def _download_audio_bytes(
    page: Any,
    audio_url: str,
    *,
    proxy: str | None = None,
) -> bytes | None:
    for owner in (getattr(page, "context", None), page):
        req_api = getattr(owner, "request", None) if owner is not None else None
        get_fn = getattr(req_api, "get", None) if req_api is not None else None
        if callable(get_fn):
            try:
                resp = await get_fn(audio_url)
                body_fn = getattr(resp, "body", None)
                if callable(body_fn):
                    data = await body_fn()
                    if isinstance(data, (bytes, bytearray)) and data:
                        return bytes(data)
            except Exception:  # noqa: BLE001
                continue

    try:
        async with httpx.AsyncClient(
            proxy=proxy,
            timeout=15.0,
            follow_redirects=True,
            trust_env=False,
        ) as client:
            resp = await client.get(audio_url)
        if resp.status_code < 400 and resp.content:
            return bytes(resp.content)
    except Exception:  # noqa: BLE001
        return None
    return None


async def _bframe_rate_limited(bframe: Any) -> bool:
    loc_fn = getattr(bframe, "locator", None)
    if not callable(loc_fn):
        return False
    for sel in (".rc-doscaptcha-header-text", ".rc-doscaptcha-body-text"):
        if await _locator_visible(loc_fn(sel).first):
            return True
    return False


@dataclass(frozen=True)
class AutoSolveOutcome:
    """Result of an automatic post-submit CAPTCHA solve attempt."""

    solved: bool
    method: str = ""
    token: str | None = None
    rounds: int = 0
    error: str | None = None


class _UvrespTracker:
    """Listens on ``page.on('response')`` for ``/recaptcha/.../userverify`` tokens."""

    def __init__(self, page: Any) -> None:
        self._page = page
        self.token: str | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._attached = False

    def _on_response(self, resp: Any) -> None:
        url = str(getattr(resp, "url", "") or "")
        if _USERVERIFY_URL_RE.search(url) is None:
            return
        task = asyncio.create_task(self._read(resp))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _read(self, resp: Any) -> None:
        text_fn = getattr(resp, "text", None)
        if not callable(text_fn):
            return
        try:
            body = str(await text_fn() or "")
        except Exception:  # noqa: BLE001
            return
        match = _UVRESP_RE.search(body)
        if match:
            self.token = match.group(1)

    def __enter__(self) -> "_UvrespTracker":
        on_fn = getattr(self._page, "on", None)
        if callable(on_fn):
            on_fn("response", self._on_response)
            self._attached = True
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._attached:
            rem_fn = getattr(self._page, "remove_listener", None)
            if callable(rem_fn):
                try:
                    rem_fn("response", self._on_response)
                except Exception:  # noqa: BLE001
                    pass
            self._attached = False
        for task in list(self._tasks):
            if not task.done():
                task.cancel()


async def _solve_bframe_via_audio(
    page: Any,
    bframe: Any,
    *,
    tracker: _UvrespTracker,
    kmouse: KinematicMouse,
    proxy: str | None = None,
    max_rounds: int = 4,
    detect_challenge_fn: Any = None,
) -> AutoSolveOutcome:
    loc_fn = getattr(bframe, "locator", None)
    if not callable(loc_fn):
        return AutoSolveOutcome(solved=False, error="bframe has no locator API")

    if await _bframe_rate_limited(bframe):
        return AutoSolveOutcome(
            solved=False, error="reCAPTCHA audio challenge is rate-limited"
        )

    audio_input = loc_fn("#audio-response").first
    if not await _locator_visible(audio_input):
        audio_btn = loc_fn("#recaptcha-audio-button").first
        if not await _locator_visible(audio_btn):
            return AutoSolveOutcome(
                solved=False, error="audio challenge button is not available"
            )
        await asyncio.sleep(random.uniform(0.35, 0.7))
        await _human_click_locator(page, audio_btn, kmouse=kmouse)

        switch_deadline = time.monotonic() + 5.5
        while time.monotonic() < switch_deadline:
            if await _bframe_rate_limited(bframe):
                img_btn = loc_fn("#recaptcha-image-button").first
                if await _locator_visible(img_btn):
                    await _human_click_locator(page, img_btn, kmouse=kmouse)
                return AutoSolveOutcome(
                    solved=False,
                    error="reCAPTCHA audio challenge blocked with dOScaptcha",
                )
            if (
                await _locator_visible(audio_input)
                or await _extract_bframe_audio_url(bframe) is not None
            ):
                break
            await asyncio.sleep(0.2)

    language = _audio_language_for_frame_url(str(getattr(bframe, "url", "") or ""))
    seen_urls: set[str] = set()

    for round_idx in range(max_rounds):
        if await _bframe_rate_limited(bframe):
            img_btn = loc_fn("#recaptcha-image-button").first
            if await _locator_visible(img_btn):
                await _human_click_locator(page, img_btn, kmouse=kmouse)
            return AutoSolveOutcome(
                solved=False,
                rounds=round_idx,
                error="reCAPTCHA audio challenge rate-limited mid-solve",
            )

        audio_url: str | None = None
        url_deadline = time.monotonic() + 4.5
        while time.monotonic() < url_deadline:
            candidate = await _extract_bframe_audio_url(bframe)
            if candidate and candidate not in seen_urls:
                audio_url = candidate
                break
            await asyncio.sleep(0.2)

        if not audio_url:
            reload_btn = loc_fn("#recaptcha-reload-button").first
            if await _locator_visible(reload_btn):
                await _human_click_locator(page, reload_btn, kmouse=kmouse)
                await asyncio.sleep(0.8)
                audio_url = await _extract_bframe_audio_url(bframe)
        if not audio_url:
            return AutoSolveOutcome(
                solved=False,
                rounds=round_idx,
                error="could not locate audio MP3 URL in bframe",
            )
        seen_urls.add(audio_url)

        play_started = time.monotonic()
        play_btn = loc_fn(".rc-audiochallenge-play-button button").first
        if await _locator_visible(play_btn):
            await _human_click_locator(page, play_btn, kmouse=kmouse)

        raw_audio = await _download_audio_bytes(page, audio_url, proxy=proxy)
        pcm_le = (
            await decode_mp3_via_browser_webaudio(page, raw_audio)
            if raw_audio
            else None
        )
        transcript_raw = (
            await transcribe_pcm16_google(pcm_le, language=language, proxy=proxy)
            if pcm_le
            else None
        )
        if not transcript_raw and language != "en-US" and pcm_le:
            transcript_raw = await transcribe_pcm16_google(
                pcm_le, language="en-US", proxy=proxy
            )
        transcript = _normalize_audio_transcript(transcript_raw)

        if not transcript:
            reload_btn = loc_fn("#recaptcha-reload-button").first
            if await _locator_visible(reload_btn):
                await _human_click_locator(page, reload_btn, kmouse=kmouse)
                await asyncio.sleep(0.7)
            continue

        elapsed_listen = time.monotonic() - play_started
        min_listen = random.uniform(1.35, 1.95)
        if elapsed_listen < min_listen:
            await asyncio.sleep(min_listen - elapsed_listen)

        await _human_type_into_locator(
            page, loc_fn("#audio-response").first, transcript, kmouse=kmouse
        )
        await asyncio.sleep(random.uniform(0.18, 0.34))
        verify_btn = loc_fn("#recaptcha-verify-button").first
        await _human_click_locator(page, verify_btn, kmouse=kmouse)

        verify_deadline = time.monotonic() + 5.5
        while time.monotonic() < verify_deadline:
            await asyncio.sleep(0.22)
            if tracker.token:
                return AutoSolveOutcome(
                    solved=True,
                    method="browser_audio",
                    token=tracker.token,
                    rounds=round_idx + 1,
                )
            if callable(getattr(bframe, "is_detached", None)) and bframe.is_detached():
                return AutoSolveOutcome(
                    solved=True,
                    method="browser_audio",
                    token=tracker.token,
                    rounds=round_idx + 1,
                )
            if await _anchor_is_checked(page):
                return AutoSolveOutcome(
                    solved=True,
                    method="browser_audio",
                    token=tracker.token,
                    rounds=round_idx + 1,
                )
            if callable(detect_challenge_fn):
                obs_now = await detect_challenge_fn(page)
                if isinstance(obs_now, Mapping) and not obs_now.get("kind"):
                    return AutoSolveOutcome(
                        solved=True,
                        method="browser_audio",
                        token=tracker.token,
                        rounds=round_idx + 1,
                    )
            if await _bframe_rate_limited(bframe):
                break
            next_url = await _extract_bframe_audio_url(bframe)
            if next_url and next_url not in seen_urls:
                break
            err_msg = loc_fn(".rc-audiochallenge-error-message").first
            if await _locator_visible(err_msg):
                reload_btn = loc_fn("#recaptcha-reload-button").first
                if await _locator_visible(reload_btn):
                    await _human_click_locator(page, reload_btn, kmouse=kmouse)
                break

    return AutoSolveOutcome(
        solved=False,
        rounds=max_rounds,
        error="exhausted audio challenge rounds without verification",
    )


def _match_capsolver_object_id(prompt_text: str) -> str | None:
    lowered = prompt_text.lower()
    for obj_id, keywords in _CAPSOLVER_TASK_OBJECTS.items():
        if any(kw in lowered for kw in keywords):
            return obj_id
    return None


async def _solve_bframe_via_capsolver(
    page: Any,
    bframe: Any,
    *,
    api_key: str,
    tracker: _UvrespTracker,
    kmouse: KinematicMouse,
    proxy: str | None = None,
    max_rounds: int = 5,
    detect_challenge_fn: Any = None,
) -> AutoSolveOutcome:
    loc_fn = getattr(bframe, "locator", None)
    if not callable(loc_fn):
        return AutoSolveOutcome(solved=False, error="bframe has no locator API")

    img_btn = loc_fn("#recaptcha-image-button").first
    if await _locator_visible(img_btn):
        await _human_click_locator(page, img_btn, kmouse=kmouse)
        await asyncio.sleep(0.8)

    for round_idx in range(max_rounds):
        prompt_text = ""
        for sel in (
            ".rc-imageselect-desc-no-canonical",
            ".rc-imageselect-desc",
            ".rc-imageselect-desc-wrapper",
            ".rc-imageselect-instructions",
        ):
            loc = loc_fn(sel).first
            if await _locator_visible(loc):
                try:
                    prompt_text = str(await loc.inner_text() or "")
                    if prompt_text.strip():
                        break
                except Exception:  # noqa: BLE001
                    continue

        obj_id = _match_capsolver_object_id(prompt_text)
        img_url = None
        for img_sel in (
            ".rc-imageselect-challenge img",
            ".rc-imageselect-target img",
        ):
            img_loc = loc_fn(img_sel).first
            try:
                candidate_url = await img_loc.get_attribute("src")
                if isinstance(candidate_url, str) and candidate_url:
                    img_url = candidate_url
                    break
            except Exception:  # noqa: BLE001
                continue

        if not obj_id or not isinstance(img_url, str) or not img_url:
            reload_btn = loc_fn("#recaptcha-reload-button").first
            if await _locator_visible(reload_btn):
                await _human_click_locator(page, reload_btn, kmouse=kmouse)
                await asyncio.sleep(0.9)
                continue
            return AutoSolveOutcome(
                solved=False, error="unrecognized visual challenge prompt or image"
            )

        img_bytes = await _download_audio_bytes(page, img_url, proxy=proxy)
        if not img_bytes:
            return AutoSolveOutcome(
                solved=False, error="failed to download challenge grid image"
            )

        payload = {
            "clientKey": api_key,
            "task": {
                "type": "ReCaptchaV2Classification",
                "image": base64.b64encode(img_bytes).decode("ascii"),
                "question": obj_id,
            },
        }
        try:
            async with httpx.AsyncClient(
                proxy=proxy, timeout=20.0, trust_env=False
            ) as client:
                resp = await client.post(
                    "https://api.capsolver.com/createTask", json=payload
                )
            data = resp.json()
        except Exception as exc:  # noqa: BLE001
            return AutoSolveOutcome(solved=False, error=f"CapSolver error: {exc}")

        if not isinstance(data, Mapping) or int(data.get("errorId", 1)) != 0:
            desc = data.get("errorDescription") if isinstance(data, Mapping) else data
            return AutoSolveOutcome(solved=False, error=f"CapSolver rejected: {desc}")

        solution = data.get("solution")
        raw_objects = (
            solution.get("objects") if isinstance(solution, Mapping) else None
        )
        indexes: Sequence[Any] = (
            raw_objects
            if isinstance(raw_objects, Sequence)
            and not isinstance(raw_objects, (str, bytes))
            else ()
        )
        tiles = loc_fn(".rc-imageselect-tile")
        for idx in indexes:
            if isinstance(idx, int):
                await _human_click_locator(page, tiles.nth(idx), kmouse=kmouse)
                await asyncio.sleep(random.uniform(0.12, 0.28))

        verify_btn = loc_fn("#recaptcha-verify-button").first
        await _human_click_locator(page, verify_btn, kmouse=kmouse)
        await asyncio.sleep(1.2)

        if (
            tracker.token
            or (callable(getattr(bframe, "is_detached", None)) and bframe.is_detached())
            or await _anchor_is_checked(page)
        ):
            return AutoSolveOutcome(
                solved=True,
                method="capsolver_image",
                token=tracker.token,
                rounds=round_idx + 1,
            )
        if callable(detect_challenge_fn):
            obs_now = await detect_challenge_fn(page)
            if isinstance(obs_now, Mapping) and not obs_now.get("kind"):
                return AutoSolveOutcome(
                    solved=True,
                    method="capsolver_image",
                    token=tracker.token,
                    rounds=round_idx + 1,
                )

    return AutoSolveOutcome(
        solved=False,
        rounds=max_rounds,
        error="exhausted CapSolver visual rounds",
    )


async def auto_solve_challenge_on_page(
    page: Any,
    obs: Mapping[str, Any],
    *,
    detect_challenge_fn: Any = None,
    proxy: str | None = None,
    capsolver_api_key: str | None = None,
    toolkit_solver: Any = None,
    status_stream: TextIO | None = None,
    max_audio_rounds: int = 4,
) -> AutoSolveOutcome:
    """Automatically solve a detected post-submit challenge on ``page``.

    1. Clicks visible checkboxes (``recaptcha_anchor``, ``turnstile``,
       ``hcaptcha``) with human pointer trajectories.
    2. When a reCAPTCHA ``bframe`` challenge is open, solves it automatically
       via Chromium WebAudio MP3 decoding + pure-Python FLAC + Google Speech
       HTTPS (zero FFmpeg required), falling back to CapSolver image
       classification (when ``CAPSOLVER_API_KEY`` is set) or ``vision_ai``.
    """
    kind = str(obs.get("kind") or "")
    if not kind:
        return AutoSolveOutcome(solved=True, method="none")

    kmouse = KinematicMouse(page)
    resolved_capsolver_key = (
        capsolver_api_key
        or os.environ.get("CAPSOLVER_API_KEY")
        or None
    )

    with _UvrespTracker(page) as tracker:
        if kind in ("recaptcha_anchor", "turnstile", "hcaptcha"):
            already_checked = (
                await _anchor_is_checked(page)
                if kind == "recaptcha_anchor"
                else False
            )
            if not already_checked:
                x = float(obs.get("x") or 0.0)
                y = float(obs.get("y") or 0.0)
                await asyncio.sleep(random.uniform(0.28, 0.55))
                clicked = False
                if x > 0 and y > 0:
                    clicked = await _human_click_point(page, x, y, kmouse=kmouse)
                if not clicked and kind == "recaptcha_anchor":
                    for frame in getattr(page, "frames", None) or ():
                        f_url = str(getattr(frame, "url", "") or "")
                        if (
                            "recaptcha" in f_url
                            and "anchor" in f_url
                            and "size=invisible" not in f_url
                        ):
                            loc_fn = getattr(frame, "locator", None)
                            if callable(loc_fn):
                                clicked = await _human_click_locator(
                                    page, loc_fn("#recaptcha-anchor").first, kmouse=kmouse
                                )
                                if clicked:
                                    break

            wait_fn = getattr(page, "wait_for_timeout", None)
            if callable(wait_fn):
                await wait_fn(800)
            else:
                await asyncio.sleep(0.8)

            if tracker.token or (
                kind == "recaptcha_anchor" and await _anchor_is_checked(page)
            ):
                return AutoSolveOutcome(
                    solved=True,
                    method="checkbox",
                    token=tracker.token,
                    rounds=1,
                )

            if callable(detect_challenge_fn):
                next_obs = await detect_challenge_fn(page)
                next_kind = (
                    str(next_obs.get("kind") or "")
                    if isinstance(next_obs, Mapping)
                    else ""
                )
                if not next_kind:
                    return AutoSolveOutcome(
                        solved=True,
                        method="checkbox",
                        token=tracker.token,
                        rounds=1,
                    )
                kind = next_kind

        if kind != "recaptcha_bframe":
            return AutoSolveOutcome(
                solved=False,
                error=f"interactive challenge {kind!r} stayed open after checkbox click",
            )

        bframe = await _find_active_recaptcha_bframe(page)
        if bframe is None:
            return AutoSolveOutcome(
                solved=False,
                error="recaptcha_bframe detected in DOM, but Frame handle was not found",
            )

        if status_stream is not None:
            print(
                "[arena-api] обнаружена капча — выполняется авторешение...",
                file=status_stream,
                flush=True,
            )

        audio_outcome = await _solve_bframe_via_audio(
            page,
            bframe,
            tracker=tracker,
            kmouse=kmouse,
            proxy=proxy,
            max_rounds=max_audio_rounds,
            detect_challenge_fn=detect_challenge_fn,
        )
        if audio_outcome.solved:
            if status_stream is not None:
                print(
                    "[arena-api] капча решена автоматически!",
                    file=status_stream,
                    flush=True,
                )
            return audio_outcome

        if resolved_capsolver_key:
            bframe_img = await _find_active_recaptcha_bframe(page) or bframe
            img_outcome = await _solve_bframe_via_capsolver(
                page,
                bframe_img,
                api_key=resolved_capsolver_key,
                tracker=tracker,
                kmouse=kmouse,
                proxy=proxy,
                detect_challenge_fn=detect_challenge_fn,
            )
            if img_outcome.solved:
                if status_stream is not None:
                    print(
                        "[arena-api] капча решена автоматически (CapSolver)!",
                        file=status_stream,
                        flush=True,
                    )
                return img_outcome

        if toolkit_solver is not None and str(
            getattr(toolkit_solver, "backend", "")
        ) == "vision_ai":
            asolve_fn = getattr(toolkit_solver, "asolve", None)
            if callable(asolve_fn):
                try:
                    attempt = await asolve_fn(page)
                    if getattr(attempt, "ok", False):
                        if status_stream is not None:
                            print(
                                "[arena-api] капча решена автоматически (Vision AI)!",
                                file=status_stream,
                                flush=True,
                            )
                        return AutoSolveOutcome(
                            solved=True,
                            method="vision_ai",
                            token=getattr(attempt, "token", None) or tracker.token,
                            rounds=1,
                        )
                except Exception:  # noqa: BLE001
                    pass

        return audio_outcome


@dataclass
class BrowserChallengeAutoSolver:
    """``CaptchaSolver`` implementation backed by :func:`auto_solve_challenge_on_page`."""

    proxy: str | None = None
    capsolver_api_key: str | None = None
    max_audio_rounds: int = 4
    backend: str = "autosolve"

    def describe(self) -> str:
        return f"BrowserChallengeAutoSolver(backend={self.backend!r})"

    def supports(self, observation: Any) -> bool:
        from .challenge import ChallengeKind

        kind = getattr(observation, "kind", None)
        if kind is not None:
            return kind in (
                ChallengeKind.RECAPTCHA,
                ChallengeKind.TURNSTILE,
                ChallengeKind.HCAPTCHA,
                ChallengeKind.CLOUDFLARE_MANAGED,
            )
        return bool(getattr(observation, "is_challenge", True))

    async def asolve(self, page: Any, observation: Any = None) -> Any:
        from .captcha import CaptchaAttempt

        started = time.perf_counter()
        bframe = await _find_active_recaptcha_bframe(page)
        kind = "recaptcha_bframe" if bframe is not None else "recaptcha_anchor"
        outcome = await auto_solve_challenge_on_page(
            page,
            {"kind": kind},
            proxy=self.proxy,
            capsolver_api_key=self.capsolver_api_key,
            max_audio_rounds=self.max_audio_rounds,
        )
        backend_label = (
            f"{self.backend}:{outcome.method}" if outcome.method else self.backend
        )
        return CaptchaAttempt(
            token=outcome.token,
            cleared=outcome.solved,
            backend=backend_label,
            version="v2",
            duration=time.perf_counter() - started,
            error=None if outcome.solved else (outcome.error or "autosolve failed"),
            observation=observation,
        )

    def solve(self, page: Any, observation: Any = None) -> Any:
        from .browser import run_sync

        return run_sync(self.asolve(page, observation))


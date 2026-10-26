"""Тесты ``recaptcha_toolkit``, не требующие браузера и сетевых зависимостей.

Проверяется «чистая» логика пакета: конфигурация, построение stealth-скриптов,
преобразование ошибок и автоопределение site key. Всё, что требует реального
браузера, вынесено в примеры.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arena_api._vendor.recaptcha_toolkit import (
    BrowserOptions,
    CaptchaError,
    PlaywrightSolverOptions,
    RecaptchaNotFoundError,
    RecaptchaRateLimitError,
    RecaptchaSolveError,
    RecaptchaTimeoutError,
    SeleniumSolverOptions,
    SeleniumStealthOptions,
    SiteKeyDetectionError,
    SolverBackend,
    SolverDependencyError,
    StealthOptions,
    VisionAIOptions,
)
from arena_api._vendor.recaptcha_toolkit.errors import (
    require_dependency,
    translate_playwright_recaptcha_error,
    translate_selenium_error,
    translate_vision_ai_error,
)
from arena_api._vendor.recaptcha_toolkit.playwright_bot import _run_key_detection, detect_site_key
from arena_api._vendor.recaptcha_toolkit.stealth import build_browser_launch_kwargs, build_context_kwargs


# --------------------------------------------------------------------- конфиг


def test_backend_accepts_string_values() -> None:
    """Бэкенд можно задать строкой — конфиг часто приходит из ENV/YAML."""
    assert SolverBackend("audio") is SolverBackend.AUDIO
    assert SolverBackend("vision_ai") is SolverBackend.VISION_AI
    assert SolverBackend.AUDIO == "audio"


def test_solver_options_reject_bad_attempts() -> None:
    """Некорректные значения отлавливаются на этапе создания конфига."""
    with pytest.raises(ValueError):
        PlaywrightSolverOptions(attempts=0)

    with pytest.raises(ValueError):
        PlaywrightSolverOptions(wait_timeout=0)


def test_selenium_solver_options_reject_bad_timeout() -> None:
    """Таймаут iframe должен быть положительным."""
    with pytest.raises(ValueError):
        SeleniumSolverOptions(iframe_timeout=-1)


def test_vision_options_skip_none_values() -> None:
    """``None`` не попадает в SolverConfig — там свои дефолты."""
    kwargs = VisionAIOptions(timeout=120).to_solver_config_kwargs()
    assert kwargs["timeout"] == 120
    assert "proxy" not in kwargs
    assert "browser_path" not in kwargs
    assert "download_dir" not in kwargs


def test_vision_options_include_download_dir_when_set(tmp_path: Path) -> None:
    """Заданный ``download_dir`` превращается в ``Path``."""
    kwargs = VisionAIOptions(download_dir=tmp_path).to_solver_config_kwargs()
    assert kwargs["download_dir"] == tmp_path


# ---------------------------------------------------------------- маскировка


def test_selenium_stealth_script_hides_webdriver() -> None:
    """Ключевая проверка: скрипт прячет navigator.webdriver."""
    script = SeleniumStealthOptions().build_init_script()
    assert "webdriver" in script
    assert "return undefined" in script


def test_selenium_stealth_script_sets_languages_and_platform() -> None:
    """Языки и платформа должны подменяться согласованно с UA."""
    script = SeleniumStealthOptions(languages=("ru-RU", "ru")).build_init_script()
    assert "'ru-RU'" in script
    assert "'Win32'" in script


def test_selenium_stealth_can_be_disabled() -> None:
    """Отключённая маскировка не должна ничего подменять."""
    options = SeleniumStealthOptions(hide_webdriver=False)
    script = options.build_init_script()
    assert "webdriver" not in script


def test_launch_kwargs_parse_proxy_with_credentials() -> None:
    """Прокси с логином/паролем разбирается в формат Playwright."""
    kwargs = build_browser_launch_kwargs(
        BrowserOptions(proxy="http://user:pw@1.2.3.4:8080"), stealth=StealthOptions()
    )
    assert kwargs["proxy"] == {
        "server": "http://1.2.3.4:8080",
        "username": "user",
        "password": "pw",
    }


def test_launch_kwargs_drop_chromium_args_for_firefox() -> None:
    """Firefox не понимает Chromium-флаги — они должны отбрасываться."""
    from arena_api._vendor.recaptcha_toolkit.playwright_bot import _PlaywrightBotBase

    bot = _PlaywrightBotBase.__new__(_PlaywrightBotBase)
    bot._browser_opts = BrowserOptions(browser_type="firefox")
    bot._stealth_opts = StealthOptions()
    assert "args" not in bot._launch_kwargs()


def test_context_kwargs_include_user_agent_only_when_set() -> None:
    """UA в контексте задаётся только если он задан явно."""
    assert "user_agent" not in build_context_kwargs(StealthOptions(), BrowserOptions())
    kwargs = build_context_kwargs(
        StealthOptions(navigator_user_agent="Custom/1.0"), BrowserOptions()
    )
    assert kwargs["user_agent"] == "Custom/1.0"


# ------------------------------------------------------------------- ошибки


@pytest.mark.parametrize(
    ("class_name", "expected"),
    [
        ("RecaptchaNotFoundError", RecaptchaNotFoundError),
        ("RecaptchaRateLimitError", RecaptchaRateLimitError),
        ("RecaptchaTimeoutError", RecaptchaTimeoutError),
        ("RecaptchaSolveError", RecaptchaSolveError),
        ("CapSolverError", RecaptchaSolveError),
        ("SomethingWeird", RecaptchaSolveError),
    ],
)
def test_translate_playwright_errors(class_name: str, expected: type) -> None:
    """Исключения playwright-recaptcha отображаются на наши классы."""
    exc = type(class_name, (Exception,), {})("boom")
    translated = translate_playwright_recaptcha_error(exc, backend="test")
    assert isinstance(translated, expected)
    assert isinstance(translated, CaptchaError)
    # Первопричина не теряется.
    assert translated.__cause__ is exc


def test_translate_vision_ai_errors() -> None:
    """Типовые ошибки YOLO-солвера распознаются по имени класса."""
    not_found = type("CaptchaNotFoundError", (Exception,), {})("no captcha")
    assert isinstance(translate_vision_ai_error(not_found), RecaptchaNotFoundError)

    timeout = type("SolverTimeoutError", (Exception,), {})("timeout")
    assert isinstance(translate_vision_ai_error(timeout), RecaptchaTimeoutError)


def test_translate_selenium_rate_limit_is_detected() -> None:
    """Фраза про автоматические запросы превращается в rate-limit ошибку."""
    exc = type("RecaptchaException", (Exception,), {})(
        "Google has detected automated queries. Try again later."
    )
    assert isinstance(
        translate_selenium_error(exc, where="click"), RecaptchaRateLimitError
    )


def test_translate_selenium_timeout_is_not_found() -> None:
    """TimeoutException при поиске iframe — это «виджет не найден»."""
    exc = type("TimeoutException", (Exception,), {})("timed out")
    assert isinstance(
        translate_selenium_error(exc, where="find"), RecaptchaNotFoundError
    )


def test_require_dependency_raises_typed_error() -> None:
    """Отсутствие пакета даёт понятную ошибку с подсказкой по установке."""
    with pytest.raises(SolverDependencyError) as info:
        require_dependency("definitely_not_installed_pkg", "some-pkg", extra="captcha")

    assert info.value.package == "some-pkg"
    assert info.value.extra == "captcha"
    assert "some-pkg" in str(info.value)


# ------------------------------------------------------------ site key / токен


def test_run_key_detection_falls_back_to_url() -> None:
    """Если JS вернул пусто, ключ достаётся из URL iframe."""
    key = _run_key_detection(None, "https://www.google.com/recaptcha/api2/anchor?k=ABC123")
    assert key == "ABC123"


def test_run_key_detection_prefers_js_result() -> None:
    """Результат JS приоритетнее разбора URL."""
    assert _run_key_detection("  FROM_JS  ", "https://x/?k=FROM_URL") == "FROM_JS"


def test_run_key_detection_returns_none_when_nothing_found() -> None:
    """Когда ключа нет нигде — возвращается None, а не пустая строка."""
    assert _run_key_detection("", "https://example.com/") is None


class _FakePage:
    """Минимальная заглушка страницы Playwright."""

    def __init__(self, url: str, evaluate_result: str | None) -> None:
        self.url = url
        self._evaluate_result = evaluate_result

    def evaluate(self, _script: str) -> str | None:
        return self._evaluate_result


def test_detect_site_key_uses_page_script() -> None:
    """Site key берётся из результата JS на странице."""
    page = _FakePage("https://example.com/", "6Le-wvkSVVABCPBMRTvw0Q4Muexq1bi0DJwx_mJ-")
    assert detect_site_key(page) == "6Le-wvkSVVABCPBMRTvw0Q4Muexq1bi0DJwx_mJ-"


def test_detect_site_key_raises_when_missing() -> None:
    """Отсутствие ключа — отдельная, понятная ошибка."""
    page = _FakePage("https://example.com/", None)
    with pytest.raises(SiteKeyDetectionError):
        detect_site_key(page)


# ------------------------------------------------------------- интеграция бота


def test_playwright_bot_requires_context_manager() -> None:
    """Попытка создать страницу без запуска — явная RuntimeError."""
    from arena_api._vendor.recaptcha_toolkit import PlaywrightBot

    bot = PlaywrightBot()
    with pytest.raises(RuntimeError):
        bot.new_page()


def test_selenium_bot_rejects_vision_backend() -> None:
    """YOLO-солвер недоступен для Selenium и падает сразу при конструировании."""
    from arena_api._vendor.recaptcha_toolkit import SeleniumBot

    with pytest.raises(ValueError, match="VISION_AI"):
        SeleniumBot(driver=None, backend=SolverBackend.VISION_AI)  # type: ignore[arg-type]


def test_close_is_idempotent() -> None:
    """Повторный close() не должен бросать."""
    from arena_api._vendor.recaptcha_toolkit import PlaywrightBot

    bot = PlaywrightBot()
    bot.close()
    bot.close()

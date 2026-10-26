"""Конфигурационные объекты :mod:`recaptcha_toolkit`.

Всё переключение между солверами и режимами маскировки сделано через
dataclass'ы: код бота не меняется, меняется только конфигурация.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Sequence


class SolverBackend(str, Enum):
    """Какой солвер использовать для reCAPTCHA v2.

    Значения совместимы со ``str`` (``SolverBackend.AUDIO == "audio"``),
    поэтому бэкенд можно задавать строкой из конфиг-файла.
    """

    #: ``playwright-recaptcha``: аудио-челлендж + Google Speech API.
    #: Не требует внешних сервисов, но нужен установленный FFmpeg.
    AUDIO = "audio"

    #: ``playwright-recaptcha``: image-челлендж через CapSolver API.
    #: Требует ключ ``capsolver_api_key`` (или переменную ``CAPSOLVER_API_KEY``).
    IMAGE = "image"

    #: ``VisionAIRecaptchaSolver-0``: локальные YOLO-модели, v2 и v3.
    #: Работает полностью офлайн, но сам поднимает отдельный браузер.
    VISION_AI = "vision_ai"


class RecaptchaVersion(str, Enum):
    """Версия reCAPTCHA."""

    V2 = "v2"
    V3 = "v3"


# Актуальный «не headless» User-Agent. Именно на таком виде строки настаивает
# документация selenium-recaptcha-solver: любой UA с подстрокой Headless
# поднимает риск детекта на порядок.
DEFAULT_CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


@dataclass(frozen=True)
class StealthOptions:
    """Маскировка автоматизации в Playwright (обёртка над ``playwright-stealth``).

    :param enabled: применять ли stealth-скрипты вообще.
    :param navigator_webdriver: подменить ``navigator.webdriver`` на ``undefined``.
    :param navigator_languages: значения ``navigator.languages``.
    :param navigator_user_agent: подменить ``navigator.userAgent``;
        ``None`` — оставить нативное значение браузера.
    :param platform_override: значение ``navigator.platform``.
    :param vendor_override: значение ``navigator.vendor``.
    :param locale: локаль контекста Playwright (влияет на ``Accept-Language``).
    :param timezone_id: таймзона контекста (``Europe/Moscow``, ``UTC``, ...).
    :param init_scripts_only: передать в ``Stealth`` — не патчить CLI-аргументы
        браузера, только init-скрипты. Полезно с уже запущенным Chromium.
    """

    enabled: bool = True
    navigator_webdriver: bool = True
    navigator_languages: tuple[str, ...] = ("en-US", "en")
    navigator_user_agent: str | None = None
    platform_override: str = "Win32"
    vendor_override: str = "Google Inc."
    locale: str = "en-US"
    timezone_id: str = "America/New_York"
    init_scripts_only: bool = False


@dataclass(frozen=True)
class BrowserOptions:
    """Параметры запуска браузера (общие для Playwright и Selenium).

    :param headless: запускать без GUI. Для аудио-солвера headless допустим,
        но для ``SolverBackend.VISION_AI`` надёжнее ``headless=False``.
    :param channel: канал Playwright (``"chrome"``, ``"msedge"``, ``None``).
    :param proxy: прокси в формате ``protocol://[user:pass@]host:port``.
    :param extra_args: дополнительные CLI-аргументы браузера.
    :param slow_mo: задержка между действиями Playwright, мс.
    :param timeout: таймаут по умолчанию для операций Playwright, мс.
    :param viewport: размер окна ``{"width": .., "height": ..}``.
    :param browser_type: какой движок Playwright использовать
        (``chromium`` / ``firefox`` / ``webkit``). Для аудио-солвера
        ``playwright-recaptcha`` рекомендует ``firefox``.
    """

    headless: bool = False
    channel: str | None = None
    proxy: str | None = None
    extra_args: tuple[str, ...] = ()
    slow_mo: int = 0
    timeout: float | None = None
    viewport: dict[str, int] | None = None
    browser_type: str = "chromium"


@dataclass(frozen=True)
class PlaywrightSolverOptions:
    """Параметры солвера ``playwright-recaptcha``.

    :param attempts: сколько раз перерешать челлендж перед сдачей.
    :param capsolver_api_key: ключ CapSolver для ``SolverBackend.IMAGE``;
        ``None`` — берётся переменная окружения ``CAPSOLVER_API_KEY``.
    :param image_challenge: решать image-челлендж вместо аудио.
    :param wait: ждать появления виджета на странице.
    :param wait_timeout: сколько секунд ждать появления виджета.
    :param v3_timeout: таймаут перехвата токена для reCAPTCHA v3, сек.
    """

    attempts: int = 5
    capsolver_api_key: str | None = None
    image_challenge: bool = False
    wait: bool = True
    wait_timeout: float = 30.0
    v3_timeout: float = 30.0

    def __post_init__(self) -> None:
        """Провалидировать значения, чтобы падать рано, а не в середине решения."""
        if self.attempts < 1:
            raise ValueError("attempts должен быть >= 1")
        if self.wait_timeout <= 0 or self.v3_timeout <= 0:
            raise ValueError("таймауты должны быть положительными")


@dataclass(frozen=True)
class VisionAIOptions:
    """Параметры YOLO-солвера ``VisionAIRecaptchaSolver-0``.

    Значения повторяют ``SolverConfig`` исходной библиотеки; поля, которые там
    отсутствуют, просто не пробрасываются.

    :param timeout: максимум секунд на решение.
    :param headless: headless-режим внутреннего Chromium.
    :param server_port: локальный HTTPS-порт репликатора домена. Для
        параллельных солверов каждому нужен свой порт.
    :param download_dir: каталог для скачанных изображений.
    :param proxy: прокси ``protocol://[user:pass@]host:port``.
    :param browser_path: путь к Chromium/Chrome, если автоопределение не сработало.
    :param model_path: путь к ONNX-модели классификации (по умолчанию
        скачивается с Hugging Face).
    :param detection_model_path: путь к модели детекции (по умолчанию ``yolo12x.pt``).
    :param max_attempts: максимум попыток на один челлендж.
    :param conf_threshold: порог уверенности классификации плиток.
    :param log_level: уровень логирования библиотеки.
    :param is_invisible: невидимая reCAPTCHA (v3-поток).
    :param action: ``action`` для невидимой reCAPTCHA (``"login"``, ...).
    :param is_enterprise: использовать enterprise-эндпоинт.
    :param api_domain: ``google.com`` или ``recaptcha.net``.
    :param user_agent: User-Agent для внутреннего браузера.
    """

    timeout: float = 180.0
    headless: bool = False
    server_port: int = 8443
    download_dir: Path | None = None
    proxy: str | None = None
    browser_path: str | None = None
    model_path: str | None = None
    detection_model_path: str | None = None
    max_attempts: int = 12
    conf_threshold: float = 0.7
    log_level: str = "WARNING"
    is_invisible: bool = False
    action: str | None = None
    is_enterprise: bool = False
    api_domain: str = "google.com"
    user_agent: str | None = None

    def to_solver_config_kwargs(self) -> dict[str, Any]:
        """Собрать kwargs для конструктора ``SolverConfig``.

        Пропускаются только ``None``-значения: у ``SolverConfig`` свои
        дефолты, и подсовывать ему ``None`` вместо них нельзя.

        :returns: словарь kwargs, готовый к ``SolverConfig(**kwargs)``.
        """
        raw: dict[str, Any] = {
            "timeout": self.timeout,
            "headless": self.headless,
            "server_port": self.server_port,
            "proxy": self.proxy,
            "browser_path": self.browser_path,
            "model_path": self.model_path,
            "detection_model_path": self.detection_model_path,
            "max_attempts": self.max_attempts,
            "conf_threshold": self.conf_threshold,
            "log_level": self.log_level,
        }
        if self.download_dir is not None:
            raw["download_dir"] = Path(self.download_dir)
        return {key: value for key, value in raw.items() if value is not None}


@dataclass(frozen=True)
class SeleniumStealthOptions:
    """Маскировка автоматизации для Selenium.

    Selenium в отличие от Playwright не умеет «из коробки» прятать
    ``navigator.webdriver``, поэтому используется CDP-хук
    ``Page.addScriptToEvaluateOnNewDocument`` плюс набор CLI-флагов Chrome.

    :param enabled: применять ли маскировку.
    :param user_agent: User-Agent. Обязательно «не headless» — см.
        :data:`DEFAULT_CHROME_UA`.
    :param languages: языки для ``navigator.languages`` и ``Accept-Language``.
    :param platform: значение ``navigator.platform``.
    :param hide_webdriver: удалить ``navigator.webdriver``.
    :param hide_automation_flags: убрать флаг ``--enable-automation`` и
        связанные с ним свойства (``window.cdc_*``, ``domAutomation``).
    :param extra_js: дополнительный JS, который выполнится до загрузки страницы.
    """

    enabled: bool = True
    user_agent: str = DEFAULT_CHROME_UA
    languages: tuple[str, ...] = ("en-US", "en")
    platform: str = "Win32"
    hide_webdriver: bool = True
    hide_automation_flags: bool = True
    extra_js: str = ""

    def build_init_script(self) -> str:
        """Собрать JS, который выполнится до загрузки любой страницы.

        :returns: исходный текст скрипта для CDP.
        """

        def js_array(values: Sequence[str]) -> str:
            return "[" + ", ".join(repr(value) for value in values) + "]"

        parts: list[str] = [
            "(function () {",
            f"  const languages = {js_array(self.languages)};",
        ]

        if self.hide_webdriver:
            # Самый массовый признак автоматизации: Selenium выставляет его в true.
            parts.append(
                "  Object.defineProperty(Object.getPrototypeOf(navigator), 'webdriver', {"
                "get: function () { return undefined; }, configurable: true});"
            )
            parts.append(
                "  Object.defineProperty(navigator, 'webdriver', {"
                "get: function () { return undefined; }, configurable: true});"
            )

        # Языки и платформа должны совпадать с Accept-Language и реальным UA,
        # иначе расхождение само по себе становится сигналом детекта.
        parts.append(
            "  Object.defineProperty(navigator, 'languages', {"
            "get: function () { return " + js_array(self.languages) + "; }, configurable: true});"
        )
        parts.append(
            f"  Object.defineProperty(navigator, 'platform', {{"
            f"get: function () {{ return {self.platform!r}; }}, configurable: true}});"
        )
        parts.append(
            "  Object.defineProperty(navigator, 'plugins', {"
            "get: function () { return {length: 5}; }, configurable: true});"
        )

        if self.hide_automation_flags:
            parts.extend(
                [
                    "  window.chrome = window.chrome || { runtime: {} };",
                    "  delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;",
                    "  delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;",
                    "  delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;",
                    "  try { delete document.$cdc_asdjflasutopfhvcZLmcfl_; } catch (e) {}",
                    "  try { delete document.$chrome_asyncScriptInfo; } catch (e) {}",
                ]
            )

        if self.user_agent:
            parts.append(
                f"  Object.defineProperty(navigator, 'userAgent', {{"
                f"get: function () {{ return {self.user_agent!r}; }}, configurable: true}});"
            )

        if self.extra_js:
            parts.append("  " + self.extra_js)

        parts.append("})();")
        return "\n".join(parts)


@dataclass(frozen=True)
class SeleniumSolverOptions:
    """Параметры солвера ``selenium-recaptcha-solver``.

    :param iframe_xpath: XPath для поиска iframe чекбокса. Стандартный виджет
        Google рендерит ``<iframe title="reCAPTCHA">``.
    :param challenge_iframe_xpath: XPath iframe с самим челленджем (``bframe``).
    :param iframe_timeout: сколько секунд ждать появления iframe.
    :param service_language: язык распознавания речи (``"en-US"``, ``"ru-RU"``).
    :param humanize_delays: добавлять человеческие паузы между действиями
        (через ``StandardDelayConfig`` исходной библиотеки).
    :param delay_min: минимальная пауза, сек.
    :param delay_max: максимальная пауза, сек.
    """

    iframe_xpath: str = '//iframe[@title="reCAPTCHA"]'
    challenge_iframe_xpath: str = (
        '//iframe[contains(@src, "recaptcha") and contains(@src, "bframe")]'
    )
    iframe_timeout: float = 10.0
    service_language: str = "en-US"
    humanize_delays: bool = True
    delay_min: float = 0.75
    delay_max: float = 1.25

    def __post_init__(self) -> None:
        """Проверить, что таймаут положительный."""
        if self.iframe_timeout <= 0:
            raise ValueError("iframe_timeout должен быть положительным")


@dataclass
class BotConfig:
    """Готовая связка настроек «на всё сразу».

    Удобна, когда один и тот же профиль (браузер + stealth + солвер)
    переиспользуется в нескольких местах.

    :param backend: бэкенд решения v2.
    :param stealth: настройки ``playwright-stealth``.
    :param browser: параметры запуска браузера.
    :param solver: параметры ``playwright-recaptcha``.
    :param vision_ai: параметры YOLO-солвера.
    :param selenium_stealth: настройки маскировки Selenium.
    :param selenium_solver: параметры Selenium-солвера.
    """

    backend: SolverBackend = SolverBackend.AUDIO
    stealth: StealthOptions = field(default_factory=StealthOptions)
    browser: BrowserOptions = field(default_factory=BrowserOptions)
    solver: PlaywrightSolverOptions = field(default_factory=PlaywrightSolverOptions)
    vision_ai: VisionAIOptions = field(default_factory=VisionAIOptions)
    selenium_stealth: SeleniumStealthOptions = field(default_factory=SeleniumStealthOptions)
    selenium_solver: SeleniumSolverOptions = field(default_factory=SeleniumSolverOptions)

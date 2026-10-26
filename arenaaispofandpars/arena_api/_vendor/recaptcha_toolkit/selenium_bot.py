"""Бот на Selenium: маскировка автоматизации + решение reCAPTCHA v2.

От Playwright-бота отличается моделью работы с iframe: ``selenium-recaptcha-solver``
не ищет виджет сам, ему нужно передать WebElement нужного iframe. Поэтому здесь
есть отдельный шаг :meth:`SeleniumBot.find_recaptcha_iframe`.

User-Agent по умолчанию — «не headless»: именно на этом настаивает документация
``selenium-recaptcha-solver``, потому что любая подстрока ``Headless`` в UA
многократно повышает риск детекта.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .config import (
    DEFAULT_CHROME_UA,
    SeleniumSolverOptions,
    SeleniumStealthOptions,
    SolverBackend,
)
from .errors import (
    CaptchaError,
    RecaptchaNotFoundError,
    require_dependency,
    translate_selenium_error,
)
from .stealth import apply_selenium_stealth

if TYPE_CHECKING:  # pragma: no cover - только для аннотаций
    from selenium.webdriver.remote.webdriver import WebDriver
    from selenium.webdriver.remote.webelement import WebElement

__all__ = ["SeleniumBot"]

_SELENIUM_PACKAGE = "selenium"
_SOLVER_PACKAGE = "selenium-recaptcha-solver"

# Текстовое поле, в которое grecaptcha складывает готовый токен.
_TOKEN_READ_JS = """
var el = document.querySelector('[name="g-recaptcha-response"], #g-recaptcha-response');
if (el) { return el.value || null; }
try {
  if (typeof grecaptcha !== 'undefined' && grecaptcha.getResponse) {
    return grecaptcha.getResponse();
  }
  if (window.___grecaptcha_cfg && window.___grecaptcha_cfg.clients) {
    for (var key in window.___grecaptcha_cfg.clients) {
      var client = window.___grecaptcha_cfg.clients[key];
      if (client && client.$ && client.$.$ && client.$.$.$ &&
          typeof client.$.$.$.getResponse === 'function') {
        return client.$.$.$.getResponse();
      }
    }
  }
} catch (e) { return null; }
return null;
"""


class SeleniumBot:
    """Обёртка над Selenium WebDriver: antidetect + решение reCAPTCHA v2.

    Пример::

        from arena_api._vendor.recaptcha_toolkit import SeleniumBot

        with SeleniumBot.launch_chrome() as bot:
            bot.driver.get("https://www.google.com/recaptcha/api2/demo")
            bot.solve_recaptcha_v2()
            print(bot.get_token())

    :param driver: готовый WebDriver.
    :param stealth: настройки маскировки; ``None`` — по умолчанию.
    :param solver: параметры поиска iframe и солвера.
    :param backend: зарезервировано для совместимости с Playwright-ботом;
        ``selenium-recaptcha-solver`` решает только аудио-челлендж v2, поэтому
        ``VISION_AI`` здесь не поддерживается.
    :param own_driver: закрывать ли драйвер в :meth:`close`.

    Язык распознавания речи задаётся в ``SeleniumSolverOptions.service_language``.
    """

    def __init__(
        self,
        driver: "WebDriver",
        *,
        stealth: SeleniumStealthOptions | None = None,
        solver: SeleniumSolverOptions | None = None,
        backend: SolverBackend = SolverBackend.AUDIO,
        own_driver: bool = True,
    ) -> None:
        if backend is SolverBackend.VISION_AI:
            raise ValueError(
                "SolverBackend.VISION_AI недоступен для Selenium: YOLO-солвер "
                "работает только через Playwright. Используйте PlaywrightBot."
            )

        self._driver: WebDriver = driver
        self._stealth_opts: SeleniumStealthOptions = stealth or SeleniumStealthOptions()
        self._solver_opts: SeleniumSolverOptions = solver or SeleniumSolverOptions()
        self._backend: SolverBackend = SolverBackend(backend)
        self._own_driver: bool = own_driver
        self._solver: Any = None

        # Маскировку нужно накатить до первой навигации, иначе страница
        # успеет прочитать «родной» navigator.webdriver.
        apply_selenium_stealth(self._driver, self._stealth_opts)

    # ---------------------------------------------------------------- фабрики

    @classmethod
    def launch_chrome(
        cls,
        *,
        user_agent: str = DEFAULT_CHROME_UA,
        headless: bool = False,
        proxy: str | None = None,
        language: str = "en-US",
        stealth: SeleniumStealthOptions | None = None,
        solver: SeleniumSolverOptions | None = None,
        window_size: tuple[int, int] = (1920, 1080),
        extra_args: tuple[str, ...] = (),
        driver_factory: Any = None,
        **kwargs: Any,
    ) -> SeleniumBot:
        """Создать Chrome-драйвер с antidetect-настройками.

        :param user_agent: «не headless» User-Agent.
        :param headless: запускать без GUI (для отладки; повышает риск детекта).
        :param proxy: прокси в формате ``host:port`` или ``protocol://host:port``.
        :param language: язык интерфейса и ``Accept-Language``.
        :param stealth: настройки маскировки; ``None`` — соберутся из
            ``user_agent`` / ``language``.
        :param solver: параметры солвера.
        :param window_size: размер окна.
        :param extra_args: дополнительные аргументы Chrome.
        :param driver_factory: вызываемый объект ``(options) -> WebDriver``,
            если нужен свой драйвер (undetected-chromedriver, Selenium Grid, ...).
        :param kwargs: пробрасываются в конструктор :class:`SeleniumBot`.
        :returns: готовый бот.
        :raises SolverDependencyError: если Selenium не установлен.
        """
        require_dependency("selenium", _SELENIUM_PACKAGE, extra="captcha")

        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options

        stealth = stealth or SeleniumStealthOptions(
            user_agent=user_agent, languages=(language, language.split("-")[0])
        )

        options = Options()
        options.add_argument(f"--user-agent={stealth.user_agent}")
        options.add_argument(f"--window-size={window_size[0]},{window_size[1]}")
        options.add_argument(f"--lang={language}")

        # Базовый набор «тихого» Chromium.
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-gpu")

        if stealth.hide_automation_flags:
            # Убираем баннер «Chrome is being controlled...» и сам флаг
            # автоматизации в объекте navigator.
            options.add_experimental_option("excludeSwitches", ["enable-automation"])
            options.add_experimental_option("useAutomationExtension", False)
            options.add_argument("--disable-blink-features=AutomationControlled")

        # Языки, чтобы navigator.languages и Accept-Language совпадали.
        options.add_experimental_option(
            "prefs", {"intl.accept_languages": ",".join(stealth.languages)}
        )

        if proxy:
            options.add_argument(f"--proxy-server={proxy}")

        if headless:
            options.add_argument("--headless=new")

        for arg in extra_args:
            options.add_argument(arg)

        factory = driver_factory or webdriver.Chrome
        driver = factory(options=options)

        return cls(driver, stealth=stealth, solver=solver, own_driver=True, **kwargs)

    # ------------------------------------------------------------- свойства

    @property
    def driver(self) -> "WebDriver":
        """Подлежащий WebDriver."""
        return self._driver

    @property
    def stealth_options(self) -> SeleniumStealthOptions:
        """Настройки маскировки."""
        return self._stealth_opts

    @property
    def solver_options(self) -> SeleniumSolverOptions:
        """Настройки солвера."""
        return self._solver_opts

    # ------------------------------------------------------------- жизненный цикл

    def __enter__(self) -> SeleniumBot:
        """Войти в контекст менеджера."""
        return self

    def __exit__(self, *exc_info: Any) -> None:
        """Закрыть драйвер."""
        self.close()

    def close(self) -> None:
        """Закрыть драйвер, если бот им владеет."""
        if self._own_driver and self._driver is not None:
            try:
                self._driver.quit()
            except Exception:  # noqa: BLE001 - драйвер мог уже закрыться
                pass

    # ----------------------------------------------------------------- солвер

    def _get_solver(self) -> Any:
        """Ленитно создать ``selenium_recaptcha_solver.RecaptchaSolver``.

        Создание отложено, чтобы отсутствие пакета не мешало использовать бота
        только для маскировки.

        :returns: экземпляр ``RecaptchaSolver``.
        :raises SolverDependencyError: если пакет не установлен.
        """
        if self._solver is not None:
            return self._solver

        module = require_dependency("selenium_recaptcha_solver", _SOLVER_PACKAGE, extra="captcha")
        delay_config = None
        if self._solver_opts.humanize_delays:
            delay_config = module.StandardDelayConfig(
                min_delay=self._solver_opts.delay_min,
                max_delay=self._solver_opts.delay_max,
            )

        self._solver = module.RecaptchaSolver(
            driver=self._driver,
            service_language=self._solver_opts.service_language,
            delay_config=delay_config,
        )
        return self._solver

    def find_recaptcha_iframe(
        self,
        *,
        timeout: float | None = None,
        xpath: str | None = None,
    ) -> "WebElement":
        """Найти iframe виджета reCAPTCHA.

        :param timeout: сколько секунд ждать; ``None`` — из настроек.
        :param xpath: XPath iframe; ``None`` — из настроек
            (по умолчанию ``//iframe[@title="reCAPTCHA"]``).
        :returns: WebElement iframe.
        :raises RecaptchaNotFoundError: если iframe не найден вовремя.
        """
        require_dependency("selenium", _SELENIUM_PACKAGE, extra="captcha")

        from selenium.webdriver.common.by import By
        from selenium.webdriver.support import expected_conditions as ec
        from selenium.webdriver.support.ui import WebDriverWait

        locator = xpath or self._solver_opts.iframe_xpath
        wait_timeout = timeout if timeout is not None else self._solver_opts.iframe_timeout

        try:
            return WebDriverWait(self._driver, wait_timeout).until(
                ec.presence_of_element_located((By.XPATH, locator))
            )
        except Exception as exc:  # noqa: BLE001 - TimeoutException и производные
            raise RecaptchaNotFoundError(
                f"iframe reCAPTCHA не найден по XPath {locator!r} за {wait_timeout} с. "
                "Убедитесь, что виджет отрисован и не вложен в другой iframe."
            ) from exc

    def recaptcha_is_present(self, *, xpath: str | None = None) -> bool:
        """Проверить, есть ли на странице виджет reCAPTCHA.

        :param xpath: XPath iframe; ``None`` — из настроек.
        :returns: ``True``, если iframe найден.
        """
        require_dependency("selenium", _SELENIUM_PACKAGE, extra="captcha")

        from selenium.webdriver.common.by import By

        locator = xpath or self._solver_opts.iframe_xpath
        try:
            return bool(self._driver.find_elements(By.XPATH, locator))
        except Exception:  # noqa: BLE001 - страница могла перезагрузиться
            return False

    def solve_recaptcha_v2(
        self,
        *,
        iframe: "WebElement | None" = None,
        timeout: float | None = None,
        xpath: str | None = None,
    ) -> None:
        """Кликнуть «Я не робот» и решить v2-челлендж.

        Метод не возвращает токен: ``selenium-recaptcha-solver`` только
        проставляет его в форму. Токен забирайте через :meth:`get_token`.

        :param iframe: уже найденный iframe; ``None`` — найти автоматически.
        :param timeout: таймаут поиска iframe, сек.
        :param xpath: XPath iframe (если стандартный не подходит).
        :raises RecaptchaNotFoundError: iframe не найден.
        :raises CaptchaError: солвер не смог решить капчу.
        """
        element = iframe if iframe is not None else self.find_recaptcha_iframe(
            timeout=timeout, xpath=xpath
        )

        solver = self._get_solver()
        try:
            solver.click_recaptcha_v2(iframe=element)
        except CaptchaError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise translate_selenium_error(exc, where="click_recaptcha_v2") from exc

    def solve_recaptcha_v2_challenge(
        self,
        *,
        iframe: "WebElement | None" = None,
        timeout: float | None = None,
    ) -> None:
        """Решить уже открытый челлендж (для invisible reCAPTCHA).

        Вызывайте, когда чекбокса нет — например, капча всплыла после отправки
        формы (бейдж invisible reCAPTCHA).

        :param iframe: iframe челленджа (``bframe``); ``None`` — найти автоматически.
        :param timeout: таймаут поиска iframe, сек.
        :raises RecaptchaNotFoundError: iframe челленджа не найден.
        :raises CaptchaError: солвер не смог решить капчу.
        """
        element = iframe if iframe is not None else self.find_recaptcha_iframe(
            timeout=timeout, xpath=self._solver_opts.challenge_iframe_xpath
        )

        solver = self._get_solver()
        try:
            solver.solve_recaptcha_v2_challenge(iframe=element)
        except CaptchaError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise translate_selenium_error(exc, where="solve_recaptcha_v2_challenge") from exc

    def get_token(self) -> str | None:
        """Прочитать токен ``g-recaptcha-response`` из формы.

        Сначала ищется скрытое текстовое поле, затем — ответ ``grecaptcha``.

        :returns: токен или ``None``, если капча ещё не решена.
        """
        try:
            value = self._driver.execute_script(_TOKEN_READ_JS)
        except Exception:  # noqa: BLE001 - драйвер мог закрыться
            return None
        return value or None

    def wait_for_token(self, timeout: float = 30.0) -> str:
        """Дождаться появления токена в форме.

        :param timeout: сколько секунд ждать.
        :returns: непустой токен.
        :raises CaptchaError: токен не появился за отведённое время.
        """
        import time

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            token = self.get_token()
            if token:
                return token
            time.sleep(0.5)

        raise CaptchaError(
            f"Токен g-recaptcha-response не появился за {timeout} с. "
            "Возможно, капча не была решена или форма не содержит виджета."
        )

    def solve_and_get_token(
        self,
        *,
        iframe: "WebElement | None" = None,
        timeout: float | None = None,
        token_timeout: float = 30.0,
    ) -> str:
        """Решить капчу и сразу вернуть токен (склейка двух шагов).

        :param iframe: iframe виджета; ``None`` — найти автоматически.
        :param timeout: таймаут поиска iframe, сек.
        :param token_timeout: таймаут ожидания токена, сек.
        :returns: токен ``g-recaptcha-response``.
        """
        self.solve_recaptcha_v2(iframe=iframe, timeout=timeout)
        return self.wait_for_token(timeout=token_timeout)

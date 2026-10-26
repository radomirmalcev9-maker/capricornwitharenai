"""Маскировка признаков автоматизации (antidetect).

Playwright обслуживается библиотекой ``playwright-stealth``, Selenium —
собственным CDP-хуком (см. :meth:`SeleniumStealthOptions.build_init_script`),
поскольку для Selenium готового equivalents нет.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .config import StealthOptions
from .errors import require_dependency

if TYPE_CHECKING:  # pragma: no cover - только для аннотаций
    from playwright.async_api import BrowserContext as AsyncBrowserContext
    from playwright.async_api import Page as AsyncPage
    from playwright.sync_api import BrowserContext, Page

    from .config import SeleniumStealthOptions

__all__ = [
    "apply_stealth_async",
    "apply_stealth_sync",
    "build_stealth",
    "build_browser_launch_kwargs",
    "apply_selenium_stealth",
]


def build_stealth(options: StealthOptions | None = None) -> Any:
    """Собрать объект :class:`playwright_stealth.Stealth` по нашим настройкам.

    :param options: настройки; ``None`` — значения по умолчанию.
    :returns: сконфигурированный ``Stealth``.
    :raises SolverDependencyError: если ``playwright-stealth`` не установлен.
    """
    module = require_dependency("playwright_stealth", "playwright-stealth", extra="captcha")
    options = options or StealthOptions()

    return module.Stealth(
        navigator_webdriver=options.navigator_webdriver,
        navigator_languages=options.navigator_languages is not None,
        navigator_languages_override=tuple(options.navigator_languages),
        navigator_user_agent=options.navigator_user_agent is not None,
        navigator_user_agent_override=options.navigator_user_agent,
        navigator_platform_override=options.platform_override,
        navigator_vendor_override=options.vendor_override,
        init_scripts_only=options.init_scripts_only,
    )


def build_browser_launch_kwargs(
    browser_options: Any,
    *,
    stealth: StealthOptions | None = None,
) -> dict[str, Any]:
    """Собрать kwargs для ``playwright.<engine>.launch(**kwargs)``.

    Отдельной функцией вынесено, чтобы синхронный и асинхронный боты
    получали абсолютно одинаковый набор аргументов.

    :param browser_options: :class:`~recaptcha_toolkit.config.BrowserOptions`.
    :param stealth: настройки stealth (нужны для прокси/языка уровня браузера).
    :returns: словарь kwargs.
    """

    kwargs: dict[str, Any] = {
        "headless": browser_options.headless,
        "slow_mo": browser_options.slow_mo,
    }

    args: list[str] = list(browser_options.extra_args)

    if browser_options.channel:
        kwargs["channel"] = browser_options.channel

    # Отключаем панель «Chrome is being controlled by automated test software»
    # и убираем наиболее массовые флаги автоматизации.
    args += [
        "--disable-blink-features=AutomationControlled",
        "--exclude-switches=enable-automation",
        "--disable-infobars",
        "--no-first-run",
        "--no-default-browser-check",
    ]

    if stealth is not None and stealth.locale:
        args.append(f"--lang={stealth.locale}")

    kwargs["args"] = args

    if browser_options.proxy:
        kwargs["proxy"] = _normalize_proxy(browser_options.proxy)

    if browser_options.timeout is not None:
        kwargs["timeout"] = browser_options.timeout

    return kwargs


def build_context_kwargs(
    stealth: StealthOptions | None,
    browser_options: Any,
) -> dict[str, Any]:
    """Собрать kwargs для ``browser.new_context(**kwargs)``.

    Локаль и таймзона задаются на уровне контекста — именно их значения
    видит JS страницы через ``Intl`` и ``Date``.

    :param stealth: настройки stealth.
    :param browser_options: параметры браузера (нужен viewport).
    :returns: словарь kwargs (без ``user_agent``, если он не задан явно).
    """
    kwargs: dict[str, Any] = {}

    if stealth is not None:
        kwargs["locale"] = stealth.locale
        kwargs["timezone_id"] = stealth.timezone_id
        if stealth.navigator_user_agent:
            # UA уровня контекста обязательно должен совпадать с тем, что
            # подменяет stealth-скрипт, иначе расхождение детектится.
            kwargs["user_agent"] = stealth.navigator_user_agent

    if browser_options is not None and browser_options.viewport:
        kwargs["viewport"] = browser_options.viewport

    return kwargs


def _normalize_proxy(proxy: Any) -> Any:
    """Привести прокси к формату, который понимает Playwright.

    Playwright принимает либо строку, либо словарь с ключами
    ``server`` / ``username`` / ``password`` / ``bypass``.

    :param proxy: строка прокси или уже готовая структура Playwright.
    :returns: значение, пригодное для аргумента ``proxy``.
    """
    if isinstance(proxy, dict):
        return proxy

    # Строковый формат Playwright не понимает username/password внутри URL,
    # поэтому разбираем его в словарь.
    from urllib.parse import urlparse

    parsed = urlparse(proxy)
    if parsed.username or parsed.password:
        server = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            server = f"{server}:{parsed.port}"
        result: dict[str, str] = {"server": server}
        if parsed.username:
            result["username"] = parsed.username
        if parsed.password:
            result["password"] = parsed.password
        return result

    return {"server": proxy}


def apply_stealth_sync(
    page_or_context: "Page | BrowserContext",
    options: StealthOptions | None = None,
) -> "Page | BrowserContext":
    """Накатить stealth-скрипты на существующий объект Playwright (sync).

    Альтернатива ``Stealth().use_sync(sync_playwright())`` для случаев, когда
    Playwright уже запущен (например, управляется внешним фреймворком).

    :param page_or_context: ``Page`` или ``BrowserContext``.
    :param options: настройки stealth.
    :returns: тот же объект (для chaining).
    """
    stealth = build_stealth(options)
    stealth.apply_stealth_sync(page_or_context)
    return page_or_context


async def apply_stealth_async(
    page_or_context: "AsyncPage | AsyncBrowserContext",
    options: StealthOptions | None = None,
) -> "AsyncPage | AsyncBrowserContext":
    """Накатить stealth-скрипты на существующий объект Playwright (async).

    :param page_or_context: ``Page`` или ``BrowserContext``.
    :param options: настройки stealth.
    :returns: тот же объект (для chaining).
    """
    stealth = build_stealth(options)
    await stealth.apply_stealth_async(page_or_context)
    return page_or_context


def apply_selenium_stealth(driver: Any, options: "SeleniumStealthOptions") -> None:
    """Применить antidetect-настройки к уже созданному Selenium-драйверу.

    Шлёт CDP-команду ``Page.addScriptToEvaluateOnNewDocument``: скрипт
    выполнится до загрузки документа на каждой странице, поэтому подмены
    ``navigator.*`` видны скриптам проверки сразу.

    :param driver: экземпляр Selenium WebDriver (Chrome/Edge).
    :param options: настройки маскировки.
    """
    if not options.enabled:
        return

    script = options.build_init_script()
    try:
        driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument", {"source": script}
        )
    except Exception:  # noqa: BLE001 - CDP есть только у Chromium-драйверов
        # Firefox/Safari не поддерживают CDP: молча продолжаем, CLI-флаги и
        # не-headless UA уже применены на этапе создания драйвера.
        pass

    if options.languages:
        # Accept-Language должен совпадать с navigator.languages.
        try:
            driver.execute_cdp_cmd(
                "Network.setUserAgentOverride",
                {
                    "userAgent": options.user_agent,
                    "acceptLanguage": ", ".join(options.languages),
                    "platform": options.platform,
                },
            )
        except Exception:  # noqa: BLE001
            pass

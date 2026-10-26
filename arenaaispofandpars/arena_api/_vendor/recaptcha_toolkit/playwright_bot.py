"""Боты на Playwright: stealth-контекст + решение reCAPTCHA v2/v3.

Поддерживаются оба стиля работы — синхронный (:class:`PlaywrightBot`) и
асинхронный (:class:`AsyncPlaywrightBot`), API у них зеркальный.

Выбор солвера делается флагом :class:`~recaptcha_toolkit.config.SolverBackend`:

* ``AUDIO`` / ``IMAGE`` — ``playwright-recaptcha`` работает **внутри** уже
  открытой страницы;
* ``VISION_AI`` — YOLO-солвер поднимает **свой** браузер и требует
  ``website_key`` + ``website_url``; они определяются автоматически, если
  страница уже открыта.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from .config import (
    BrowserOptions,
    PlaywrightSolverOptions,
    RecaptchaVersion,
    SolverBackend,
    StealthOptions,
    VisionAIOptions,
)
from .errors import (
    CaptchaError,
    SiteKeyDetectionError,
    require_dependency,
    translate_playwright_recaptcha_error,
)
from .stealth import build_browser_launch_kwargs, build_context_kwargs, build_stealth
from .vision_ai import VisionAISolver, backend_label

if TYPE_CHECKING:  # pragma: no cover - только для аннотаций
    from playwright.async_api import Page as AsyncPage
    from playwright.sync_api import Page

__all__ = [
    "AsyncPlaywrightBot",
    "PlaywrightBot",
    "detect_site_key",
    "detect_site_key_async",
    "extract_token",
    "extract_token_async",
]

_PLAYWRIGHT_PACKAGE = "playwright"
_RECAPTCHA_PACKAGE = "playwright-recaptcha"

# Site key ищется в трёх местах: разметке виджета, src iframe и глобальных
# переменных grecaptcha. Порядок — от самого надёжного к самому хрупкому.
_SITE_KEY_JS = """
() => {
  const direct = document.querySelector('[data-sitekey]');
  if (direct) {
    const key = direct.getAttribute('data-sitekey');
    if (key) return key;
  }
  const frames = Array.from(document.querySelectorAll('iframe'));
  for (const frame of frames) {
    const src = frame.getAttribute('src') || '';
    if (/\\/recaptcha\\/(api2|enterprise)\\//.test(src) ||
        /\\/recaptcha\\/(api2|enterprise)\\/(anchor|bframe)/.test(src)) {
      const match = src.match(/[?&]k=([^&]+)/);
      if (match) return decodeURIComponent(match[1]);
    }
  }
  const scripts = Array.from(document.querySelectorAll('script'));
  for (const script of scripts) {
    const text = script.textContent || '';
    const match = text.match(/(?:sitekey|siteKey|"k")\\s*[:=]\\s*['"]([A-Za-z0-9_-]{20,})['"]/);
    if (match) return match[1];
  }
  return null;
}
"""

# Значение текстового поля, куда grecaptcha складывает готовый токен.
_TOKEN_JS = """
() => {
  const field = document.querySelector('[name="g-recaptcha-response"], #g-recaptcha-response');
  if (field) return field.value || null;
  if (typeof window.grecaptcha !== 'undefined' && window.grecaptcha.getResponse) {
    try { return window.grecaptcha.getResponse(); } catch (e) { return null; }
  }
  return null;
}
"""


def detect_site_key(page: Any) -> str:
    """Определить site key reCAPTCHA на открытой странице (sync).

    :param page: страница Playwright.
    :returns: site key.
    :raises SiteKeyDetectionError: если ключ определить не удалось.
    """
    key = _run_key_detection(page.evaluate(_SITE_KEY_JS), getattr(page, "url", ""))
    if key:
        return key
    raise SiteKeyDetectionError(
        "Не удалось определить website_key (site key) на странице. "
        "Передайте его вручную: solve_recaptcha_v2(page, website_key='...')."
    )


async def detect_site_key_async(page: Any) -> str:
    """Определить site key reCAPTCHA на открытой странице (async).

    :param page: страница Playwright.
    :returns: site key.
    :raises SiteKeyDetectionError: если ключ определить не удалось.
    """
    key = _run_key_detection(await page.evaluate(_SITE_KEY_JS), getattr(page, "url", ""))
    if key:
        return key
    raise SiteKeyDetectionError(
        "Не удалось определить website_key (site key) на странице. "
        "Передайте его вручную: await solve_recaptcha_v2(page, website_key='...')."
    )


def _run_key_detection(raw: Any, url: str) -> str | None:
    """Нормализовать результат JS-поиска site key.

    :param raw: то, что вернул ``page.evaluate``.
    :param url: URL страницы (используется как запасной источник).
    :returns: site key или ``None``.
    """
    if isinstance(raw, str) and raw.strip():
        return raw.strip()

    # Запасной путь: URL вида .../anchor?...&k=<key>
    match = re.search(r"[?&]k=([^&]+)", url or "")
    if match:
        from urllib.parse import unquote

        return unquote(match.group(1))

    return None


def extract_token(page: Any) -> str | None:
    """Прочитать уже готовый токен ``g-recaptcha-response`` со страницы (sync).

    Полезно после Selenium-солвера, который не возвращает токен, а только
    проставляет его в форму.

    :param page: страница Playwright.
    :returns: токен или ``None``, если капча ещё не решена.
    """
    try:
        value = page.evaluate(_TOKEN_JS)
    except Exception:  # noqa: BLE001 - страница могла закрыться/перезагрузиться
        return None
    return value or None


async def extract_token_async(page: Any) -> str | None:
    """Прочитать токен ``g-recaptcha-response`` со страницы (async).

    :param page: страница Playwright.
    :returns: токен или ``None``.
    """
    try:
        value = await page.evaluate(_TOKEN_JS)
    except Exception:  # noqa: BLE001
        return None
    return value or None


class _PlaywrightBotBase:
    """Общая логика запуска браузера для sync/async ботов.

    Разделение нужно, потому что у Playwright полностью независимые
    sync/async классы, а дублировать логику построения аргументов не хочется.
    """

    def __init__(
        self,
        *,
        backend: SolverBackend = SolverBackend.AUDIO,
        stealth: StealthOptions | None = None,
        browser: BrowserOptions | None = None,
        solver: PlaywrightSolverOptions | None = None,
        vision_ai: VisionAIOptions | None = None,
    ) -> None:
        # Нормализуем enum: конфиг часто приходит строкой из YAML/ENV.
        self._backend: SolverBackend = SolverBackend(backend)
        self._stealth_opts: StealthOptions = stealth or StealthOptions()
        self._browser_opts: BrowserOptions = browser or BrowserOptions()
        self._solver_opts: PlaywrightSolverOptions = solver or PlaywrightSolverOptions()
        self._vision_ai: VisionAISolver = VisionAISolver(vision_ai)

        self._stealth: Any = (
            build_stealth(self._stealth_opts) if self._stealth_opts.enabled else None
        )

        self._pw_cm: Any = None
        self._wrapped_cm: Any = None
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None

    # ------------------------------------------------------------------ свойства

    @property
    def backend(self) -> SolverBackend:
        """Текущий бэкенд решения капчи."""
        return self._backend

    @property
    def playwright(self) -> Any:
        """Объект ``Playwright`` (доступен после входа в контекст менеджера)."""
        return self._playwright

    @property
    def browser(self) -> Any:
        """Запущенный браузер."""
        return self._browser

    @property
    def context(self) -> Any:
        """Браузерный контекст со stealth-скриптами."""
        return self._context

    # ------------------------------------------------------------------- helpers

    @property
    def _engine(self) -> Any:
        """Объект движка Playwright (``chromium`` / ``firefox`` / ``webkit``)."""
        name = self._browser_opts.browser_type
        try:
            return getattr(self._playwright, name)
        except AttributeError as exc:  # pragma: no cover - опечатка в конфиге
            raise ValueError(
                f"Неизвестный движок Playwright: {name!r}. "
                "Допустимо: chromium, firefox, webkit."
            ) from exc

    def _launch_kwargs(self) -> dict[str, Any]:
        """Аргументы для ``playwright.<engine>.launch(**kwargs)``."""
        kwargs = build_browser_launch_kwargs(self._browser_opts, stealth=self._stealth_opts)
        # Firefox/WebKit не понимают Chromium-специфичные флаги.
        if self._browser_opts.browser_type != "chromium":
            kwargs.pop("args", None)
        return kwargs

    def _context_kwargs(self) -> dict[str, Any]:
        """Аргументы для ``browser.new_context(**kwargs)``."""
        return build_context_kwargs(self._stealth_opts, self._browser_opts)

    def _resolve_vision_targets(
        self, page: Any, website_key: str | None, website_url: str | None
    ) -> tuple[str, str]:
        """Подготовить ``website_key`` и ``website_url`` для YOLO-солвера.

        Ключ берётся из аргумента, иначе — со страницы (разметка виджета,
        ``src`` iframe, ``grecaptcha``), иначе из URL.

        :param page: страница, из которой можно вытащить оба значения.
        :param website_key: явно переданный ключ (приоритетнее).
        :param website_url: явно переданный URL (приоритетнее).
        :returns: пара ``(website_key, website_url)``.
        :raises SiteKeyDetectionError: ключ не найден и не передан.
        """
        url = website_url or getattr(page, "url", "")
        if not url:
            raise SiteKeyDetectionError(
                "Для SolverBackend.VISION_AI нужен website_url: либо откройте "
                "страницу, либо передайте website_url вручную."
            )

        if website_key:
            return website_key, url

        return detect_site_key(page), url


class PlaywrightBot(_PlaywrightBotBase):
    """Синхронный бот: stealth-браузер + решение reCAPTCHA v2/v3.

    Пример::

        from arena_api._vendor.recaptcha_toolkit import PlaywrightBot, SolverBackend

        with PlaywrightBot(backend=SolverBackend.AUDIO) as bot:
            page = bot.new_page()
            page.goto("https://www.google.com/recaptcha/api2/demo")
            token = bot.solve_recaptcha_v2(page)
            print(token)

    :param backend: какой солвер использовать.
    :param stealth: настройки ``playwright-stealth``; ``None`` — по умолчанию.
    :param browser: параметры запуска браузера.
    :param solver: параметры ``playwright-recaptcha``.
    :param vision_ai: параметры YOLO-солвера (для ``SolverBackend.VISION_AI``).
    """

    def __enter__(self) -> PlaywrightBot:
        """Запустить Playwright, браузер и stealth-контекст."""
        require_dependency("playwright.sync_api", _PLAYWRIGHT_PACKAGE, extra="captcha")

        from playwright.sync_api import sync_playwright

        self._pw_cm = sync_playwright()

        if self._stealth is not None:
            # Stealth().use_sync() патчит new_context/new_page и CLI-аргументы,
            # поэтому все созданные объекты получают маскировку автоматически.
            self._wrapped_cm = self._stealth.use_sync(self._pw_cm)
            self._playwright = self._wrapped_cm.__enter__()
        else:
            self._playwright = self._pw_cm.__enter__()

        try:
            self._browser = self._engine.launch(**self._launch_kwargs())
            self._context = self._browser.new_context(**self._context_kwargs())
        except BaseException:
            self.close()
            raise

        return self

    def __exit__(self, *exc_info: Any) -> None:
        """Закрыть контекст, браузер и Playwright."""
        self.close()

    def close(self) -> None:
        """Освободить ресурсы. Повторный вызов безопасен."""
        for attr in ("_context", "_browser"):
            obj = getattr(self, attr, None)
            if obj is None:
                continue
            try:
                obj.close()
            except Exception:  # noqa: BLE001 - браузер мог уже упасть
                pass
            setattr(self, attr, None)

        if self._wrapped_cm is not None:
            try:
                self._wrapped_cm.__exit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass
            self._wrapped_cm = None

        if self._pw_cm is not None:
            try:
                self._pw_cm.__exit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass
            self._pw_cm = None

        self._playwright = None

    def new_page(self, **kwargs: Any) -> "Page":
        """Создать страницу в stealth-контексте.

        :param kwargs: дополнительные аргументы ``context.new_page()``.
        :returns: страница Playwright.
        :raises RuntimeError: если бот не запущен (нет ``with``).
        """
        if self._context is None:
            raise RuntimeError("PlaywrightBot не запущен: используйте `with PlaywrightBot() as bot`.")
        return self._context.new_page(**kwargs)

    # ------------------------------------------------------------------ решение

    def solve_recaptcha_v2(
        self,
        page: "Page | None" = None,
        *,
        website_key: str | None = None,
        website_url: str | None = None,
        attempts: int | None = None,
        wait: bool | None = None,
        wait_timeout: float | None = None,
        image_challenge: bool | None = None,
    ) -> str:
        """Решить reCAPTCHA v2 и вернуть ``g-recaptcha-response``.

        :param page: страница с виджетом; ``None`` — будет создана новая.
        :param website_key: site key (обязателен только для ``VISION_AI``).
        :param website_url: URL страницы (только для ``VISION_AI``).
        :param attempts: сколько попыток; ``None`` — из настроек.
        :param wait: ждать появления виджета; ``None`` — из настроек.
        :param wait_timeout: сколько секунд ждать виджет.
        :param image_challenge: решать картинки вместо аудио; ``None`` —
            определяется бэкендом (``IMAGE`` → ``True``).
        :returns: токен ``g-recaptcha-response``.
        :raises CaptchaError: виджет не найден, таймаут, лимит, сбой солвера.
        """
        page = page if page is not None else self.new_page()

        if self._backend is SolverBackend.VISION_AI:
            key, url = self._resolve_vision_targets(page, website_key, website_url)
            return self._vision_ai.solve(
                website_key=key,
                website_url=url,
                is_invisible=False,
            )

        module = require_dependency(
            "playwright_recaptcha.recaptchav2", _RECAPTCHA_PACKAGE, extra="captcha"
        )
        use_image = (
            self._backend is SolverBackend.IMAGE if image_challenge is None else image_challenge
        )

        try:
            with module.SyncSolver(
                page,
                attempts=attempts or self._solver_opts.attempts,
                capsolver_api_key=self._solver_opts.capsolver_api_key,
            ) as solver:
                return str(
                    solver.solve_recaptcha(
                        attempts=attempts,
                        wait=self._solver_opts.wait if wait is None else wait,
                        wait_timeout=(
                            self._solver_opts.wait_timeout
                            if wait_timeout is None
                            else wait_timeout
                        ),
                        image_challenge=use_image,
                    )
                )
        except CaptchaError:
            raise
        except Exception as exc:  # noqa: BLE001 - библиотека бросает свои типы
            raise translate_playwright_recaptcha_error(
                exc, backend=backend_label(self._backend)
            ) from exc

    def solve_recaptcha_v3(
        self,
        page: "Page | None" = None,
        *,
        timeout: float | None = None,
        reload: bool = False,
    ) -> str:
        """Перехватить токен reCAPTCHA v3.

        В v3 браузер решает капчу сам: библиотека лишь слушает POST на
        ``/recaptcha/api2/reload`` и вынимает токен из ответа. Слушатель надо
        подключить **до** того, как браузер сделает этот запрос — поэтому,
        если страница уже загружена, используйте ``reload=True``.

        :param page: страница с виджетом v3; ``None`` — новая страница.
        :param timeout: таймаут ожидания токена, сек.
        :param reload: перезагрузить страницу сразу после подключения слушателя.
        :returns: токен ``g-recaptcha-response``.
        :raises CaptchaError: таймаут или сбой солвера.
        """
        page = page if page is not None else self.new_page()

        if self._backend is SolverBackend.VISION_AI:
            key, url = self._resolve_vision_targets(page, None, None)
            return self._vision_ai.solve(
                website_key=key,
                website_url=url,
                is_invisible=True,
                action=self._vision_ai.options.action,
            )

        module = require_dependency(
            "playwright_recaptcha.recaptchav3", _RECAPTCHA_PACKAGE, extra="captcha"
        )

        try:
            with module.SyncSolver(
                page, timeout=timeout or self._solver_opts.v3_timeout
            ) as solver:
                if reload:
                    page.reload()
                return str(solver.solve_recaptcha(timeout=timeout))
        except CaptchaError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise translate_playwright_recaptcha_error(
                exc, backend=backend_label(self._backend)
            ) from exc

    def solve_recaptcha(
        self,
        page: "Page | None" = None,
        *,
        version: RecaptchaVersion | str = RecaptchaVersion.V2,
        **kwargs: Any,
    ) -> str:
        """Универсальная точка входа: решить v2 или v3.

        :param page: страница с виджетом.
        :param version: :class:`RecaptchaVersion` (или ``"v2"`` / ``"v3"``).
        :param kwargs: пробрасываются в ``solve_recaptcha_v2`` / ``solve_recaptcha_v3``.
        :returns: токен ``g-recaptcha-response``.
        """
        version = RecaptchaVersion(version)
        if version is RecaptchaVersion.V3:
            return self.solve_recaptcha_v3(page, **kwargs)
        return self.solve_recaptcha_v2(page, **kwargs)

    def get_token(self, page: "Page") -> str | None:
        """Прочитать токен, уже проставленный в форму (sync).

        :param page: страница Playwright.
        :returns: токен или ``None``.
        """
        return extract_token(page)

    def apply_stealth(self, page_or_context: Any) -> Any:
        """Накатить stealth на произвольную страницу/контекст вручную.

        Полезно, когда Playwright создаётся не ботом (например, в pytest-фикстуре).

        :param page_or_context: ``Page`` или ``BrowserContext``.
        :returns: тот же объект.
        """
        from .stealth import apply_stealth_sync

        return apply_stealth_sync(page_or_context, self._stealth_opts)


class AsyncPlaywrightBot(_PlaywrightBotBase):
    """Асинхронный бот: stealth-браузер + решение reCAPTCHA v2/v3.

    Пример::

        import asyncio
        from arena_api._vendor.recaptcha_toolkit import AsyncPlaywrightBot

        async def main():
            async with AsyncPlaywrightBot() as bot:
                page = await bot.new_page()
                await page.goto("https://www.google.com/recaptcha/api2/demo")
                print(await bot.solve_recaptcha_v2(page))

        asyncio.run(main())

    Параметры конструктора совпадают с :class:`PlaywrightBot`.
    """

    async def __aenter__(self) -> AsyncPlaywrightBot:
        """Запустить Playwright, браузер и stealth-контекст."""
        require_dependency("playwright.async_api", _PLAYWRIGHT_PACKAGE, extra="captcha")

        from playwright.async_api import async_playwright

        self._pw_cm = async_playwright()

        if self._stealth is not None:
            # Асинхронный вариант: Stealth().use_async().
            self._wrapped_cm = self._stealth.use_async(self._pw_cm)
            self._playwright = await self._wrapped_cm.__aenter__()
        else:
            self._playwright = await self._pw_cm.__aenter__()

        try:
            self._browser = await self._engine.launch(**self._launch_kwargs())
            self._context = await self._browser.new_context(**self._context_kwargs())
        except BaseException:
            await self.close()
            raise

        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        """Закрыть контекст, браузер и Playwright."""
        await self.close()

    async def close(self) -> None:
        """Освободить ресурсы. Повторный вызов безопасен."""
        for attr in ("_context", "_browser"):
            obj = getattr(self, attr, None)
            if obj is None:
                continue
            try:
                await obj.close()
            except Exception:  # noqa: BLE001
                pass
            setattr(self, attr, None)

        if self._wrapped_cm is not None:
            try:
                await self._wrapped_cm.__aexit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass
            self._wrapped_cm = None

        if self._pw_cm is not None:
            try:
                await self._pw_cm.__aexit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass
            self._pw_cm = None

        self._playwright = None

    async def new_page(self, **kwargs: Any) -> "AsyncPage":
        """Создать страницу в stealth-контексте.

        :param kwargs: дополнительные аргументы ``context.new_page()``.
        :returns: страница Playwright.
        :raises RuntimeError: если бот не запущен.
        """
        if self._context is None:
            raise RuntimeError(
                "AsyncPlaywrightBot не запущен: используйте `async with AsyncPlaywrightBot() as bot`."
            )
        return await self._context.new_page(**kwargs)

    # ------------------------------------------------------------------ решение

    async def solve_recaptcha_v2(
        self,
        page: "AsyncPage | None" = None,
        *,
        website_key: str | None = None,
        website_url: str | None = None,
        attempts: int | None = None,
        wait: bool | None = None,
        wait_timeout: float | None = None,
        image_challenge: bool | None = None,
    ) -> str:
        """Решить reCAPTCHA v2 и вернуть ``g-recaptcha-response`` (async).

        :param page: страница с виджетом; ``None`` — новая страница.
        :param website_key: site key (для ``VISION_AI``).
        :param website_url: URL страницы (для ``VISION_AI``).
        :param attempts: сколько попыток.
        :param wait: ждать появления виджета.
        :param wait_timeout: сколько секунд ждать виджет.
        :param image_challenge: решать картинки вместо аудио.
        :returns: токен ``g-recaptcha-response``.
        :raises CaptchaError: виджет не найден, таймаут, лимит, сбой солвера.
        """
        page = page if page is not None else await self.new_page()

        if self._backend is SolverBackend.VISION_AI:
            if website_key is None:
                website_key = await detect_site_key_async(page)
            url = website_url or getattr(page, "url", "")
            if not url:
                raise SiteKeyDetectionError(
                    "Для SolverBackend.VISION_AI нужен website_url."
                )
            result = await self._vision_ai.solve_async(
                website_key=website_key,
                website_url=url,
                is_invisible=False,
            )
            return result.token

        module = require_dependency(
            "playwright_recaptcha.recaptchav2", _RECAPTCHA_PACKAGE, extra="captcha"
        )
        use_image = (
            self._backend is SolverBackend.IMAGE if image_challenge is None else image_challenge
        )

        try:
            async with module.AsyncSolver(
                page,
                attempts=attempts or self._solver_opts.attempts,
                capsolver_api_key=self._solver_opts.capsolver_api_key,
            ) as solver:
                return str(
                    await solver.solve_recaptcha(
                        attempts=attempts,
                        wait=self._solver_opts.wait if wait is None else wait,
                        wait_timeout=(
                            self._solver_opts.wait_timeout
                            if wait_timeout is None
                            else wait_timeout
                        ),
                        image_challenge=use_image,
                    )
                )
        except CaptchaError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise translate_playwright_recaptcha_error(
                exc, backend=backend_label(self._backend)
            ) from exc

    async def solve_recaptcha_v3(
        self,
        page: "AsyncPage | None" = None,
        *,
        timeout: float | None = None,
        reload: bool = False,
    ) -> str:
        """Перехватить токен reCAPTCHA v3 (async).

        См. замечание про порядок подключения слушателя в
        :meth:`PlaywrightBot.solve_recaptcha_v3`.

        :param page: страница с виджетом v3.
        :param timeout: таймаут ожидания токена, сек.
        :param reload: перезагрузить страницу после подключения слушателя.
        :returns: токен ``g-recaptcha-response``.
        :raises CaptchaError: таймаут или сбой солвера.
        """
        page = page if page is not None else await self.new_page()

        if self._backend is SolverBackend.VISION_AI:
            key = await detect_site_key_async(page)
            url = getattr(page, "url", "")
            if not url:
                raise SiteKeyDetectionError(
                    "Для SolverBackend.VISION_AI нужен website_url."
                )
            result = await self._vision_ai.solve_async(
                website_key=key,
                website_url=url,
                is_invisible=True,
                action=self._vision_ai.options.action,
            )
            return result.token

        module = require_dependency(
            "playwright_recaptcha.recaptchav3", _RECAPTCHA_PACKAGE, extra="captcha"
        )

        try:
            async with module.AsyncSolver(
                page, timeout=timeout or self._solver_opts.v3_timeout
            ) as solver:
                if reload:
                    await page.reload()
                return str(await solver.solve_recaptcha(timeout=timeout))
        except CaptchaError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise translate_playwright_recaptcha_error(
                exc, backend=backend_label(self._backend)
            ) from exc

    async def solve_recaptcha(
        self,
        page: "AsyncPage | None" = None,
        *,
        version: RecaptchaVersion | str = RecaptchaVersion.V2,
        **kwargs: Any,
    ) -> str:
        """Универсальная точка входа: решить v2 или v3 (async).

        :param page: страница с виджетом.
        :param version: :class:`RecaptchaVersion`.
        :param kwargs: пробрасываются в ``solve_recaptcha_v2/v3``.
        :returns: токен ``g-recaptcha-response``.
        """
        version = RecaptchaVersion(version)
        if version is RecaptchaVersion.V3:
            return await self.solve_recaptcha_v3(page, **kwargs)
        return await self.solve_recaptcha_v2(page, **kwargs)

    async def get_token(self, page: "AsyncPage") -> str | None:
        """Прочитать токен, уже проставленный в форму (async).

        :param page: страница Playwright.
        :returns: токен или ``None``.
        """
        return await extract_token_async(page)

    async def apply_stealth(self, page_or_context: Any) -> Any:
        """Накатить stealth на произвольную страницу/контекст (async).

        :param page_or_context: ``Page`` или ``BrowserContext``.
        :returns: тот же объект.
        """
        from .stealth import apply_stealth_async

        return await apply_stealth_async(page_or_context, self._stealth_opts)

"""Обёртка над ``VisionAIRecaptchaSolver-0`` — локальный YOLO-солвер.

В отличие от ``playwright-recaptcha`` этот солвер **не работает с уже
открытой страницей**: он сам поднимает Chromium, реплицирует виджет через
``recaptcha-domain-replicator`` и решает челлендж картинками. Поэтому вход у
него не ``Page``, а пара ``website_key`` / ``website_url``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import SolverBackend, VisionAIOptions
from .errors import CaptchaError, require_dependency, translate_vision_ai_error

__all__ = ["VisionAISolver", "VisionAIResult"]

_PACKAGE = "vision-ai-recaptcha-solver"


@dataclass(frozen=True)
class VisionAIResult:
    """Результат решения капчи YOLO-солвером.

    Поля повторяют ``SolveResult`` исходной библиотеки, но пакет не зависит от
    её типов: вызывающий код может работать с результатом, даже если
    ``vision_ai_recaptcha_solver`` не установлен.

    :param token: токен ``g-recaptcha-response``.
    :param captcha_type: тип челленджа (``dynamic_3x3``, ``square_4x4``, ...).
    :param elapsed: затраченное время, сек.
    :param attempts: сколько попыток понадобилось.
    :param cookies: cookie сессии внутреннего браузера.
    """

    token: str
    captcha_type: str | None = None
    elapsed: float | None = None
    attempts: int | None = None
    cookies: list[dict[str, Any]] | None = None


class VisionAISolver:
    """Тонкая типизированная обёртка над ``RecaptchaSolver`` / ``AsyncRecaptchaSolver``.

    Пример (синхронно)::

        solver = VisionAISolver(VisionAIOptions(timeout=120))
        token = solver.solve(
            website_key="6Le-wvkSVVABCPBMRTvw0Q4Muexq1bi0DJwx_mJ-",
            website_url="https://www.google.com/recaptcha/api2/demo",
        )

    :param options: настройки солвера; ``None`` — значения по умолчанию.
    """

    def __init__(self, options: VisionAIOptions | None = None) -> None:
        self._options: VisionAIOptions = options or VisionAIOptions()

    @property
    def options(self) -> VisionAIOptions:
        """Текущие настройки солвера."""
        return self._options

    def solve(
        self,
        *,
        website_key: str,
        website_url: str,
        is_invisible: bool | None = None,
        action: str | None = None,
        is_enterprise: bool | None = None,
        api_domain: str | None = None,
        cookies: list[dict[str, Any]] | None = None,
        user_agent: str | None = None,
    ) -> str:
        """Решить reCAPTCHA и вернуть токен.

        :param website_key: site key виджета (атрибут ``data-sitekey``).
        :param website_url: страница, на которой размещён виджет.
        :param is_invisible: невидимая reCAPTCHA (v3-поток); ``None`` — из настроек.
        :param action: ``action`` для невидимой reCAPTCHA.
        :param is_enterprise: enterprise-эндпоинт.
        :param api_domain: ``google.com`` или ``recaptcha.net``.
        :param cookies: cookie, которые нужно подложить в браузер солвера.
        :param user_agent: User-Agent внутреннего браузера.
        :returns: токен ``g-recaptcha-response``.
        :raises CaptchaError: любая ошибка решения (см. :mod:`.errors`).
        """
        return self.solve_detailed(
            website_key=website_key,
            website_url=website_url,
            is_invisible=is_invisible,
            action=action,
            is_enterprise=is_enterprise,
            api_domain=api_domain,
            cookies=cookies,
            user_agent=user_agent,
        ).token

    def solve_detailed(
        self,
        *,
        website_key: str,
        website_url: str,
        is_invisible: bool | None = None,
        action: str | None = None,
        is_enterprise: bool | None = None,
        api_domain: str | None = None,
        cookies: list[dict[str, Any]] | None = None,
        user_agent: str | None = None,
    ) -> VisionAIResult:
        """Решить reCAPTCHA и вернуть расширенный результат.

        Отличается от :meth:`solve` только типом возвращаемого значения:
        здесь доступны тип челленджа, время и число попыток.

        :param website_key: site key виджета.
        :param website_url: страница с виджетом.
        :param is_invisible: переопределить ``VisionAIOptions.is_invisible``.
        :param action: переопределить ``VisionAIOptions.action``.
        :param is_enterprise: переопределить ``VisionAIOptions.is_enterprise``.
        :param api_domain: переопределить ``VisionAIOptions.api_domain``.
        :param cookies: cookie для браузера солвера.
        :param user_agent: User-Agent внутреннего браузера.
        :returns: :class:`VisionAIResult`.
        :raises CaptchaError: любая ошибка решения.
        """
        module = require_dependency("vision_ai_recaptcha_solver", _PACKAGE, extra="vision")
        config = module.SolverConfig(**self._options.to_solver_config_kwargs())

        try:
            with module.RecaptchaSolver(config) as solver:
                result = solver.solve(
                    website_key=website_key,
                    website_url=website_url,
                    is_invisible=(
                        self._options.is_invisible if is_invisible is None else is_invisible
                    ),
                    action=action if action is not None else self._options.action,
                    is_enterprise=(
                        self._options.is_enterprise if is_enterprise is None else is_enterprise
                    ),
                    api_domain=api_domain or self._options.api_domain,
                    cookies=cookies,
                    user_agent=user_agent or self._options.user_agent,
                )
        except CaptchaError:
            raise
        except Exception as exc:  # noqa: BLE001 - библиотека бросает свои типы
            raise translate_vision_ai_error(exc) from exc

        if not getattr(result, "token", None):
            raise CaptchaError(
                f"[vision-ai] солвер вернул пустой токен (тип: "
                f"{getattr(result, 'captcha_type', 'unknown')})."
            )

        return VisionAIResult(
            token=result.token,
            captcha_type=_stringify_captcha_type(getattr(result, "captcha_type", None)),
            elapsed=getattr(result, "time_taken", None),
            attempts=getattr(result, "attempts", None),
            cookies=getattr(result, "cookies", None),
        )

    async def solve_async(
        self,
        *,
        website_key: str,
        website_url: str,
        is_invisible: bool | None = None,
        action: str | None = None,
        is_enterprise: bool | None = None,
        api_domain: str | None = None,
        cookies: list[dict[str, Any]] | None = None,
        user_agent: str | None = None,
    ) -> VisionAIResult:
        """Асинхронный вариант :meth:`solve_detailed`.

        ``AsyncRecaptchaSolver`` поднимает свой event loop работы с браузером,
        поэтому конкурентные вызовы должны использовать разные
        ``server_port`` / ``download_dir`` (см. ``VisionAIOptions``).

        :param website_key: site key виджета.
        :param website_url: страница с виджетом.
        :param is_invisible: переопределить ``VisionAIOptions.is_invisible``.
        :param action: переопределить ``VisionAIOptions.action``.
        :param is_enterprise: переопределить ``VisionAIOptions.is_enterprise``.
        :param api_domain: переопределить ``VisionAIOptions.api_domain``.
        :param cookies: cookie для браузера солвера.
        :param user_agent: User-Agent внутреннего браузера.
        :returns: :class:`VisionAIResult`.
        :raises CaptchaError: любая ошибка решения.
        """
        module = require_dependency("vision_ai_recaptcha_solver", _PACKAGE, extra="vision")
        config = module.SolverConfig(**self._options.to_solver_config_kwargs())

        try:
            async with module.AsyncRecaptchaSolver(config) as solver:
                result = await solver.solve(
                    website_key=website_key,
                    website_url=website_url,
                    is_invisible=(
                        self._options.is_invisible if is_invisible is None else is_invisible
                    ),
                    action=action if action is not None else self._options.action,
                    is_enterprise=(
                        self._options.is_enterprise if is_enterprise is None else is_enterprise
                    ),
                    api_domain=api_domain or self._options.api_domain,
                    cookies=cookies,
                    user_agent=user_agent or self._options.user_agent,
                )
        except CaptchaError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise translate_vision_ai_error(exc) from exc

        if not getattr(result, "token", None):
            raise CaptchaError(
                f"[vision-ai] солвер вернул пустой токен (тип: "
                f"{getattr(result, 'captcha_type', 'unknown')})."
            )

        return VisionAIResult(
            token=result.token,
            captcha_type=_stringify_captcha_type(getattr(result, "captcha_type", None)),
            elapsed=getattr(result, "time_taken", None),
            attempts=getattr(result, "attempts", None),
            cookies=getattr(result, "cookies", None),
        )


def _stringify_captcha_type(value: Any) -> str | None:
    """Привести ``captcha_type`` (обычно Enum) к строке.

    :param value: значение из ``SolveResult``.
    :returns: строковое имя типа или ``None``.
    """
    if value is None:
        return None
    return getattr(value, "value", str(value))


def backend_label(backend: SolverBackend) -> str:
    """Человекочитаемое имя бэкенда для сообщений об ошибках.

    :param backend: бэкенд решения.
    :returns: название бэкенда.
    """
    return {
        SolverBackend.AUDIO: "playwright-recaptcha/audio",
        SolverBackend.IMAGE: "playwright-recaptcha/capsolver",
        SolverBackend.VISION_AI: "vision-ai/yolo",
    }.get(backend, str(backend))

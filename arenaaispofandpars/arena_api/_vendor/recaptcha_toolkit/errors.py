"""Иерархия исключений :mod:`recaptcha_toolkit`.

Все ошибки пакета наследуются от :class:`CaptchaError`, поэтому вызывающий код
может перехватить одной конструкцией всё, что связано с капчей, и при этом
отличать частные случаи (нет iframe, таймаут, rate limit, отсутствует
зависимость) по конкретным подклассам.
"""

from __future__ import annotations

from typing import Any


class CaptchaError(Exception):
    """Базовая ошибка пакета. Наследуют все остальные."""


class SolverDependencyError(CaptchaError):
    """Не установлена опциональная зависимость (playwright, selenium, ...).

    Атрибут :attr:`package` хранит имя пакета, :attr:`extra` — имя extra из
    ``pyproject.toml``, если зависимость поставляется через него.
    """

    def __init__(
        self,
        message: str,
        *,
        package: str | None = None,
        extra: str | None = None,
    ) -> None:
        super().__init__(message)
        self.package: str | None = package
        self.extra: str | None = extra


class RecaptchaNotFoundError(CaptchaError):
    """На странице не найден виджет reCAPTCHA (ни iframe, ни разметки)."""


class RecaptchaTimeoutError(CaptchaError):
    """Капча не была решена за отведённое время."""

    def __init__(self, message: str, *, timeout: float | None = None) -> None:
        super().__init__(message)
        self.timeout: float | None = timeout


class RecaptchaRateLimitError(CaptchaError):
    """Google ответил «Try again later» — включён лимит на попытки с этого IP."""


class RecaptchaSolveError(CaptchaError):
    """Солвер исчерпал попытки и не смог решить капчу."""

    def __init__(self, message: str, *, attempts: int | None = None) -> None:
        super().__init__(message)
        self.attempts: int | None = attempts


class SiteKeyDetectionError(CaptchaError):
    """Не удалось автоматически определить ``website_key`` (site key) страницы."""


def _chain(
    error_class: type[CaptchaError],
    message: str,
    cause: BaseException,
    **kwargs: Any,
) -> CaptchaError:
    """Создать ошибку пакета, сохранив ссылку на исходное исключение.

    Конструкция ``raise X from exc`` здесь неприменима: функции этого модуля
    не бросают, а *возвращают* исключение (бросает вызывающий код). Чтобы
    трассировка не теряла первопричину, проставляем ``__cause__`` вручную.

    :param error_class: класс ошибки пакета.
    :param message: человекочитаемое сообщение.
    :param cause: исходное исключение.
    :param kwargs: дополнительные аргументы конструктора ошибки.
    :returns: подготовленное исключение.
    """
    error = error_class(message, **kwargs)
    error.__cause__ = cause
    return error


def translate_playwright_recaptcha_error(exc: BaseException, *, backend: str) -> CaptchaError:
    """Преобразовать исключение ``playwright-recaptcha`` в ошибку пакета.

    Сопоставление идёт по имени класса, поэтому сам ``playwright_recaptcha``
    может быть не установлен — файл импортируется без него.

    :param exc: исходное исключение.
    :param backend: человекочитаемое имя бэкенда для сообщения.
    :returns: исключение иерархии :class:`CaptchaError`.
    """
    name = type(exc).__name__

    if name == "RecaptchaNotFoundError":
        return _chain(
            RecaptchaNotFoundError,
            f"[{backend}] виджет reCAPTCHA не найден на странице.",
            exc,
        )
    if name == "RecaptchaRateLimitError":
        return _chain(
            RecaptchaRateLimitError,
            f"[{backend}] reCAPTCHA отклоняет запросы с этого IP (rate limit). "
            "Смените прокси или подождите.",
            exc,
        )
    if name == "RecaptchaTimeoutError":
        return _chain(
            RecaptchaTimeoutError,
            f"[{backend}] истекло время ожидания токена.",
            exc,
        )
    if name == "RecaptchaSolveError":
        return _chain(
            RecaptchaSolveError, f"[{backend}] не удалось решить капчу: {exc}", exc
        )
    if name == "CapSolverError":
        return _chain(
            RecaptchaSolveError,
            f"[{backend}] CapSolver API вернул ошибку: {exc}. Проверьте ключ и "
            "баланс либо переключитесь на SolverBackend.AUDIO.",
            exc,
        )

    return _chain(
        RecaptchaSolveError, f"[{backend}] непредвиденная ошибка солвера: {exc!r}", exc
    )


def translate_vision_ai_error(exc: BaseException) -> CaptchaError:
    """Преобразовать исключение ``VisionAIRecaptchaSolver-0`` в ошибку пакета.

    :param exc: исходное исключение.
    :returns: исключение иерархии :class:`CaptchaError`.
    """
    mapping: dict[str, type[CaptchaError]] = {
        "CaptchaNotFoundError": RecaptchaNotFoundError,
        "ElementNotFoundError": RecaptchaNotFoundError,
        "SolverTimeoutError": RecaptchaTimeoutError,
        "TimeoutError": RecaptchaTimeoutError,
        "ModelDownloadError": SolverDependencyError,
    }
    target = mapping.get(type(exc).__name__, RecaptchaSolveError)
    return _chain(target, f"[vision-ai] {exc}", exc)


def translate_selenium_error(exc: BaseException, *, where: str) -> CaptchaError:
    """Преобразовать исключение Selenium/``selenium-recaptcha-solver``.

    :param exc: исходное исключение.
    :param where: описание операции, на которой произошёл сбой.
    :returns: исключение иерархии :class:`CaptchaError`.
    """
    name = type(exc).__name__

    if name == "RecaptchaException":
        message = str(exc)
        if "detected automated queries" in message.lower():
            return _chain(RecaptchaRateLimitError, f"[selenium] {where}: {message}", exc)
        return _chain(RecaptchaSolveError, f"[selenium] {where}: {message}", exc)
    if name in {"NoSuchElementException", "TimeoutException"}:
        return _chain(
            RecaptchaNotFoundError,
            f"[selenium] {where}: элемент/iframe reCAPTCHA не найден. "
            "Проверьте XPath и наличие виджета на странице.",
            exc,
        )

    return _chain(RecaptchaSolveError, f"[selenium] {where}: {exc!r}", exc)


def require_dependency(module_name: str, package: str, extra: str | None = None) -> Any:
    """Импортировать опциональную зависимость и обернуть ошибку её отсутствия.

    :param module_name: имя модуля для ``importlib``.
    :param package: имя дистрибутива для подсказки в сообщении.
    :param extra: имя extra из ``pyproject.toml`` (например ``"captcha"``).
    :returns: импортированный модуль.
    :raises SolverDependencyError: если модуль не установлен.
    """
    import importlib

    try:
        return importlib.import_module(module_name)
    except ImportError as exc:  # pragma: no cover - зависит от окружения
        hint = f'pip install "{package}"' + (f'  # или pip install ".[{extra}]"' if extra else "")
        raise SolverDependencyError(
            f"Для этого бэкенда требуется пакет {package!r} ({hint}).",
            package=package,
            extra=extra,
        ) from exc

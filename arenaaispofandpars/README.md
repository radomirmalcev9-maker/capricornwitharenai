# arena-api

Типизированный синхронный и асинхронный Python-клиент и CLI для **Arena (`arena.ai`)** с автоматическим подхватом сессии и прокси из браузера, TLS-имперсонацией (`curl_cffi`), **невидимым фоновым браузером** для прохождения reCAPTCHA Enterprise v3 и встроенным аудио-авторешателем капчи **без внешнего `ffmpeg`**.

---

## Возможности

- **Zero-config подхват сессии и прокси**: автоматически читает куки из локального профиля Firefox (включая живую сессию `recovery.jsonlz4` Firefox 136+ и настройки прокси `prefs.js` / системного прокси Windows), профилей Chromium (`rookiepy`), `state/cookies.json` или `ARENA_COOKIE`.
- **Невидимый фоновый режим**: запросы Direct Chat выполняются через настоящий десктопный Chrome / Edge / Chromium со скрытым за пределами экрана окном (`WS_EX_TOOLWINDOW`, без иконки в панели задач, без `Alt+Tab` и без перехвата фокуса).
- **Встроенное авторешение капчи без FFmpeg**: при появлении Cloudflare Turnstile или Google reCAPTCHA v2 челлендж автоматически решается в фоне (декодирование аудио через WebAudio `OfflineAudioContext` + встроенный чистый Python FLAC-кодер).
- **Чистый UTF-8 поток**: корректно декодирует кириллицу и эмодзи из стриминговых ответов `arena.ai` и безопасно выводит текст в консоль Windows (`cp1251` / `cp866` / `utf-8`).
- **Лёгкое ядро**: базовый `import arena_api` зависит только от `httpx[http2]`; тяжёлые зависимости (`playwright`, `curl_cffi`, `rookiepy`, `arena_api._vendor.recaptcha_toolkit`) подгружаются лениво только тогда, когда реально нужны.

---

## Установка

```bash
# Полная установка со всеми возможностями (рекомендуется)
python -m pip install -e ".[auto]"

# Если на ПК нет установленного Google Chrome или Microsoft Edge:
python -m playwright install chromium
```

Дополнительные профили зависимостей в `pyproject.toml`:
- `.[impersonate]` — отправка HTTP/2 и TLS-отпечатка реального браузера (`curl-cffi`, `httpx-curl-cffi`);
- `.[firefox]` — чтение профилей браузеров через `rookiepy` (для Firefox также есть встроенный lock-safe читатель `cookies.sqlite` + `recovery.jsonlz4`);
- `.[e2e]` / `.[captcha]` / `.[auth-captcha]` / `.[vision]` — браузерное окружение и дополнительные бэкенды капчи;
- `.[dev]` — `pytest`, `mypy`, `pyflakes`.

---

## Быстрый старт (CLI)

Достаточно один раз быть авторизованным на `https://arena.ai` в своём браузере (например, Firefox) или выполнить `--login`:

```bash
# Отправить запрос и получить потоковый ответ (браузер работает полностью невидимо)
python -m arena_api --prompt "Привет! Чем хорош дебют Гроба?"

# Указать конкретную модель (по умолчанию используется авто-выбор самой свежей модели сайта)
python -m arena_api --model claude-opus-4-6 --prompt "Объясни разницу между TCP и UDP."

# Список доступных моделей
python -m arena_api --models

# Проверить найденную сессию и статус доступа
python -m arena_api --status
arena-api --status

# Показать все проверенные источники кук, прокси и TLS-профиль без сетевых запросов
python -m arena_api --explain

# Диагностика профилей Firefox
python -m arena_api --diagnose

# Разовый ручной вход в окне браузера с сохранением кук в ./state/cookies.json
python -m arena_api --login

# При необходимости показать окно браузера для визуальной отладки
python -m arena_api --show-browser --prompt "Тест с видимым окном"
```

---

## Использование из Python

### Direct Chat (`arena.ai`, синхронно и потоково)

```python
import sys
from arena_api import AutoOptions, auto_direct_client

with auto_direct_client(AutoOptions(), verification_token="auto") as client:
    for event in client.stream("Привет! Напиши 3 коротких совета по Python."):
        if event.kind == "text" and event.text:
            sys.stdout.write(event.text)
            sys.stdout.flush()
```

### Асинхронный Direct Chat

```python
import asyncio
from arena_api import AutoOptions, auto_async_direct_client

async def main() -> None:
    async with await auto_async_direct_client(
        AutoOptions(), verification_token="auto"
    ) as client:
        answer = await client.acomplete("Коротко сравни SQLite и PostgreSQL.")
        print(answer)

asyncio.run(main())
```

### Классический Gradio-клиент

Для развёртываний со стандартной очередью Gradio (`/queue/join`) доступен `auto_client()` (и асинхронный `auto_async_client()`):

```python
from arena_api import auto_client

with auto_client() as client:
    print(client.complete("Hello!"))
```

---

## Примеры (`examples/`)

Все готовые скрипты собраны в каталоге [`examples/`](examples/):

- [`examples/quickstart.py`](examples/quickstart.py) — минимальный запуск Direct Chat с потоковым выводом ответа в консоль;
- [`examples/firefox_session.py`](examples/firefox_session.py) — прямое чтение сессии и прокси из профиля Firefox (`FirefoxSessionManager`);
- [`examples/login_save_cookies.py`](examples/login_save_cookies.py) — разовый вход через браузер с сохранением `./state/cookies.json`;
- [`examples/captcha_autosolve.py`](examples/captcha_autosolve.py) — автономная демонстрация встроенного решателя reCAPTCHA без `ffmpeg`.

---

## Структура пакета

| Модуль | Описание |
| --- | --- |
| `arena_api/auto.py` | Zero-config обнаружение сессий, `AutoOptions`, `DirectVerificationToken`, `auto_direct_client`, `auto_client` и CLI. |
| `arena_api/_window_cloak.py` | Скрытие окна браузера на уровне ОС (Win32 `ctypes` ToolWindow, CDP `setWindowBounds`, Preferences) и восстановление UTF-8 из CDP. |
| `arena_api/_direct_page.py` | Нативная работа с UI-композером `arena.ai`, инъекция кук доверия и детекция челленджей после отправки. |
| `arena_api/direct.py` | Клиенты `DirectArenaClient` / `AsyncDirectArenaClient` и парсер стрима Vercel AI Data Stream / SSE. |
| `arena_api/transport.py` | HTTP/2 транспорт, нормализация кук и прокси, TLS-имперсонация (`curl_cffi`). |
| `arena_api/auth/` | Менеджеры сессий (`FirefoxSessionManager`, `BrowserSessionManager`), `BrowserEnvironment`, кинематика мыши и встроенный `autosolve.py`. |
| `arena_api/_vendor/recaptcha_toolkit/` | Встроенный подпакет `arena_api._vendor.recaptcha_toolkit` для интеграции дополнительных солверов без конфликтов имён в PyPI. |

---

## Проверка и тесты

```bash
python -m pyflakes arena_api tests examples
python -m mypy
python -m pytest -q
```

Лицензия: [Apache-2.0](LICENSE).

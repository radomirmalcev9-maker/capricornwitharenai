"""Разговор с Капри через arena-api — личный аккаунт Arena вместо локальной модели.

Модуль — ровно та же «розетка», что была у local_ai.LocalAI: main.py и actions.py
зовут ask(), chatter(), summarize_report() и start_server(), а внутри вместо Ollama
теперь arena-api из папки arenaaispofandpars.

Если Arena недоступна (нет сессии, нет интернета, не установлены зависимости),
все методы возвращают None, и Капри, как и раньше, откатывается на поиск в Google.
"""
import datetime
import logging
import os
import random
import sys
import threading
import time

from answer_style import clean, clean_short, looks_broken
from persona import CHARACTER, SPEECH_RULES, user_context

log = logging.getLogger("capri")

BASE = os.path.dirname(os.path.abspath(__file__))
VENDOR = os.path.join(BASE, "arenaaispofandpars")
STATE = os.path.join(BASE, "arena_state", "cookies.json")

#: Короткое напоминание о характере — в каждом запросе. Полный SYSTEM (весь CHARACTER)
#: уходит один раз, в первое сообщение Direct Chat: дальше сервер помнит разговор сам.
COMPACT = ("Ты — Капри, цифровая собеседница из Найт-Сити, живёшь в компьютере пользователя. "
           "Говоришь живо, с иронией и лёгкой дерзостью, о себе только «я». "
           "Не представляйся и не рассказывай, кто ты, если прямо не спросили.")

TAIL = ("Ответь по-русски, 2–3 предложения, без markdown, списков, эмодзи и ремарок "
        "в звёздочках и скобках.")

SYSTEM = f"""{CHARACTER}

{SPEECH_RULES}
Отвечай на любые вопросы о науке, истории, технике, языке, о себе, советы и просьбы рассказать что-то."""

CHATTER_TOPICS = [
    "пожалуйся, что тебе скучно", "подразни пользователя за то, что он долго сидит за компьютером",
    "пошути про то, как тесно жить в компьютере", "сделай комплимент с подколкой",
    "пошути про его рабочий стол или файлы", "скажи что-нибудь загадочное и чуть жутковатое",
    "напомни отдохнуть, но в своём стиле", "похвастайся, что ты быстрее его процессора",
    "вспомни о небе и о том, что хочешь собственное тело",
]


class _LogStream:
    """Поток для служебных сообщений arena-api: у Капри нет консоли, всё идёт в capri.log."""

    def write(self, text):
        text = (text or "").strip()
        if text:
            log.info("%s", text)
        return len(text or "")

    def flush(self):
        pass

    def isatty(self):
        return False


class ArenaAI:
    """Ответы через arena-api. Интерфейс совпадает с прежним LocalAI."""

    def __init__(self, cfg, client=None):
        cfg = cfg or {}
        self.model = str(cfg.get("arena_model") or "").strip()
        self.backend = str(cfg.get("arena_backend") or "auto").strip().lower()
        self.base_url = str(cfg.get("arena_base_url") or "https://arena.ai").strip()
        self.timeout = float(cfg.get("arena_timeout") or 90)
        self.state_path = str(cfg.get("arena_state_path") or STATE)
        self.history = []          # [{"role": ..., "content": ...}] — как у LocalAI
        self.on_model_change = None  # main записывает выбранную модель в config.json
        self.last_error = ""
        self.mode = None           # "gradio" | "direct"
        self._pkg = None
        self._options = None
        self._client = client      # Gradio-клиент (или DirectArenaClient в режиме direct)
        self._direct = None
        self._direct_chat = None
        self._lock = threading.Lock()
        self._gradio_failures = 0
        self._retry_at = 0.0       # раньше этого времени не пробуем подключаться заново

    # ---------- подключение ----------

    @staticmethod
    def installed():
        """Есть ли рядом папка arenaaispofandpars с модулем arena_api."""
        if VENDOR not in sys.path:
            sys.path.insert(0, VENDOR)
        try:
            import arena_api  # noqa: F401
            return True
        except Exception as e:
            log.info("arena-api не загрузилась: %s", e)
            return False

    @property
    def available(self):
        return self._client is not None or self._direct is not None

    def _import(self):
        if self._pkg is not None:
            return self._pkg
        if VENDOR not in sys.path:
            sys.path.insert(0, VENDOR)
        try:
            import arena_api
        except ImportError as e:
            self.last_error = (f"не хватает библиотеки ({e.name or e}) — запусти setup_ai.bat "
                               "или: pip install httpx[http2]")
            log.info("arena-api: %s", self.last_error)
            return None
        except Exception as e:  # noqa: BLE001 — модуль есть, но сломан
            self.last_error = f"arena-api не загрузилась: {e}"
            log.info("%s", self.last_error)
            return None
        self._pkg = arena_api
        return arena_api

    def _make_options(self, pkg):
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        return pkg.AutoOptions(
            base_url=self.base_url,
            storage_path=self.state_path,
            artifacts_dir=os.path.join(os.path.dirname(self.state_path), "artifacts"),
            interactive=False,          # у Капри нет консоли: ждать Enter некому
            prompt=lambda _message: "",
            verify=True,
            solve_captchas="auto",
            output=_LogStream(),
        )

    def _connect(self):
        """Создаёт клиент. Возвращает True, если получилось."""
        with self._lock:
            if self.available:
                if self._pkg is None:
                    self._import()  # клиент могли передать снаружи (тесты, свой транспорт)
                return True
            if time.monotonic() < self._retry_at:
                return False
            pkg = self._import()
            if pkg is None:
                self._retry_at = time.monotonic() + 60
                return False
            if self._options is None:
                self._options = self._make_options(pkg)
            errors = []
            modes = ["gradio", "direct"] if self.backend not in ("gradio", "direct") else [self.backend]
            for mode in modes:
                try:
                    if mode == "gradio":
                        self._client = pkg.auto_client(self._options)
                        self.mode = "gradio"
                        log.info("arena-api: подключилась (Gradio, %s)", self.base_url)
                    else:
                        self._direct = pkg.auto_direct_client(self._options, verification_token="auto")
                        self.mode = "direct"
                        log.info("arena-api: подключилась (Direct Chat, %s)", self.base_url)
                    self.last_error = ""
                    return True
                except Exception as e:  # noqa: BLE001 — пробуем следующий режим
                    errors.append(f"{mode}: {e}")
                    log.info("arena-api: режим %s не подошёл — %s", mode, e)
            self.last_error = self._explain(errors)
            self._retry_at = time.monotonic() + 60  # не долбим Arena на каждую фразу
            log.info("arena-api недоступна: %s", self.last_error)
            return False

    def _explain(self, errors):
        text = " | ".join(errors) or "неизвестная ошибка"
        low = text.lower()
        if "no session found" in low or "нет сессии" in low:
            return ("нет сессии Arena — войди на arena.ai в своём браузере (Firefox или Chrome) "
                    "или запусти setup_ai.bat и войди в открывшемся окне")
        if "proxy" in low or "connect" in low or "timed out" in low or "timeout" in low:
            return f"нет связи с {self.base_url} — проверь интернет или VPN ({text})"
        if "playwright" in low:
            return f"для входа нужен Playwright: {text}"
        return text

    def start_server(self):
        """Фоновое подключение при запуске Капри (main зовёт в отдельном потоке)."""
        try:
            self._connect()
        except Exception as e:  # noqa: BLE001 — Капри должна запуститься в любом случае
            self.last_error = str(e) or e.__class__.__name__
            log.info("arena-api: не удалось подключиться — %s", self.last_error)

    def close(self):
        for client in (self._client, self._direct):
            try:
                if client is not None:
                    client.close()
            except Exception:  # noqa: BLE001
                pass

    # ---------- запросы ----------

    def _now(self):
        return datetime.datetime.now().strftime("%d.%m.%Y %H:%M")

    def _prompt(self, question):
        return f"{COMPACT}\n{user_context()}\nСейчас {self._now()}.\n\n{question}\n\n[{TAIL}]"

    def _system_prompt(self, question):
        """Первое сообщение Direct Chat: там весь характер, дальше хватает COMPACT."""
        return f"{SYSTEM}\n{user_context()}\nСейчас {self._now()}.\n\n{question}\n\n[{TAIL}]"

    def _chat_gradio(self, prompt, history, timeout=None):
        pkg = self._pkg
        messages = [pkg.Message(m["role"], m["content"]) for m in history]
        config = pkg.GenerationConfig(queue_timeout=timeout or self.timeout)
        chunks = self._client.stream(prompt, model=self.model or None, config=config, history=messages)
        return "".join(chunk.delta for chunk in chunks)

    def _direct_client(self):
        if self._direct is None:
            pkg = self._import()
            if pkg is None:
                raise RuntimeError(self.last_error or "arena-api не загрузилась")
            if self._options is None:
                self._options = self._make_options(pkg)
            self._direct = pkg.auto_direct_client(self._options, verification_token="auto")
        return self._direct

    def _direct_model(self, client):
        """Какая модель Direct Chat: из настроек, иначе лучшая доступная (и запоминаем)."""
        if self.model:
            return self.model
        models = [m for m in client.get_models() if m.available]
        if not models:
            raise RuntimeError("Arena не отдала список доступных моделей")
        try:
            from arena_api.direct import model_chat_score
            best = min(models, key=model_chat_score)
        except Exception:  # noqa: BLE001 — приватная эвристика недоступна, берём первую
            best = models[0]
        self.model = best.id
        log.info("arena-api: выбрана модель %s (%s)", best.id, best.display_name or "")
        if self.on_model_change:
            self.on_model_change(best.id)
        return best.id

    def _chat_direct(self, prompt, history, fresh=False, timeout=None):
        client = self._direct_client()
        config = self._pkg.GenerationConfig(queue_timeout=timeout or self.timeout)
        if fresh:
            # отдельный разговор, чтобы реплика «ни о чём» не оседала в основном контексте
            return client.chat(model=self._direct_model(client), config=config).send_message(prompt)
        if self._direct_chat is None:
            # контекст разговора сервер помнит сам по conversation_id
            self._direct_chat = client.chat(model=self._direct_model(client), config=config)
        return self._direct_chat.send_message(prompt)

    def _complete(self, prompt, history=(), fresh=False, timeout=None):
        """Один запрос. Gradio первым, при его отказе — Direct Chat."""
        if not self._connect():
            return None
        if self.mode == "direct":
            return self._chat_direct(prompt, history, fresh=fresh, timeout=timeout)
        try:
            answer = self._chat_gradio(prompt, history, timeout=timeout)
            self._gradio_failures = 0
            return answer
        except Exception as e:  # noqa: BLE001 — Gradio мог отвалиться, пробуем Direct
            self._gradio_failures += 1
            log.info("arena-api: Gradio не ответил (%s), отвечаю через Direct Chat", e)
            if self._gradio_failures >= 2:  # два раза подряд — дальше сразу Direct
                self.mode = "direct"
                log.info("arena-api: переключаюсь на Direct Chat постоянно")
            return self._chat_direct(prompt, history, fresh=fresh, timeout=timeout)

    # ---------- то, что зовёт Капри ----------

    def ask(self, question):
        """Текст ответа или None, если лучше открыть поиск."""
        if not self._connect():
            return None
        prompt = self._prompt(question)
        if self.mode == "direct" and self._direct_chat is None:
            prompt = self._system_prompt(question)
        try:
            raw = self._complete(prompt, self.history)
        except Exception as e:  # noqa: BLE001
            self.last_error = str(e) or e.__class__.__name__
            log.info("Arena не ответила: %s", self.last_error)
            return None
        if raw is None:
            return None
        answer = clean(raw, question, self.history)
        if looks_broken(answer):
            log.info("Arena вернула пустой или оборванный ответ: %r", (raw or "")[:200])
            return None
        self.history.append({"role": "user", "content": question})
        self.history.append({"role": "assistant", "content": answer})
        self.history = self.history[-6:]
        return answer

    def chatter(self):
        """Короткая спонтанная реплика, когда Капри появляется сама. None — если не вышло."""
        prompt = (f"{COMPACT}\n{user_context()}\n\n"
                  "Ты сама решила ненадолго появиться на экране. Скажи одну короткую спонтанную фразу, "
                  f"до пятнадцати слов. Тема: {random.choice(CHATTER_TOPICS)}. "
                  f"Не спрашивай, чем помочь, и не упоминай команды.\n\n[{TAIL}]")
        try:
            raw = self._complete(prompt, fresh=True, timeout=min(self.timeout, 25))
        except Exception as e:  # noqa: BLE001
            log.info("Arena: реплика не получилась — %s", e)
            return None
        return clean_short(raw)

    def summarize_report(self, report):
        prompt = (f"{COMPACT}\n\n"
                  "Вот отчёт диагностики моего ПК. Скажи 2–4 предложения: общее состояние, главные "
                  "проблемы и что сделать. Безвредные ошибки вроде DistributedCOM не раздувай.\n\n"
                  f"{report[:6000]}\n\n[{TAIL}]")
        try:
            raw = self._complete(prompt, fresh=True)
        except Exception as e:  # noqa: BLE001
            log.info("Arena: отчёт не разобрала — %s", e)
            return None
        return clean(raw or "", "отчёт диагностики", []) or None

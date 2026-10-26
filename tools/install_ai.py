"""Подключение Капри к Arena через arena-api.

    python tools/install_ai.py

Вызывается из setup_ai.bat. Делает три вещи: доставляет недостающие библиотеки,
находит (или создаёт) сессию Arena и прописывает настройки в config.json.
Все сообщения здесь, а не в .bat: cmd плохо читает русский текст в батниках.
"""
import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR = os.path.join(BASE, "arenaaispofandpars")
STATE = os.path.join(BASE, "arena_state", "cookies.json")
CONFIG = os.path.join(BASE, "config.json")

#: Минимум для работы и максимум для удобства: чтение профилей Chrome/Edge и
#: TLS-отпечаток настоящего браузера заметно снижают шанс словить проверку.
NEEDED = ["httpx[http2]>=0.27"]
EXTRA = ["rookiepy>=0.5", "curl_cffi>=0.7", "httpx-curl-cffi>=0.1.5"]


def say(text=""):
    print(text, flush=True)


def pip(*packages):
    try:
        return subprocess.run([sys.executable, "-m", "pip", "install", *packages]).returncode == 0
    except Exception as e:  # noqa: BLE001
        say(f"[Capri] pip не сработал: {e}")
        return False


def ensure_packages():
    say("[Capri] Проверяю библиотеки для arena-api...")
    if not pip(*NEEDED):
        say("[Capri] Не удалось поставить httpx — проверь интернет и запусти setup_ai.bat ещё раз.")
        return False
    if not pip(*EXTRA):
        say("[Capri] Дополнительные библиотеки не встали — Капри всё равно попробует подключиться,")
        say("        просто проверок от Arena может быть больше.")
    return True


def import_api():
    if VENDOR not in sys.path:
        sys.path.insert(0, VENDOR)
    try:
        import arena_api
        return arena_api
    except Exception as e:  # noqa: BLE001
        say(f"[Capri] Модуль arena_api не загрузился: {e}")
        say("        Проверь, что папка arenaaispofandpars лежит рядом с main.py.")
        return None


def options_for(api, interactive):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    return api.AutoOptions(
        storage_path=STATE,
        interactive=interactive,
        verify=True,
        solve_captchas="auto",
        output=sys.stdout,
    )


def show_models(client):
    try:
        models = [m for m in client.get_models() if m.available]
    except Exception:  # noqa: BLE001
        return
    if not models:
        return
    say(f"[Capri] Доступных моделей: {len(models)}. Например:")
    for model in models[:8]:
        say(f"        {model.id}" + (f" — {model.display_name}" if model.display_name else ""))

    say("[Capri] Модель можно закрепить в config.json: \"arena_model\": \"…\" (пусто — выбирать самой).")


def check_session(api):
    """Есть ли уже готовая сессия Arena (браузер, state/cookies.json, ARENA_COOKIE)."""
    say("[Capri] Ищу сессию Arena в браузере...")
    options = options_for(api, interactive=False)
    try:
        discovered = api.discover_session(options)
    except Exception as e:  # noqa: BLE001
        say(f"[Capri] Поиск сессии не получился: {e}")
        return False
    if discovered is None:
        say("[Capri] Сессия не найдена.")
        return False
    say(f"[Capri] Нашла: {discovered.description}")
    try:
        client = api.auto_client(options)
    except Exception as e:  # noqa: BLE001
        say(f"[Capri] Сессия есть, но Arena её не приняла: {e}")
        return False
    try:
        show_models(client)
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass
    say("[Capri] Проверка пройдена: Arena отвечает.")
    return True


def playwright_ready():
    try:
        import playwright  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def install_playwright():
    if not playwright_ready():
        choice = input("[Capri] Для окна входа нужен Playwright (~40 МБ). Установить? [y/N]: ").strip().lower()
        if choice not in ("y", "yes", "д", "да"):
            return False
        if not pip("playwright>=1.44"):
            return False
    say("[Capri] Проверяю браузер для окна входа...")
    subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"])
    return True


def login(api):
    say()
    say("[Capri] Можно войти вручную: откроется окно браузера, войди на arena.ai,")
    say("        потом вернись сюда и нажми Enter.")
    choice = input("Открыть окно входа? [y/N]: ").strip().lower()
    if choice not in ("y", "yes", "д", "да"):
        return False
    if not install_playwright():
        say("[Capri] Без Playwright окно входа не открыть.")
        return False
    try:
        outcome = api.interactive_login(options_for(api, interactive=True), path=STATE)
    except Exception as e:  # noqa: BLE001
        say(f"[Capri] Вход не получился: {e}")
        say("        Если ошибка про браузер — выполни: python -m playwright install chromium")
        return False
    if outcome.ok:
        say(f"[Capri] Сессия сохранена: {outcome.path or STATE}")
        return True
    say("[Capri] Вход не подтвердился. Проверь, что ты вошёл на arena.ai, и попробуй снова.")
    return False


def save_settings():
    """Прописать arena_ai в config.json, убрать старые ключи Ollama и не тронуть остальное."""
    data = {}
    if os.path.exists(CONFIG):
        try:
            with open(CONFIG, encoding="utf-8-sig") as f:
                text = f.read()
            data = json.loads(text) if text.strip() else {}
        except ValueError:
            say("[Capri] В config.json ошибка, не могу туда записать.")
            say('        Впиши вручную: "arena_ai": true')
            return False
    data["arena_ai"] = True
    data.setdefault("arena_model", "")
    data.setdefault("arena_backend", "auto")
    data.setdefault("arena_base_url", "https://arena.ai")
    data.setdefault("arena_timeout", 90)
    data.pop("local_ai", None)
    data.pop("local_model", None)
    with open(CONFIG, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    say("[Capri] В config.json записано: \"arena_ai\": true")
    return True


def main():
    say("[Capri] Подключаю разговор через Arena (arena-api).")
    say()
    if not ensure_packages():
        return 1
    api = import_api()
    if api is None:
        return 1

    ready = check_session(api)
    if not ready:
        say()
        say("[Capri] Можно войти двумя способами:")
        say("        1) войти на https://arena.ai в своём браузере (Firefox, Chrome, Edge) и запустить")
        say("           setup_ai.bat заново — Капри сама найдёт сессию;")
        say("        2) войти в окне, которое откроет этот скрипт.")
        ready = login(api)
        if ready:
            check_session(api)

    save_settings()
    say()
    if ready:
        say("[Capri] Готово! Перезапусти Капри (значок в трее -> «Выход», затем run.bat) — и можно болтать.")
        return 0
    say("[Capri] Настройки записаны, но сессии пока нет: без неё Капри будет отвечать только поиском.")
    say("        Войди на arena.ai в браузере и запусти setup_ai.bat ещё раз.")
    return 1


if __name__ == "__main__":
    sys.exit(main())

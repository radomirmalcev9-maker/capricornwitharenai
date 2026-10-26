# Примеры использования (`examples/`)

| Скрипт | Назначение |
| --- | --- |
| `examples/quickstart.py` | Минимальный запуск Direct Chat (`auto_direct_client(..., verification_token="auto")`) с потоковым выводом ответа, невидимым фоновым браузером и авто-капчей. |
| `examples/firefox_session.py` | Чтение кук и прокси напрямую из профиля Firefox (`FirefoxSessionManager`) и отправка запроса. |
| `examples/login_save_cookies.py` | Ручной вход в аккаунт один раз с сохранением сессии в `./state/cookies.json`. |
| `examples/captcha_autosolve.py` | Демонстрация встроенного аудио-решателя reCAPTCHA (`auto_solve_challenge_on_page`) без внешнего `ffmpeg`. |

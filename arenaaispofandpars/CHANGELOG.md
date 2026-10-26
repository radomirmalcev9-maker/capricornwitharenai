# История изменений

Формат: краткий список по версиям. Версии до 0.3.0 в этом файле не описаны —
смотрите историю git.

## Unreleased

### Точный отпечаток Firefox (`User-Agent`, `Accept-Language`, H2-заголовки) и фильтрация пассивного `jsd`-маяка Cloudflare

- **Исправлено (`FirefoxSessionManager.user_agent()`):** начиная с Firefox 120
  Mozilla разморозила `rv:109.0` (`nsHttpHandler.cpp`: `rv:<major>.0` и
  `Firefox/<major>.0` без `.patch`-версии из `compatibility.ini`). Старое
  значение `rv:109.0` и передача `.patch`-номера ломали криптографическую
  привязку `cf_clearance` к `User-Agent`, из-за чего Cloudflare отклонял живую
  сессию Firefox даже с `impersonate="firefox"`. Также добавлено чтение
  `general.useragent.override` из `prefs.js`.
- **Исправлено (`FirefoxSessionManager.accept_language()` на Windows):** в
  Windows `locale.getlocale()` возвращает словесные названия локалей CRT вроде
  `Russian_Russia` или `English_United States` вместо BCP-47 (`ru-RU`, `en-US`),
  что приводило к отправке невалидного заголовка
  `Accept-Language: Russian-Russia,russian;q=0.8,...`. Теперь используется
  Windows UI LCID (`GetUserDefaultUILanguage` -> `locale.windows_locale`),
  `intl.locale.requested` из `prefs.js` и строгая проверка синтаксиса BCP-47.
- **Исправлено (`ArenaTransport` при `impersonate=`):** при работе через
  `curl_cffi` теперь передаются браузерные заголовки транспортного уровня
  (`Accept-Encoding: gzip, deflate, br, zstd`, `Referer` для `same-origin`,
  а для профилей `firefox*` — `Te: trailers` и `Priority: u=4`), вместо
  урезанного `Accept-Encoding: gzip, deflate` от `httpx`.
- **Исправлено (`transport.py`, `auto.py`, `challenge.py`):** пассивный скрипт
  телеметрии Cloudflare `/cdn-cgi/challenge-platform/scripts/jsd/main.js` и
  упоминание `turnstile` в обычных страницах Next.js (`200` и `404` на `/config`)
  больше не принимаются ошибочно за блокирующую капчу `ChallengeRequiredError`.

### Приоритет авторизованного профиля над гостевым `state/cookies.json` и чистое поведение `--status`

- **Исправлено:** незавершённый запуск `--login` мог сохранить в `./state/cookies.json`
  только гостевые и аналитические cookie (`provisional_user_id`, `_ga`, `_dd_s`,
  `cf_clearance`, `sidebar_state`), которые затем затеняли реально авторизованный
  профиль Firefox (`arena-auth-prod-v1.*`). Теперь среди неявных локальных
  источников (`./state/cookies.json` по умолчанию и профили браузеров)
  авторизованная сессия (`has_session_cookie`) имеет приоритет над гостевой, а
  `login_and_save()` не засчитывает появление фоновых гостевых/телеметрийных
  cookie за завершённый вход.
- **Исправлено в `--status`:** флаг `--status` больше не запускает лестницу
  самовосстановления и браузер Playwright при проверке отклонённой сессии — он
  делает ровно один проверочный запрос, выводит вердикт (и подсказку про
  `pip install -e ".[impersonate]"`, если отсутствует `curl_cffi` при ответе
  Cloudflare) и завершает работу с кодом `2`.
- **Исправлено:** когда `AutoSessionManager` использует интерактивный
  `ChallengeWaitSolver` (`solve it in the browser window`), браузер теперь
  открывается с видимым окном (`headless=False`), а не в невидимом headless-режиме.
- **Исправлено в `--diagnose`:** короткие подсказки `sid` / `sess` сопоставляются
  по границам токенов (поэтому `sidebar_state` больше не помечается звёздочкой как
  cookie сессии), а в шапку отчёта добавлена строка `impersonation` со статусом
  `curl_cffi` + `httpx_curl_cffi`.

### Firefox 136+: миллисекундный `expiry`, `recovery.jsonlz4` и живой WAL

- **Исправлено:** начиная со схемы БД 16 (Firefox 136+), `moz_cookies.expiry`
  хранится в **миллисекундах** (`~1.8e12`), а не в секундах (`~1.8e9`) или
  микросекундах (`~1.8e15`), и `rookiepy` возвращает это поле без пересчёта.
  Деление значений `> 1e12` на `1_000_000` превращало все постоянные cookie
  современного Firefox в январь 1970 года (`~1.8e6` с) и отбрасывало их как
  просроченные — в результате `--diagnose` показывал `matching cookies: 0 (12
  expired skipped)`, хотя сессия была живой. Теперь `_expiry_seconds()` различает
  секунды, миллисекунды, микросекунды и наносекунды.
- **Исправлено:** сессионные cookie Firefox (без `Expires`/`Max-Age`) хранятся не
  в `cookies.sqlite`, а в `sessionstore-backups/recovery.jsonlz4` (при открытом
  браузере) и `sessionstore.jsonlz4` / `sessionstore.js` (после закрытия).
  Встроенный читатель и `--diagnose` теперь распаковывают `mozLz40` средствами
  стандартной библиотеки (с откатом на `recovery.baklz4`), поэтому отчёт по
  профилю, счётчик cookie при выборе профиля и `load_cookies()` видят одни и те
  же cookie даже без `rookiepy`.
- **Исправлено:** `rookiepy.firefox()` открывает `cookies.sqlite` с параметром
  `?mode=ro&immutable=1` (SQLite при этом полностью игнорирует `cookies.sqlite-wal`),
  не знает про `--profile-root` / `ARENA_FIREFOX_ROOT` и при явном `--profile`
  на не-дефолтный профиль всё равно читал дефолтный (`candidates[0]` совпадал с
  единственным выбранным кандидатом). Во всех трёх случаях теперь используется
  снимковый читатель с воспроизведением `-wal` и `recovery.jsonlz4`, а записи
  `rookiepy` дополнительно проверяются по целевым доменам (у `rookiepy` в SQL
  используется подстрочный `LIKE '%domain%'`).
- **Исправлено в `--diagnose`:** успешное чтение больше не добавляется в секцию
  `warnings` с маркером `! session read successfully` (из-за чего ветка
  `none -- the session was found and read` никогда не выполнялась, а при пустом
  SQLite и живом `sessionstore` отчёт противоречил сам себе); старые просроченные
  cookie рядом с живым сессионным токеном учитываются в `(N expired skipped)`, не
  объявляя рабочую сессию устаревшей; форматирование дат до 9999 года больше не
  упирается в ограничение `_gmtime64_s` на Windows.

### Firefox: читается тот профиль, где реально лежит сессия (+ `--diagnose`)

- **Исправлено:** профиль выбирался по `profiles.ini` — секция `[Install...]` →
  `Default`, затем профиль с `Default=1`, затем `*.default-release`. На машине с
  несколькими профилями (рабочий, сделанный через `about:profiles`, оставшийся от
  прошлой установки) это регулярно **не** тот профиль, где выполнен вход: менеджер
  возвращал пустой `dict`, а `auto_client()` сообщал «сессия не найдена», хотя
  cookie лежали в соседнем каталоге. Теперь собираются все профили всех каталогов,
  и используется тот, в котором есть cookie для целевых доменов; порядок из
  `profiles.ini` сохранён как порядок предпочтения, поэтому при отсутствии cookie
  везде выбирается он (и `--explain` честно показывает `0 cookies`). Переключение
  печатается в stderr: «using Firefox profile … (it holds the cookies; … does not)».
- **Исправлено:** `rookiepy.firefox()` читает только профиль по умолчанию. Если
  выбран другой профиль, `rookiepy` больше не спрашивают — иначе он вернул бы
  cookie чужого профиля, которые выглядят настоящими. `rookiepy` остаётся первым
  путём для профиля по умолчанию, как и раньше.
- **Новые каталоги профилей:** кроме обычного для ОС, на Linux ищутся
  `~/snap/firefox/common/.mozilla/firefox`, `~/.var/app/org.mozilla.firefox/.mozilla/firefox`
  и `~/snap/firefox/current/.mozilla/firefox`. На Ubuntu со snap-сборкой Firefox
  (и на Flatpak) `~/.mozilla/firefox` не существует, поэтому поиск всегда
  заканчивался «профиль не найден». Новые переменные `ARENA_FIREFOX_ROOT` (каталог
  профилей или путь к `profiles.ini`) и `ARENA_FIREFOX_PROFILE` (имя или абсолютный
  путь), CLI-флаги `--profile-root` / `--profile`; имя профиля ищется и внутри
  `<root>/Profiles`.
- **Исправлено:** срок действия cookie приводится к секундам. `moz_cookies.expiry`
  в старых профилях — микросекунды, а сравнивался он с `time.time()`; теперь
  `_expiry_seconds()` понимает оба варианта, ISO-строки и `0` = сессионная cookie,
  просроченные отбрасываются в Python (а не SQL-условием, зависящим от единиц).
  Записи `cookie_records()` всегда отдают секунды.
- **Исправлено:** контейнерные каталоги (`Profiles`, `Crash Reports`) больше не
  считаются профилями; сообщение об ошибке перечисляет все каталоги, которые
  просматривались, а не один; сообщение о неудачном чтении больше не начинается с
  безобидного «rookiepy не установлен».
- **`--diagnose` (новое):** отчёт о профилях, безопасный для пересылки —
  значения cookie не печатаются никогда, вместо них длина и первые 8 hex SHA-256,
  плюс хост, имя, путь, `Secure`/`HttpOnly`/`SameSite`, срок действия, число строк
  в `cookies.sqlite`, `journal_mode`, выбранный профиль с причиной выбора и
  предупреждения (профиль пуст; cookie просрочены; cookie лежат на другом хосте,
  включая поддомены — тогда нужен `--base-url`; нет «сессионного» имени; каталог
  профилей не найден). `--diagnose --json` — та же структура в JSON.
  Реализация — `arena_api.auth.diagnostics` (`collect_firefox_report`,
  `format_firefox_report`, `report_as_json`), доступна и из Python.
- **`--status`** печатает имена найденных cookie (без значений), `--explain` —
  строку на каждый профиль и строку `Firefox selected`.
- Тесты: `tests/test_firefox_profiles.py` (выбор по содержимому, несколько
  профилей и каталогов, snap, переменные окружения, обход `rookiepy`, единицы
  срока действия, контейнерные каталоги) и `tests/test_diagnostics.py`
  (значение cookie не попадает ни в текст, ни в JSON; предупреждения о просрочке,
  чужом хосте, поддомене, пустом профиле; повреждённая база не ломает отчёт).

### Отпечаток браузера, а не только его cookie: `impersonate`

- Новая причина `ChallengeRequiredError` при формально верной сессии: `cf_clearance`
  и родственные cookie привязаны не только к IP и User-Agent, но и к отпечатку
  соединения (TLS ClientHello + настройки HTTP/2), а у httpx он свой, «питоновский».
  Сессия, аккуратно перенесённая из Firefox, из-за одного этого может получить
  страницу проверки — именно то, что видно в `example_firefox.py` после успешного
  чтения профиля (`arena-auth-prod-v1.0`, `cf_clearance`, `__cf_bm` читаются, а
  запрос к `/config` отбит челленджем).
- `arena_api.transport` умеет отдавать запросы через `curl_cffi` с профилем
  браузера: `ArenaTransport(impersonate="firefox")` строит
  `httpx_curl_cffi.CurlTransport` (async — `AsyncCurlTransport`), не меняя ни
  одного внешнего API: httpx-клиент, SSE-парсер, ретраи и обновление сессии
  работают как раньше. Зависимость ленивая, extra — `[impersonate]`
  (`curl-cffi` + `httpx-curl-cffi`), он же добавлен в `[auto]`.
- Выбор профиля: `impersonate=None` (по умолчанию) следует за источником сессии —
  Firefox-менеджер даёт `firefox`, `BrowserSessionManager` передаёт своё поле
  `impersonate` (его заполняет `arena_api.auto` по найденному браузеру); `False`
  выключает, строка (`"firefox147"`, `"chrome"`) задаёт явно. Если extra не
  установлен, производное значение молча остаётся выключенным, а явное — падает с
  подсказкой `pip install 'arena-api[impersonate]'`; `impersonate=` вместе с
  `http_transport=` — ошибка (impersonation и есть транспорт).
- `auto_client()` / `python -m arena_api` включают это сами: `AutoOptions.impersonate
  = "auto"`, CLI-флаг `--impersonate auto|off|chrome|firefox|…`, строка
  `fingerprint` в `--explain`, уведомление в stderr о выбранном профиле.
  Отображение источников: Firefox → `firefox`; Chrome/Chromium/Brave/Vivaldi/Opera
  → `chrome`; `state/cookies.json`, `ARENA_COOKIE`, `cookies=` → `chrome`
  (заголовки в этих путях и так Chromium-shaped); неизвестный источник — ничего.
- Валидация сессии (`BrowserSessionManager`) использует тот же профиль, что и
  клиент: проба и рабочие запросы больше не идут разными стеками.
- Тесты: `tests/test_impersonate.py` — политика выбора профиля, наличие/отсутствие
  зависимости, сборка sync/async транспорта (записывающий двойник), взаимоисключение
  с `http_transport`, обвязка bootstrap через менеджер, CLI-флаг, а также проверки
  на **реальном сокете**: запрос через curl-транспорт сохраняет наши заголовки и
  cookie, а SSE приходит инкрементально, а не одним куском. CI ставит
  extra `[impersonate]` и гоняет их на всех платформах.
- README: раздел «Отпечаток вместо „нейтрального“ клиента» с таблицей выбора;
  `example_firefox.py` печатает, какой отпечаток ушёл на сервер.

### `--login` в настоящем браузере: `--channel chrome`

- `AutoOptions.channel` + флаг CLI `--channel chrome|msedge`: окно входа
  запускается в установленном браузере, а не во встроенном Chromium. Это
  единственный способ войти в аккаунт, который авторизуется **через Google**:
  Google отклоняет вход из анонимной сборки Playwright («этот браузер или
  приложение может быть небезопасным»), а установленный Chrome принимает.
  Раньше этот путь был доступен только из Python (`login_and_save(channel=...)`),
  CLI его не умел.
- Подсказка при неудачном запуске окна различает случаи: без `--channel` —
  «`playwright install chromium`», с `--channel` — «поставьте Google Chrome либо
  уберите `--channel`», потому что скачивание встроенной сборки такой запуск не
  починит.
- README: раздел «Если Google не даёт войти» — три выхода, включая
  рекомендуемый: войти своим обычным браузером и дать библиотеке прочитать его
  cookie (`auto_client()`, профиль Firefox, `rookiepy` для Chrome/Edge/…), вообще
  не используя Playwright.
- Тесты: `channel` в `AutoOptions`/CLI/override и текст подсказки
  (`tests/test_auto.py`).

### `--hide-automation`: окно входа перестаёт представляться роботом

- `login_environment_options(hide_automation=True)` (и `--hide-automation` в CLI,
  `AutoOptions.hide_automation`) убирает из окна `--login` то, по чему Google
  отличает управляемый браузер: `--enable-automation` уходит в
  `ignore_default_args`, добавляется `--disable-blink-features=AutomationControlled`,
  а на страницу ставится init-скрипт `HIDE_WEBDRIVER_SCRIPT`, снимающий
  `navigator.webdriver` (удаление из прототипа, с `defineProperty` для сборок,
  где `delete` запрещён). Пара `--channel chrome --hide-automation` — рабочая
  комбинация для аккаунта, который входит **через Google**.
- Новое поле `BrowserEnvironmentOptions.extra_init_scripts` — init-скрипты,
  которые ставятся на каждую страницу из `new_page()` **до** первой навигации
  (маска ставится только так: скрипт, добавленный после `goto`, уже опоздал).
  Явные `ignore_default_args`/`launch_args`/`extra_init_scripts`, переданные в
  `login_environment_options`, не затираются, а дополняются.
- Маскировка остаётся opt-in и не проникает в обычный путь: `build_init_script`
  по-прежнему не содержит ни одного стелс-маркера (это стережёт отдельный тест),
  `hide_automation=False` по умолчанию, а при явном `environment_options=`
  вариант вызывающего используется как есть.
- `HIDE_WEBDRIVER_SCRIPT` экспортируется из `arena_api.auth`; заодно убраны
  дубликаты `TOOLKIT_PACKAGE`/`inspect_page` в его `__all__` и добавлен тест
  гигиены (`arena_api.auth` как и верхний уровень: всё импортированное
  объявлено, ничего не объявлено дважды).

### Тесты

- `test_a_saved_result_names_the_file` больше не сравнивает вывод `describe()` с
  POSIX-литералом: `LoginResult.describe()` печатает путь платформо-нативно, и на
  `windows-latest` тот же `Path('state/cookies.json')` читается как
  `state\cookies.json`. Из-за этого CI на `main` был красным — падал только этот
  тест.

## 0.4.0

### Вход руками один раз: `arena-api --login`

- `arena_api/auth/login.py`: `login_and_save()` / `alogin_and_save()` открывают
  **headed** Chromium с настройками обычного браузера (`identify_automation=False`,
  без детерминизма тестов), ждут, пока вы войдёте, и пишут Playwright
  `storage_state` в `state/cookies.json` — тот самый путь, который
  `auto_client()` ищет в первую очередь. Учётные данные через библиотеку не
  проходят; при желании форму заполняет ваш `LoginFlow`.
- Успех определяется сравнением cookie до и после: раунд засчитывается, когда для
  доменов сайта появились новые cookie, поэтому знать имя сессионного cookie не
  нужно. Файл пишется с правами `0600`, `state/` добавлен в `.gitignore`, а
  «пустое» состояние никогда не перезаписывает рабочую сессию (тогда
  `saved=False`, файл не тронут).
- Существующий `cookies.json` по умолчанию используется как посев контекста
  (`reuse_existing`), чтобы не входить заново; `fresh=True` — войти под другим
  аккаунтом. Отмена (Ctrl-C / закрытый stdin) останавливает ожидание, но всё
  равно возвращает то, что браузер уже накопил.
- `arena_api.auto.interactive_login()` + `LoginOutcome`: тот же вход из кода, с
  последующей проверкой сохранённого файла запросом к `/config`. Проверка
  намеренно не лечит сессию сама (`interactive=False`, `verify=False`) —
  иначе «лекарством» от отказа оказался бы ещё один вход.
- CLI: `--login` (коды возврата 0/1/2), `--fresh`, `--headless`,
  `--login-rounds`, а `--storage` теперь описывает и куда сессия сохраняется.
  `--login --models` входит и сразу выполняет задачу с новой сессией.

### Другие типы капчи, а не только reCAPTCHA

- `ChallengeKind.DATADOME`: DataDome определяется по фреймам
  `captcha-delivery.com`/`geo.captcha-delivery.com`, заголовкам
  `x-datadome`/`x-datadome-cid` и селекторам `DATADOME_SELECTORS` — и в быстром
  HTTP-пути, и в браузере.
- `ChallengeWaitSolver` закрывает виды, у которых токена не существует:
  Turnstile и managed Cloudflare ожидаются (страница пересканивается, пока
  challenge не исчезнет), hCaptcha/DataDome/неизвестный экран передаются
  человеку в headed-окне (`interactive=True` — подсказка и продление ожидания по
  Enter). Результат — `CaptchaAttempt(cleared=True, token=None)`; успех, как и
  прежде, определяет `ChallengeHandler` своим пересканированием.
- Enter в интерактивном ожидании спрашивается в рабочем потоке
  (`asyncio.to_thread`): блокировка event loop остановила бы и Playwright, то
  есть как раз ту страницу, которая должна пройти проверку.
- `CompositeSolver` распределяет виды между солверами (первый поддержавший
  выигрывает), `solver_for()`/`describe_solver()` — публичные помощники.
- `DirectVerificationToken` (`verification_token="auto"`) больше не может тихо
  вернуть пустой assertion: композитный солвер разворачивается до токен-моста
  (`_token_solver`), солвер, который reCAPTCHA не поддерживает (ожидание на
  машине без `playwright-recaptcha`), отклоняется с подсказкой, а пустой токен
  после «успешного» снятия экрана превращается в `AuthenticationError`.
- `resolve_solver()` собирает композит автоматически: токен-мост (если
  зависимости на месте) + ожидание. Так как ожиданию нужен только Playwright,
  `solve_captchas="auto"` больше не «ничего» на машине без
  `playwright-recaptcha`. Новые поля `AutoOptions`: `wait_out_challenges=True`,
  `challenge_wait_timeout=30.0`; флаги `--no-wait`, `--wait-timeout`; строка
  `--explain` показывает, какой солвер действительно будет работать.
- `inspect_page_sync()` — синхронный двойник инспектора страницы (те же сигналы,
  классификация и диагностика на диске); общий код вынесен в `_frame_signals`,
  `_scan_signals`, `_capture_target`/`_finish_capture`.
- Исправлена классификация по селектору: `.h-captcha` (документированный класс
  виджета из `HCAPTCHA_SELECTORS`) не содержал подстроки `hcaptcha` и потому
  попадал в `UNKNOWN`. Сравнение теперь игнорирует пунктуацию.
- `REMEDIATION_TEMPLATE` подсказывает не только инфраструктурные решения, но и
  то, что экран можно подождать или решить руками там, где это разрешено.

### Упаковка и лицензия

- `recaptcha_toolkit` переехал внутрь пакета:
  `arena_api._vendor.recaptcha_toolkit`. Установка `arena-api` больше не может
  перезаписать одноимённый проект из PyPI (и наоборот), а glob `arena_api*`
  подхватывает подпакет сам. Импорты — относительные внутри тулкита, поэтому
  изменились только публичные пути: `from arena_api._vendor.recaptcha_toolkit
  import ...`. `pyproject.toml` больше не собирает отдельный top-level пакет.
- Добавлен `LICENSE` — Apache-2.0 (канонический текст, сверенный с независимой
  копией), в `pyproject.toml` лицензия объявлена SPDX-выражением
  `license = "Apache-2.0"` + `license-files` (PEP 639, `setuptools>=77`);
  классификатор `License ::` убран — с PEP 639 он несовместим. Добавлены
  остальные классификаторы и секция «Лицензия» в README.
- Тесты: `tests/test_login.py`, блоки про ожидание/композит в
  `tests/test_auth_captcha.py`, DataDome и `inspect_page_sync` в
  `tests/test_auth_challenge.py`, `interactive_login` и `--login` в
  `tests/test_auto.py`, лицензия и вендоринг в `tests/test_packaging.py`.
  Всего 580 офлайн-тестов.
- Прогоны герметичны: `isolated_options()` в `tests/test_auto.py` теперь
  фиксирует `profiles_root` несуществующим каталогом внутри `tmp_path`. Без
  этого ступень Firefox разрешала профиль **разработчика**
  (`~/.mozilla/firefox`, на Windows `%APPDATA%\Mozilla\Firefox\Profiles`) и
  отвечала раньше проверяемой ступени: на машине, где в Firefox есть cookie
  arena.ai, `test_other_browsers_are_read_through_rookiepy` падал с
  `'firefox' == 'browser:chrome'`. Добавлен сторожевой тест
  `test_isolated_options_never_point_at_a_host_browser_profile`.
- Новые примеры: `example_login.py` (вход руками) и
  `example_challenge_wait.py` (челленджи без токена).

## 0.3.0

### Ноль настроек: `arena_api.auto`

- `auto_client()`, `auto_async_client()`, `auto_direct_client()`,
  `auto_async_direct_client()` — единственный ручной шаг теперь вход в аккаунт в
  своём браузере. Библиотека сама находит сессию (`cookies=` →
  `ARENA_COOKIE`/`ARENA_COOKIES_FILE` → `state/cookies.json` → профиль Firefox →
  Chrome/Chromium/Edge/Brave/Vivaldi/Opera через `rookiepy`), подставляет
  заголовки того же браузера, проверяет сессию одним запросом и обновляет её.
- «Лестница» обновления `AutoSessionManager`: перечитать источник → вход по
  форме из полного набора `ARENA_*` → решить reCAPTCHA в браузере.
- Проверка сессии замечает капчу-интерстициал, отданный с кодом 200 вместо JSON
  (страница Direct Chat при этом не считается капчей — она и должна содержать
  v3-assertion).
- CLI: `python -m arena_api` (`--explain`, `--status`, `--models`, `--prompt`,
  `--solve auto|on|off`, `--non-interactive`, …) и консольная команда
  `arena-api`. Коды возврата: 0 — работает, 1 — сессия не найдена, 2 — сессия
  отвергнута.
- `DirectArenaClient`/`AsyncDirectArenaClient` принимают `session_source` и
  `max_auth_refreshes`: Direct Chat теперь обновляет сессию и повторяет запрос
  так же, как основной клиент. Assertion по-прежнему добывает вызывающий;
  `verification_token="auto"` — отдельный явный opt-in.
- Транспорт получил публичный `apply_session_cookies()` — для обновления,
  выполненного вне запроса.
- Обновление сессии сериализовано: параллельные запросы, получившие 403, не
  запускают по браузеру и не спрашивают Enter по разу каждый — первый обновляет,
  остальные берут его результат.

### Решение reCAPTCHA во время auth-прогона

- `arena_api/auth/captcha.py`: мост к `recaptcha_toolkit` — определение v2/v3,
  бэкенды AUDIO/IMAGE/перехват v3/VisionAI (YOLO), stealth всегда, без Selenium
  и без второго браузера (используется страница самого прогона).
- Подключено в `ChallengeHandler.check()`/`install()`,
  `BrowserEnvironment.with_captcha_solving()` и обновление
  `BrowserSessionManager`; всё opt-in.
- Новая ошибка `CaptchaSolveError` (подкласс `ChallengeRequiredError`) с полным
  отчётом о попытках.
- Extras: `auth-captcha` (мост), `auto` (всё для bootstrap сразу).

### Исправления и гигиена

- `ClientClosedError`: запрос через закрытый клиент больше не выглядит как
  `RuntimeError` из `httpx` и ловится через `except ArenaError`.
- Сообщения об ошибке `session_source` называют источник: профиль Firefox и
  свой менеджер сессии больше не путаются.
- `arena_api/py.typed` + `[tool.setuptools.package-data]`: аннотации видны
  mypy/pyright у тех, кто ставит пакет (PEP 561).
- `__all__` пакета полный (62 имени): `from arena_api import *` и статический
  анализ больше не расходятся с фактическим API.
- pyflakes чистый по всему репозиторию; mypy чистый при конфигурации из
  `pyproject.toml` (`check_untyped_defs`, `warn_unused_ignores`).
- CI: `.github/workflows/tests.yml` — pytest на Python 3.10–3.13 (Ubuntu) и
  дополнительно macOS/Windows, pyflakes, mypy, проверка «лёгкого» импорта,
  smoke-тест CLI, наличие `py.typed`.
- Тесты платформенных путей Firefox (`default_profiles_root`, User-Agent-токен)
  для Windows/macOS/Linux — раньше эта логика не была покрыта.
- `arena_api.egg-info/` убран из-под версионного контроля (артефакт сборки;
  `.gitignore` его уже покрывал).
- Конфигурация pytest (`testpaths`) и extra `dev` (pytest, pyflakes, mypy).

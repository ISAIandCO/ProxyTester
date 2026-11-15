# ProxyTester

Тестер подписок **VLESS / Hysteria2** для Windows 10/11 x64. Сравнивает каждый
сервер в двух режимах: **VPN** и **VPN → Cloudflare WARP**, проверяет NotebookLM,
Gemini и ваши сайты, измеряет задержку и скорость, создаёт интерактивный HTML.

Нужен для выбора сервера под конкретный сервис. Страница входа или HTTP 200
сами по себе **не считаются подтверждением доступности**.

## Запуск на Windows

1. Откройте [Actions → Test and build Windows portable](https://github.com/ISAIandCO/ProxyTester/actions/workflows/windows.yml),
   выберите успешную сборку и скачайте artifact **ProxyTester-windows-x64**.
   Внутри него находится `ProxyTester-windows-x64.zip` и контрольная сумма.
2. Распакуйте вложенный ZIP целиком в доступную для записи папку.
3. Откройте `Start.cmd` или `ProxyTester.exe`.
4. Введите URL подписки, необязательный HWID, параметры проверок. Можно добавить
   несколько подписок или указать локальный файл. Настройки сохраняются.
5. Дождитесь окончания. Откроется `reports/report.html`; рядом будут JSON и CSV.

В переносимой сборке уже есть Python, оба VPN-ядра и Chromium. Устанавливать
браузер, драйвер TUN, системный VPN или права администратора не требуется.
Первый запуск исходников скачивает компоненты из официальных релизов.
Сборка Windows запускается при изменении кода и вручную; правка только README
её не запускает. Автоматической публикации релизов нет.

### Из исходников

Установите Python 3.12 x64, затем в PowerShell в папке проекта:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
python -m proxytester setup
python -m proxytester configure
python -m proxytester run --open
```

Пользователям Windows с ограниченным PowerShell можно выполнять те же команды
через `.venv\Scripts\python.exe` без активации окружения.

## Настройки

`configure` создаёт **config.json**. Полный пример — [config.example.json](config.example.json).
В примере нет действующих подписок: добавьте URL или локальный файл.

```json
{
  "subscriptions": [
    {
      "url": "https://provider.example/subscription/TOKEN",
      "hwid": "YOUR-HWID",
      "hwid_mode": "header",
      "hwid_name": "x-hwid",
      "headers": {"User-Agent": "Your client"}
    },
    {"url": "https://another.example/subscription"}
  ],
  "files": [],
  "parallel": 2,
  "timeout": 20,
  "node_timeout": 240,
  "retries": 1,
  "latency_samples": 3,
  "speed": true,
  "download_bytes": 5000000,
  "upload_bytes": 0,
  "speed_repeats": 1,
  "warp": true,
  "browser": true
}
```

Неуказанные настройки получают значения по умолчанию.

| Настройка | Значение |
|---|---|
| `hwid_mode` | `header`, `query` или `bearer` (`Authorization: Bearer HWID`) |
| `hwid_name` | Имя HTTP-заголовка или query-параметра |
| `headers`, `query` в источнике | Дополнительные заголовки/параметры провайдера |
| `parallel` | 1–8 изолированных серверов одновременно; 1 для сравнения скорости без конкуренции |
| `timeout` | Таймаут сетевой операции, секунды |
| `node_timeout` | Общий бюджет на сервер с обоими маршрутами; увеличьте для медленных сервисов |
| `retries` | Ограниченные повторы проверки внешнего IP (0–3); регистрации не повторяются |
| `latency_samples` | Число свежих HTTPS-соединений (1–20) |
| `speed` | Отключить дорогие тесты скорости через `false` |
| `download_bytes` | Объём одного download (по умолчанию 5 MB на маршрут) |
| `upload_bytes` | Объём upload; 0 выключает его |
| `speed_repeats` | Повторы скорости (1–5), отчёт показывает медиану/разброс |
| `warp` | Отключить весь каскад и регистрацию через `false` |
| `browser` | JavaScript-проверки в Chromium; `false` оставляет HTTP-проверки |
| `warp_cache_days` | Срок повторного использования identity на тот же сервер, по умолчанию 7 дней |
| `storage_state` | Путь к сохранённой авторизованной сессии Chromium |

Для 90 серверов default download на двух маршрутах — около **900 MB** плюс
страницы сервисов, загрузки ядер/Chromium и сетевые накладные расходы. Неуспешные
серверы отсекаются проверкой IP до страниц и скорости. Отключите `speed` или
уменьшите `download_bytes`, если трафик ограничен.

### Свои сервисы и доказательство доступности

```json
{
  "services": [
    {
      "name": "NotebookLM",
      "url": "https://notebooklm.google.com/",
      "success_selector": "button:has-text('New notebook'), button:has-text('Create new')"
    },
    {
      "name": "My service",
      "url": "https://service.example/app",
      "success_selector": "[data-testid=application-ready]"
    }
  ],
  "cloudflare_urls": ["https://www.cloudflare.com/"]
}
```

`success_selector` должен находить **видимый элемент рабочего интерфейса**,
не рекламную кнопку или ссылку на вход. Playwright выполняет JavaScript.
Дополнительно поддерживается `success_regex` по тексту страницы (работает и в
HTTP-режиме). Без такого признака сайт остаётся «Не подтверждено».

Для NotebookLM распознаётся `location=unsupported` в цепочке перенаправлений,
включая переходы JavaScript, и типовые тексты региональных ограничений.
По умолчанию положительный признак — кнопка создания блокнота; у Gemini —
редактор запроса. Эти проверки показывают готовность интерфейса. Тестер не
создаёт блокноты и не отправляет запросы от имени пользователя; способность
аккаунта выполнить конкретную платную операцию отдельно не доказывается.
При изменении интерфейса Google обновите selectors в настройках.

Cloudflare различается как `challenge`, `captcha`, `block`, `clear_observed`,
`not_observed`, `http_error`, `unknown`; обычный встроенный Turnstile сам по себе
не считается срабатыванием защиты. CAPTCHA автоматически не решаются.

### Авторизованная сессия

```powershell
ProxyTester.exe list
ProxyTester.exe login --node NODE_ID
ProxyTester.exe run --open
```

В открытом браузере войдите в сервис вручную и вернитесь в консоль. Вход
проходит через выбранный VPN; сохранённая сессия используется в новых
изолированных контекстах обоих маршрутов. `session.json` содержит cookies,
localStorage и IndexedDB — храните его как пароль. Серверные проверки аккаунта
могут блокировать отдельные страны независимо от IP.

## Повторные проверки и прерывание

```powershell
ProxyTester.exe run --resume
ProxyTester.exe run --retry-failed
ProxyTester.exe list
ProxyTester.exe run --only ID1,ID2
ProxyTester.exe report --output reports/recovered.html
```

`Ctrl+C` останавливает тесты, закрывает процессы и сохраняет промежуточный
отчёт. `--resume` продолжает незавершённые строки, `--retry-failed` повторяет
ошибки сервера/каскада/сети. Региональная блокировка — результат измерения,
а не техническая ошибка; её повторяют через `--only`.
Если настройки поменялись, начните новый запуск без флагов продолжения.
Результаты сохраняются в `data/run.json` после этапов и каждого сервера.
Предыдущие результаты выбранных повторных тестов остаются с их временем.
Для независимых запусков укажите другие `--data` и `--output`.

Глобальные параметры ставятся **перед командой**:

```powershell
ProxyTester.exe --config other.json --data other-data run --output reports/other.html
```

## Отчёт

Один HTML открывается с диска без сервера и внешних библиотек. Он содержит
сводку по сервисам, лучшие серверы, таблицу двух маршрутов, сортировку,
комбинированные фильтры, поиск, раскрытие деталей, светлую/тёмную тему.
Кнопки CSV/JSON экспортируют **отфильтрованные** строки; соседние файлы содержат
весь запуск. Зелёная метка выделяет VPN, синяя — доступ только через WARP.
«Только WARP» требует подтверждения WARP и установленной ошибки/блокировки VPN;
неподтверждённый VPN не выдаётся за заведомо неработающий.

Настройки соединений, URL подписок, HWID, UUID/пароли, приватные ключи,
токены API, cookies и содержимое страниц не включаются в результаты.
Внешний IP, название сервера, страна из названия и проверенные URL без query
остаются в отчёте. Не помещайте секреты в пользовательские названия/пути сайтов.
Сами config.json, data/warp и session.json содержат секреты, их нельзя публиковать.
Временные core-конфиги удаляются; штатные логи ядер отключены.

## Как проходит трафик

* VLESS: локальный HTTP/mixed sing-box → SOCKS5 Xray → выбранный сервер.
  REALITY, XHTTP (включая `extra`), TCP/RAW, WebSocket, gRPC, HTTPUpgrade
  обрабатывает Xray. Несовместимые `flow` с XHTTP/WS/gRPC отклоняются явно.
* Hysteria2: локальный mixed sing-box → Hysteria2, в том числе Salamander и
  hopping из `mport`. TLS и SNI сохраняются.
* Каскад: mixed sing-box → userspace WireGuard с `detour: vpn` → основной
  VPN-сервер → WARP endpoint. Для VLESS UDP идёт через SOCKS5 UDP/Xray;
  сервер должен разрешать UDP. Без UDP каскад завершится ошибкой.
* Регистрация WARP: явный HTTP-прокси **этого же VPN**, после проверки внешнего
  IP. Нет direct fallback, environment proxy или отдельного регистратора.
  Ключ X25519 создаётся локально; приватный ключ не передаётся API.
* Identity кэшируется **отдельно на сервер**. Повторное использование не делает
  регистрации через другой сервер. POST `/reg` не повторяется автоматически;
  после HTTP 429 новые регистрации останавливаются до следующего запуска.
* У каждого сервера свои порты/процессы; TUN и системные маршруты не меняются.
  DNS целей — через VPN/DoH, а в каскаде DoH тоже проходит WireGuard. Локальный
  DNS нужен только для bootstrap адреса физического VPN-сервера (включая
  дополнительные физические endpoint в native XHTTP).
* До сервисов запрашиваются HTTPS Cloudflare trace и независимый IP endpoint.
  Каскад требует `warp=on/plus` и смены IP на обоих endpoints. Их IP могут
  различаться у провайдера с балансировкой; это явно видно в деталях.
  Chromium отдельно сверяет trace со своим HTTP-маршрутом; QUIC, прямой
  WebRTC UDP и локальное разрешение доменов браузером отключены.

Успех локального proxy-порта не считается успехом VPN. Конфигурация без
доказанного внешнего выхода не получает проверок сервисов. Это проверка графа
маршрутизации и наблюдаемого выхода, а не криптографическая аттестация того,
как провайдер реализует свой сервер.

## Форматы подписок

* Построчные URI `vless://`, `hysteria2://`, `hy2://`.
* Base64/base64url списки URI.
* Xray JSON: одиночный конфиг, массив конфигов или outbound.
* sing-box JSON: VLESS/Hysteria2 outbounds; VLESS переводится в Xray.
* Clash/Mihomo YAML с `proxies` VLESS/Hysteria2.

Импортируются **самостоятельные узлы**, а не пользовательские routing rules,
selector/urltest-группы, внешние файлы сертификатов или цепочки произвольных
outbound. Неизвестные протоколы, параметры и ошибочные записи попадают в отчёт
с причиной. Некоторые редкие native-опции проверяются самим закреплённым ядром;
его отказ отображается как ошибка конфигурации. Приватные CA/нестандартные
надстройки поставщика могут требовать дополнений парсера.

## Разработка и сборка

```powershell
python -m unittest discover -s tests -v
$env:PROXYTESTER_BROWSER_TESTS="1"
python -m unittest discover -s tests -v
python -m pip install pyinstaller==6.17.0
.\scripts\build_windows.ps1
```

Версия приложения — **proxytester/__init__.py**. Версии VPN-ядер, имена архивов
и SHA-256 — **proxytester/cores.lock.json**. Скачанные архивы проверяются до
распаковки; извлекается только ожидаемый executable. Зависимости закреплены
в pyproject.toml. Лицензии и исходники компонентов — [THIRD_PARTY.md](THIRD_PARTY.md).

Тесты используют настоящий Xray/sing-box: VLESS TCP, XHTTP, REALITY, сочетание
XHTTP+REALITY, Hysteria2+Salamander, WireGuard поверх VLESS/XHTTP/Hysteria2,
передачу download/upload и запрет fallback после остановки VPN-сервера.
Локальный WARP API — **фикстура**, не настоящая регистрация Cloudflare.
Браузерные тесты проверяют JS redirect и появление рабочего интерфейса.

Без действующей подписки нельзя проверить конкретные коммерческие серверы,
принятие HWID провайдером, регистрацию в публичном WARP API через эти серверы
и доступ NotebookLM/Gemini с аккаунтом пользователя. Программа не добавляет
демонстрационные результаты к настоящим измерениям.

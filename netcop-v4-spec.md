# NetCop v4 — доработки безопасности и UX

Прочитай весь документ перед началом. Задай вопросы если что-то непонятно. Не добавляй ничего сверх написанного — если что-то покажется нужным, спроси сначала.

---

## 1. Автогенерация API-ключа

### Сервер
- При первом запуске: если `NETCOP_API_KEY` не задан в переменных окружения и нет `server/config.json` — сгенерировать ключ через `secrets.token_urlsafe(32)`.
- Записать в `server/config.json`:
  ```json
  {"api_key": "сгенерированный_ключ"}
  ```
- Напечатать в консоль крупно:
  ```
  ============================================
  NEW API KEY GENERATED:
  aB3x...длинный_ключ...7Zq
  Save this key — you will need it for agents.
  ============================================
  ```
- Приоритет загрузки ключа: env `NETCOP_API_KEY` → `config.json` → генерация нового.
- Если загруженный ключ == `"secret"` или короче 16 символов — отказ запуска с сообщением об ошибке. Никаких дефолтов.
- Убрать `default="secret"` из кода полностью.

### Агент (install.bat)
- Убрать дефолтное значение ключа.
- Поле ключа обязательное. Если юзер нажал Enter без ввода — показать ошибку и спросить заново:
  ```batch
  :ask_key
  set /p APIKEY="Enter API Key (required): "
  if "%APIKEY%"=="" (
      echo ERROR: API Key is required. Get it from server console on first run.
      goto ask_key
  )
  ```

---

## 2. Bind адрес сервера

- Дефолтный bind: `127.0.0.1` (только локальные подключения).
- Настраивается через `config.json`:
  ```json
  {"api_key": "...", "host": "0.0.0.0", "port": 8000}
  ```
- Или через аргументы: `python launcher.py --host 192.168.1.100 --port 8000`
- Приоритет: аргументы CLI → config.json → дефолт 127.0.0.1:8000.
- При старте сервер печатает:
  ```
  NetCop Server starting...
  Bind: http://192.168.1.100:8000
  Database: /path/to/netcop.db
  Auth: enabled (key loaded from config.json)
  ```

### launcher.py
- Добавить `argparse` для `--host` и `--port`.
- Передавать в `uvicorn.run(app, host=host, port=port)`.

---

## 3. Audit log

### SQLite — новая таблица
```sql
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    hostname TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    params TEXT,
    source_ip TEXT
);
```

### Сервер
- При каждой команде (limit, unlimit, limit_process, unlimit_process, full_throttle, full_unthrottle, kill, priority_mode on/off) — вставлять запись.
- `source_ip` — брать из `request.client.host`.
- Новые эндпоинты:
  - `GET /api/audit?hostname=X&limit=50&offset=0` — возвращает записи с пагинацией.
  - Фильтр по `hostname` опциональный. Без него — все записи.

### Дашборд
- Новая кнопка в шапке: "Audit Log".
- По клику — модалка с таблицей: Time | Agent | Action | Target | Details | Source IP.
- Пагинация: кнопки "Older" / "Newer", по 50 записей.
- Фильтр по агенту (dropdown из текущих агентов).
- Без графиков, без аналитики — просто лог.

---

## 4. Priority Mode

### Концепция
Одна кнопка — глобально задушить все "тяжёлые" категории на всех агентах. Сценарий: надо срочно использовать канал, а кто-то качает обновления.

### Сервер

Priority profile хранится в `config.json` (дефолт):
```json
{
  "priority_profile": {
    "torrent": {"in_kbps": 128, "out_kbps": 64},
    "gaming": {"in_kbps": 256, "out_kbps": 128},
    "streaming": {"in_kbps": 256, "out_kbps": 128}
  }
}
```
Категории `web` и `system` — не трогаем.

- Новое состояние в памяти: `priority_mode_active: bool = False`.
- `POST /api/priority_mode/on` — включить:
  1. Для каждого агента в `agents_state`: пройтись по `top_processes`.
  2. Для каждого процесса с категорией из `priority_profile` — отправить команду `full_throttle` с лимитом из профиля.
  3. Сохранить список применённых лимитов в `priority_mode_limits[hostname]` (чтобы знать что снимать).
  4. `priority_mode_active = True`.
  5. Audit log: "priority_mode ON".

- `POST /api/priority_mode/off` — выключить:
  1. Для каждого агента: для каждого процесса в `priority_mode_limits[hostname]` — отправить `full_unthrottle`.
  2. Очистить `priority_mode_limits`.
  3. `priority_mode_active = False`.
  4. Audit log: "priority_mode OFF".

- `GET /api/status` — добавить поле `priority_mode: bool`.

**Важно:** priority mode — это временная маска. Не перезаписывает per-process лимиты в `process_limits_state`. Если у процесса уже стоит индивидуальный лимит меньше чем priority profile — оставляем индивидуальный (он строже).

### Дашборд
- В шапке: большая кнопка "Priority Mode" с индикатором ON/OFF.
  - OFF: серая, текст "Priority Mode".
  - ON: красная пульсирующая, текст "PRIORITY MODE ACTIVE".
- По клику — тогл. Без подтверждения на включение (скорость важна). С подтверждением на выключение ("Remove all priority limits?").
- Хоткей: `Ctrl+Shift+P` — тогл.
- Когда priority mode активен — в таблице агентов показывать бейдж "PM" рядом с hostname.

---

## 5. README

### Заменить формулировки
- "скрытый агент, работающий на целевых машинах" → "фоновый агент-служба на управляемых рабочих станциях"
- "целевые машины" → "управляемые машины" / "рабочие станции"
- "System Tray Agent: Агент может работать как фоновый процесс без консоли" → "Service mode: агент работает как фоновая служба с индикатором в системном трее"
- "Массовое управление" → "Групповые политики"
- "Сбор метрик" → "Телеметрия процессов"

### Добавить в начало (перед фичами)
> NetCop — инструмент администрирования сети для малых организаций (учебные классы, коворкинги, локальные офисы). Позволяет распределять полосу пропускания между процессами и контролировать сетевую нагрузку на рабочих станциях.

### Добавить секцию "First run"
1. Запустите сервер: `python launcher.py --host 0.0.0.0`
2. Сервер напечатает сгенерированный API-ключ — скопируйте его.
3. На рабочей станции запустите `install.bat` от имени Администратора.
4. Введите адрес сервера и скопированный ключ.
5. Откройте дашборд в браузере по адресу из консоли сервера.

---

## 6. Улучшения логирования

### Сервер
- При старте печатать: bind адрес, порт, путь к БД, статус auth.
- При 403 (неверный ключ) — логировать в консоль: `WARNING: Auth failed from {ip} - invalid API key`. Помогает дебажить "забыл указать ключ в агенте".
- При первом подключении нового агента: `INFO: New agent connected: {hostname} ({ip})` (уже есть, убедиться что работает).

---

## Файловые изменения
```
server/
  config.json       — НОВЫЙ (автогенерация при первом запуске)
  main.py           — изменён (audit log, priority mode, автогенерация ключа, bind config)
  launcher.py       — изменён (argparse для host/port)
  static/
    index.html      — изменён (кнопка priority mode, audit log кнопка)
    styles.css      — изменён (стили priority mode, audit modal)
    app.js          — изменён (priority mode тогл, audit log модалка, хоткей)

agent/
  install.bat       — изменён (обязательный ключ)
  (остальное без изменений)

README.md           — переписан
```

## Чего НЕ делаем
- Per-agent токены, ротация ключей, HMAC
- TLS / mTLS
- Тесты автоматические
- CI/CD
- Round-robin балансировка
- WebSocket / SSE
- Внешняя БД
- RBAC, юзеры, роли

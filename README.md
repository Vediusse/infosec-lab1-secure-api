# Лабораторная работа 1 — защищённый REST API

Рублёв Валерий Георгиевич, P3432. ИТМО, Информационная безопасность, 2026.

Учебный Flask API личных заметок. Классификация рисков — [OWASP Top 10:2025](https://top10.owasp.org/2025/).

## Запуск

Требуется Python 3.12. SQLite входит в Python.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
export JWT_SECRET=$(python -c 'import secrets; print(secrets.token_hex(32))')
export DEMO_PASSWORD='Laboratory-Demo-2026!'
flask --app app seed
flask --app app run --host 127.0.0.1 --port 5051
```

Демонстрационный пароль используется только локально; он не является секретом реальной системы. На другом терминале активируйте venv, экспортируйте DEMO_PASSWORD и запустите `bash scripts/demo.sh`.

## API

| Метод | Путь | Назначение |
|---|---|---|
| POST | /auth/login | JSON username/password → JWT, срок 900 секунд |
| GET | /api/data | Заметки текущего пользователя; Bearer JWT обязателен |
| POST | /api/notes | JSON text, 1–500 символов; Bearer JWT обязателен |

Пример входа:

```bash
curl -i http://127.0.0.1:5051/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"student","password":"Laboratory-Demo-2026!"}'
curl -i http://127.0.0.1:5051/api/data -H 'Authorization: Bearer <access_token>'
```

Ошибки: 400 — неверный JSON/ввод, 401 — неверные учётные данные/JWT, 413 — тело более 8 КБ, 429 — более пяти попыток входа в минуту с одного IP.

## Меры защиты

* **A01:2025 Broken Access Control.** Оба метода с данными проходят JWT middleware. `owner_id` берётся из проверенного `sub`, SQL выбирает только заметки владельца.
* **A05:2025 Injection.** SQL использует placeholders `?` с отдельными параметрами. HTML экранируется через `html.escape` при выдаче, ответы имеют JSON content type, `nosniff` и CSP. При создании полноценного UI необходим безопасный вывод в соответствующий HTML-контекст.
* **A07:2025 Authentication Failures.** scrypt с индивидуальной солью; JWT HS256 с обязательными exp/iat/sub/iss/aud и списком разрешённых алгоритмов. Секрет минимум 32 символа из окружения. Токен действует 15 минут.
* **A02:2025 Security Misconfiguration.** Debug выключен, запуск по умолчанию на loopback, секрет не хранится в git, ограничено тело запроса.
* **A03:2025 Software Supply Chain Failures.** Версии runtime-зависимостей зафиксированы; pip-audit и OWASP Dependency-Check проверяют известные уязвимости. Это частичное покрытие категории, а не защита всей цепочки поставок.
* **A09:2025 Security Logging and Alerting Failures.** События входа и отклонения JWT логируются без паролей и токенов. Централизованный сбор и оповещения не реализованы.
* **A10:2025 Mishandling of Exceptional Conditions.** Некорректный ввод получает контролируемый JSON-ответ. Неожиданные ошибки скрыты от клиента, детали сохраняются в серверном журнале.

Стенд учебный: limiter локальный для процесса, нет отзыва токенов, refresh, MFA, TLS termination и полноценного мониторинга. Для публикации API нужны HTTPS, production WSGI, shared limiter и управление секретами. CD не выполняется: задание проверяет CI, развертывание в нём не требуется.

## Проверки

```bash
bash scripts/verify.sh
```

14 регрессионных тестов: вход, запрет без JWT, SQLi, XSS, изоляция пользователей, пять вариантов неверного JWT, scrypt, limiter, валидация и заголовки, обязательный секрет.

GitHub Actions (`.github/workflows/ci.yml`) запускается при push, pull_request и вручную. Два jobs:

1. Pytest, Bandit SAST, pip-audit. Любая находка Bandit или pip-audit завершает проверку ошибкой.
2. OWASP Dependency-Check 13.0.0, experimental Pip Analyzer, HTML/JSON, порог CVSS ≥ 7. OSS Index выключен, так как требует отдельной учётной записи; NVD остаётся включённым. Необязательный repository secret `NVD_API_KEY` ускоряет загрузку NVD. Ошибки обновления базы не подавляются. Python-анализатор экспериментальный; pip-audit дополняет его сопоставлением пакетов PyPI.

Отчёты доступны как artifacts каждого запуска. Скриншоты и ссылки на выполненные проверки добавляются после запуска.

## Источники

* https://top10.owasp.org/2025/
* https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
* https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
* https://pyjwt.readthedocs.io/en/stable/usage.html
* https://dependency-check.github.io/DependencyCheck/analyzers/pip.html
* https://docs.github.com/en/actions/tutorials/build-and-test-code/python

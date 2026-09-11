# 📖 Использование

## CLI

### Флаги

| Флаг | Обязателен | По умолчанию | Описание |
|---|---|---|---|
| `--path` | нет | `.` | Путь к проекту (директория) или к одному файлу |
| `--level` | нет | `easy,medium,hard` | Уровни проверки через запятую: `easy`, `medium`, `hard` в любой комбинации |
| `--json` | нет | выключен | Вывести отчёт в формате JSON вместо человекочитаемой сводки |

### Примеры

```bash
# Проверить текущую директорию всеми уровнями, человекочитаемый вывод
python find_file.py

# Проверить конкретный проект
python find_file.py --path ./infra

# Только Easy-проверки
python find_file.py --level easy

# Easy + Medium (Hard пропускается)
python find_file.py --level easy,medium

# Только Hard, JSON-вывод
python find_file.py --level hard --path . --json

# Проверить один файл, а не всю директорию
python find_file.py --path ./deployment.yaml --level easy
```

### Вывод

**Человекочитаемый (`summary()`):**

```
======================================================================
📊 ИТОГОВАЯ СВОДКА АУДИТА
======================================================================
   Проект: ./infra
   Уровни: easy, medium
   Файлов просканировано: 12
   Всего находок: 7
      CRITICAL: 2
      HIGH: 3
      MEDIUM: 2
   Ошибок при проверке: 0
======================================================================
```

**JSON (`--json`):**

```json
{
  "project_path": "./infra",
  "levels": ["easy", "medium"],
  "files_scanned": 12,
  "total_findings": 7,
  "critical_count": 2,
  "findings": [
    {
      "level": "easy",
      "severity": "CRITICAL",
      "check_id": "privileged-container",
      "title": "Privileged Container",
      "file_path": "./infra/deployment.yaml",
      "line_num": 11,
      "line_text": "privileged: true"
    }
  ],
  "errors": []
}
```

> Про `check_id` в JSON: это слаг заголовка находки (`_slugify(title)`), а не официальный номер проверки — подробности в [ARCHITECTURE.md](ARCHITECTURE.md#-известное-архитектурное-ограничение).

## Python API

### `audit_project(path='.', levels=None) -> AuditReport`

Главная точка входа.

```python
from find_file import audit_project

report = audit_project(path="./infra", levels=["easy", "medium"])
```

- `levels=None` → используются все три уровня (`sorted(VALID_LEVELS)`).
- Неизвестное значение в `levels` (что угодно кроме `easy`/`medium`/`hard`) → `ValueError` с перечислением допустимых значений.
- Путь, по которому не найдено ни одного подходящего файла → пустой `AuditReport` с записью в `errors`, без исключения.

### Обёртки для одного уровня

```python
from find_file import audit_easy, audit_medium, audit_hard

report = audit_easy("./infra")     # levels=['easy']
report = audit_medium("./infra")   # levels=['medium']
report = audit_hard("./infra")     # levels=['hard']
```

### Работа с результатом

```python
report = audit_project("./infra")

print(f"Просканировано файлов: {report.files_scanned}")
print(f"Всего находок: {report.total_findings}")
print(f"CRITICAL: {report.critical_count}")

for finding in report.findings:
    print(f"[{finding.severity}] {finding.file_path}:{finding.line_num}")
    print(f"    {finding.title}: {finding.line_text}")

if report.errors:
    print("Ошибки при проверке:")
    for err in report.errors:
        print(f"  - {err}")

import json
with open("report.json", "w", encoding="utf-8") as f:
    json.dump(report.to_dict(), f, ensure_ascii=False, indent=2)
```

### Интеграция с FastAPI

```python
from fastapi import FastAPI
from find_file import audit_project

app = FastAPI()

@app.post("/api/audit")
def run_audit(path: str = ".", levels: str = "easy,medium,hard"):
    level_list = levels.split(',')
    report = audit_project(path, level_list)
    return report.to_dict()
```

## Интеграция в CI/CD

Во всех примерах используется exit code процесса: `0`, если CRITICAL-находок нет, `1` — если есть хотя бы одна (см. таблицу exit codes ниже).

### GitLab CI

```yaml
security_audit:
  stage: test
  image: python:3.11-slim
  script:
    - python find_file.py --path . --level easy,medium,hard --json > audit-report.json
  artifacts:
    paths:
      - audit-report.json
    when: always
  allow_failure: false   # job упадёт при exit code 1 (есть CRITICAL-находки)
```

### GitHub Actions

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run MisconfigHunter
        run: python find_file.py --path . --level easy,medium,hard --json > audit-report.json
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: audit-report
          path: audit-report.json
```

### Jenkins (Declarative Pipeline)

```groovy
pipeline {
    agent any
    stages {
        stage('Security Audit') {
            steps {
                sh 'python find_file.py --path . --level easy,medium,hard --json > audit-report.json'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'audit-report.json'
        }
    }
}
```

`sh` в Jenkins по умолчанию завершает stage с ошибкой, если команда вернула ненулевой exit code — то есть job упадёт сам при наличии CRITICAL-находок, без дополнительной логики.

## Exit codes

| Код | Когда | Источник |
|---|---|---|
| `0` | Аудит завершился успешно, CRITICAL-находок нет | `main()` в `find_file.py` |
| `1` | Аудит завершился успешно, но есть ≥1 находка с `severity == 'CRITICAL'` | `main()` в `find_file.py` |
| `2` | Передан невалидный `--level` (значение вне `easy`/`medium`/`hard`) | `main()` перехватывает `ValueError` из `audit_project()` |

Обратите внимание: exit code завязан именно на **CRITICAL**, а не на любые находки — HIGH/MEDIUM/LOW-находки не приводят к ненулевому коду завершения.

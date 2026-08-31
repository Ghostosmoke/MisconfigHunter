# 🛡️ MisconfigHunter

Статический аудитор безопасности инфраструктурного кода: находит небезопасные настройки в Kubernetes-манифестах, Docker/Docker Compose, Terraform, CloudFormation и CI/CD-пайплайнах — до того, как они попадут в прод.

MisconfigHunter не требует сети, аккаунтов в облаке или доступа к кластеру — он читает файлы с диска и ищет в них конкретные, документированные паттерны небезопасной конфигурации (open security group, privileged-контейнер, секрет в переменной окружения, отсутствие шифрования и т.д.). Каждая находка приходит с номером строки, текстом строки и понятной причиной — не просто «тут что-то не так», а точное место и объяснение.

Проверки разбиты на три уровня сложности — **Easy** (одиночный файл, прямые паттерны), **Medium** (одиночный файл + простая кросс-проверка внутри набора) и **Hard** (настоящий кросс-файловый анализ: связи между ServiceAccount и RoleBinding, IAM-политиками из разных ресурсов, Ingress и NetworkPolicy). Именно уровень Hard отличает MisconfigHunter от линтеров, которые проверяют файлы независимо друг от друга — он строит связи между ресурсами в разных файлах одного проекта.

## ✨ Ключевые возможности

- 🔍 **75 проверок** безопасности, сгруппированных по трём уровням сложности (25 / 25 / 25)
- 📍 **Точные находки** — номер строки, текст строки, причина для каждой проблемы
- 🔗 **Кросс-файловый анализ** на уровне Hard — например, «в наборе файлов есть Deployment, но нигде нет NetworkPolicy»
- ☁️ **Мультиоблачность** — AWS, GCP, Azure, plain Kubernetes, Docker/Compose, Terraform, GitLab CI, GitHub Actions
- 📦 **Zero external dependencies** — только стандартная библиотека Python, ничего не нужно ставить через pip
- 🧩 **Структурированный вывод** через `AuditReport`/`Finding` — готов для JSON и веб-API
- 🖥️ **CLI и библиотека** одновременно — тот же код работает и из терминала, и как импортируемый модуль
- 🚦 **Exit code для CI/CD** — процесс завершается кодом `1`, если найдена хотя бы одна CRITICAL-находка

> ⚠️ **Текущий статус:** Easy (25/25) и Medium (25/25) проверки реализованы полностью. Hard-уровень содержит 2 из 25 проверок с реальной логикой (51 — Cross-File Network Policy, 52 — IAM Privilege Escalation Path); остальные 23 — заглушки с описанием уязвимости, но без анализа файлов (см. [docs/CHECKS.md](docs/CHECKS.md#hard) за точным списком). Это сделано осознанно: лучше честно показывать заглушку, чем выдавать выдуманный результат.

## 🚀 Быстрый старт

```bash
# Проверить весь текущий проект всеми уровнями
python find_file.py

# Только Easy-проверки, конкретный путь
python find_file.py --path ./my-project --level easy

# Несколько уровней через запятую
python find_file.py --level easy,medium

# JSON-вывод для интеграции (CI/CD, веб-сервис)
python find_file.py --level easy,medium --json
```

## 📦 Установка

**Требования:** Python 3.8+, ничего кроме стандартной библиотеки.

```bash
git clone <repo-url> misconfighunter
cd misconfighunter
python find_file.py --path .
```

Подробности — в [docs/INSTALLATION.md](docs/INSTALLATION.md).

## 📖 Примеры использования

### CLI

```bash
python find_file.py --path ./infra --level hard --json > report.json
echo "Exit code: $?"   # 1, если есть CRITICAL-находки
```

### Python API

```python
from find_file import audit_project

report = audit_project(path="./infra", levels=["easy", "medium"])

print(report.summary())
print(f"Всего находок: {report.total_findings}")
print(f"Из них CRITICAL: {report.critical_count}")

for finding in report.findings:
    print(f"[{finding.severity}] {finding.file_path}:{finding.line_num} — {finding.title}")
```

Полное описание API, включая ограничения текущей реализации — в [docs/USAGE.md](docs/USAGE.md).

## 🏗️ Архитектура проекта

```
                     ┌─────────────────┐
   CLI / Python API  │   find_file.py   │  ← оркестратор
                     └────────┬────────┘
                              │ находит файлы, группирует по папкам,
                              │ вызывает нужный уровень проверок
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
      Easy_Check.py   Medium_Check.py   Hard_Check.py
      (01–25, файл)   (26–50, файл/     (51–75, кросс-
                        простой batch)    файловый batch)
              │               │               │
              └───────────────┴───────────────┘
                              ▼
                      печать отчёта в stdout
                              │
                    (find_file.py перехватывает
                     stdout и строит Finding[])
                              ▼
                        AuditReport
                    (findings, errors, summary,
                     to_dict() для JSON)
```

Подробное описание компонентов, потока данных и того, как добавить новую проверку — в [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## 📊 Поддерживаемые проверки

| Уровень | Файл | Диапазон | Количество | Реализовано полностью | Пример |
|---|---|---|---|---|---|
| Easy | `Easy_Check.py` | 01–25 | 25 | ✅ 25/25 | Privileged Container, Secrets in Env Vars, SSH Open to Internet |
| Medium | `Medium_Check.py` | 26–50 | 25 | ✅ 25/25 | Network Policy Missing, RDS Publicly Accessible, Docker Socket Mounted |
| Hard | `Hard_Check.py` | 51–75 | 25 | ⚠️ 2/25 | Cross-File Network Policy, IAM Privilege Escalation Path |

Полный список всех 75 проверок с описанием, критичностью и стандартом (CIS/NIST/SLSA, где применимо) — в [docs/CHECKS.md](docs/CHECKS.md).

## 🎯 Поддерживаемые форматы файлов

| Формат | Расширения / имена файлов |
|---|---|
| Kubernetes манифесты | `.yaml`, `.yml` |
| Docker Compose | `docker-compose.yml`, `docker-compose.yaml` |
| Dockerfile | `Dockerfile` |
| Terraform | `.tf`, `.tfvars` |
| CloudFormation | `.yaml`, `.yml`, `.json` |
| GitLab CI | `.gitlab-ci.yml` |
| GitHub Actions | `.yml`/`.yaml` внутри `.github/workflows/` |
| Jenkins | `Jenkinsfile` |

Файлы крупнее 5 МБ и содержимое директорий `.git`, `node_modules`, `__pycache__`, `venv`, `.venv`, `dist`, `build`, `.terraform`, `.idea`, `.vscode` при сканировании пропускаются автоматически.

## 🔧 Конфигурация

Конфигурация задаётся константами в `find_file.py` (пока без внешнего конфиг-файла — прямое редактирование модуля):

```python
IGNORE_DIRS = {'.git', 'node_modules', '__pycache__', 'venv', '.venv',
               'dist', 'build', '.terraform', '.idea', '.vscode'}
TARGET_EXTENSIONS = {'.yaml', '.yml', '.json', '.tf', '.tfvars'}
TARGET_FILES = {'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
                 '.gitlab-ci.yml', 'Jenkinsfile'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 МБ
```

## 🤝 Contributing

Как добавить новую проверку, требования к коду и процесс PR — в [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

## 📄 License

Лицензия проекта не зафиксирована в текущей кодовой базе — добавьте файл `LICENSE` перед публикацией.

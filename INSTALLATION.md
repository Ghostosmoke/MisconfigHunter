# 📦 Установка

## Системные требования

- **Python 3.8+** (используются `dataclasses`, type hints с `List[...]`/`Optional[...]`, `from __future__ import annotations` в `find_file.py`).
- Никакой ОС-специфики — код не использует ничего платформозависимого, работает на Linux/macOS/Windows везде, где есть Python.

## Зависимости

**Ноль внешних зависимостей.** Весь проект — `Easy_Check.py`, `Medium_Check.py`, `Hard_Check.py`, `find_file.py`, `found_files_need_check.py` — использует только стандартную библиотеку Python:

```
re, json, pathlib, argparse, contextlib, io, sys,
collections.defaultdict, dataclasses, typing
```

`pip install` для запуска не требуется вообще. Если вы видите упоминания PyYAML или похожих пакетов в связанной документации/тикетах — это не относится к текущей кодовой базе: YAML/JSON-содержимое разбирается через regex-эвристики, а не через структурный парсер.

## Установка из git

```bash
git clone <repo-url> misconfighunter
cd misconfighunter
```

Всё — файлы уже готовы к запуску, отдельного шага установки пакета (`pip install -e .`, `setup.py` и т.п.) в текущей структуре проекта нет.

## Виртуальное окружение (опционально)

Поскольку внешних зависимостей нет, venv строго не обязателен, но остаётся хорошей практикой для изоляции версии интерпретатора:

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
python find_file.py --path .
```

## Проверка установки

```bash
python -c "import find_file; print('OK')"
python find_file.py --level easy --path .
```

Если обе команды отработали без исключений — всё установлено верно.

## Troubleshooting

**`ModuleNotFoundError: No module named 'Easy_Check'` (или `Medium_Check`/`Hard_Check`/`found_files_need_check`)**
Все пять файлов должны находиться в одной директории (или быть доступны через `PYTHONPATH`) — `find_file.py` импортирует их по имени модуля, без пакетной структуры (`from Easy_Check import all_easy_check` и т.п.).

**Находки не появляются, хотя файл явно небезопасный**
Проверьте, что путь к файлу/директории передан верно (`--path`) и что расширение файла входит в `TARGET_EXTENSIONS` (`.yaml`, `.yml`, `.json`, `.tf`, `.tfvars`) либо имя файла — в `TARGET_FILES` (`Dockerfile`, `docker-compose.yml`, `docker-compose.yaml`, `.gitlab-ci.yml`, `Jenkinsfile`). Файлы с другими именами/расширениями `find_config_files()` не найдёт.

**Файл найден, но не проверен**
Файлы крупнее 5 МБ (`MAX_FILE_SIZE`) пропускаются молча на этапе поиска. Также проверьте, не лежит ли файл внутри одной из игнорируемых директорий (`.git`, `node_modules`, `__pycache__`, `venv`, `.venv`, `dist`, `build`, `.terraform`, `.idea`, `.vscode`).

**`python find_file.py --level foo` падает с сообщением про `Неизвестные уровни проверки`**
Ожидаемое поведение — допустимы только `easy`, `medium`, `hard` (в любой комбинации через запятую). Опечатка в названии уровня приводит к `ValueError` и exit code `2`.

**На Hard-уровне почти нет находок, хотя в проекте явно есть проблемы**
Ожидаемое поведение на текущем этапе — 23 из 25 Hard-проверок пока заглушки без реального анализа файлов (см. [CHECKS.md](CHECKS.md#hard)). Это не баг конфигурации, а текущий объём реализации.

# 🏗️ Архитектура

## Обзор

MisconfigHunter состоит из пяти модулей с чёткой ответственностью каждого:

```
find_file.py                    ← оркестратор: находит файлы, вызывает проверки, строит отчёт
    │
    ├── Easy_Check.py            ← проверки 01–25, вызываются на КАЖДЫЙ файл отдельно
    ├── Medium_Check.py          ← проверки 26–50, вызываются на список файлов ОДНОЙ папки
    ├── Hard_Check.py            ← проверки 51–75, вызываются на список файлов, но КАЖДАЯ
    │                              проверка получает (file_path, file) по одному файлу за раз
    └── found_files_need_check.py ← низкоуровневая утилита записи результатов в текстовый файл
```

Ни одна из трёх проверочных библиотек не импортирует другую — они полностью независимы. `find_file.py` — единственная точка, которая их связывает.

## Компоненты

### `find_file.py` — оркестратор

Отвечает за:
1. Поиск конфигурационных файлов (`find_config_files`) с фильтрацией по `IGNORE_DIRS`/`TARGET_EXTENSIONS`/`TARGET_FILES`/`MAX_FILE_SIZE`.
2. Группировку файлов по родительским папкам (`group_files_by_folder`) — нужна для проверок Medium/Hard, которые принимают список файлов одной папки за раз.
3. Выбор уровня проверки (`levels: List[str]`, валидируется против `VALID_LEVELS = {'easy', 'medium', 'hard'}`).
4. Перехват `stdout` каждой проверки и восстановление структурированных `Finding` (см. ниже — «Известное ограничение»).
5. Сборку `AuditReport` с итоговой статистикой, ошибками и методами `to_dict()`/`summary()`.
6. CLI-слой (`build_parser`, `main`) — единственное место, где что-либо печатается в консоль напрямую; сама `audit_project()` ничего не печатает, только возвращает данные.

### `Easy_Check.py` — проверки 01–25

Каждая проверка — функция `check_<название>_<номер>(file_path, file)`, принимающая путь и уже прочитанное содержимое **одного** файла. Точка входа — `all_easy_check(file_path)`, которая сама читает файл и последовательно вызывает все 25 функций.

Внутренняя логика опирается на набор построчных helper'ов:
- `remove_inline_comment(line)` — quote-aware удаление `#`-комментария (не путает `#` внутри строки с началом комментария).
- `normalize_boolean_value(value)` — приводит `true/True/TRUE/"true"/yes/on` и обратные варианты к `True`/`False`/`None`.
- `split_container_blocks(file)` — разбивает YAML на блоки `- name: ...` внутри `containers:`/`initContainers:`, но **только** если файл содержит `kind:` одного из workload-типов Kubernetes (Pod/Deployment/StatefulSet/DaemonSet/Job/CronJob/ReplicaSet) — это защита от ложных срабатываний на `- name:` в volumes, CI-степах или совсем других ресурсах.

### `Medium_Check.py` — проверки 26–50

Те же принципы, но точка входа — `all_medium_check(files)`, принимающая **список** файлов (или один путь). Большинство проверок по-прежнему анализируют один файл за раз внутри цикла, но несколько (например, check 35 — VPC Flow Logs Disabled) реально смотрят на весь набор через модульный кэш `_CURRENT_BATCH_CONTENTS`, который `all_medium_check()` заполняет перед циклом.

Общий формат отчёта — через `_report_finding(file_path, severity, title, findings, issue, risk, insecure, secure, remediation)`, где `findings` — список `(line_num, line_text, reason)`.

### `Hard_Check.py` — проверки 51–75

Точка входа — `all_hard_check(files=None)`:

- `files=None` → демо-режим, каждая проверка вызывается один раз с `("", "")`;
- `files` — строка/`Path` → читается один файл;
- `files` — список → читается каждый файл, нечитаемые пропускаются с предупреждением (аудит не падает из-за одного битого файла).

**Ключевая архитектурная деталь:** перед циклом `all_hard_check()` заполняет модульный кэш `_CURRENT_BATCH_CONTENTS = {путь: содержимое}` для **всего** набора файлов. Сигнатура каждой проверки остаётся `(file_path, file)` — она видит содержимое только «своего» файла напрямую, но через `_CURRENT_BATCH_CONTENTS` может заглянуть в остальные файлы того же набора. Именно так реализован кросс-файловый анализ в проверке 51 (Cross-File Network Policy — ищет `NetworkPolicy` во всём наборе, а не только в файле с workload'ом).

Статус реализации на данный момент:

| Проверка | Статус | Что делает |
|---|---|---|
| 51 — Cross-File Network Policy | ✅ реальная логика | Кросс-файловая: workload в этом файле + NetworkPolicy где угодно в наборе |
| 52 — IAM Privilege Escalation Path | ✅ реальная логика | Собирает `Effect: Allow` действия в файле, сверяет с каталогом известных цепочек эскалации (PassRole+RunInstances, CreatePolicyVersion и т.д.) |
| 53–75 | ⚠️ заглушки | Печатают формат находки (Issue/Risk/Insecure/Secure/Remediation) с фиксированным демонстрационным примером, но не анализируют переданный файл |

### `found_files_need_check.py` — утилита записи

Две функции, не зависящие от остального кода:
- `write_to_file(data, filename=...)` — дописывает данные в конец файла (append), между блоками ставит `===` разделитель.
- `rewrite_to_file(data, filename=...)` — перезаписывает файл с нуля.

Обе печатают `✅ Данные записаны в {filename}` — **это единственная причина, по которой парсер stdout в `find_file.py` явно не завязан на точное количество строк вывода**: подтверждающее сообщение просто не матчится ни regex'ом заголовка находки, ни regex'ом строки локации, и безопасно игнорируется при разборе.

## Поток данных

```
audit_project(path, levels)
        │
        ▼
find_config_files(path) ──────► List[Path]
        │
        ▼
group_files_by_folder(files) ─► Dict[Path, List[Path]]
        │
        ├─ level == 'easy'  ──► для каждого файла: all_easy_check(file)
        ├─ level == 'medium'──► для каждой папки:  all_medium_check(folder_files)
        └─ level == 'hard'  ──► для каждой папки:  all_hard_check(folder_files)
        │
        │   (каждый вызов обёрнут в contextlib.redirect_stdout)
        ▼
_parse_findings_from_output(stdout_text, level, file_path) ──► List[Finding]
        │
        ▼
AuditReport.findings.extend(...)
AuditReport.errors.append(...)  ← если проверка бросила исключение
        │
        ▼
report.to_dict() / report.summary()
```

## Структуры данных

```python
@dataclass
class Finding:
    level: str            # 'easy' | 'medium' | 'hard'
    severity: str          # 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN'
    check_id: str           # слаг из заголовка находки — см. ограничение ниже
    title: str
    file_path: str
    line_num: int
    line_text: str

@dataclass
class AuditReport:
    project_path: str
    levels: List[str]
    files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    total_findings: int      # property, len(findings)
    critical_count: int      # property, кол-во findings с severity == 'CRITICAL'

    def to_dict(self) -> dict: ...   # для JSON
    def summary(self) -> str: ...    # человекочитаемая сводка
```

## ⚠️ Известное архитектурное ограничение

`Easy_Check.all_easy_check()`, `Medium_Check.all_medium_check()` и `Hard_Check.all_hard_check()` не возвращают структурированные данные — они только печатают отчёт в `stdout`. Чтобы не переписывать эти три модуля, `find_file.py` перехватывает их `stdout` (`contextlib.redirect_stdout`) и восстанавливает объекты `Finding` через regex-парсинг печатаемого текста (`_TITLE_RE`, `_LOCATION_RE` в `find_file.py`).

Отсюда три следствия, о которых нужно знать при работе с отчётом:

1. **`check_id` — не официальный идентификатор.** В печатаемом отчёте нет номера проверки (`E-01`, `M-26` и т.д.), поэтому `check_id` — это слаг, построенный из текста заголовка (`_slugify(title)`). Два разных файла с одинаковым названием находки получат одинаковый `check_id`, но он не гарантированно совпадает с номером функции в коде.
2. **Для medium/hard `file_path` находки — это путь папки-батча, а не конкретный файл.** Medium и Hard вызываются на список файлов одной папки одним вызовом (`all_medium_check(folder_files)`), поэтому парсер stdout не может надёжно восстановить, из какого именно файла батча пришла конкретная находка — используется метка вида `<папка> (batch: N файлов)`.
3. **Hard-уровень не превращается в findings вовсе.** Поскольку 23 из 25 Hard-проверок — заглушки, печатающие один и тот же демонстрационный пример независимо от содержимого файла, извлечение findings из их вывода выдавало бы вымышленные результаты. Вместо этого `audit_project()` добавляет явную запись в `report.errors` с пометкой `hard-проверки пока заглушки`.

Долгосрочное решение — переход Easy/Medium/Hard на прямой возврат `List[Finding]` вместо печати в stdout. Это отдельная задача, не входящая в текущий объём.

## Расширяемость: как добавить новую проверку

Кратко (подробности — в [CONTRIBUTING.md](CONTRIBUTING.md)):

1. Выбрать следующий свободный номер в нужном уровне (Easy: 01–25, Medium: 26–50, Hard: 51–75 — диапазоны сейчас заполнены полностью, добавление нового номера потребует решения о нумерации).
2. Написать функцию с сигнатурой `check_<name>_<NN>(file_path, file)`.
3. Собрать findings в список `(line_num, line_text, reason)` (Medium/Hard) или `(line_num, line_text)` (часть Easy-проверок используют более короткий формат — см. существующий код для соответствующей проверки).
4. Напечатать отчёт в едином формате (`⚠️  [SEVERITY] Title`, `📍 Найдено проблем: N`, построчные локации, `💥 Issue`, `🎯 Risk`, `❌ Insecure`, `✅ Secure`, `🛠️ Remediation`) — именно этот формат парсит `find_file.py`.
5. Зарегистрировать вызов в соответствующей `all_<level>_check()`.
6. Для Hard-уровня, если проверке нужен доступ к другим файлам набора — использовать `_CURRENT_BATCH_CONTENTS`, как это сделано в проверках 51 и 52.

# 🤝 Contributing

## Как добавить новую проверку

Пошагово, на примере гипотетической новой проверки в `Medium_Check.py`.

### 1. Выберите номер

Диапазоны сейчас заполнены полностью: Easy 01–25, Medium 26–50, Hard 51–75. Добавление 76-й проверки — решение на уровне проекта (новый диапазон или пересмотр нумерации), а не техническая деталь одной функции.

### 2. Напишите функцию с правильной сигнатурой

```python
def check_something_new_76(file_path, file):
    """
    Проверка 76: Something New.
    Короткое описание того, что ищет проверка и какое у неё
    ограничение (если оно есть — см. пример в check 51/52 Hard_Check.py).
    """
    if not file:
        return None

    findings = []
    for line_num, line in enumerate(file.splitlines(), start=1):
        clean = remove_inline_comment(line)   # обязательно — иначе закомментированные
                                                # строки дадут ложные срабатывания
        # ... ваша логика поиска проблемы ...
        if <условие срабатывания>:
            findings.append((line_num, line.strip(), "причина находки"))

    if not findings:
        return None

    # печать в едином формате — см. секцию "Формат отчёта" ниже
    ...
```

**Обязательно:**
- `file_path, file` как аргументы (в Easy_Check.py принят стиль с пробелом перед запятой — `file_path , file` — Medium/Hard используют обычный `file_path, file`; придерживайтесь стиля файла, в который добавляете проверку).
- `if not file: return None` в начале — защита от пустого содержимого (демо-режим Hard_Check.py вызывает проверки с `file=""`).
- Использование `remove_inline_comment(line)` перед любым regex-матчингом строки — иначе `# privileged: true` в комментарии даст ложное срабатывание.
- Для boolean-значений — `normalize_boolean_value(value)`, а не самодельное сравнение строк (`true`/`True`/`"true"`/`yes` должны трактоваться одинаково).
- `return None`, если находок нет. Никогда не возвращайте пустой список молча в отрыве от `return None` — единообразие важно для того, кто вызывает функцию в цикле.

### 3. Формат findings

- В `Medium_Check.py` и `Hard_Check.py`: `(line_num, line_text, reason)` — три элемента, `reason` обязателен.
- В `Easy_Check.py`: часть проверок использует двухэлементный `(line_num, line_text)` (например, check 01), часть — трёхэлементный с `reason` (например, check 02). Смотрите на соседние проверки в том же файле и следуйте их формату — единообразие внутри файла важнее сокращения различий между файлами.

### 4. Формат отчёта (то, что печатается)

Это критично: `find_file.py` **парсит именно этот текст** regex'ами, чтобы восстановить структурированные `Finding` (см. [ARCHITECTURE.md](ARCHITECTURE.md#-известное-архитектурное-ограничение)). Отклонение от формата — findings молча пропадут из отчёта `audit_project()`, при этом сама проверка продолжит работать при прямом вызове.

Обязательные строки, в этом порядке:

```python
print(f"⚠️  [{severity}] {title}")             # severity: CRITICAL/HIGH/MEDIUM/LOW
print(f"  📍 Найдено проблем: {len(findings)}")
print(locations)   # каждая строка вида: "    Строка {num}: {text}  ← {reason}"
print(f"  💥 Issue: ...")
print(f"  🎯 Risk: ...")
print("  ❌ Insecure:")
print("        <пример уязвимого кода>")
print("  ✅ Secure:")
print("        <пример безопасного кода>")
print("  🛠️ Remediation:")
print("      • <шаг 1>")
print("      • <шаг 2>")
print()
```

Строку локации проще всего собрать так:

```python
locations = '\n'.join(
    f"    Строка {num}: {text}  ← {reason}"
    for num, text, reason in findings
)
```

`Medium_Check.py` инкапсулирует весь этот вывод в общую функцию `_report_finding(file_path, severity, title, findings, issue, risk, insecure, secure, remediation)` — если добавляете проверку туда, используйте её вместо ручного дублирования `print`.

### 5. Кросс-файловый доступ (только для Hard-уровня)

Если проверке нужно видеть содержимое **других** файлов набора, а не только своего:

```python
def check_something_new_76(file_path, file):
    if not file:
        return None
    batch = _CURRENT_BATCH_CONTENTS or {file_path: file}
    for other_path, other_content in batch.items():
        ...
```

`_CURRENT_BATCH_CONTENTS` заполняется `all_hard_check()` перед циклом по файлам — см. реализацию check 51 (Cross-File Network Policy) как референс.

### 6. Зарегистрируйте вызов

Добавьте вызов новой функции в соответствующую `all_<level>_check()`:

```python
check_something_new_76(file_path, file_content)           # 76
```

### 7. Если логика ещё не готова — сделайте честную заглушку

Формат заглушки (как сейчас у Hard-проверок 53–75):

```python
def check_something_new_76(file_path, file):
    """
    Проверка 76: Something New.
    Пока заглушка. Реальная логика будет добавлена позже.
    """
    print("⚠️  [HIGH] Something New")
    print("  📍 Статус: проверка пока в режиме заглушки")
    print()
    return None
```

Не выдавайте вымышленные находки — заглушка должна быть явно опознаваема как заглушка.

## Требования к проверкам

- **Никаких лишних зависимостей.** Проект намеренно не тянет ничего кроме стандартной библиотеки Python (`re`, `pathlib`, `json`, `argparse`, `contextlib`, `io`, `dataclasses`, `typing`). Если проверке кажется нужен YAML-парсер — сначала попробуйте regex-эвристику по образцу существующих проверок; полноценный парсинг YAML/HCL — тема отдельного архитектурного решения, а не отдельной проверки.
- **Явно документируйте эвристики и их пределы.** Если проверка не делает точного структурного анализа (например, не сопоставляет `Resource`/`Condition` в IAM-политиках, как check 52), напишите это прямо в docstring — так делают уже реализованные check 51 и 52.
- **Не давайте false positive на закомментированный код.** Всегда `remove_inline_comment()` перед матчингом.
- **Не давайте false negative на кавычки/регистр.** `key: value`, `key: "value"`, `key: 'value'`, `KEY=value` и `true/True/TRUE/"true"` должны обрабатываться одинаково там, где это применимо.

## Тестирование

Формального test suite в репозитории пока нет. Перед тем как предлагать PR, вручную проверьте на минимальном insecure/secure примере:

```python
import contextlib, io
from Medium_Check import all_medium_check   # или Easy_Check/Hard_Check

insecure = '''
privileged: true
'''
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    all_medium_check("test.yaml")  # или запишите insecure во временный файл и передайте путь
print(buf.getvalue())   # находка должна появиться

secure = '''
privileged: false
'''
# ... то же самое — находки быть не должно
```

Обязательно проверьте оба направления: находка есть на insecure-примере **и** находки нет на secure-примере. Проверка, которая срабатывает всегда (или никогда), хуже отсутствия проверки — она создаёт ложное доверие к отчёту.

## Code style

- 4 пробела отступа.
- `Easy_Check.py` использует нестандартный стиль с пробелом перед запятой в сигнатурах и списках аргументов (`def check(file_path , file):`) — это существующая конвенция файла, не считается ошибкой в этом контексте, но и не стоит переносить её в `Medium_Check.py`/`Hard_Check.py`, где принят обычный PEP 8.
- Docstring на русском, с номером и названием проверки в первой строке.
- `remove_inline_comment` и `normalize_boolean_value` (импортируются из `Easy_Check.py` в `Medium_Check.py`) — используйте их вместо самодельных аналогов.

## Pull Request процесс

1. Одна проверка (или один связный набор правок) — один PR.
2. В описании PR укажите: номер и название проверки, insecure/secure примеры, которые вы использовали для ручной проверки.
3. Убедитесь, что `python -m py_compile <файл>.py` проходит без ошибок для каждого изменённого файла.
4. Убедитесь, что `python -c "import find_file"` по-прежнему работает — это сигнал, что вы не сломали ничего в цепочке импортов.
5. Если проверка новая и добавлена в `all_<level>_check()` — убедитесь, что `all_<level>_check()` по-прежнему запускается в демо-режиме без исключений.

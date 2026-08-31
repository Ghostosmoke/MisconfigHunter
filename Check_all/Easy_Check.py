from found_files_need_check import write_to_file
import re
import json

try:
    import yaml
except ImportError:  # pragma: no cover - yaml is optional
    yaml = None

"""
╔════════════════════════════════════════════════════════════════╗
║  🔐 Security Auditor — Easy Level Checks (01–25)              ║
║  CIS Kubernetes | Docker | AWS | GCP | Azure | CI/CD          ║
╚════════════════════════════════════════════════════════════════╝

Все проверки реализуют реальный анализ содержимого файла:
line-based regex сканирование там, где это уместно, и
структурный разбор YAML/JSON там, где нужно обнаружить
ОТСУТСТВИЕ поля (missing resource limits, missing health probes и т.д.).
"""

# ═══════════════════════════════════════════════════════════════
# 🔹 ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (helpers)
# ═══════════════════════════════════════════════════════════════

SECRET_NAME_RE = re.compile(
    r'(PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|APIKEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)' ,
    re.IGNORECASE ,
)

# Имена переменных, которые часто содержат SECRET/TOKEN, но сами по себе
# секретом не являются (ссылка на секрет, а не значение секрета).
SECRET_NAME_ALLOWLIST = {
    'SECRET_NAME' , 'SECRET_PATH' , 'SECRET_KEY_NAME' , 'SECRET_ARN' , 'SECRET_ID' ,
    'TOKEN_URL' , 'TOKEN_ENDPOINT' , 'TOKEN_PATH' , 'TOKEN_TYPE' ,
    'API_KEY_HEADER' , 'API_KEY_NAME' ,
}

# Значения-плейсхолдеры, которые не являются реальными секретами.
PLACEHOLDER_VALUES = {
    'changeme' , 'change_me' , 'example' , 'dummy' , 'placeholder' ,
    'xxx' , 'xxxx' , '<secret>' , 'your-secret-here' , 'redacted' , 'test' , 'todo' ,
}


def _is_placeholder_value(value):
    v = value.strip().strip('"').strip("'").lower()
    return v in PLACEHOLDER_VALUES


# Ключи с такими суффиксами обычно являются ССЫЛКОЙ на ресурс/секрет
# (имя, путь, ARN, ID, тип), а не самим секретным значением.
# Пример: secretName, roleArn, subnetId, apiKeySourceType.
_REFERENCE_KEY_SUFFIX_RE = re.compile(
    r'(Name|Ref|Path|Arn|Id|Type|Source)$'
)

# Значения, которые технически совпадают по имени ключа с "секретом",
# но сами по себе секретом быть не могут (булевы флаги, enum-константы).
_NON_SECRET_VALUES = {
    'true' , 'false' , 'yes' , 'no' , 'on' , 'off' ,
    'enabled' , 'disabled' , 'header' , 'body' , 'null' , 'none' ,
    '[]' , '{}' ,
}


def _is_reference_key(key):
    """True, если имя ключа похоже на ссылку (name/ref/path/arn/id/type), а не на сам секрет."""
    return bool(_REFERENCE_KEY_SUFFIX_RE.search(key))


def _is_non_secret_value(value):
    v = value.strip().strip('"').strip("'").lower()
    if v in _NON_SECRET_VALUES:
        return True
    # Terraform-ссылки на переменные/локали/данные — это не хардкод секрета
    if re.match(r'^(var\.|local\.|data\.)' , v):
        return True
    return False

DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN" , "NET_ADMIN" , "SYS_PTRACE" , "SYS_MODULE" ,
    "DAC_READ_SEARCH" , "DAC_OVERRIDE" , "SETUID" , "SETGID" ,
}


def normalize_boolean_value(value):
    """Приводит строковое значение true/True/TRUE/false/False/FALSE к bool.
    Возвращает None, если значение не является булевым."""
    if value is None:
        return None
    cleaned = str(value).strip().strip('"').strip("'").lower()
    if cleaned == 'true':
        return True
    if cleaned == 'false':
        return False
    return None


def remove_inline_comment(line):
    """Убирает инлайн-комментарий YAML (# ...), не трогая '#' внутри кавычек."""
    in_single = False
    in_double = False
    for i , ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == '#' and not in_single and not in_double:
            return line[:i]
    return line


def is_template_variable(value):
    """Определяет, является ли значение шаблонной переменной/ссылкой на секрет,
    например: $VAR, ${VAR}, {{ ... }}, ${{ secrets.* }}."""
    if value is None:
        return True
    v = str(value).strip()
    if not v:
        return True
    if v.startswith('$'):
        return True
    if '{{' in v and '}}' in v:
        return True
    if re.search(r'\$\{[^}]*\}' , v):
        return True
    return False


def parse_yaml_documents(file):
    """Пытается распарсить YAML-документы. Возвращает список документов
    или None, если PyYAML недоступен или парсинг не удался."""
    if yaml is None:
        return None
    try:
        return [doc for doc in yaml.safe_load_all(file) if doc]
    except Exception:
        return None


def iter_containers_from_yaml(doc):
    """Возвращает список словарей-контейнеров (containers/initContainers)
    из одного распарсенного Kubernetes-манифеста."""
    containers = []
    if not isinstance(doc , dict):
        return containers

    spec = doc.get('spec')
    candidate_specs = []

    if isinstance(spec , dict):
        candidate_specs.append(spec)
        template = spec.get('template')
        if isinstance(template , dict):
            candidate_specs.append(template.get('spec') or {})
        job_template = spec.get('jobTemplate')
        if isinstance(job_template , dict):
            jt_spec = job_template.get('spec') or {}
            jt_template = jt_spec.get('template') if isinstance(jt_spec , dict) else None
            if isinstance(jt_template , dict):
                candidate_specs.append(jt_template.get('spec') or {})

    for c_spec in candidate_specs:
        if not isinstance(c_spec , dict):
            continue
        for key in ('containers' , 'initContainers'):
            for c in c_spec.get(key) or []:
                if isinstance(c , dict) and c.get('name'):
                    containers.append(c)

    return containers


WORKLOAD_KINDS_RE = re.compile(
    r'^\s*kind\s*:\s*["\']?(Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|ReplicaSet)["\']?\s*$' ,
    re.IGNORECASE ,
)


def split_container_blocks(file):
    """Разбивает файл на блоки по признаку '- name: xxx' (элемент списка
    containers/initContainers) — используется как heuristic fallback,
    когда структурный YAML-парсинг недоступен.

    Чтобы не путать контейнеры с другими элементами списков ('- name:'
    также встречается в volumes, CI steps, ServiceAccount и т.д.),
    применяются два фильтра:
      1. Файл должен содержать kind одного из K8s workload-типов
         (Pod/Deployment/StatefulSet/...); иначе блоки не ищутся вовсе.
      2. Каждый найденный '- name:' должен находиться под ближайшим
         (по отступу) предком containers: или initContainers:.
    """
    lines = file.splitlines()

    has_workload_kind = any(
        WORKLOAD_KINDS_RE.match(remove_inline_comment(l)) for l in lines
    )
    if not has_workload_kind:
        return []

    def _indent(s):
        return len(s) - len(s.lstrip(' '))

    def _has_container_ancestor(idx):
        target_indent = _indent(lines[idx])
        for k in range(idx - 1 , max(-1 , idx - 60) , -1):
            candidate = lines[k]
            if not candidate.strip():
                continue
            cand_indent = _indent(candidate)
            if cand_indent <= target_indent:
                if re.match(r'^\s*(containers|initContainers)\s*:\s*$' , remove_inline_comment(candidate) , re.IGNORECASE):
                    return True
                if cand_indent < target_indent:
                    target_indent = cand_indent  # поднимаемся по дереву отступов
                # cand_indent == target_indent и это не containers: — sibling, продолжаем поиск выше
        return False

    blocks = []
    current_name = None
    current_start = None
    current_lines = []

    for i , line in enumerate(lines):
        m = re.match(r'^(\s*)-\s*name:\s*["\']?([A-Za-z0-9_.\-]+)["\']?\s*$' , line)
        if m and _has_container_ancestor(i):
            if current_name is not None:
                blocks.append((current_name , current_start , current_lines))
            current_name = m.group(2)
            current_start = i + 1
            current_lines = [line]
        elif m:
            # '- name:' есть, но это не контейнер (volume, шаг CI, и т.п.) —
            # закрываем текущий контейнерный блок, если он был открыт.
            if current_name is not None:
                blocks.append((current_name , current_start , current_lines))
            current_name = None
            current_lines = []
        elif current_name is not None:
            current_lines.append(line)

    if current_name is not None:
        blocks.append((current_name , current_start , current_lines))

    return blocks


def find_windows_around(file , pattern , window=10 , flags=re.IGNORECASE):
    """Находит все строки, соответствующие pattern, и возвращает список
    (line_num, matched_line, window_text), где window_text — окружающий
    контекст (используется для проверки соседних ключей в policy-блоках)."""
    lines = file.splitlines()
    results = []
    for i , line in enumerate(lines):
        if re.search(pattern , line , flags):
            start = max(0 , i - window)
            end = min(len(lines) , i + window + 1)
            results.append((i + 1 , line.strip() , '\n'.join(lines[start:end])))
    return results


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 1: KUBERNETES SECURITY CHECKS (01–14)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 01: Privileged Container                        │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.2.1                                │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Контейнер запущен с привилегированным        │
# │                доступом к хост-системе                      │
# └─────────────────────────────────────────────────────────────┘
def check_privileged_container_01(file_path , file):
    """
    Проверяет наличие privileged: true в securityContext.
    При нахождении уязвимости выводит детальный отчёт.
    """

    findings = []

    for line_num , line in enumerate(file.splitlines() , start=1):
        clean = remove_inline_comment(line)
        m = re.search(r'privileged\s*[:=]\s*["\']?(\w+)["\']?' , clean , re.IGNORECASE)
        if m and normalize_boolean_value(m.group(1)) is True:
            findings.append((line_num , line.strip()))

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}"
        for num , text in findings
    )

    string_mistake = f'''
⚠️  [CRITICAL] Privileged Container
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Контейнер имеет почти полный доступ к хост-системе.
🎯 Risk: Злоумышленник может получить полный контроль над узлом.
❌ Insecure:
    securityContext:
      privileged: true
✅ Secure:
    securityContext:
      privileged: false
🛠️ Remediation:
    • Установите privileged: false

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [CRITICAL] Privileged Container")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: Контейнер имеет почти полный доступ к хост-системе.")
    print("  🎯 Risk: Злоумышленник может получить полный контроль над узлом...")
    print("  ❌ Insecure:")
    print("        securityContext:\n          privileged: true")
    print("  ✅ Secure:")
    print("        securityContext:\n          privileged: false")
    print("  🛠️ Remediation:")
    print("      • Установите privileged: false")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 02: Run as Root                                 │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.2.6                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Контейнер запускается от имени root (UID 0) │
# └─────────────────────────────────────────────────────────────┘
def check_run_as_root_02(file_path , file):
    """
    Проверяет запуск контейнера от root или отсутствие runAsNonRoot.
    """

    findings = []

    for line_num , line in enumerate(file.splitlines() , start=1):
        clean = remove_inline_comment(line)
        m_uid = re.search(r'runAsUser\s*[:=]\s*["\']?(\d+)["\']?' , clean , re.IGNORECASE)
        if m_uid and m_uid.group(1) == '0':
            findings.append((line_num , line.strip() , 'runAsUser: 0'))
            continue
        m_nonroot = re.search(r'runAsNonRoot\s*[:=]\s*["\']?(\w+)["\']?' , clean , re.IGNORECASE)
        if m_nonroot and normalize_boolean_value(m_nonroot.group(1)) is False:
            findings.append((line_num , line.strip() , 'runAsNonRoot: false'))

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}  ← {reason}"
        for num , text , reason in findings
    )

    string_mistake = f'''
⚠️  [HIGH] Run as Root
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Процессы внутри контейнера выполняются от имени root.
🎯 Risk: При уязвимости в приложении злоумышленник получит права root внутри контейнера, что облегчает выход за пределы контейнера.
❌ Insecure:
    securityContext:
      runAsUser: 0
    # или отсутствие runAsNonRoot
✅ Secure:
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      runAsGroup: 1000
🛠️ Remediation:
    • Установите runAsNonRoot: true
    • Укажите конкретного пользователя runAsUser: 1000
    • Добавьте runAsGroup для групповых разрешений

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [HIGH] Run as Root")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: Процессы внутри контейнера выполняются от имени root.")
    print(
        "  🎯 Risk: При уязвимости в приложении злоумышленник получит права root внутри контейнера, что облегчает выход за пределы контейнера.")
    print("  ❌ Insecure:")
    print("        securityContext:\n          runAsUser: 0")
    print("        # или отсутствие runAsNonRoot")
    print("  ✅ Secure:")
    print(
        "        securityContext:\n          runAsNonRoot: true\n          runAsUser: 1000\n          runAsGroup: 1000")
    print("  🛠️ Remediation:")
    print("      • Установите runAsNonRoot: true")
    print("      • Укажите конкретного пользователя runAsUser: 1000")
    print("      • Добавьте runAsGroup для групповых разрешений")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 03: Latest Tag                                  │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   NIST-CM-2                                    │
# │ ⚡ Критичность: 🟡 MEDIUM                                    │
# │ 📝 Описание:   Использование плавающего тега 'latest'       │
# └─────────────────────────────────────────────────────────────┘
def check_latest_tag_03(file_path , file):
    """
    Проверяет использование тега :latest в образах контейнеров
    (Kubernetes/CloudFormation/Terraform-манифесты; docker-compose
    покрывается отдельной проверкой 14, чтобы не дублировать находки).
    """
    if re.search(r'^services\s*:\s*$' , file , re.MULTILINE):
        return None

    findings = []

    for line_num , line in enumerate(file.splitlines() , start=1):
        clean = remove_inline_comment(line)
        # YAML: image: value | JSON: "image": value | HCL: image = value
        match = re.search(r'["\']?image["\']?\s*[:=]\s*(.+)' , clean , re.IGNORECASE)
        if not match:
            continue

        # Убираем пробелы и кавычки
        image_value = match.group(1).strip().strip('"').strip("'").rstrip(',')

        # Пропускаем переменные и шаблоны
        if '$' in image_value or '{' in image_value:
            continue

        # ✅ Digest — всегда безопасно
        if '@sha256:' in image_value:
            continue

        # Берём часть после последнего "/" (там name:tag)
        image_name_part = image_value.split('/')[-1]

        # Ищем тег
        if ':' in image_name_part:
            tag = image_name_part.split(':')[-1]
            if tag == 'latest':
                findings.append((line_num , image_value , "явный тег :latest"))
            # else: конкретный тег — ок
        else:
            # Тега нет вообще → по умолчанию latest
            findings.append((line_num , image_value , "тег отсутствует (по умолчанию latest)"))

    if findings:
        locations = '\n'.join(
            f"    Строка {num}: {img}  ← {reason}"
            for num , img , reason in findings
        )

        string_mistake = f'''
⚠️  [MEDIUM] Latest Tag
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Использование плавающего тега latest в образах.
🎯 Risk: Непредсказуемые обновления, тихое внедрение уязвимостей.
❌ Insecure:
    image: nginx:latest
    image: nginx
✅ Secure:
    image: nginx:1.24.0
    image: nginx@sha256:abc123...
🛠️ Remediation:
    • Указывайте конкретную версию образа
    • Используйте SHA-хеш для production

    '''
        write_to_file(str(file_path) + '\n' + string_mistake)
        print("⚠️  [MEDIUM] Latest Tag")
        print(f"  📍 Найдено проблем: {len(findings)}")
        print(locations)
        print("  💥 Issue: Использование плавающего тега latest в образах.")
        print(
            "  🎯 Risk: Непредсказуемые обновления, поломка совместимости, тихое внедрение уязвимостей в новую версию образа.")
        print("  ❌ Insecure:")
        print("        containers:\n          image: nginx:latest\n        # или просто image: nginx")
        print("  ✅ Secure:")
        print("        containers:\n          image: nginx:1.21.0\n        # или image: nginx@sha256:abc123...")
        print("  🛠️ Remediation:")
        print("      • Всегда указывайте конкретную версию образа")
        print("      • Используйте SHA-хеш для максимальной воспроизводимости")
        print("      • Настройте автоматическое обновление через Dependabot/Renovate")
        print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 04: Host Network                                │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.2.4                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Контейнер использует hostNetwork: true      │
# └─────────────────────────────────────────────────────────────┘
def check_host_network_04(file_path , file):
    """
    Проверяет использование сетевого стека хоста контейнером.
    """
    findings = []

    for line_num , line in enumerate(file.splitlines() , start=1):
        # Ищем hostNetwork с любым регистром и кавычками
        match = re.search(r'hostNetwork:\s*["\']?(\w+)["\']?' , line)
        if match:
            value = match.group(1).lower()
            if value == 'true':
                findings.append((line_num , line.strip()))

    if findings:
        locations = '\n'.join(
            f"    Строка {num}: {text}"
            for num , text in findings
        )

        string_mistake = f'''
⚠️  [HIGH] Host Network
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Контейнер использует сетевой стек хоста.
🎯 Risk: Доступ ко всем сетевым интерфейсам хоста, сниффинг трафика, обход NetworkPolicies, доступ к сервисам на localhost хоста.
❌ Insecure:
    spec:
      hostNetwork: true
✅ Secure:
    spec:
      hostNetwork: false
🛠️ Remediation:
    • Установите hostNetwork: false
    • Используйте стандартную сеть Kubernetes
    • Настройте NetworkPolicy для контроля трафика

    '''
        write_to_file(str(file_path) + '\n' + string_mistake)
        print("⚠️  [HIGH] Host Network")
        print(f"  📍 Найдено проблем: {len(findings)}")
        print(locations)
        print("  💥 Issue: Контейнер использует сетевой стек хоста.")
        print(
            "  🎯 Risk: Доступ ко всем сетевым интерфейсам хоста, возможность сниффинга трафика, обход NetworkPolicies Kubernetes, доступ к сервисам на localhost хоста.")
        print("  ❌ Insecure:")
        print("        spec:\n          hostNetwork: true")
        print("  ✅ Secure:")
        print("        spec:\n          hostNetwork: false")
        print("  🛠️ Remediation:")
        print("      • Установите hostNetwork: false")
        print("      • Используйте стандартную сеть Kubernetes")
        print("      • Настройте NetworkPolicy для контроля трафика")
        print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 05: Host PID                                    │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.2.2                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Контейнер видит PID хоста (hostPID: true)   │
# └─────────────────────────────────────────────────────────────┘
def check_host_pid_05(file_path , file):
    """
    Проверяет использование пространства процессов хоста.
    """

    findings = []

    for line_num , line in enumerate(file.splitlines() , start=1):
        # Убираем inline-комментарии YAML (всё после #)
        clean_line = line.split('#')[0].rstrip()

        # Ищем hostPID с любым количеством пробелов, кавычками и регистром
        match = re.search(
            r'hostPID\s*:\s*["\']?(true|false|True|False|TRUE|FALSE)["\']?' ,
            clean_line ,
            re.IGNORECASE
        )

        if match:
            value = match.group(1).lower()
            if value == 'true':
                findings.append((line_num , line.strip()))

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}"
        for num , text in findings
    )

    string_mistake = f'''
⚠️  [HIGH] Host PID
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Контейнер видит пространство процессов хоста.
🎯 Risk: Возможность видеть все процессы на узле, отправлять сигналы (kill)
   процессам хоста, читать переменные окружения чужих процессов.

❌ Insecure:
    spec:
      hostPID: true

✅ Secure:
    spec:
      hostPID: false

🛠️ Remediation:
    • Установите hostPID: false
    • Изолируйте пространство процессов контейнера
    • Используйте стандартные механизмы мониторинга Kubernetes
'''

    write_to_file(str(file_path) + '\n' + string_mistake)

    print("⚠️  [HIGH] Host PID")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: Контейнер видит пространство процессов хоста.")
    print(
        "  🎯 Risk: Возможность видеть все процессы на узле, отправлять сигналы (kill) процессам хоста, анализировать работу других приложений.")
    print("  ❌ Insecure:")
    print("        spec:\n          hostPID: true")
    print("  ✅ Secure:")
    print("        spec:\n          hostPID: false")
    print("  🛠️ Remediation:")
    print("      • Установите hostPID: false")
    print("      • Изолируйте пространство процессов контейнера")
    print("      • Используйте стандартные механизмы мониторинга Kubernetes")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 06: Host IPC                                    │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.2.3                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Контейнер использует IPC хоста              │
# └─────────────────────────────────────────────────────────────┘
def check_host_ipc_06(file_path , file):
    """
    Проверяет использование IPC-пространства хоста.
    """

    findings = []

    for line_num , line in enumerate(file.splitlines() , start=1):
        # Ищем hostIPC с любым регистром и кавычками
        match = re.search(r'hostIPC:\s*["\']?(\w+)["\']?' , line)
        if match:
            value = match.group(1).lower()
            if value == 'true':
                findings.append((line_num , line.strip()))

    if findings:
        locations = '\n'.join(
            f"    Строка {num}: {text}"
            for num , text in findings
        )

        string_mistake = f'''
⚠️  [HIGH] Host IPC
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Контейнер использует пространство IPC хоста.
🎯 Risk: Доступ к shared memory хоста, возможность перехвата данных между процессами на узле, атаки типа race condition.
❌ Insecure:
    spec:
      hostIPC: true
✅ Secure:
    spec:
      hostIPC: false
🛠️ Remediation:
    • Установите hostIPC: false
    • Изолируйте межпроцессное взаимодействие
    • Используйте стандартные механизмы IPC Kubernetes

'''
        write_to_file(str(file_path) + '\n' + string_mistake)
        print("⚠️  [HIGH] Host IPC")
        print(f"  📍 Найдено проблем: {len(findings)}")
        print(locations)
        print("  💥 Issue: Контейнер использует пространство IPC хоста.")
        print(
            "  🎯 Risk: Доступ к shared memory хоста, возможность перехвата данных между процессами на узле, атаки типа race condition.")
        print("  ❌ Insecure:")
        print("        spec:\n          hostIPC: true")
        print("  ✅ Secure:")
        print("        spec:\n          hostIPC: false")
        print("  🛠️ Remediation:")
        print("      • Установите hostIPC: false")
        print("      • Изолируйте межпроцессное взаимодействие")
        print("      • Используйте стандартные механизмы IPC Kubernetes")
        print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 07: Allow Privilege Escalation                  │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.2.5                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Разрешено повышение привилегий процесса     │
# └─────────────────────────────────────────────────────────────┘
def check_allow_privilege_escalation_07(file_path , file):
    """
    Проверяет allowPrivilegeEscalation: true в securityContext.
    """
    findings = []

    for line_num , line in enumerate(file.splitlines() , start=1):
        # Ищем allowPrivilegeEscalation с любым регистром и кавычками
        match = re.search(r'allowPrivilegeEscalation:\s*["\']?(\w+)["\']?' , line)
        if match:
            value = match.group(1).lower()
            if value == 'true':
                findings.append((line_num , line.strip() , 'allowPrivilegeEscalation enabled'))

    if findings:
        locations = '\n'.join(
            f"    Строка {num}: {text}  ← {reason}"
            for num , text , reason in findings
        )

        string_mistake = f'''
⚠️  [HIGH] Allow Privilege Escalation
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Разрешено повышение привилегий процесса.
🎯 Risk: Процесс может получить больше прав, чем у родительского процесса (например, через setuid бинарники), что ведёт к правам root.
❌ Insecure:
    securityContext:
      allowPrivilegeEscalation: true
✅ Secure:
    securityContext:
      allowPrivilegeEscalation: false
🛠️ Remediation:
    • Установите allowPrivilegeEscalation: false
    • Проверьте все контейнеры в workload
    • Добавьте в PodSecurityPolicy/PodSecurity Admission

'''
        write_to_file(str(file_path) + '\n' + string_mistake)
        print("⚠️  [HIGH] Allow Privilege Escalation")
        print(f"  📍 Найдено проблем: {len(findings)}")
        print(locations)
        print("  💥 Issue: Разрешено повышение привилегий процесса.")
        print(
            "  🎯 Risk: Процесс может получить больше прав, чем у родительского процесса (например, через setuid бинарники), что ведёт к правам root.")
        print("  ❌ Insecure:")
        print("        securityContext:\n          allowPrivilegeEscalation: true")
        print("  ✅ Secure:")
        print("        securityContext:\n          allowPrivilegeEscalation: false")
        print("  🛠️ Remediation:")
        print("      • Установите allowPrivilegeEscalation: false")
        print("      • Проверьте все контейнеры в workload")
        print("      • Добавьте в PodSecurityPolicy/PodSecurity Admission")
        print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 08: Docker Exposed Ports                        │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-Docker-5.4                               │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Порт проброшен на 0.0.0.0                   │
# └─────────────────────────────────────────────────────────────┘
def check_docker_exposed_ports_08(file_path , file):
    """
    Проверяет проброс портов Docker Compose на все интерфейсы (0.0.0.0).
    """
    findings = []

    for line_num , line in enumerate(file.splitlines() , start=1):
        clean_line = remove_inline_comment(line).rstrip()
        stripped = clean_line.strip()
        if not stripped or not stripped.startswith('-'):
            continue

        value = stripped.lstrip('-').strip().strip('"').strip("'")
        if is_template_variable(value):
            continue

        # Форматы: "80:80", "0.0.0.0:80:80", "127.0.0.1:80:80", "80:80/tcp"
        value_no_proto = value.split('/')[0]
        m = re.match(
            r'^(?:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):)?(\d+):(\d+)$' ,
            value_no_proto ,
        )
        if not m:
            continue

        bind_ip = m.group(1)
        if bind_ip is None or bind_ip == '0.0.0.0':
            findings.append((line_num , stripped))
        # 127.0.0.1 и другие явные IP не флагуем

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}"
        for num , text in findings
    )

    string_mistake = f'''
⚠️  [HIGH] Docker Exposed Ports
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Порт проброшен на все интерфейсы (0.0.0.0).
🎯 Risk: Сервис становится доступным из внешней сети, увеличение поверхности атаки, доступ без авторизации.
❌ Insecure:
    ports:
        - "0.0.0.0:80:80"
        # Или без указания IP (подразумевается 0.0.0.0)
        - "80:80"
✅ Secure:
    ports:
        - "127.0.0.1:80:80"  # Только localhost
        # Или использование overlay сети без публикации
🛠️ Remediation:
    • Укажите конкретный IP для binding (127.0.0.1)
    • Используйте Docker networks для внутренней коммуникации
    • Настройте reverse proxy для внешнего доступа

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [HIGH] Docker Exposed Ports")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: Порт проброшен на все интерфейсы (0.0.0.0).")
    print(
        "  🎯 Risk: Сервис становится доступным из внешней сети, увеличение поверхности атаки, доступ без авторизации.")
    print("  ❌ Insecure:")
    print(
        '        ports:\n          "0.0.0.0:80:80"\n        # Или без указания IP (подразумевается 0.0.0.0)\n        "80:80"')
    print("  ✅ Secure:")
    print(
        '        ports:\n          "127.0.0.1:80:80"  # Только localhost\n        # Или использование overlay сети без публикации')
    print("  🛠️ Remediation:")
    print("      • Укажите конкретный IP для binding (127.0.0.1)")
    print("      • Используйте Docker networks для внутренней коммуникации")
    print("      • Настройте reverse proxy для внешнего доступа")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 09: Docker Privileged                           │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-Docker-5.2                               │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Контейнер Docker в privileged режиме        │
# └─────────────────────────────────────────────────────────────┘
def check_docker_privileged_09(file_path , file):
    """
    Проверяет запуск Docker-контейнера в привилегированном режиме
    (privileged: true в docker-compose).
    """
    findings = []

    for line_num , line in enumerate(file.splitlines() , start=1):
        clean_line = remove_inline_comment(line)
        normalized = re.sub(r'\s*:\s*' , ':' , clean_line)
        m = re.search(r'privileged:["\']?(\w+)["\']?' , normalized , re.IGNORECASE)
        if m and normalize_boolean_value(m.group(1)) is True:
            findings.append((line_num , line.strip()))

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}"
        for num , text in findings
    )

    string_mistake = f'''
⚠️  [CRITICAL] Docker Privileged
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Контейнер запущен в привилегированном режиме Docker.
🎯 Risk: Полный доступ к устройствам хоста, возможность загрузки модулей ядра, обход изоляции, container escape.
❌ Insecure:
    services:
        app:
            image: myapp
            privileged: true  # ❌ Опасно!
✅ Secure:
    services:
        app:
            image: myapp
            privileged: false
            cap_add:
                - NET_BIND_SERVICE
            security_opt:
                - no-new-privileges:true
            read_only: true
🛠️ Remediation:
    • Установите privileged: false
    • Используйте cap_add только для необходимых capabilities
    • Добавьте security_opt: no-new-privileges:true

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [CRITICAL] Docker Privileged")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: Контейнер запущен в привилегированном режиме Docker.")
    print(
        "  🎯 Risk: Полный доступ к устройствам хоста, возможность загрузки модулей ядра, обход изоляции, container escape.")
    print("  ❌ Insecure:")
    print("        services:\n          app:\n            image: myapp\n            privileged: true  # ❌ Опасно!")
    print("  ✅ Secure:")
    print(
        "        services:\n          app:\n            image: myapp\n            privileged: false\n            cap_add:\n              - NET_BIND_SERVICE\n            security_opt:\n              - no-new-privileges:true\n            read_only: true")
    print("  🛠️ Remediation:")
    print("      • Установите privileged: false")
    print("      • Используйте cap_add только для необходимых capabilities")
    print("      • Добавьте security_opt: no-new-privileges:true")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 10: Secrets in Env Vars                         │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.4.1                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Секреты в переменных окружения в plaintext  │
# └─────────────────────────────────────────────────────────────┘
def check_secrets_in_env_vars_10(file_path , file):
    """
    Проверяет хранение секретов в env-переменных в открытом виде
    (Kubernetes env list, docker-compose environment, .env-style KEY=VALUE).
    """
    findings = []
    lines = file.splitlines()

    for i , line in enumerate(lines):
        clean = remove_inline_comment(line).rstrip()
        stripped = clean.strip()
        if not stripped:
            continue

        # Стиль Kubernetes: - name: SECRET_NAME  (значение на следующей строке)
        m_name = re.match(r'-\s*name:\s*["\']?([A-Za-z0-9_.\-]+)["\']?\s*$' , stripped)
        if (m_name and SECRET_NAME_RE.search(m_name.group(1))
                and m_name.group(1).upper() not in SECRET_NAME_ALLOWLIST
                and not _is_reference_key(m_name.group(1))):
            for j in range(i + 1 , min(i + 4 , len(lines))):
                next_line = remove_inline_comment(lines[j]).strip()
                if not next_line:
                    continue
                if next_line.startswith('valueFrom') or 'secretKeyRef' in next_line or 'configMapKeyRef' in next_line:
                    break
                m_val = re.match(r'value:\s*(.+)$' , next_line)
                if m_val:
                    val = m_val.group(1).strip().strip('"').strip("'")
                    if val and not is_template_variable(val) and not _is_placeholder_value(val) and not _is_non_secret_value(val):
                        findings.append((j + 1 , lines[j].strip()))
                break
            continue

        # Стиль KEY: "value" / KEY=value (docker-compose environment, .env)
        m_kv = re.match(r'([A-Za-z0-9_.\-]+)\s*[:=]\s*["\']?([^"\'#]+?)["\']?\s*$' , stripped)
        if m_kv:
            key , val = m_kv.group(1) , m_kv.group(2).strip()
            if 'secretKeyRef' in stripped or 'valueFrom' in stripped:
                continue
            if key.upper() in SECRET_NAME_ALLOWLIST:
                continue
            if _is_reference_key(key):
                continue
            if _is_non_secret_value(val):
                continue
            if SECRET_NAME_RE.search(key) and val and not is_template_variable(val) and not _is_placeholder_value(val):
                findings.append((i + 1 , stripped))

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}"
        for num , text in findings
    )

    string_mistake = f'''
⚠️  [HIGH] Secrets in Env Vars
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Секреты хранятся в переменных окружения в открытом виде.
🎯 Risk: Секреты видны через kubectl describe, docker inspect, могут попасть в логи систем мониторинга или отладки.
❌ Insecure:
    env:
        - name: DB_PASSWORD
          value: "super_secret_password"
        - name: API_KEY
          value: "sk-1234567890abcdef"
✅ Secure:
    envFrom:
        secretRef:
            name: app-secrets
🛠️ Remediation:
    • Используйте Kubernetes Secrets вместо plaintext values
    • Монтируйте секреты как файлы с readOnly: true
    • Включите encryption at rest для etcd

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [HIGH] Secrets in Env Vars")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: Секреты хранятся в переменных окружения в открытом виде.")
    print(
        "  🎯 Risk: Секреты видны через kubectl describe, docker inspect, могут попасть в логи систем мониторинга или отладки.")
    print("  ❌ Insecure:")
    print(
        "        env:\n          - name: DB_PASSWORD\n            value: \"super_secret_password\"\n          - name: API_KEY\n            value: \"sk-1234567890abcdef\"")
    print("  ✅ Secure:")
    print("        envFrom:\n          secretRef:\n            name: app-secrets")
    print("  🛠️ Remediation:")
    print("      • Используйте Kubernetes Secrets вместо plaintext values")
    print("      • Монтируйте секреты как файлы с readOnly: true")
    print("      • Включите encryption at rest для etcd")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 11: Missing Resource Limits                     │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.2.7                                │
# │ ⚡ Критичность: 🟡 MEDIUM                                    │
# │ 📝 Описание:   Отсутствуют лимиты CPU/Memory               │
# └─────────────────────────────────────────────────────────────┘
def check_missing_resource_limits_11(file_path , file):
    """
    Проверяет наличие resources.limits (cpu/memory) у containers/initContainers.
    Сначала пробует структурный YAML-разбор, при неудаче — heuristic по блокам.
    """
    findings = []  # (line_num, text, reason)

    for name , start , block_lines in split_container_blocks(file):
        block_text = '\n'.join(block_lines)
        missing = []
        if 'limits:' not in block_text:
            missing = ['cpu' , 'memory']
        else:
            after_limits = block_text[block_text.index('limits:'):]
            if 'cpu:' not in after_limits:
                missing.append('cpu')
            if 'memory:' not in after_limits:
                missing.append('memory')
        if missing:
            findings.append(
                (start , block_lines[0].strip() , f"container '{name}' missing limits: {', '.join(missing)}")
            )

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}  ← {reason}"
        for num , text , reason in findings
    )

    string_mistake = f'''
⚠️  [MEDIUM] Missing Resource Limits
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Не ограничены ресурсы CPU/Memory для контейнера.
🎯 Risk: Один контейнер может занять все ресурсы узла (DoS), падение других приложений на узле, нестабильность кластера.
❌ Insecure:
    resources:
        requests:
            memory: "64Mi"
            # limits отсутствуют
✅ Secure:
    resources:
        limits:
            cpu: "500m"
            memory: "128Mi"
        requests:
            cpu: "250m"
            memory: "64Mi"
🛠️ Remediation:
    • Укажите limits.cpu и limits.memory
    • Настройте LimitRange для namespace
    • Используйте ResourceQuota для контроля

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [MEDIUM] Missing Resource Limits")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: Не ограничены ресурсы CPU/Memory для контейнера.")
    print(
        "  🎯 Risk: Один контейнер может занять все ресурсы узла (DoS), падение других приложений на узле, нестабильность кластера.")
    print("  ❌ Insecure:")
    print("        resources:\n          requests:\n            memory: \"64Mi\"\n          # limits отсутствуют")
    print("  ✅ Secure:")
    print(
        "        resources:\n          limits:\n            cpu: \"500m\"\n            memory: \"128Mi\"\n          requests:\n            cpu: \"250m\"\n            memory: \"64Mi\"")
    print("  🛠️ Remediation:")
    print("      • Укажите limits.cpu и limits.memory")
    print("      • Настройте LimitRange для namespace")
    print("      • Используйте ResourceQuota для контроля")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 12: Missing Health Probes                       │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.2.8                                │
# │ ⚡ Критичность: 🟡 MEDIUM                                    │
# │ 📝 Описание:   Отсутствуют liveness/readiness probes       │
# └─────────────────────────────────────────────────────────────┘
def check_missing_health_probes_12(file_path , file):
    """
    Проверяет наличие livenessProbe/readinessProbe у containers.
    Сначала пробует структурный YAML-разбор, при неудаче — heuristic по блокам.
    """
    findings = []  # (line_num, text, reason)

    for name , start , block_lines in split_container_blocks(file):
        block_text = '\n'.join(block_lines)
        missing = []
        if 'livenessProbe' not in block_text:
            missing.append('livenessProbe')
        if 'readinessProbe' not in block_text:
            missing.append('readinessProbe')
        if missing:
            findings.append(
                (start , block_lines[0].strip() , f"container '{name}' missing probes: {', '.join(missing)}")
            )

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}  ← {reason}"
        for num , text , reason in findings
    )

    string_mistake = f'''
⚠️  [MEDIUM] Missing Health Probes
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Отсутствуют проверки здоровья (livenessProbe/readinessProbe).
🎯 Risk: Трафик направляется на неработающие поды, зависшие контейнеры не перезапускаются автоматически.
❌ Insecure:
    containers:
        - name: app
          # livenessProbe отсутствует
          # readinessProbe отсутствует
✅ Secure:
    containers:
        - name: app
          livenessProbe:
              httpGet:
                  path: /healthz
                  port: 8080
              initialDelaySeconds: 15
              periodSeconds: 10
          readinessProbe:
              httpGet:
                  path: /ready
                  port: 8080
              initialDelaySeconds: 5
              periodSeconds: 5
🛠️ Remediation:
    • Добавьте livenessProbe для перезапуска зависших контейнеров
    • Добавьте readinessProbe для контроля готовности
    • Настройте startupProbe для медленно стартующих приложений

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [MEDIUM] Missing Health Probes")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: Отсутствуют проверки здоровья (livenessProbe/readinessProbe).")
    print("  🎯 Risk: Трафик направляется на неработающие поды, зависшие контейнеры не перезапускаются автоматически.")
    print("  ❌ Insecure:")
    print(
        "        containers:\n          - name: app\n            # livenessProbe отсутствует\n            # readinessProbe отсутствует")
    print("  ✅ Secure:")
    print(
        "        containers:\n          - name: app\n            livenessProbe:\n              httpGet:\n                path: /healthz\n                port: 8080\n              initialDelaySeconds: 15\n              periodSeconds: 10\n            readinessProbe:\n              httpGet:\n                path: /ready\n                port: 8080\n              initialDelaySeconds: 5\n              periodSeconds: 5")
    print("  🛠️ Remediation:")
    print("      • Добавьте livenessProbe для перезапуска зависших контейнеров")
    print("      • Добавьте readinessProbe для контроля готовности")
    print("      • Настройте startupProbe для медленно стартующих приложений")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 13: Insecure Capabilities Add                   │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.2.9                                │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Добавлены опасные Linux capabilities        │
# └─────────────────────────────────────────────────────────────┘
def check_insecure_capabilities_add_13(file_path , file):
    """
    Проверяет добавление опасных Linux capabilities (SYS_ADMIN и др.)
    внутри securityContext.capabilities.add.
    """
    findings = []
    lines = file.splitlines()
    in_add_block = False
    add_indent = 0

    for i , line in enumerate(lines):
        clean = remove_inline_comment(line)
        stripped = clean.strip()
        if not stripped:
            continue
        indent = len(clean) - len(clean.lstrip())

        m_add = re.match(r'(?:cap_add|add):\s*(\[.*\])?\s*$' , stripped)
        if m_add:
            in_add_block = True
            add_indent = indent
            inline_list = m_add.group(1)
            if inline_list:
                for cap in re.findall(r'[A-Za-z_]+' , inline_list):
                    if cap.upper() in DANGEROUS_CAPABILITIES:
                        findings.append((i + 1 , line.strip() , f'dangerous capability {cap.upper()} added'))
            continue

        if in_add_block:
            m_item = re.match(r'-\s*["\']?([A-Za-z_]+)["\']?' , stripped)
            if m_item and indent > add_indent:
                cap = m_item.group(1).upper()
                if cap in DANGEROUS_CAPABILITIES:
                    findings.append((i + 1 , line.strip() , f'dangerous capability {cap} added'))
                continue
            else:
                in_add_block = False

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}  ← {reason}"
        for num , text , reason in findings
    )

    string_mistake = f'''
⚠️  [CRITICAL] Insecure Capabilities Add
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Добавлены опасные Linux capabilities (SYS_ADMIN, NET_ADMIN).
🎯 Risk: SYS_ADMIN позволяет монтировать ФС, менять настройки ядра. Фактически даёт права, близкие к root.
❌ Insecure:
    securityContext:
        capabilities:
            add:
                  - SYS_ADMIN
                  - NET_ADMIN
✅ Secure:
    securityContext:
        capabilities:
            drop:
                  - ALL
🛠️ Remediation:
    • Удалите все dangerous capabilities из add
    • Используйте drop: ALL по умолчанию
    • Добавляйте только минимально необходимые capabilities

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [CRITICAL] Insecure Capabilities Add")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: Добавлены опасные Linux capabilities (SYS_ADMIN, NET_ADMIN).")
    print("  🎯 Risk: SYS_ADMIN позволяет монтировать ФС, менять настройки ядра. Фактически даёт права, близкие к root.")
    print("  ❌ Insecure:")
    print(
        "        securityContext:\n          capabilities:\n            add:\n              - SYS_ADMIN\n              - NET_ADMIN")
    print("  ✅ Secure:")
    print("        securityContext:\n          capabilities:\n            drop:\n              - ALL")
    print("  🛠️ Remediation:")
    print("      • Удалите все dangerous capabilities из add")
    print("      • Используйте drop: ALL по умолчанию")
    print("      • Добавляйте только минимально необходимые capabilities")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 14: Docker Latest Tag                           │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-Docker-4.1                               │
# │ ⚡ Критичность: 🟡 MEDIUM                                    │
# │ 📝 Описание:   Использование :latest в Docker Compose      │
# └─────────────────────────────────────────────────────────────┘
def check_docker_latest_tag_14(file_path , file):
    """
    Проверяет использование тега :latest или отсутствие тега у образов
    в Docker Compose файлах (Kubernetes/CloudFormation/Terraform
    покрываются проверкой 03, чтобы не дублировать находки).
    """
    if not re.search(r'^services\s*:\s*$' , file , re.MULTILINE):
        return None

    findings = []

    for line_num , line in enumerate(file.splitlines() , start=1):
        clean_line = remove_inline_comment(line)
        match = re.search(r'image:\s*(.+)' , clean_line)
        if not match:
            continue

        image_value = match.group(1).strip().strip('"').strip("'")
        if not image_value or is_template_variable(image_value):
            continue

        if '@sha256:' in image_value:
            continue

        image_name_part = image_value.split('/')[-1]

        if ':' in image_name_part:
            tag = image_name_part.split(':')[-1]
            if tag.lower() == 'latest':
                findings.append((line_num , image_value , "явный тег :latest"))
        else:
            findings.append((line_num , image_value , "тег отсутствует (по умолчанию latest)"))

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {img}  ← {reason}"
        for num , img , reason in findings
    )

    string_mistake = f'''
⚠️  [MEDIUM] Docker Latest Tag
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Использование тега latest в Docker Compose.
🎯 Risk: Невозможность воспроизведения окружения, риск получения битой или уязвимой версии при пересоздании.
❌ Insecure:
    services:
        web:
            image: nginx
            # или image: nginx:latest
✅ Secure:
    services:
        web:
            image: nginx:1.21.0
🛠️ Remediation:
    • Всегда указывайте конкретную версию образа
    • Используйте SHA-хеш для production
    • Настройте Dependabot для обновления образов

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [MEDIUM] Docker Latest Tag")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: Использование тега latest в Docker Compose.")
    print(
        "  🎯 Risk: Невозможность воспроизведения окружения, риск получения битой или уязвимой версии при пересоздании.")
    print("  ❌ Insecure:")
    print("        services:\n          web:\n            image: nginx\n            # или image: nginx:latest")
    print("  ✅ Secure:")
    print("        services:\n          web:\n            image: nginx:1.21.0")
    print("  🛠️ Remediation:")
    print("      • Всегда указывайте конкретную версию образа")
    print("      • Используйте SHA-хеш для production")
    print("      • Настройте Dependabot для обновления образов")
    print()


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 2: AWS SECURITY CHECKS (15–19)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 15: S3 Public Read                              │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-1.13                                 │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   S3 bucket доступен для публичного чтения    │
# └─────────────────────────────────────────────────────────────┘
def check_s3_public_read_15(file_path , file):
    """Проверяет ACL PublicRead у S3 bucket по строкам файла."""
    findings = []
    acl_pattern = re.compile(
        r'["\']?AccessControl["\']?\s*:\s*["\']?PublicRead["\']?(?![A-Za-z])' ,
        re.IGNORECASE ,
    )

    for line_num , line in enumerate(file.splitlines() , start=1):
        clean = remove_inline_comment(line).strip()
        if not clean:
            continue
        if acl_pattern.search(clean):
            findings.append((line_num , line.strip() , 'public read ACL'))

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}  ← {reason}"
        for num , text , reason in findings
    )

    string_mistake = f'''
⚠️  [CRITICAL] S3 Public Read
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: S3 bucket настроен с ACL для публичного чтения.
🎯 Risk: Данные в bucket могут быть доступны любому пользователю в интернете, что ведёт к утечке конфиденциальной информации.
❌ Insecure:
    Resources:
      VulnerableBucket:
        Type: AWS::S3::Bucket
        Properties:
          AccessControl: PublicRead
✅ Secure:
    Resources:
      SecureBucket:
        Type: AWS::S3::Bucket
        Properties:
          AccessControl: Private
🛠️ Remediation:
    • Замените AccessControl: PublicRead на private ACL
    • Включите S3 Block Public Access
    • Проверьте bucket policy и IAM-доступ отдельно от ACL

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [CRITICAL] S3 Public Read")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: S3 bucket настроен с ACL для публичного чтения.")
    print("  🎯 Risk: Данные в bucket могут быть доступны любому пользователю в интернете, что ведёт к утечке конфиденциальной информации.")
    print("  ❌ Insecure:")
    print(
        "        Resources:\n          VulnerableBucket:\n            Type: AWS::S3::Bucket\n            Properties:\n              AccessControl: PublicRead")
    print("  ✅ Secure:")
    print(
        "        Resources:\n          SecureBucket:\n            Type: AWS::S3::Bucket\n            Properties:\n              AccessControl: Private")
    print("  🛠️ Remediation:")
    print("      • Замените AccessControl: PublicRead на private ACL")
    print("      • Включите S3 Block Public Access")
    print("      • Проверьте bucket policy и IAM-доступ отдельно от ACL")
    print()




# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 16: S3 Public Write                             │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-1.14                                 │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   S3 bucket доступен для публичной записи     │
# └─────────────────────────────────────────────────────────────┘
def check_s3_public_write_16(file_path , file):
    """Проверяет ACL PublicReadWrite у S3 bucket по строкам файла (CloudFormation и Terraform)."""
    findings = []
    acl_pattern = re.compile(
        r'["\']?AccessControl["\']?\s*:\s*["\']?PublicReadWrite["\']?(?![A-Za-z])'
        r'|["\']?acl["\']?\s*=\s*["\']?public-read-write["\']?' ,
        re.IGNORECASE ,
    )

    for line_num , line in enumerate(file.splitlines() , start=1):
        clean = remove_inline_comment(line).strip()
        if not clean:
            continue
        if acl_pattern.search(clean):
            findings.append((line_num , line.strip() , 'public write ACL'))

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}  ← {reason}"
        for num , text , reason in findings
    )

    string_mistake = f'''
⚠️  [CRITICAL] S3 Public Write
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: S3 bucket настроен с ACL для публичной записи.
🎯 Risk: Любой пользователь в интернете может загружать, изменять или перезаписывать объекты в bucket.
❌ Insecure:
    Resources:
      VulnerableBucket:
        Type: AWS::S3::Bucket
        Properties:
          AccessControl: PublicReadWrite
✅ Secure:
    Resources:
      SecureBucket:
        Type: AWS::S3::Bucket
        Properties:
          AccessControl: Private
🛠️ Remediation:
    • Замените AccessControl: PublicReadWrite на private ACL
    • Включите S3 Block Public Access
    • Ограничьте запись через IAM roles и bucket policies

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [CRITICAL] S3 Public Write")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: S3 bucket настроен с ACL для публичной записи.")
    print("  🎯 Risk: Любой пользователь в интернете может загружать, изменять или перезаписывать объекты в bucket.")
    print("  ❌ Insecure:")
    print(
        "        Resources:\n          VulnerableBucket:\n            Type: AWS::S3::Bucket\n            Properties:\n              AccessControl: PublicReadWrite")
    print("  ✅ Secure:")
    print(
        "        Resources:\n          SecureBucket:\n            Type: AWS::S3::Bucket\n            Properties:\n              AccessControl: Private")
    print("  🛠️ Remediation:")
    print("      • Замените AccessControl: PublicReadWrite на private ACL")
    print("      • Включите S3 Block Public Access")
    print("      • Ограничьте запись через IAM roles и bucket policies")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 17: Unencrypted EBS                             │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-2.1.1                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   EBS volume не зашифрован                    │
# └─────────────────────────────────────────────────────────────┘
def check_unencrypted_ebs_17(file_path , file):
    """Проверяет шифрование EBS volumes (CloudFormation YAML/JSON и Terraform)."""
    findings = []
    lines = file.splitlines()

    # --- CloudFormation-style: Type: AWS::EC2::Volume ---
    for i , line in enumerate(lines):
        if not re.search(r'AWS::EC2::Volume' , line):
            continue

        start = i + 1
        end = min(len(lines) , i + 25)
        block = lines[start:end]

        # Ограничиваем блок следующим "Type:" (началом нового ресурса)
        for j , bline in enumerate(block):
            if re.search(r'^\s*Type\s*:' , bline) or re.search(r'"Type"\s*:' , bline):
                block = block[:j]
                break

        block_text = '\n'.join(block)
        m_enc = re.search(r'Encrypted["\']?\s*:\s*["\']?(true|false|True|False)["\']?' , block_text)
        if m_enc:
            if normalize_boolean_value(m_enc.group(1)) is False:
                enc_line_offset = block_text[:m_enc.start()].count('\n')
                enc_line_num = start + enc_line_offset + 1
                enc_line_text = block[enc_line_offset].strip() if enc_line_offset < len(block) else 'Encrypted: false'
                findings.append((enc_line_num , enc_line_text , 'Encrypted: false'))
        else:
            findings.append((i + 1 , line.strip() , 'AWS::EC2::Volume без Encrypted (по умолчанию не зашифровано)'))

    # --- Terraform-style: resource "aws_ebs_volume" "x" { ... } ---
    i = 0
    while i < len(lines):
        m = re.search(r'resource\s+"aws_ebs_volume"\s+"[\w_]+"\s*\{' , lines[i])
        if not m:
            i += 1
            continue
        start = i
        depth = lines[i].count('{') - lines[i].count('}')
        block = [lines[i]]
        i += 1
        while i < len(lines) and depth > 0:
            block.append(lines[i])
            depth += lines[i].count('{') - lines[i].count('}')
            i += 1
        block_text = '\n'.join(block)
        m_enc = re.search(r'\bencrypted\s*=\s*(true|false)' , block_text , re.IGNORECASE)
        if m_enc:
            if normalize_boolean_value(m_enc.group(1)) is False:
                off = block_text[:m_enc.start()].count('\n')
                findings.append((start + off + 1 , block[off].strip() , 'encrypted = false'))
        else:
            findings.append((start + 1 , block[0].strip() , 'aws_ebs_volume без encrypted (по умолчанию не зашифровано)'))

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}  ← {reason}"
        for num , text , reason in findings
    )

    string_mistake = f'''
⚠️  [HIGH] Unencrypted EBS
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: EBS volume не зашифрован.
🎯 Risk: При физическом доступе к диску или снимке снапшота данные могут быть прочитаны в открытом виде.
❌ Insecure:
    Type: AWS::EC2::Volume
        Properties:
              Size: 100
              Encrypted: false
✅ Secure:
    Type: AWS::EC2::Volume
        Properties:
              Size: 100
              Encrypted: true
              KmsKeyId: arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
🛠️ Remediation:
    • Включите шифрование для всех новых EBS volumes
    • Настройте default encryption для региона
    • Зашифруйте существующие volumes через snapshot copy

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [HIGH] Unencrypted EBS")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: EBS volume не зашифрован.")
    print("  🎯 Risk: При физическом доступе к диску или снимке снапшота данные могут быть прочитаны в открытом виде.")
    print("  ❌ Insecure:")
    print("        Type: AWS::EC2::Volume\n        Properties:\n          Size: 100\n          Encrypted: false")
    print("  ✅ Secure:")
    print(
        "        Type: AWS::EC2::Volume\n        Properties:\n          Size: 100\n          Encrypted: true\n          KmsKeyId: arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012")
    print("  🛠️ Remediation:")
    print("      • Включите шифрование для всех новых EBS volumes")
    print("      • Настройте default encryption для региона")
    print("      • Зашифруйте существующие volumes через snapshot copy")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 18: RDP Open to Internet                        │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-5.2                                  │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Порт 3389 открыт на 0.0.0.0/0               │
# └─────────────────────────────────────────────────────────────┘
def _find_port_open_to_internet(file , port):
    """Ищет ingress-правила security group, где указанный порт открыт
    для 0.0.0.0/0. Поддерживает CloudFormation- и Terraform-style ключи."""
    findings = []
    lines = file.splitlines()

    for i , line in enumerate(lines):
        if not re.search(r'(CidrIp|cidr_blocks|CidrBlock|CidrIpv6|ipv6_cidr_blocks)["\']?\s*:?\s*.*(0\.0\.0\.0/0|::/0)' , line , re.IGNORECASE):
            continue

        start = max(0 , i - 10)
        end = min(len(lines) , i + 10)
        window = '\n'.join(lines[start:end])

        from_m = re.search(r'(FromPort|from_port)["\']?\s*:\s*["\']?(\d+)' , window , re.IGNORECASE)
        to_m = re.search(r'(ToPort|to_port)["\']?\s*:\s*["\']?(\d+)' , window , re.IGNORECASE)

        if from_m and to_m:
            try:
                fp = int(from_m.group(2))
                tp = int(to_m.group(2))
                if fp <= port <= tp:
                    findings.append((i + 1 , line.strip()))
            except ValueError:
                continue

    return findings


def check_rdp_open_to_internet_18(file_path , file):
    """Проверяет открытие порта RDP (3389) для всего интернета."""
    findings = _find_port_open_to_internet(file , 3389)

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}  ← 0.0.0.0/0"
        for num , text in findings
    )

    string_mistake = f'''
⚠️  [CRITICAL] RDP Open to Internet
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Порт RDP (3389) открыт для всего интернета.
🎯 Risk: Брутфорс паролей, уязвимости типа BlueKeep, шифровальщики (ransomware), полный доступ к серверу.
❌ Insecure:
    SecurityGroupIngress:
        IpProtocol: tcp
        FromPort: 3389
        ToPort: 3389
        CidrIp: 0.0.0.0/0
✅ Secure:
    SecurityGroupIngress:
        IpProtocol: tcp
        FromPort: 3389
        ToPort: 3389
        CidrIp: 10.0.0.0/8
🛠️ Remediation:
    • Немедленно ограничьте CIDR до доверенных IP
    • Используйте AWS Systems Manager Session Manager
    • Настройте VPN для удалённого доступа

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [CRITICAL] RDP Open to Internet")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: Порт RDP (3389) открыт для всего интернета.")
    print("  🎯 Risk: Брутфорс паролей, уязвимости типа BlueKeep, шифровальщики (ransomware), полный доступ к серверу.")
    print("  ❌ Insecure:")
    print(
        "        SecurityGroupIngress:\n          IpProtocol: tcp\n          FromPort: 3389\n          ToPort: 3389\n          CidrIp: 0.0.0.0/0")
    print("  ✅ Secure:")
    print(
        "        SecurityGroupIngress:\n          IpProtocol: tcp\n          FromPort: 3389\n          ToPort: 3389\n          CidrIp: 10.0.0.0/8")
    print("  🛠️ Remediation:")
    print("      • Немедленно ограничьте CIDR до доверенных IP")
    print("      • Используйте AWS Systems Manager Session Manager")
    print("      • Настройте VPN для удалённого доступа")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 19: SSH Open to Internet                        │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-5.1                                  │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Порт 22 открыт на 0.0.0.0/0                 │
# └─────────────────────────────────────────────────────────────┘
def check_ssh_open_to_internet_19(file_path , file):
    """Проверяет открытие порта SSH (22) для всего интернета."""
    findings = _find_port_open_to_internet(file , 22)

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}  ← 0.0.0.0/0"
        for num , text in findings
    )

    string_mistake = f'''
⚠️  [CRITICAL] SSH Open to Internet
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Порт SSH (22) открыт для всего интернета.
🎯 Risk: Постоянная атака ботнетов, брутфорс, утечка ключей, несанкционированный доступ.
❌ Insecure:
    SecurityGroupIngress:
        IpProtocol: tcp
        FromPort: 22
        ToPort: 22
        CidrIp: 0.0.0.0/0
✅ Secure:
    SecurityGroupIngress:
        IpProtocol: tcp
        FromPort: 22
        ToPort: 22
        CidrIp: 10.0.0.0/8
🛠️ Remediation:
    • Используйте AWS Systems Manager Session Manager (без SSH)
    • Ограничьте Security Group до конкретных IP
    • Включите ключевую аутентификацию, отключите password auth

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [CRITICAL] SSH Open to Internet")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: Порт SSH (22) открыт для всего интернета.")
    print("  🎯 Risk: Постоянная атака ботнетов, брутфорс, утечка ключей, несанкционированный доступ.")
    print("  ❌ Insecure:")
    print(
        "        SecurityGroupIngress:\n          IpProtocol: tcp\n          FromPort: 22\n          ToPort: 22\n          CidrIp: 0.0.0.0/0")
    print("  ✅ Secure:")
    print(
        "        SecurityGroupIngress:\n          IpProtocol: tcp\n          FromPort: 22\n          ToPort: 22\n          CidrIp: 10.0.0.0/8")
    print("  🛠️ Remediation:")
    print("      • Используйте AWS Systems Manager Session Manager (без SSH)")
    print("      • Ограничьте Security Group до конкретных IP")
    print("      • Включите ключевую аутентификацию, отключите password auth")
    print()


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 3: CLOUD STORAGE CHECKS (20–21)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 20: Cloud Storage Public (GCP)                  │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-GCP-6.2.1                                │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   GCS bucket доступен allUsers                │
# └─────────────────────────────────────────────────────────────┘
def check_cloud_storage_public_20(file_path , file):
    """Проверяет публичный доступ к Google Cloud Storage bucket
    (allUsers / allAuthenticatedUsers в IAM bindings)."""
    findings = []
    lines = file.splitlines()

    for i , line in enumerate(lines):
        clean = remove_inline_comment(line)
        if not re.search(r'\b(allUsers|allAuthenticatedUsers)\b' , clean):
            continue

        role = None
        for j in range(i , max(-1 , i - 6) , -1):
            rm = re.search(r'role["\']?\s*:\s*["\']?(roles/[\w.\-]+)' , lines[j])
            if rm:
                role = rm.group(1)
                break

        window = '\n'.join(lines[max(0 , i - 15):i + 1])
        is_storage_context = bool(
            (role and 'storage' in role.lower()) or
            re.search(r'google_storage_bucket|storage\.googleapis\.com|"kind"\s*:\s*"storage#|gs://' , window , re.IGNORECASE)
        )
        if not is_storage_context:
            continue

        findings.append((i + 1 , clean.strip() , role or 'неизвестна'))

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}  ← role: {role}"
        for num , text , role in findings
    )

    string_mistake = f'''
⚠️  [CRITICAL] Cloud Storage Public (GCP)
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: GCS bucket доступен всем пользователям (allUsers).
🎯 Risk: Публичный доступ к файлам, утечка данных, несанкционированное чтение конфиденциальной информации.
❌ Insecure:
    bindings:
        - role: roles/storage.objectViewer
        members:
            - allUsers
✅ Secure:
    bindings:
        - role: roles/storage.objectViewer
        members:
            - user:specific@example.com
🛠️ Remediation:
    • Удалите allUsers и allAuthenticatedUsers из IAM policies
    • Используйте Uniform bucket-level access
    • Настройте VPC Service Controls

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [CRITICAL] Cloud Storage Public (GCP)")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: GCS bucket доступен всем пользователям (allUsers).")
    print("  🎯 Risk: Публичный доступ к файлам, утечка данных, несанкционированное чтение конфиденциальной информации.")
    print("  ❌ Insecure:")
    print(
        "        bindings:\n          - role: roles/storage.objectViewer\n            members:\n              - allUsers")
    print("  ✅ Secure:")
    print(
        "        bindings:\n          - role: roles/storage.objectViewer\n            members:\n              - user:specific@example.com")
    print("  🛠️ Remediation:")
    print("      • Удалите allUsers и allAuthenticatedUsers из IAM policies")
    print("      • Используйте Uniform bucket-level access")
    print("      • Настройте VPC Service Controls")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 21: Azure Storage Public                        │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-Azure-9.1                                │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Azure Storage с публичным доступом          │
# └─────────────────────────────────────────────────────────────┘
def check_azure_storage_public_21(file_path , file):
    """Проверяет публичный доступ к Azure Storage container/account."""
    findings = []

    for line_num , line in enumerate(file.splitlines() , start=1):
        clean = remove_inline_comment(line)

        m_pub = re.search(r'publicAccess["\']?\s*:\s*["\']?(Blob|Container)["\']?' , clean , re.IGNORECASE)
        if m_pub:
            findings.append((line_num , clean.strip() , f"publicAccess: {m_pub.group(1)}"))
            continue

        m_allow = re.search(r'allowBlobPublicAccess["\']?\s*:\s*["\']?(true|True|TRUE)["\']?' , clean)
        if m_allow:
            findings.append((line_num , clean.strip() , "allowBlobPublicAccess: true"))

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}  ← {reason}"
        for num , text , reason in findings
    )

    string_mistake = f'''
⚠️  [CRITICAL] Azure Storage Public
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Уровень доступа Azure Storage установлен в публичный.
🎯 Risk: Чтение данных любым пользователем интернета, утечка конфиденциальной информации, compliance violations.
❌ Insecure:
    properties:
        publicAccess: Blob
✅ Secure:
    properties:
        publicAccess: None
🛠️ Remediation:
    • Установите publicAccess: None
    • Включите 'Allow Blob anonymous access' = Disabled
    • Используйте SAS tokens с ограниченным временем жизни

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [CRITICAL] Azure Storage Public")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: Уровень доступа Azure Storage установлен в публичный.")
    print(
        "  🎯 Risk: Чтение данных любым пользователем интернета, утечка конфиденциальной информации, compliance violations.")
    print("  ❌ Insecure:")
    print("        properties:\n          publicAccess: Blob")
    print("  ✅ Secure:")
    print("        properties:\n          publicAccess: None")
    print("  🛠️ Remediation:")
    print("      • Установите publicAccess: None")
    print("      • Включите 'Allow Blob anonymous access' = Disabled")
    print("      • Используйте SAS tokens с ограниченным временем жизни")
    print()


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 4: KUBERNETES ADMIN CHECKS (22–24)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 22: Kubernetes Dashboard Exposed                │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.1.1                                │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Dashboard доступен через LoadBalancer       │
# └─────────────────────────────────────────────────────────────┘
def check_kubernetes_dashboard_exposed_22(file_path , file):
    """Проверяет экспонирование Kubernetes Dashboard наружу через LoadBalancer."""
    findings = []
    lines = file.splitlines()
    current_service_start = None
    current_service_name = ''
    current_service_kind = False
    current_has_dashboard = False

    for i , line in enumerate(lines):
        clean = remove_inline_comment(line)
        stripped = clean.strip()

        if re.match(r'^\s*---\s*$' , stripped):
            current_service_start = None
            current_service_name = ''
            current_service_kind = False
            current_has_dashboard = False
            continue

        if re.search(r'^\s*kind\s*:\s*Service\s*$' , clean , re.IGNORECASE):
            current_service_start = i + 1
            current_service_kind = True
            current_service_name = ''
            current_has_dashboard = False
            continue

        if not current_service_kind:
            continue

        if re.search(r'^\s*kind\s*:' , clean , re.IGNORECASE) and not re.search(r'^\s*kind\s*:\s*Service\s*$' , clean , re.IGNORECASE):
            current_service_start = None
            current_service_name = ''
            current_service_kind = False
            current_has_dashboard = False
            continue

        name_match = re.search(r'^\s*name\s*:\s*["\']?([A-Za-z0-9_.\-]+)["\']?\s*$' , clean)
        if name_match:
            current_service_name = name_match.group(1)
            if 'dashboard' in current_service_name.lower():
                current_has_dashboard = True

        if 'dashboard' in stripped.lower():
            current_has_dashboard = True

        if current_has_dashboard and re.search(r'^\s*type\s*:\s*["\']?LoadBalancer["\']?\s*$' , clean , re.IGNORECASE):
            findings.append((i + 1 , line.strip() , f"dashboard service '{current_service_name or '<service>'}' exposed via LoadBalancer"))
            current_service_start = None
            current_service_name = ''
            current_service_kind = False
            current_has_dashboard = False

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}  ← {reason}"
        for num , text , reason in findings
    )

    string_mistake = f'''
⚠️  [CRITICAL] Kubernetes Dashboard Exposed
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Панель управления K8s доступна извне через LoadBalancer.
🎯 Risk: Если авторизация слабая, злоумышленник получит полный контроль над кластером.
❌ Insecure:
    apiVersion: v1
    kind: Service
    metadata:
        name: kubernetes-dashboard
    spec:
        type: LoadBalancer
✅ Secure:
    apiVersion: v1
    kind: Service
    metadata:
        name: kubernetes-dashboard
    spec:
        type: ClusterIP
🛠️ Remediation:
    • Измените тип Service на ClusterIP
    • Настройте доступ через kubectl proxy
    • Или используйте Ingress с OAuth/OIDC

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [CRITICAL] Kubernetes Dashboard Exposed")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: Панель управления K8s доступна извне через LoadBalancer.")
    print("  🎯 Risk: Если авторизация слабая, злоумышленник получит полный контроль над кластером.")
    print("  ❌ Insecure:")
    print(
        "        apiVersion: v1\n        kind: Service\n        metadata:\n          name: kubernetes-dashboard\n        spec:\n          type: LoadBalancer")
    print("  ✅ Secure:")
    print(
        "        apiVersion: v1\n        kind: Service\n        metadata:\n          name: kubernetes-dashboard\n        spec:\n          type: ClusterIP")
    print("  🛠️ Remediation:")
    print("      • Измените тип Service на ClusterIP")
    print("      • Настройте доступ через kubectl proxy")
    print("      • Или используйте Ingress с OAuth/OIDC")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 23: Etcd Client Cert Auth                       │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-4.1.1                                │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Etcd без client-cert-auth                   │
# └─────────────────────────────────────────────────────────────┘
def check_etcd_client_cert_auth_23(file_path , file):
    """Проверяет требование клиентских сертификатов для etcd
    (client-cert-auth: false, либо отсутствие флага в etcd-конфигурации)."""
    findings = []
    found_true = False
    has_etcd_context = bool(
        re.search(r'^\s*-\s*etcd\s*$' , file , re.IGNORECASE | re.MULTILINE) or
        re.search(r'\betcd[/\\](server|peer)\.(crt|key)\b' , file , re.IGNORECASE) or
        re.search(r'name\s*:\s*["\']?etcd["\']?\s*$' , file , re.IGNORECASE | re.MULTILINE) or
        re.search(r'image\s*:\s*.*\betcd\b' , file , re.IGNORECASE) or
        re.search(r'--data-dir\s*[=:]\s*.*etcd' , file , re.IGNORECASE)
    )
    etcd_line_num = 0
    etcd_line_text = ''

    for line_num , line in enumerate(file.splitlines() , start=1):
        clean = remove_inline_comment(line)
        if not etcd_line_num and re.search(r'\betcd\b' , clean , re.IGNORECASE):
            etcd_line_num = line_num
            etcd_line_text = clean.strip()
        m = re.search(r'--?client-cert-auth["\']?\s*[:=]\s*["\']?(true|false|True|False)["\']?' , clean , re.IGNORECASE)
        if m:
            if normalize_boolean_value(m.group(1)) is False:
                findings.append((line_num , clean.strip() , 'явно отключено (client-cert-auth: false)'))
            else:
                found_true = True

    if not findings and has_etcd_context and not found_true:
        findings.append((etcd_line_num or 1 , etcd_line_text or 'etcd' , 'client-cert-auth не задан в конфигурации etcd'))

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}  ← {reason}"
        for num , text , reason in findings
    )

    string_mistake = f'''
⚠️  [CRITICAL] Etcd Client Cert Auth
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Etcd не требует клиентские сертификаты для аутентификации.
🎯 Risk: Любой, кто имеет доступ к порту etcd, может читать/писать все данные кластера.
❌ Insecure:
    etcd:
        client-cert-auth: false
✅ Secure:
    etcd:
        client-cert-auth: true
        cert-file: /etc/kubernetes/pki/etcd/server.crt
        key-file: /etc/kubernetes/pki/etcd/server.key
🛠️ Remediation:
    • Включите client-cert-auth: true
    • Настройте peer-client-cert-auth для etcd cluster
    • Ограничьте доступ к порту etcd firewall

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [CRITICAL] Etcd Client Cert Auth")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: Etcd не требует клиентские сертификаты для аутентификации.")
    print("  🎯 Risk: Любой, кто имеет доступ к порту etcd, может читать/писать все данные кластера.")
    print("  ❌ Insecure:")
    print("        etcd:\n          client-cert-auth: false")
    print("  ✅ Secure:")
    print(
        "        etcd:\n          client-cert-auth: true\n          cert-file: /etc/kubernetes/pki/etcd/server.crt\n          key-file: /etc/kubernetes/pki/etcd/server.key")
    print("  🛠️ Remediation:")
    print("      • Включите client-cert-auth: true")
    print("      • Настройте peer-client-cert-auth для etcd cluster")
    print("      • Ограничьте доступ к порту etcd firewall")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 24: Anonymous Auth Enabled                      │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.1.3                                │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Разрешена анонимная аутентификация API      │
# └─────────────────────────────────────────────────────────────┘
def check_anonymous_auth_enabled_24(file_path , file):
    """Проверяет включение анонимной аутентификации Kubernetes API Server
    (--anonymous-auth=true, в т.ч. с кавычками/пробелами)."""
    findings = []

    for line_num , line in enumerate(file.splitlines() , start=1):
        clean = remove_inline_comment(line)
        m = re.search(r'--anonymous-auth\s*[=:]\s*["\']?(true|True|TRUE)["\']?' , clean)
        if not m:
            m = re.search(r'["\']?anonymous[_-]?[aA]uth["\']?\s*:\s*["\']?(true|True|TRUE)["\']?' , clean)
        if m:
            findings.append((line_num , clean.strip() , 'anonymous auth enabled'))

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}  ← {reason}"
        for num , text , reason in findings
    )

    string_mistake = f'''
⚠️  [CRITICAL] Anonymous Auth Enabled
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Разрешена анонимная аутентификация Kubernetes API Server.
🎯 Risk: Неаутентифицированные запросы к API, возможность разведки кластера или эксплуатации уязвимостей.
❌ Insecure:
    kube-apiserver:
        --anonymous-auth=true
✅ Secure:
    kube-apiserver:
        --anonymous-auth=false
        --authorization-mode=Node,RBAC
🛠️ Remediation:
    • Установите --anonymous-auth=false
    • Проверьте все API Server конфигурации
    • Включите RBAC authorization mode

    '''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [CRITICAL] Anonymous Auth Enabled")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: Разрешена анонимная аутентификация Kubernetes API Server.")
    print("  🎯 Risk: Неаутентифицированные запросы к API, возможность разведки кластера или эксплуатации уязвимостей.")
    print("  ❌ Insecure:")
    print("        kube-apiserver:\n          --anonymous-auth=true")
    print("  ✅ Secure:")
    print("        kube-apiserver:\n          --anonymous-auth=false\n          --authorization-mode=Node,RBAC")
    print("  🛠️ Remediation:")
    print("      • Установите --anonymous-auth=false")
    print("      • Проверьте все API Server конфигурации")
    print("      • Включите RBAC authorization mode")
    print()


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 5: CI/CD SECURITY CHECKS (25)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 25: CI/CD Plain Text Secrets                    │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   NIST-IA-5                                    │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Секреты в коде конфигурации в plaintext     │
# └─────────────────────────────────────────────────────────────┘
def check_cicd_plaintext_secrets_25(file_path , file):
    """Проверяет хранение секретов в открытом виде в CI/CD конфигах
    (.gitlab-ci.yml, GitHub Actions, Jenkinsfile)."""
    findings = []

    secret_key_pattern = re.compile(
        r'(?:PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|APIKEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|AUTH[_-]?TOKEN|CREDENTIAL)' ,
        re.IGNORECASE ,
    )
    yaml_pattern = re.compile(
        r'^(?:-\s*)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*:\s*(.+?)\s*$'
    )
    env_pattern = re.compile(
        r'^(?:-\s*)?(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(.+?)\s*$'
    )
    blocked_value_pattern = re.compile(
        r'(\$|\$\{|\{\{|secrets\.|vault|aws\s+secretsmanager|secretKeyRef|valueFrom)' ,
        re.IGNORECASE ,
    )

    for line_num , line in enumerate(file.splitlines() , start=1):
        clean = remove_inline_comment(line).rstrip()
        stripped = clean.strip()
        if not stripped or stripped.startswith('#'):
            continue

        matches = []

        yaml_match = yaml_pattern.match(stripped)
        if yaml_match:
            matches.append((yaml_match.group(1) , yaml_match.group(2).strip() , 'hardcoded secret in CI/CD config'))

        env_match = env_pattern.match(stripped)
        if env_match:
            matches.append((env_match.group(1) , env_match.group(2).strip() , 'hardcoded secret in CI/CD script'))

        for key , raw_value , reason in matches:
            if not secret_key_pattern.search(key):
                continue
            if key.upper() in SECRET_NAME_ALLOWLIST:
                continue
            if _is_reference_key(key):
                continue
            if not raw_value:
                continue
            if blocked_value_pattern.search(raw_value):
                continue

            value = raw_value.strip().strip('"').strip("'").strip()
            if not value:
                continue
            if blocked_value_pattern.search(value):
                continue
            if _is_placeholder_value(value):
                continue
            if _is_non_secret_value(value):
                continue

            findings.append((line_num , line.strip() , reason))
            break

    if not findings:
        return None

    locations = '\n'.join(
        f"    Строка {num}: {text}  ← {reason}"
        for num , text , reason in findings
    )

    string_mistake = f'''
⚠️  [CRITICAL] CI/CD Plain Text Secrets
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: Секреты зашиты в код конфигурации CI/CD в открытом виде.
🎯 Risk: Попадание секретов в git-историю, доступ к секретам у всех разработчиков с доступом к репозиторию.
❌ Insecure:
    # .gitlab-ci.yml
    variables:
        DB_PASSWORD: "hardcoded_password"  # ❌
        API_KEY: "sk-1234567890abcdef"     # ❌
✅ Secure:
    # GitLab CI:
        variables:
            DB_PASSWORD: $SECURE_DB_PASSWORD  # ✅ Из CI/CD Variables
    # GitHub Actions:
        env:
            PASSWORD: ${{ secrets.DB_PASSWORD }}  # ✅ Из Repository Secrets
🛠️ Remediation:
    • Удалите hardcoded secrets из CI/CD конфигурации
    • Используйте GitLab CI/CD Variables или GitHub Actions Secrets
    • Подключите внешний secret manager вместо literal values
    • Ротируйте найденные секреты, если они уже использовались
'''

    write_to_file(str(file_path) + '\n' + string_mistake)
    print("⚠️  [CRITICAL] CI/CD Plain Text Secrets")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print("  💥 Issue: Секреты зашиты в код конфигурации CI/CD в открытом виде.")
    print(
        "  🎯 Risk: Попадание секретов в git-историю, доступ к секретам у всех разработчиков с доступом к репозиторию.")
    print("  ❌ Insecure:")
    print(
        "        # .gitlab-ci.yml\n        variables:\n          DB_PASSWORD: \"hardcoded_password\"  # ❌\n          API_KEY: \"sk-1234567890abcdef\"     # ❌")
    print("  ✅ Secure:")
    print(
        "        # GitLab CI:\n        variables:\n          DB_PASSWORD: $SECURE_DB_PASSWORD  # ✅ Из CI/CD Variables\n        # GitHub Actions:\n        env:\n          PASSWORD: ${{ secrets.DB_PASSWORD }}  # ✅ Из Repository Secrets")
    print("  🛠️ Remediation:")
    print("      • Удалите hardcoded secrets из CI/CD конфигурации")
    print("      • Используйте GitLab CI/CD Variables или GitHub Actions Secrets")
    print("      • Подключите внешний secret manager вместо literal values")
    print("      • Ротируйте найденные секреты, если они уже использовались")
    print()


def all_easy_check(all_files):
    """
    ╔════════════════════════════════════════════════════════════════╗
    ║  🔐 ЗАПУСК ВСЕХ ПРОВЕРОК EASY LEVEL (01–25)                   ║
    ╚════════════════════════════════════════════════════════════════╝

    Файл читается один раз, и одна и та же строка содержимого
    передаётся во все проверки.
    """
    with open(all_files , 'r' , encoding='utf-8') as f:
        content = f.read()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔹 РАЗДЕЛ 1: KUBERNETES + DOCKER SECURITY CHECKS (01–14)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    check_privileged_container_01(all_files , content)  # 01
    check_run_as_root_02(all_files , content)  # 02
    check_latest_tag_03(all_files , content)  # 03
    check_host_network_04(all_files , content)  # 04
    check_host_pid_05(all_files , content)  # 05
    check_host_ipc_06(all_files , content)  # 06
    check_allow_privilege_escalation_07(all_files , content)  # 07
    check_docker_exposed_ports_08(all_files , content)  # 08
    check_docker_privileged_09(all_files , content)  # 09
    check_secrets_in_env_vars_10(all_files , content)  # 10
    check_missing_resource_limits_11(all_files , content)  # 11
    check_missing_health_probes_12(all_files , content)  # 12
    check_insecure_capabilities_add_13(all_files , content)  # 13
    check_docker_latest_tag_14(all_files , content)  # 14

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔹 РАЗДЕЛ 2: AWS SECURITY CHECKS (15–19)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    check_s3_public_read_15(all_files , content)  # 15
    check_s3_public_write_16(all_files , content)  # 16
    check_unencrypted_ebs_17(all_files , content)  # 17
    check_rdp_open_to_internet_18(all_files , content)  # 18
    check_ssh_open_to_internet_19(all_files , content)  # 19

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔹 РАЗДЕЛ 3: CLOUD STORAGE CHECKS (20–21)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    check_cloud_storage_public_20(all_files , content)  # 20
    check_azure_storage_public_21(all_files , content)  # 21

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔹 РАЗДЕЛ 4: KUBERNETES ADMIN CHECKS (22–24)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    check_kubernetes_dashboard_exposed_22(all_files , content)  # 22
    check_etcd_client_cert_auth_23(all_files , content)  # 23
    check_anonymous_auth_enabled_24(all_files , content)  # 24

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔹 РАЗДЕЛ 5: CI/CD SECURITY CHECKS (25)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    check_cicd_plaintext_secrets_25(all_files , content)  # 25


'''
🔹 РАЗДЕЛ 1: Kubernetes Security (01–14)
📦 Форматы:
    • Kubernetes YAML манифесты (.yaml, .yml)
    • Примеры файлов:
        - 01_privileged.yaml
        - 02_run_as_root.yaml
        - 03_latest_tag.yaml
        - 04_host_network.yaml
        - 05_host_pid.yaml
        - 06_host_ipc.yaml
        - 07_allow_privilege_escalation.yaml
        - 10_secrets_in_env.yaml
        - 11_missing_resource_limits.yaml
        - 12_missing_health_probes.yaml
        - 13_insecure_capabilities.yaml

🔹 РАЗДЕЛ 2: Docker Security (08, 09, 14)
📦 Форматы:
    • Docker Compose файлы (docker-compose.yaml, docker-compose.yml)
    • Dockerfile (косвенно, через образы)
    • Примеры файлов:
        - 08_docker_exposed_ports.yaml
        - 09_docker_privileged.yaml
        - 14_docker_latest_tag.yaml

🔹 РАЗДЕЛ 3: AWS Security (15–19) 
📦 Форматы:
    • AWS CloudFormation (.yaml, .yml, .template)
    • AWS IAM Policy (.json)
    • AWS S3 Bucket Policy (.json)
    • Примеры файлов:
        - 15_s3_public_read.yaml
        - 16_s3_public_write.yaml
        - 17_unencrypted_ebs.yaml
        - 18_rdp_open_internet.yaml
        - 19_ssh_open_internet.yaml

🔹 РАЗДЕЛ 4: Cloud Storage (20–21)
📦 Форматы:
    • GCP IAM Policy (.yaml, .json)
    • Azure ARM Template (.json, .yaml)
    • Примеры файлов:
        - 20_gcs_public.yaml
        - 21_azure_storage_public.yaml

🔹 РАЗДЕЛ 5: Kubernetes Admin (22–24)
📦 Форматы:
    • Kubernetes YAML манифесты (.yaml, .yml)
    • etcd конфигурация (.yaml, .conf)
    • kube-apiserver конфигурация (.yaml, .conf)
    • Примеры файлов:
        - 22_dashboard_exposed.yaml
        - 23_etcd_client_cert.yaml
        - 24_anonymous_auth.yaml

🔹 РАЗДЕЛ 6: CI/CD Security (25)
📦 Форматы:
    • GitLab CI (.gitlab-ci.yml)
    • GitHub Actions (.github/workflows/*.yml)
    • Jenkinsfile (Jenkins)
    • Примеры файлов:
        - 25_cicd_plaintext_secrets.yaml
'''
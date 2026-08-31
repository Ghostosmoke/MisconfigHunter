from found_files_need_check import write_to_file
from Easy_Check import remove_inline_comment, normalize_boolean_value, split_container_blocks
import re
from pathlib import Path
# 1 2 3 10 13 16 17 18 19 20 23 24 25 переделай он ничего не находит
"""
╔════════════════════════════════════════════════════════════════╗
║  🔐 Security Auditor — Medium Level Checks (26–50)            ║
║  CIS Kubernetes | Docker | AWS | GCP | Azure | CI/CD          ║
╚════════════════════════════════════════════════════════════════╝

Все проверки реализуют реальный анализ содержимого файла:
line-based regex сканирование и эвристики по блокам YAML/JSON/HCL.
"""

# ═══════════════════════════════════════════════════════════════
# 🔹 ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (helpers)
# ═══════════════════════════════════════════════════════════════

WORKLOAD_KINDS = {'Pod', 'Deployment', 'StatefulSet', 'DaemonSet'}
_CURRENT_BATCH_PATHS = []
_CURRENT_BATCH_CONTENTS = {}


def _normalize_line(line):
    return re.sub(r'\s*:\s*', ':', remove_inline_comment(line))


def _extract_kv_value(line, key):
    """
    Извлекает значение свойства `key` из строки независимо от формата:
      YAML:  key: value | key: "value" | key: 'value'
      JSON:  "key": value | "key": "value"
      HCL:   key = value | key = "value"
    Комментарии должны быть удалены заранее (remove_inline_comment).
    Возвращает None, если ключ не найден.
    """
    pattern = r'["\']?%s["\']?\s*[:=]\s*["\']?([^"\',\s}\]]+)["\']?' % re.escape(key)
    m = re.search(pattern, line, re.IGNORECASE)
    if not m:
        return None
    return m.group(1).rstrip(',')


def _split_yaml_documents(file):
    parts = re.split(r'^---\s*$', file, flags=re.MULTILINE)
    return [p for p in parts if p.strip()]


def _find_kind_blocks(file):
    """Возвращает список (kind, start_line, block_lines) для каждого YAML-документа."""
    blocks = []
    for doc in _split_yaml_documents(file):
        doc_lines = doc.splitlines()
        kind = None
        kind_idx = None
        for i, line in enumerate(doc_lines):
            clean = remove_inline_comment(line)
            m = re.match(r'^\s*["\']?kind["\']?\s*[:=]\s*["\']?(\w+)["\']?\s*,?\s*$', clean, re.IGNORECASE)
            if m:
                kind = m.group(1)
                kind_idx = i
                break
        if kind is None:
            continue
        pos = file.find(doc)
        if pos == -1:
            continue
        doc_start_line = file[:pos].count('\n') + 1
        blocks.append((kind, doc_start_line + kind_idx, doc_lines))
    return blocks


def _block_text(block_lines):
    return '\n'.join(block_lines)


def _is_permissive_cidr(cidr):
    cidr = cidr.strip().strip('"').strip("'")
    if cidr in ('0.0.0.0/0', '::/0'):
        return True
    m = re.match(r'^[\d.:a-fA-F]+/(\d+)$', cidr)
    if not m:
        return False
    prefix = int(m.group(1))
    if ':' in cidr:
        return prefix <= 48  # IPv6: /48 или шире считается широким диапазоном
    return prefix <= 16


TRUSTED_REGISTRIES = {
    'docker.io', 'gcr.io', 'ghcr.io', 'quay.io', 'registry.k8s.io',
    'public.ecr.aws', 'mcr.microsoft.com', 'registry.hub.docker.com',
}


def _is_untrusted_image(image):
    image = image.strip().strip('"').strip("'")
    if not image or image.startswith('$') or '{{' in image:
        return False
    if '/' not in image:
        # 'nginx:1.24' — официальный образ Docker Hub (library/nginx), доверенный
        return False
    registry = image.split('/')[0]
    registry_host = registry.split(':')[0]
    if registry_host in ('localhost', '127.0.0.1'):
        return False
    if '.' not in registry and ':' not in registry:
        # 'bitnami/nginx:1.24' — пользовательский образ Docker Hub, доверенный
        return False
    if registry.lower() in TRUSTED_REGISTRIES:
        return False
    # Неизвестный реестр с явным доменом (например, some-shady-registry.ru/app)
    return True


def _is_pinned_action(ref):
    ref = ref.strip()
    if '@' not in ref:
        return False
    version = ref.rsplit('@', 1)[1]
    if re.fullmatch(r'[0-9a-f]{40}', version):
        return True
    if re.search(r'^(v\d+|main|master)$', version, re.IGNORECASE):
        return False
    return False


def _find_job_blocks(file):
    """GitLab CI (top-level keys) и GitHub Actions (jobs: <id>: с отступом) job blocks."""
    lines = file.splitlines()
    blocks = []
    current_name = None
    current_start = None
    current_lines = []

    for i, line in enumerate(lines):
        if re.match(r'^[A-Za-z0-9_.-]+:\s*$', line) and not line.startswith(' '):
            if current_name is not None:
                blocks.append((current_name, current_start, current_lines))
            current_name = line.split(':')[0]
            current_start = i + 1
            current_lines = [line]
        elif current_name is not None:
            if line and not line.startswith(' ') and ':' in line and not line.startswith('-'):
                blocks.append((current_name, current_start, current_lines))
                if re.match(r'^[A-Za-z0-9_.-]+:\s*$', line):
                    current_name = line.split(':')[0]
                    current_start = i + 1
                    current_lines = [line]
                else:
                    current_name = None
                    current_lines = []
            else:
                current_lines.append(line)

    if current_name is not None:
        blocks.append((current_name, current_start, current_lines))

    # GitHub Actions: разворачиваем jobs: <job_id>: ... (2-пробельный отступ) в отдельные блоки
    for name, start, block_lines in list(blocks):
        if name != 'jobs':
            continue
        job_id = None
        job_start_offset = None
        job_lines = []
        for j, line in enumerate(block_lines[1:], start=1):
            m = re.match(r'^  ([A-Za-z0-9_.-]+):\s*$', line)
            if m:
                if job_id is not None:
                    blocks.append((job_id, start + job_start_offset, job_lines))
                job_id = m.group(1)
                job_start_offset = j
                job_lines = [line]
            elif job_id is not None:
                job_lines.append(line)
        if job_id is not None:
            blocks.append((job_id, start + job_start_offset, job_lines))

    return blocks


def _find_terraform_s3_backends(file):
    """Возвращает (start_line, block_text) для backend \"s3\" блоков."""
    lines = file.splitlines()
    backends = []
    i = 0
    while i < len(lines):
        if re.search(r'backend\s+"s3"\s*\{', lines[i]):
            start = i + 1
            depth = lines[i].count('{') - lines[i].count('}')
            block = [lines[i]]
            i += 1
            while i < len(lines) and depth > 0:
                block.append(lines[i])
                depth += lines[i].count('{') - lines[i].count('}')
                i += 1
            backends.append((start, block))
        else:
            i += 1
    return backends


def _read_batch(files):
    paths = [Path(f) for f in files] if not isinstance(files, (str, Path)) else [Path(files)]
    contents = {}
    for path in paths:
        with open(path, 'r', encoding='utf-8') as f:
            contents[path] = f.read()
    return paths, contents


def _report_finding(file_path, severity, title, findings, issue, risk, insecure, secure, remediation):
    locations = '\n'.join(
        f"    Строка {num}: {text}  ← {reason}"
        for num, text, reason in findings
    )
    string_mistake = f'''
⚠️  [{severity}] {title}
📁 Файл: {file_path}
📍 Найдено проблем: {len(findings)}
{locations}

💥 Issue: {issue}
🎯 Risk: {risk}
❌ Insecure:
{insecure}
✅ Secure:
{secure}
🛠️ Remediation:
{remediation}

'''
    write_to_file(str(file_path) + '\n' + string_mistake)
    print(f"⚠️  [{severity}] {title}")
    print(f"  📍 Найдено проблем: {len(findings)}")
    print(locations)
    print(f"  💥 Issue: {issue}")
    print(f"  🎯 Risk: {risk}")
    print("  ❌ Insecure:")
    for line in insecure.strip().splitlines():
        print(f"        {line.lstrip()}")
    print("  ✅ Secure:")
    for line in secure.strip().splitlines():
        print(f"        {line.lstrip()}")
    print("  🛠️ Remediation:")
    for line in remediation.strip().splitlines():
        print(f"      {line.lstrip()}")
    print()


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 1: KUBERNETES SECURITY CHECKS (26–29)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 26: Network Policy Missing                      │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.3.2                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Под без NetworkPolicy в namespace            │
# └─────────────────────────────────────────────────────────────┘
def check_network_policy_missing_26(file_path, file):
    """
    Проверяет наличие NetworkPolicy для сегментации трафика между подами.
    Вызывается из all_medium_check() после анализа всего набора файлов.
    """
    findings = []
    for line_num, line in enumerate(file.splitlines(), start=1):
        clean = remove_inline_comment(line)
        m = re.match(r'^\s*["\']?kind["\']?\s*[:=]\s*["\']?(Pod|Deployment|StatefulSet|DaemonSet)["\']?\s*,?\s*$', clean, re.IGNORECASE)
        if m:
            findings.append((line_num, line.strip(), f"workload {m.group(1)} без NetworkPolicy в наборе файлов"))
            break

    if not findings:
        return None

    _report_finding(
        file_path, 'HIGH', 'Network Policy Missing', findings,
        'Pod без соответствующего NetworkPolicy в namespace.',
        'Отсутствует сегментация сети. Атакующий может сканировать и атаковать другие сервисы изнутри кластера (lateral movement).',
        '''        # Pod без соответствующего NetworkPolicy
        apiVersion: v1
        kind: Pod
        metadata:
          name: vulnerable-pod
        # В namespace нет NetworkPolicy, селектирующей этот под''',
        '''        # Явный NetworkPolicy, разрешающий только необходимый трафик
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: allow-frontend-only
        spec:
          podSelector:
            matchLabels:
              app: backend
          policyTypes:
          - Ingress
          - Egress''',
        '''      • Создайте NetworkPolicy для каждого namespace
      • Используйте default-deny политику по умолчанию
      • Разрешайте только необходимый трафик между подами''',
    )


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 27: Service Account Token Mount                 │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.2.10                               │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Токен SA автоматически монтируется в под     │
# └─────────────────────────────────────────────────────────────┘
def check_service_account_token_mount_27(file_path, file):
    """Проверяет автоматическое монтирование токена ServiceAccount в поды."""
    findings = []
    for line_num, line in enumerate(file.splitlines(), start=1):
        clean = remove_inline_comment(line)
        val = _extract_kv_value(clean, 'automountServiceAccountToken')
        if val is not None and normalize_boolean_value(val) is True:
            findings.append((line_num, line.strip(), 'automountServiceAccountToken: true'))

    if not findings:
        return None

    _report_finding(
        file_path, 'HIGH', 'Service Account Token Mount', findings,
        'Токен ServiceAccount автоматически монтируется в под (automountServiceAccountToken: true).',
        'Утечка токена = доступ к Kubernetes API. Возможность создания/удаления ресурсов в кластере в зависимости от RBAC.',
        '''        spec:
          serviceAccountName: default
          automountServiceAccountToken: true''',
        '''        automountServiceAccountToken: false
        spec:
          serviceAccountName: app-sa
          automountServiceAccountToken: false''',
        '''      • Установите automountServiceAccountToken: false на ServiceAccount
      • Переопределите на уровне Pod если нужно
      • Используйте отдельные SA для каждого приложения''',
    )


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 28: Image from Untrusted Registry               │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   NIST-SI-2                                    │
# │ ⚡ Критичность: 🟡 MEDIUM                                    │
# │ 📝 Описание:   Образы из публичных/недоверенных реестров   │
# └─────────────────────────────────────────────────────────────┘
def check_image_from_untrusted_registry_28(file_path, file):
    """Проверяет использование образов из недоверенных контейнерных реестров."""
    findings = []
    for line_num, line in enumerate(file.splitlines(), start=1):
        m = re.search(r'\bimage:\s*(.+)$', remove_inline_comment(line))
        if not m:
            continue
        image = m.group(1).strip()
        if _is_untrusted_image(image):
            findings.append((line_num, line.strip(), f'образ из недоверенного реестра: {image}'))

    if not findings:
        return None

    _report_finding(
        file_path, 'MEDIUM', 'Image from Untrusted Registry', findings,
        'Используются образы из публичных/недоверенных реестров (docker.io вместо private).',
        'Запуск непроверенного кода. Риск supply-chain атаки. Отсутствие аудита и сканирования уязвимостей.',
        '''        containers:
        - name: app
          image: docker.io/randomuser/suspicious-app:latest''',
        '''        containers:
        - name: app
          image: registry.company.internal/team/app:v1.2.3
        spec:
          imagePullSecrets:
          - name: registry-credentials''',
        '''      • Используйте только доверенные приватные реестры
      • Настройте imagePullSecrets для аутентификации
      • Внедрите сканирование образов на уязвимости''',
    )


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 29: Ingress Without TLS                         │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.1.7                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Ingress без шифрования TLS                  │
# └─────────────────────────────────────────────────────────────┘
def check_ingress_without_tls_29(file_path, file):
    """Проверяет наличие TLS-конфигурации в Kubernetes Ingress ресурсах."""
    findings = []
    for kind, start_line, block_lines in _find_kind_blocks(file):
        if kind.lower() != 'ingress':
            continue
        block = _block_text([remove_inline_comment(l) for l in block_lines])
        if not re.search(r'^\s*tls\s*:\s*$', block, re.MULTILINE | re.IGNORECASE):
            kind_line = block_lines[0] if block_lines else ''
            for i, line in enumerate(block_lines):
                if re.match(r'^\s*kind:\s*Ingress\s*$', line, re.IGNORECASE):
                    findings.append((start_line + i, line.strip(), 'Ingress без секции tls:'))
                    break
            else:
                findings.append((start_line, kind_line.strip(), 'Ingress без секции tls:'))

    if not findings:
        return None

    _report_finding(
        file_path, 'HIGH', 'Ingress Without TLS', findings,
        'Ingress без tls: секции (входящий трафик не шифруется).',
        'Трафик передаётся в открытом виде. Перехват данных в публичных сетях. Утечка чувствительной информации, сессионных токенов.',
        '''        kind: Ingress
        spec:
          rules:
          - host: app.example.com
            http:
              paths: [...]
        # Секция tls: отсутствует!''',
        '''        kind: Ingress
        spec:
          tls:
          - hosts:
            - app.example.com
            secretName: app-tls-secret
          rules:
          - host: app.example.com''',
        '''      • Добавьте tls: секцию во все Ingress ресурсы
      • Используйте cert-manager для автоматических сертификатов
      • Настройте редирект HTTP → HTTPS''',
    )


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 2: AWS SECURITY CHECKS (30–37)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 30: LoadBalancer Internal                       │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-5.4                                  │
# │ ⚡ Критичность: 🟡 MEDIUM                                    │
# │ 📝 Описание:   Публичный LB создан без необходимости       │
# └─────────────────────────────────────────────────────────────┘
def check_loadbalancer_internal_30(file_path, file):
    """Проверяет, что внутренние сервисы не экспонируются публичными LoadBalancer."""
    findings = []
    for kind, start_line, block_lines in _find_kind_blocks(file):
        if kind.lower() != 'service':
            continue
        block = _block_text([remove_inline_comment(l) for l in block_lines])
        if not re.search(r'type\s*:\s*LoadBalancer', block, re.IGNORECASE):
            continue
        is_internal = (
            re.search(r'aws-load-balancer-internal\s*:\s*["\']?true["\']?', block, re.IGNORECASE) or
            re.search(r'azure-load-balancer-internal\s*:\s*["\']?true["\']?', block, re.IGNORECASE) or
            re.search(r'load-balancer-type\s*:\s*["\']?internal["\']?', block, re.IGNORECASE) or
            re.search(r'cloud\.google\.com/load-balancer-type\s*:\s*["\']?internal["\']?', block, re.IGNORECASE)
        )
        if is_internal:
            continue
        for i, line in enumerate(block_lines):
            if re.search(r'type:\s*LoadBalancer', line, re.IGNORECASE):
                findings.append((start_line + i, line.strip(), 'LoadBalancer без aws-load-balancer-internal: true'))
                break

    if not findings:
        return None

    _report_finding(
        file_path, 'MEDIUM', 'LoadBalancer Internal', findings,
        'Публичный облачный LoadBalancer создан без необходимости (нет internal: true).',
        'Внутренний сервис доступен из интернета. Прямая атака на приложение без необходимости обхода периметра.',
        '''        kind: Service
        spec:
          type: LoadBalancer''',
        '''        metadata:
          annotations:
            service.beta.kubernetes.io/aws-load-balancer-internal: "true"
        spec:
          type: LoadBalancer''',
        '''      • Добавьте аннотацию для внутреннего LB
      • Используйте PrivateLink для доступа из других VPC
      • Проверьте все Service типа LoadBalancer''',
    )


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 31: Security Group Overly Permissive            │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-5.3                                  │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Правила безопасности разрешают слишком широкий доступ │
# └─────────────────────────────────────────────────────────────┘
def check_security_group_overly_permissive_31(file_path, file):
    """Проверяет чрезмерно разрешительные правила Security Group."""
    findings = []
    for line_num, line in enumerate(file.splitlines(), start=1):
        clean = remove_inline_comment(line)
        cidrs = []
        m = re.search(r'CidrIp\s*[:=]\s*["\']?([\d.]+/\d+)["\']?', clean, re.IGNORECASE)
        if m:
            cidrs.append(m.group(1))
        m = re.search(r'CidrIpv6\s*[:=]\s*["\']?([0-9a-fA-F:]+/\d+)["\']?', clean, re.IGNORECASE)
        if m:
            cidrs.append(m.group(1))
        # Terraform: cidr_blocks = ["0.0.0.0/0", "10.0.0.0/8"]
        if re.search(r'\bcidr_blocks\s*=', clean, re.IGNORECASE):
            cidrs.extend(re.findall(r'["\']([\d.]+/\d+)["\']', clean))
        if re.search(r'\bipv6_cidr_blocks\s*=', clean, re.IGNORECASE):
            cidrs.extend(re.findall(r'["\']([0-9a-fA-F:]+/\d+)["\']', clean))
        for cidr in cidrs:
            if _is_permissive_cidr(cidr):
                findings.append((line_num, line.strip(), f'слишком широкий CIDR: {cidr}'))

    if not findings:
        return None

    _report_finding(
        file_path, 'HIGH', 'Security Group Overly Permissive', findings,
        'Правила безопасности разрешают доступ из слишком широкой сети (CIDR /16 или шире).',
        'Чрезмерный доступ к ресурсу. Увеличение поверхности атаки. Сложность контроля и аудита входящих соединений.',
        '''        SecurityGroupIngress:
          CidrIp: 10.0.0.0/16
          # Или хуже: 0.0.0.0/0''',
        '''        SecurityGroupIngress:
          CidrIp: 10.0.1.0/24
          # SourceSecurityGroupId: sg-frontend''',
        '''      • Ограничьте CIDR до конкретных подсетей
      • Используйте SourceSecurityGroupId вместо CIDR
      • Применяйте принцип наименьших привилегий''',
    )


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 32: IAM Policy Wildcard Service                 │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-1.17                                 │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   IAM политика использует wildcard (*) в действиях │
# └─────────────────────────────────────────────────────────────┘
def check_iam_policy_wildcard_service_32(file_path, file):
    """Проверяет использование чрезмерно широких разрешений в IAM политиках."""
    findings = []
    for line_num, line in enumerate(file.splitlines(), start=1):
        clean = remove_inline_comment(line)
        if re.search(r'\bAction:\s*\*', clean):
            findings.append((line_num, line.strip(), 'Action: *'))
            continue
        m = re.search(r'-\s*["\']([a-z0-9-]+:\*)["\']', clean, re.IGNORECASE)
        if m:
            findings.append((line_num, line.strip(), f'wildcard action: {m.group(1)}'))
            continue
        m = re.search(r'["\']([a-z0-9-]+:\*)["\']', clean, re.IGNORECASE)
        if m:
            findings.append((line_num, line.strip(), f'wildcard action: {m.group(1)}'))

    if not findings:
        return None

    _report_finding(
        file_path, 'HIGH', 'IAM Policy Wildcard Service', findings,
        'IAM политика использует wildcard (*) в действиях (например s3:* или ec2:*).',
        'Избыточные права. Компрометация роли = полный доступ к сервису. Возможность удаления данных или создания дорогих ресурсов.',
        '''        Statement:
        - Effect: Allow
          Action:
          - "s3:*"
          Resource: "*"''',
        '''        Statement:
        - Effect: Allow
          Action:
          - "s3:GetObject"
          - "s3:PutObject"
          Resource: "arn:aws:s3:::my-bucket/prefix/*"''',
        '''      • Замените wildcard на конкретные действия
      • Ограничьте Resource до конкретных ARN
      • Используйте IAM Access Analyzer для аудита''',
    )


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 33: KMS Key Rotation Disabled                   │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-2.1.4                                │
# │ ⚡ Критичность: 🟡 MEDIUM                                    │
# │ 📝 Описание:   Отключена автоматическая ротация ключей KMS │
# └─────────────────────────────────────────────────────────────┘
def check_kms_key_rotation_disabled_33(file_path, file):
    """Проверяет включение автоматической ротации для KMS ключей."""
    findings = []
    for line_num, line in enumerate(file.splitlines(), start=1):
        clean = remove_inline_comment(line)
        val = _extract_kv_value(clean, 'EnableKeyRotation')
        if val is None:
            val = _extract_kv_value(clean, 'enable_key_rotation')
        if val is not None and normalize_boolean_value(val) is False:
            findings.append((line_num, line.strip(), 'EnableKeyRotation: false'))

    if not findings:
        return None

    _report_finding(
        file_path, 'MEDIUM', 'KMS Key Rotation Disabled', findings,
        'Отключена автоматическая ротация ключей KMS (enableKeyRotation: false).',
        'Длительная жизнь ключа = больший ущерб при утечке. Несоответствие требованиям безопасности (PCI-DSS, HIPAA, etc).',
        '''        Type: AWS::KMS::Key
        Properties:
          EnableKeyRotation: false''',
        '''        Type: AWS::KMS::Key
        Properties:
          EnableKeyRotation: true''',
        '''      • Включите EnableKeyRotation: true для всех ключей
      • Настройте мониторинг использования ключей
      • Регулярно аудируйте KMS ключи''',
    )


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 34: CloudTrail Logging Disabled                 │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-3.1                                  │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Логирование действий в AWS отключено        │
# └─────────────────────────────────────────────────────────────┘
def check_cloudtrail_logging_disabled_34(file_path, file):
    """Проверяет включение CloudTrail для аудита действий в аккаунте AWS."""
    findings = []
    for line_num, line in enumerate(file.splitlines(), start=1):
        clean = remove_inline_comment(line)
        val = _extract_kv_value(clean, 'IsMultiRegionTrail')
        if val is not None and normalize_boolean_value(val) is False:
            findings.append((line_num, line.strip(), 'IsMultiRegionTrail: false'))

    if not findings:
        return None

    _report_finding(
        file_path, 'HIGH', 'CloudTrail Logging Disabled', findings,
        'Логирование действий в AWS отключено или ограничено одним регионом (IsMultiRegionTrail: false).',
        'Невозможно отследить действия злоумышленника в других регионах. Отсутствие аудита = нарушение требований безопасности.',
        '''        Type: AWS::CloudTrail::Trail
        Properties:
          IsMultiRegionTrail: false''',
        '''        Type: AWS::CloudTrail::Trail
        Properties:
          IsMultiRegionTrail: true
          EnableLogFileValidation: true''',
        '''      • Включите multi-region trail для всех аккаунтов
      • Включите валидацию логов
      • Шифруйте логи через KMS''',
    )


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 35: VPC Flow Logs Disabled                      │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-3.4                                  │
# │ ⚡ Критичность: 🟡 MEDIUM                                    │
# │ 📝 Описание:   Не включены Flow Logs для мониторинга VPC   │
# └─────────────────────────────────────────────────────────────┘
def check_vpc_flow_logs_disabled_35(file_path, file):
    """Проверяет включение VPC Flow Logs для аудита сетевого трафика (across весь набор файлов)."""
    batch = _CURRENT_BATCH_CONTENTS or {file_path: file}
    has_flow_log = any(
        re.search(r'AWS::EC2::FlowLog', c, re.IGNORECASE) or re.search(r'resource\s+"aws_flow_log"', c, re.IGNORECASE)
        for c in batch.values()
    )
    findings = []
    if not has_flow_log:
        for line_num, line in enumerate(file.splitlines(), start=1):
            clean = remove_inline_comment(line)
            if re.search(r'AWS::EC2::VPC\b', clean, re.IGNORECASE) or re.search(r'resource\s+"aws_vpc"', clean, re.IGNORECASE):
                findings.append((line_num, line.strip(), 'VPC без AWS::EC2::FlowLog/aws_flow_log в наборе файлов'))

    if not findings:
        return None

    _report_finding(
        file_path, 'MEDIUM', 'VPC Flow Logs Disabled', findings,
        'Не включены Flow Logs для мониторинга сетевого трафика VPC.',
        'Слепая зона в мониторинге сети. Невозможно выявить сканирование, эксфильтрацию данных или C2-трафик.',
        '''        Type: AWS::EC2::VPC
        Properties:
          CidrBlock: 10.0.0.0/16
        # Нет связанного ресурса AWS::EC2::FlowLog''',
        '''        Type: AWS::EC2::FlowLog
        Properties:
          ResourceType: VPC
          TrafficType: ALL''',
        '''      • Включите Flow Logs для всех VPC
      • Настройте отправку в CloudWatch Logs или S3
      • Создайте алерты на аномальный трафик''',
    )


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 36: RDS Publicly Accessible                     │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-2.3.1                                │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   База данных RDS доступна из публичной сети  │
# └─────────────────────────────────────────────────────────────┘
def check_rds_publicly_accessible_36(file_path, file):
    """Проверяет, что RDS инстансы не доступны из публичной сети."""
    findings = []
    for line_num, line in enumerate(file.splitlines(), start=1):
        clean = remove_inline_comment(line)
        val = _extract_kv_value(clean, 'PubliclyAccessible')
        if val is None:
            val = _extract_kv_value(clean, 'publicly_accessible')
        if val is not None and normalize_boolean_value(val) is True:
            findings.append((line_num, line.strip(), 'PubliclyAccessible: true'))

    if not findings:
        return None

    _report_finding(
        file_path, 'CRITICAL', 'RDS Publicly Accessible', findings,
        'База данных RDS доступна из публичной сети (PubliclyAccessible: true).',
        'Прямой доступ к базе данных из интернета. Риск взлома, утечки данных, атак типа SQL injection и ransomware.',
        '''        Type: AWS::RDS::DBInstance
        Properties:
          PubliclyAccessible: true''',
        '''        Type: AWS::RDS::DBInstance
        Properties:
          PubliclyAccessible: false''',
        '''      • Установите PubliclyAccessible: false
      • Разместите БД в приватных подсетях
      • Используйте bastion host или Systems Manager для доступа''',
    )


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 37: RDS Encryption Disabled                     │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-2.3.2                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Данные на диске RDS не зашифрованы          │
# └─────────────────────────────────────────────────────────────┘
def check_rds_encryption_disabled_37(file_path, file):
    """Проверяет шифрование данных на диске для RDS инстансов."""
    findings = []
    for line_num, line in enumerate(file.splitlines(), start=1):
        clean = remove_inline_comment(line)
        val = _extract_kv_value(clean, 'StorageEncrypted')
        if val is None:
            val = _extract_kv_value(clean, 'storage_encrypted')
        if val is not None and normalize_boolean_value(val) is False:
            findings.append((line_num, line.strip(), 'StorageEncrypted: false'))

    if not findings:
        return None

    _report_finding(
        file_path, 'HIGH', 'RDS Encryption Disabled', findings,
        'Данные на диске RDS не зашифрованы (StorageEncrypted: false).',
        'Раскрытие данных при доступе к хранилищу (data at rest). Нарушение требований комплаенса (GDPR, PCI-DSS).',
        '''        Type: AWS::RDS::DBInstance
        Properties:
          StorageEncrypted: false''',
        '''        Type: AWS::RDS::DBInstance
        Properties:
          StorageEncrypted: true
          KmsKeyId: !Ref DatabaseKMSKey''',
        '''      • Включите шифрование для всех RDS инстансов
      • Используйте KMS ключи для управления
      • Зашифруйте существующие БД через snapshot copy''',
    )


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 3: DATABASE SECURITY CHECKS (38–40)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 38: Redis Without Password                      │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-Database-4.1                             │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Redis работает без аутентификации           │
# └─────────────────────────────────────────────────────────────┘
def check_redis_without_password_38(file_path, file):
    """Проверяет наличие аутентификации в конфигурации Redis."""
    findings = []

    for doc in _split_yaml_documents(file):
        pos = file.find(doc)
        doc_start_line = file[:pos].count('\n') + 1 if pos != -1 else 1

        has_requirepass = False
        bind_all = False
        bind_line = None
        bind_num = None

        for i, line in enumerate(doc.splitlines()):
            line_num = doc_start_line + i
            clean = remove_inline_comment(line).strip()
            if re.match(r'requirepass\s*$', clean, re.IGNORECASE):
                findings.append((line_num, line.strip(), 'requirepass не установлен'))
            elif re.match(r'requirepass\s+["\']?["\']?\s*$', clean, re.IGNORECASE):
                findings.append((line_num, line.strip(), 'requirepass пустой'))
            elif re.match(r'requirepass\s+\S+', clean, re.IGNORECASE):
                has_requirepass = True
            if re.search(r'\bbind\s+.*0\.0\.0\.0', clean):
                bind_all = True
                bind_line = line.strip()
                bind_num = line_num

        if bind_all and not has_requirepass and bind_num:
            findings.append((bind_num, bind_line, 'bind 0.0.0.0 без requirepass'))

    if not findings:
        return None

    _report_finding(
        file_path, 'CRITICAL', 'Redis Without Password', findings,
        'Redis работает без аутентификации (requirepass не установлен).',
        'Неавторизованный доступ к кэшу/данным. Возможность выполнения LUA-скриптов, очистки данных, использования Redis для атак на другие системы.',
        '''        port 6379
        bind 0.0.0.0
        # requirepass не установлен!''',
        '''        port 6379
        bind 127.0.0.1
        requirepass ${REDIS_PASSWORD}''',
        '''      • Установите requirepass с сложным паролем
      • Ограничьте bind до приватных интерфейсов
      • Отключите опасные команды через rename-command''',
    )


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 39: MongoDB Without Auth                        │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-Database-4.2                             │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   MongoDB работает без включения авторизации  │
# └─────────────────────────────────────────────────────────────┘
def check_mongodb_without_auth_39(file_path, file):
    """Проверяет включение авторизации в конфигурации MongoDB."""
    findings = []
    for line_num, line in enumerate(file.splitlines(), start=1):
        clean = remove_inline_comment(line)
        val = _extract_kv_value(clean, 'authorization')
        if val is not None and val.strip('"\'').lower() == 'disabled':
            findings.append((line_num, line.strip(), 'authorization: disabled'))

    if not findings:
        return None

    _report_finding(
        file_path, 'CRITICAL', 'MongoDB Without Auth', findings,
        'MongoDB работает без включения авторизации (security.authorization: disabled).',
        'Любой клиент может получить полный доступ к БД. Утечка данных, модификация, удаление, ransomware-атаки.',
        '''        security:
          authorization: disabled''',
        '''        security:
          authorization: enabled''',
        '''      • Включите authorization: enabled
      • Создайте пользователей с минимальными правами
      • Ограничьте bindIp до приватных адресов''',
    )


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 40: Elasticsearch Public Access                 │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-2.4.1                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Кластер Elasticsearch доступен публично     │
# └─────────────────────────────────────────────────────────────┘
def check_elasticsearch_public_access_40(file_path, file):
    """Проверяет политики доступа к Elasticsearch доменам."""
    if not re.search(r'AWS::Elasticsearch|AWS::OpenSearch|"es:|es:\*', file, re.IGNORECASE):
        return None
    findings = []
    for line_num, line in enumerate(file.splitlines(), start=1):
        clean = remove_inline_comment(line)
        val = _extract_kv_value(clean, 'Principal')
        if val == '*':
            findings.append((line_num, line.strip(), 'Principal: "*"'))

    if not findings:
        return None

    _report_finding(
        file_path, 'HIGH', 'Elasticsearch Public Access', findings,
        'Кластер Elasticsearch доступен публично (accessPolicies позволяют * principal).',
        'Публичный доступ к поисковому кластеру. Утечка логов, содержащих персональные данные, токены, ключи.',
        '''        Statement:
        - Effect: Allow
          Principal: "*"
          Action: "es:*"''',
        '''        Statement:
        - Effect: Allow
          Principal:
            AWS: "arn:aws:iam::account:role/app-role"
          Action:
          - "es:ESHttpGet"''',
        '''      • Ограничьте Principal до конкретных IAM ролей
      • Используйте VPC endpoint для доступа
      • Включите IAM auth или Cognito''',
    )


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 4: SERVERLESS & CLOUD FUNCTIONS (41–42)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 41: Lambda Function Public Trigger              │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-2.5.1                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Lambda вызывается публично без авторизации  │
# └─────────────────────────────────────────────────────────────┘
def check_lambda_function_public_trigger_41(file_path, file):
    """Проверяет политики разрешений на вызов Lambda-функций."""
    findings = []
    lines = file.splitlines()
    for line_num, line in enumerate(lines, start=1):
        clean = remove_inline_comment(line)
        val = _extract_kv_value(clean, 'Principal')
        if val != '*':
            continue
        start = max(0, line_num - 15)
        end = min(len(lines), line_num + 15)
        window = '\n'.join(lines[start:end])
        if re.search(r'AWS::Lambda|lambda:InvokeFunction', window, re.IGNORECASE):
            findings.append((line_num, line.strip(), 'Principal: "*" — публичный вызов Lambda'))

    if not findings:
        return None

    _report_finding(
        file_path, 'HIGH', 'Lambda Function Public Trigger', findings,
        'Lambda-функция вызывается публично без авторизации (Principal: *).',
        'Неавторизованный вызов функции. Риск исчерпания квот, выполнения вредоносных операций, утечки данных.',
        '''        Type: AWS::Lambda::Permission
        Properties:
          Principal: "*"''',
        '''        Type: AWS::Lambda::Permission
        Properties:
          Principal: apigateway.amazonaws.com
          SourceArn: !Sub "arn:aws:execute-api:..."''',
        '''      • Ограничьте Principal до конкретного сервиса
      • Добавьте SourceArn для ограничения источника
      • Включите авторизацию на уровне API Gateway''',
    )


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 42: Cloud Function HTTP Without Auth            │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-GCP-6.6.1                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   HTTP Cloud Function без аутентификации      │
# └─────────────────────────────────────────────────────────────┘
def check_cloud_function_http_without_auth_42(file_path, file):
    """Проверяет политики доступа к HTTP-триггерам Cloud Functions в GCP."""
    findings = []
    lines = [remove_inline_comment(l) for l in file.splitlines()]
    raw_lines = file.splitlines()
    for line_num, line in enumerate(lines, start=1):
        if not re.search(r'allUsers', line):
            continue
        start = max(0, line_num - 10)
        end = min(len(lines), line_num + 10)
        window = '\n'.join(lines[start:end])
        if re.search(r'cloudfunctions\.invoker|roles/cloudfunctions\.invoker', window, re.IGNORECASE):
            findings.append((line_num, raw_lines[line_num - 1].strip(), 'allUsers + cloudfunctions.invoker'))

    if not findings:
        return None

    _report_finding(
        file_path, 'HIGH', 'Cloud Function HTTP Without Auth', findings,
        'HTTP Cloud Function доступна без аутентификации (allUsers имеет роль cloudfunctions.invoker).',
        'Функция доступна любому пользователю интернета. Риск атак, утечки данных, финансовых потерь.',
        '''        members:
        - allUsers
        role: roles/cloudfunctions.invoker''',
        '''        members:
        - serviceAccount:backend-sa@project.iam.gserviceaccount.com
        role: roles/cloudfunctions.invoker''',
        '''      • Удалите allUsers из IAM policy
      • Добавьте только доверенные service accounts
      • Используйте IAM авторизацию для всех функций''',
    )


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 5: AZURE SECURITY CHECKS (43–44)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 43: Azure NSG Any-Any Rule                      │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-Azure-7.1                                │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Правило NSG разрешает весь трафик отовсюду  │
# └─────────────────────────────────────────────────────────────┘
def check_azure_nsg_any_any_rule_43(file_path, file):
    """Проверяет чрезмерно разрешительные правила в Azure Network Security Groups."""
    findings = []
    lines = file.splitlines()
    for line_num, line in enumerate(lines, start=1):
        clean = remove_inline_comment(line)
        src = _extract_kv_value(clean, 'sourceAddressPrefix') or _extract_kv_value(clean, 'source_address_prefix')
        if src != '*':
            continue
        start = max(0, line_num - 15)
        end = min(len(lines), line_num + 15)
        window = '\n'.join(lines[start:end])
        if re.search(r'["\']?destinationPortRange["\']?\s*[:=]\s*["\']?\*["\']?', window, re.IGNORECASE) or \
           re.search(r'["\']?destination_port_range["\']?\s*[:=]\s*["\']?\*["\']?', window, re.IGNORECASE):
            findings.append((line_num, line.strip(), 'sourceAddressPrefix: * и destinationPortRange: *'))

    if not findings:
        return None

    _report_finding(
        file_path, 'CRITICAL', 'Azure NSG Any-Any Rule', findings,
        'Правило NSG разрешает весь трафик отовсюду (source: *, dest: *, port: *).',
        'Полное отсутствие контроля сетевого трафика. Любой хост может подключиться к любому сервису.',
        '''        sourceAddressPrefix: "*"
        destinationPortRange: "*"''',
        '''        sourceAddressPrefix: "10.0.0.0/8"
        destinationPortRange: "443"''',
        '''      • Удалите правила Any-Any
      • Разрешайте только необходимые порты и IP
      • Используйте принцип default deny''',
    )


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 44: Azure SQL Firewall Open                     │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-Azure-9.4                                │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Брандмауэр Azure SQL разрешает подключения отовсюду │
# └─────────────────────────────────────────────────────────────┘
def check_azure_sql_firewall_open_44(file_path, file):
    """Проверяет правила брандмауэра Azure SQL Database."""
    findings = []
    lines = file.splitlines()
    for line_num, line in enumerate(lines, start=1):
        clean = remove_inline_comment(line)
        start_ip = _extract_kv_value(clean, 'startIpAddress') or _extract_kv_value(clean, 'start_ip_address')
        if start_ip != '0.0.0.0':
            continue
        start = max(0, line_num - 5)
        end = min(len(lines), line_num + 5)
        window = '\n'.join(lines[start:end])
        if re.search(r'["\']?endIpAddress["\']?\s*[:=]\s*["\']?255\.255\.255\.255["\']?', window, re.IGNORECASE) or \
           re.search(r'["\']?end_ip_address["\']?\s*[:=]\s*["\']?255\.255\.255\.255["\']?', window, re.IGNORECASE):
            findings.append((line_num, line.strip(), 'firewall 0.0.0.0 — 255.255.255.255'))

    if not findings:
        return None

    _report_finding(
        file_path, 'CRITICAL', 'Azure SQL Firewall Open', findings,
        'Брандмауэр Azure SQL разрешает подключения отовсюду (0.0.0.0 - 255.255.255.255).',
        'База данных доступна из любой точки мира. Высокий риск взлома и утечки данных.',
        '''        startIpAddress: "0.0.0.0"
        endIpAddress: "255.255.255.255"''',
        '''        startIpAddress: "10.0.1.0"
        endIpAddress: "10.0.1.255"''',
        '''      • Ограничьте firewall rules до конкретных IP
      • Используйте Private Endpoint для доступа
      • Включите Advanced Threat Protection''',
    )


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 6: CI/CD SECURITY CHECKS (45–46)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 45: CI/CD Pipeline Without Approval             │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   NIST-AC-3                                    │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Деплой в production без ручного подтверждения │
# └─────────────────────────────────────────────────────────────┘
def check_ci_cd_pipeline_without_approval_45(file_path, file):
    """Проверяет наличие ручного подтверждения для деплоя в production."""
    NON_JOB_KEYS = {'variables', 'stages', 'default', 'workflow', 'include',
                     'image', 'before_script', 'after_script', 'cache', 'on',
                     'name', 'permissions', 'env', 'concurrency', 'jobs'}
    findings = []
    for job_name, start_line, block_lines in _find_job_blocks(file):
        if job_name.lower() in NON_JOB_KEYS:
            continue
        block = _block_text([remove_inline_comment(l) for l in block_lines])
        is_production = bool(
            re.search(r'prod', job_name, re.IGNORECASE) or
            re.search(r'\bname\s*:\s*["\']?production["\']?', block, re.IGNORECASE) or
            re.search(r'^\s*-\s*["\']?(main|master|production)["\']?\s*$', block, re.IGNORECASE | re.MULTILINE) or
            re.search(r'branches\s*:.*\b(main|master|production)\b', block, re.IGNORECASE)
        )
        if not is_production:
            continue
        if re.search(r'\bwhen\s*:\s*["\']?manual["\']?', block, re.IGNORECASE) or \
           re.search(r'\bapproval', block, re.IGNORECASE) or \
           re.search(r'environment\s*:\s*\n\s*name\s*:\s*\S+\s*\n(\s*url\s*:.*\n)?\s*(reviewers|required_reviewers)', block, re.IGNORECASE):
            continue
        findings.append((start_line, block_lines[0].strip(), f"job '{job_name}' без when: manual / approval"))

    if not findings:
        return None

    _report_finding(
        file_path, 'HIGH', 'CI/CD Pipeline Without Approval', findings,
        'Развёртывание в production происходит автоматически (нет when: manual или approval).',
        'Отсутствие человеческого контроля перед продакшеном. Риск инцидентов, уязвимостей, несанкционированных изменений.',
        '''        deploy-production:
          stage: deploy
          script:
            - ./deploy.sh production''',
        '''        deploy-production:
          stage: deploy
          when: manual
          script:
            - ./deploy.sh production''',
        '''      • Добавьте when: manual для production деплоя
      • Настройте required approvals в merge requests
      • Защитите main ветку от прямых пушей''',
    )


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 46: GitHub Actions Without Pin                  │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-GitHub-5.1                               │
# │ ⚡ Критичность: 🟡 MEDIUM                                    │
# │ 📝 Описание:   Actions используются по тегу, а не по хешу  │
# └─────────────────────────────────────────────────────────────┘
def check_github_actions_without_pin_46(file_path, file):
    """Проверяет фиксацию версий GitHub Actions по полному хешу коммита."""
    findings = []
    for line_num, line in enumerate(file.splitlines(), start=1):
        m = re.search(r'uses:\s*(\S+)', remove_inline_comment(line))
        if not m:
            continue
        ref = m.group(1).strip('"\'')
        if ref.startswith('./') or ref.startswith('docker://'):
            continue
        if not _is_pinned_action(ref):
            findings.append((line_num, line.strip(), f'action не закреплён SHA: {ref}'))

    if not findings:
        return None

    _report_finding(
        file_path, 'MEDIUM', 'GitHub Actions Without Pin', findings,
        'Actions используются по тегу/ветке, а не по хешу (uses: actions/checkout@v2 вместо SHA).',
        'Supply-chain атака через компрометацию action. Непредсказуемое поведение пайплайна при обновлении тега.',
        '''        - uses: actions/checkout@v2
        - uses: some/user-action@main''',
        '''        - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11''',
        '''      • Используйте полные SHA хеши для всех actions
      • Настройте Dependabot для обновления зависимостей
      • Аудируйте используемые actions регулярно''',
    )


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 7: CONTAINER & KUBERNETES CHECKS (47–48)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 47: Docker Socket Mounted                       │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-Docker-5.31                              │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   В контейнер примонтирован Docker socket     │
# └─────────────────────────────────────────────────────────────┘
def check_docker_socket_mounted_47(file_path, file):
    """Проверяет монтирование Docker socket в контейнеры."""
    findings = []
    for line_num, line in enumerate(file.splitlines(), start=1):
        clean = remove_inline_comment(line)
        if re.search(r'(unix://)?/(var/)?run/docker\.sock', clean, re.IGNORECASE):
            findings.append((line_num, line.strip(), 'монтирование docker.sock'))

    if not findings:
        return None

    _report_finding(
        file_path, 'CRITICAL', 'Docker Socket Mounted', findings,
        'В контейнер примонтирован Docker socket (/var/run/docker.sock).',
        'Полный контроль над хостом через Docker API. Container escape, запуск майнеров, кража данных.',
        '''        volumes:
          - /var/run/docker.sock:/var/run/docker.sock''',
        '''        services:
          app:
            image: myapp
            # volumes: без docker.sock''',
        '''      • Удалите монтирование docker.sock
      • Используйте Kaniko/Buildah для сборки в K8s
      • Вынесите сборку в изолированный CI-раннер''',
    )


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 48: Kubernetes Pod Security Policy              │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.2.13                               │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Не применяются политики безопасности подов  │
# └─────────────────────────────────────────────────────────────┘
def check_kubernetes_pod_security_policy_48(file_path, file):
    """Проверяет применение политик безопасности подов (PSP/PodSecurity Admission)."""
    findings = []

    for kind, start_line, block_lines in _find_kind_blocks(file):
        if kind.lower() == 'namespace':
            block = _block_text([remove_inline_comment(l) for l in block_lines])
            enforce_m = re.search(r'pod-security\.kubernetes\.io/enforce\s*:\s*["\']?(\w+)["\']?', block, re.IGNORECASE)
            if not enforce_m:
                for i, line in enumerate(block_lines):
                    clean = remove_inline_comment(line)
                    if re.match(r'^\s*["\']?kind["\']?\s*[:=]\s*["\']?Namespace["\']?\s*,?\s*$', clean, re.IGNORECASE):
                        findings.append((start_line + i, line.strip(), 'Namespace без pod-security.kubernetes.io/enforce'))
                        break
            elif enforce_m.group(1).lower() == 'privileged':
                for i, line in enumerate(block_lines):
                    if 'pod-security.kubernetes.io/enforce' in remove_inline_comment(line):
                        findings.append((start_line + i, line.strip(), "pod-security.kubernetes.io/enforce: privileged — самый небезопасный уровень"))
                        break

    for line_num, line in enumerate(file.splitlines(), start=1):
        normalized = _normalize_line(line).lower()
        if 'privileged:true' in normalized:
            findings.append((line_num, line.strip(), 'privileged: true без restricted Pod Security'))

    if not findings:
        return None

    _report_finding(
        file_path, 'HIGH', 'Kubernetes Pod Security Policy', findings,
        'Не применяются политики безопасности подов (отсутствие PSP или PodSecurityStandard).',
        'Отсутствие контроля за настройками безопасности подов. Риск запуска привилегированных контейнеров, escape на хост.',
        '''        kind: Namespace
        metadata:
          name: production
        # Нет pod-security.kubernetes.io/enforce''',
        '''        kind: Namespace
        metadata:
          labels:
            pod-security.kubernetes.io/enforce: restricted''',
        '''      • Включите Pod Security Admission на namespace
      • Используйте OPA/Gatekeeper для кастомных политик
      • Аудируйте все поды на нарушения security context''',
    )


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 8: INFRASTRUCTURE AS CODE CHECKS (49–50)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 49: Helm Chart Without Values Validation        │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   NIST-CM-6                                    │
# │ ⚡ Критичность: 🟡 MEDIUM                                    │
# │ 📝 Описание:   Отсутствует валидация значений Helm chart   │
# └─────────────────────────────────────────────────────────────┘
def check_helm_chart_without_values_validation_49(file_path, file):
    """Проверяет наличие values.schema.json для валидации параметров Helm chart."""
    findings = []
    path = Path(file_path)
    batch_names = {p.name for p in _CURRENT_BATCH_PATHS}
    _SCHEMA_RE = re.compile(r'(^|[_\-.])values[_.]?schema\.json$', re.IGNORECASE)
    has_schema_file = any(_SCHEMA_RE.search(n) or n.lower() == 'schema.json' for n in batch_names)

    is_values_yaml = re.search(r'(^|[_\-.])values\.ya?ml$', path.name, re.IGNORECASE)
    is_values_schema = _SCHEMA_RE.search(path.name)

    if is_values_yaml and not has_schema_file:
        lines = file.splitlines()
        first_line = lines[0] if lines else ''
        findings.append((1, first_line.strip() or '(пустой файл)', 'values.yaml без values.schema.json в наборе файлов'))

    if is_values_schema and '$schema' not in file:
        lines = file.splitlines()
        if lines:
            findings.append((1, lines[0].strip(), 'values.schema.json без $schema'))
        else:
            findings.append((1, '(пустой файл)', 'values.schema.json без $schema'))

    if not findings:
        return None

    _report_finding(
        file_path, 'MEDIUM', 'Helm Chart Without Values Validation', findings,
        'Отсутствует валидация значений Helm chart (нет values.schema.json).',
        'Ошибки конфигурации, уязвимые настройки, сложность аудита и контроля за параметрами чарта.',
        '''        # values.yaml без schema validation
        replicaCount: 3
        image:
          tag: latest''',
        '''        {
          "$schema": "http://json-schema.org/draft-07/schema#",
          "properties": { ... }
        }''',
        '''      • Добавьте values.schema.json в chart
      • Валидируйте критические параметры безопасности
      • Блокируйте опасные значения через schema''',
    )


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 50: Terraform State Remote Without Lock         │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-TF-2.1                                   │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Удалённый state Terraform без блокировки    │
# └─────────────────────────────────────────────────────────────┘
def check_terraform_state_remote_without_lock_50(file_path, file):
    """Проверяет включение state locking для удалённого бэкенда Terraform."""
    findings = []
    for start_line, block in _find_terraform_s3_backends(file):
        block_text = '\n'.join(remove_inline_comment(l) for l in block)
        has_lock = re.search(r'dynamodb_table\s*=', block_text, re.IGNORECASE) or \
            re.search(r'use_lockfile\s*=\s*true', block_text, re.IGNORECASE)
        if not has_lock:
            findings.append((start_line, block[0].strip(), 'S3 backend без dynamodb_table/use_lockfile (state locking)'))
        if not re.search(r'\bencrypt\s*=\s*true', block_text, re.IGNORECASE):
            findings.append((start_line, block[0].strip(), 'S3 backend без encrypt = true'))

    if not findings:
        return None

    _report_finding(
        file_path, 'HIGH', 'Terraform State Remote Without Lock', findings,
        'Удалённый state Terraform без блокировки (S3 backend без dynamodb_table).',
        'Повреждение state при параллельном запуске terraform apply. Потеря управления ресурсами, дублирование, удаление.',
        '''        terraform {
          backend "s3" {
            bucket = "my-terraform-state"
            key    = "prod/terraform.tfstate"
            region = "us-east-1"
          }
        }''',
        '''        terraform {
          backend "s3" {
            bucket         = "my-terraform-state"
            key            = "prod/terraform.tfstate"
            region         = "us-east-1"
            dynamodb_table = "terraform-locks"
          }
        }''',
        '''      • Добавьте dynamodb_table для state locking
      • Включите шифрование state файла
      • Настройте версионирование S3 bucket''',
    )


def all_medium_check(files):
    """
    ╔════════════════════════════════════════════════════════════════╗
    ║  🔐 ЗАПУСК ВСЕХ ПРОВЕРОК MEDIUM LEVEL (26–50)                 ║
    ╚════════════════════════════════════════════════════════════════╝

    Принимает один путь (str/Path) или список путей.
    Файлы читаются один раз; check 26 и 49 учитывают весь набор файлов.
    """
    global _CURRENT_BATCH_PATHS, _CURRENT_BATCH_CONTENTS
    paths, contents = _read_batch(files)
    _CURRENT_BATCH_PATHS = paths
    _CURRENT_BATCH_CONTENTS = contents

    has_network_policy = any(
        re.search(r'^\s*kind:\s*NetworkPolicy\s*$', content, re.MULTILINE | re.IGNORECASE)
        for content in contents.values()
    )
    if not has_network_policy:
        for path, content in contents.items():
            for line_num, line in enumerate(content.splitlines(), start=1):
                m = re.match(
                    r'^\s*kind:\s*["\']?(Pod|Deployment|StatefulSet|DaemonSet)["\']?\s*$',
                    line, re.IGNORECASE,
                )
                if m:
                    check_network_policy_missing_26(path, content)
                    break
            else:
                continue
            break

    per_file_checks = [
        check_service_account_token_mount_27,
        check_image_from_untrusted_registry_28,
        check_ingress_without_tls_29,
        check_loadbalancer_internal_30,
        check_security_group_overly_permissive_31,
        check_iam_policy_wildcard_service_32,
        check_kms_key_rotation_disabled_33,
        check_cloudtrail_logging_disabled_34,
        check_vpc_flow_logs_disabled_35,
        check_rds_publicly_accessible_36,
        check_rds_encryption_disabled_37,
        check_redis_without_password_38,
        check_mongodb_without_auth_39,
        check_elasticsearch_public_access_40,
        check_lambda_function_public_trigger_41,
        check_cloud_function_http_without_auth_42,
        check_azure_nsg_any_any_rule_43,
        check_azure_sql_firewall_open_44,
        check_ci_cd_pipeline_without_approval_45,
        check_github_actions_without_pin_46,
        check_docker_socket_mounted_47,
        check_kubernetes_pod_security_policy_48,
        check_helm_chart_without_values_validation_49,
        check_terraform_state_remote_without_lock_50,
    ]

    for path, content in contents.items():
        for check_fn in per_file_checks:
            check_fn(path, content)

    _CURRENT_BATCH_PATHS = []
    _CURRENT_BATCH_CONTENTS = {}
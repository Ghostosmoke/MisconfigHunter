# 📋 Каталог проверок

Все данные на этой странице извлечены напрямую из исходного кода (заголовки находок, severity, и — для Hard-уровня — стандарты CIS/NIST/SLSA, зафиксированные в комментариях над каждой проверкой), а не придуманы задним числом.

- [Easy (01–25)](#easy-01-25) — одиночный файл, прямые паттерны
- [Medium (26–50)](#medium-26-50) — одиночный файл или простой batch
- [Hard (51-75)](#hard) — кросс-файловый анализ (2 из 25 реализованы полностью)
- [Подробные примеры](#подробные-примеры-по-категориям)

---

## Easy (01-25)

Файл: `Easy_Check.py`. Точка входа: `all_easy_check(file_path)` — читает и проверяет **один** файл всеми 25 функциями.

| № | Название | Severity | Категория |
|---|---|---|---|
| 01 | Privileged Container | CRITICAL | Kubernetes |
| 02 | Run as Root | HIGH | Kubernetes |
| 03 | Latest Tag | MEDIUM | Kubernetes / Containers |
| 04 | Host Network | HIGH | Kubernetes |
| 05 | Host PID | HIGH | Kubernetes |
| 06 | Host IPC | HIGH | Kubernetes |
| 07 | Allow Privilege Escalation | HIGH | Kubernetes |
| 08 | Docker Exposed Ports | HIGH | Docker |
| 09 | Docker Privileged | CRITICAL | Docker |
| 10 | Secrets in Env Vars | HIGH | Kubernetes / Docker |
| 11 | Missing Resource Limits | MEDIUM | Kubernetes |
| 12 | Missing Health Probes | MEDIUM | Kubernetes |
| 13 | Insecure Capabilities Add | CRITICAL | Kubernetes / Docker |
| 14 | Docker Latest Tag | MEDIUM | Docker Compose |
| 15 | S3 Public Read | CRITICAL | AWS |
| 16 | S3 Public Write | CRITICAL | AWS |
| 17 | Unencrypted EBS | HIGH | AWS |
| 18 | RDP Open to Internet | CRITICAL | AWS / Network |
| 19 | SSH Open to Internet | CRITICAL | AWS / Network |
| 20 | Cloud Storage Public (GCP) | CRITICAL | GCP |
| 21 | Azure Storage Public | CRITICAL | Azure |
| 22 | Kubernetes Dashboard Exposed | CRITICAL | Kubernetes |
| 23 | Etcd Client Cert Auth | CRITICAL | Kubernetes |
| 24 | Anonymous Auth Enabled | CRITICAL | Kubernetes |
| 25 | CI/CD Plain Text Secrets | CRITICAL | CI/CD |

**Важная деталь реализации:** проверки 03 и 14 нарочно не пересекаются — 03 срабатывает на всём, кроме docker-compose (наличие `services:` на верхнем уровне), 14 — только на docker-compose. Это защита от дублирования одной и той же находки под двумя разными номерами.

---

## Medium (26-50)

Файл: `Medium_Check.py`. Точка входа: `all_medium_check(files)` — принимает список файлов или один путь.

| № | Название | Severity | Категория |
|---|---|---|---|
| 26 | Network Policy Missing | HIGH | Kubernetes |
| 27 | Service Account Token Mount | HIGH | Kubernetes |
| 28 | Image from Untrusted Registry | MEDIUM | Docker / Kubernetes |
| 29 | Ingress Without TLS | HIGH | Kubernetes |
| 30 | LoadBalancer Internal | MEDIUM | Kubernetes |
| 31 | Security Group Overly Permissive | HIGH | AWS |
| 32 | IAM Policy Wildcard Service | HIGH | AWS |
| 33 | KMS Key Rotation Disabled | MEDIUM | AWS |
| 34 | CloudTrail Logging Disabled | HIGH | AWS |
| 35 | VPC Flow Logs Disabled | MEDIUM | AWS |
| 36 | RDS Publicly Accessible | CRITICAL | AWS |
| 37 | RDS Encryption Disabled | HIGH | AWS |
| 38 | Redis Without Password | CRITICAL | Database |
| 39 | MongoDB Without Auth | CRITICAL | Database |
| 40 | Elasticsearch Public Access | HIGH | AWS |
| 41 | Lambda Function Public Trigger | HIGH | AWS / Serverless |
| 42 | Cloud Function HTTP Without Auth | HIGH | GCP / Serverless |
| 43 | Azure NSG Any-Any Rule | CRITICAL | Azure |
| 44 | Azure SQL Firewall Open | CRITICAL | Azure |
| 45 | CI/CD Pipeline Without Approval | HIGH | CI/CD |
| 46 | GitHub Actions Without Pin | MEDIUM | CI/CD |
| 47 | Docker Socket Mounted | CRITICAL | Docker |
| 48 | Kubernetes Pod Security Policy | HIGH | Kubernetes |
| 49 | Helm Chart Without Values Validation | MEDIUM | Kubernetes |
| 50 | Terraform State Remote Without Lock | HIGH | Terraform |

**Кросс-файловая деталь:** проверка 35 (VPC Flow Logs Disabled) не ограничивается одним файлом — она проверяет наличие `AWS::EC2::FlowLog`/`aws_flow_log` во **всём** наборе файлов через модульный кэш `_CURRENT_BATCH_CONTENTS`, а не только в файле с `AWS::EC2::VPC`.

---

## Hard

Файл: `Hard_Check.py`. Точка входа: `all_hard_check(files=None)` — демо-режим / один файл / список файлов.

| № | Название | Severity | Стандарт | Статус |
|---|---|---|---|---|
| 51 | Cross-File Network Policy | HIGH | CIS-K8S-5.3.2 | ✅ реализована |
| 52 | IAM Privilege Escalation Path | CRITICAL | CIS-AWS-1.18 | ✅ реализована |
| 53 | Service Account Token Abuse | HIGH | CIS-K8S-5.2.11 | ⚠️ заглушка |
| 54 | Lateral Movement Path | CRITICAL | NIST-AC-4 | ⚠️ заглушка |
| 55 | Secret Rotation Compliance | HIGH | NIST-IA-5.1 | ⚠️ заглушка |
| 56 | Unused IAM Credentials | MEDIUM | CIS-AWS-1.15 | ⚠️ заглушка |
| 57 | Kubernetes RBAC Overprivileged | CRITICAL | CIS-K8S-5.1.8 | ⚠️ заглушка |
| 58 | Role Binding to Default SA | HIGH | CIS-K8S-5.1.9 | ⚠️ заглушка |
| 59 | Admission Controller Disabled | HIGH | CIS-K8S-5.1.4 | ⚠️ заглушка |
| 60 | Container Breakout Potential | CRITICAL | CIS-K8S-5.2.14 | ⚠️ заглушка |
| 61 | Terraform Hardcoded Secrets | CRITICAL | CIS-TF-1.1 | ⚠️ заглушка |
| 62 | State File Public Access | CRITICAL | CIS-TF-2.2 | ⚠️ заглушка |
| 63 | CI/CD Secret Exfiltration | CRITICAL | NIST-SI-10 | ⚠️ заглушка |
| 64 | Dependency Chain Vulnerability | HIGH | NIST-SI-2 | ⚠️ заглушка |
| 65 | Kubernetes Supply Chain Attack | CRITICAL | SLSA-3 | ⚠️ заглушка |
| 66 | Cloud Resource Tagging Compliance | MEDIUM | NIST-CM-2.1 | ⚠️ заглушка |
| 67 | Encryption Key Cross-Account Access | HIGH | CIS-AWS-2.1.6 | ⚠️ заглушка |
| 68 | VPC Peering Security Gap | HIGH | CIS-AWS-5.7 | ⚠️ заглушка |
| 69 | Azure AAD Privileged Identity | CRITICAL | CIS-Azure-1.1 | ⚠️ заглушка |
| 70 | GCP Service Account Key Leakage | CRITICAL | CIS-GCP-1.1.5 | ⚠️ заглушка |
| 71 | Kubernetes Audit Log Tampering | HIGH | CIS-K8S-3.2.1 | ⚠️ заглушка |
| 72 | Container Registry Public Push | CRITICAL | CIS-Docker-4.3 | ⚠️ заглушка |
| 73 | Serverless Function Chain Exploit | CRITICAL | NIST-AC-4 | ⚠️ заглушка |
| 74 | Multi-Cloud Identity Federation | HIGH | NIST-IA-3 | ⚠️ заглушка |
| 75 | Drift Detection from Baseline | HIGH | NIST-CM-3.2 | ⚠️ заглушка |

«Заглушка» означает: функция печатает корректно оформленный отчёт (Issue/Risk/Insecure/Secure/Remediation) с фиксированным демонстрационным примером, но **не анализирует переданный файл** — вызывать её на реальном проекте пока не имеет смысла для получения находок, только для проверки, что пайплайн вызовов работает. `find_file.py` знает об этом и не пытается извлечь findings из вывода Hard-проверок (см. [ARCHITECTURE.md](ARCHITECTURE.md#-известное-архитектурное-ограничение)).

---

## Подробные примеры по категориям

Ниже — по одному подробному примеру на каждую крупную категорию. Полный текст Insecure/Secure/Remediation для любой другой проверки можно увидеть, запустив её напрямую — каждая функция печатает его при обнаружении проблемы.

### Kubernetes — Check 01: Privileged Container

**Стандарт:** де-факто CIS Kubernetes Benchmark 5.2.1. **Severity:** CRITICAL.

```yaml
# ❌ Insecure
securityContext:
  privileged: true
```

```yaml
# ✅ Secure
securityContext:
  privileged: false
```

**Remediation:** уберите `privileged: true`; если нужен доступ к конкретному устройству/capability — используйте точечные `capabilities.add` вместо полного privileged-режима.

### AWS — Check 36: RDS Publicly Accessible

**Severity:** CRITICAL.

```yaml
# ❌ Insecure
Resources:
  DB:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: true
```

```yaml
# ✅ Secure
Resources:
  DB:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: false
```

Проверка поддерживает и Terraform-эквивалент (`publicly_accessible = true`).

### Database — Check 38: Redis Without Password

**Severity:** CRITICAL.

```conf
# ❌ Insecure
bind 0.0.0.0
protected-mode no
# requirepass не задан
```

```conf
# ✅ Secure
bind 127.0.0.1
requirepass StrongP@ssw0rd123
protected-mode yes
```

**Важно:** проверка анализирует multi-document YAML-файлы по отдельным документам — если `bind 0.0.0.0` в одном документе, а `requirepass` в другом (например, insecure- и secure-примеры в одном тестовом файле, разделённые `---`), они не «перекрывают» друг друга ошибочно.

### CI/CD — Check 45: CI/CD Pipeline Without Approval

**Severity:** HIGH.

```yaml
# ❌ Insecure (GitLab CI)
deploy_production:
  stage: deploy
  script:
    - ./deploy-to-prod.sh
  only:
    - main
  # нет when: manual
```

```yaml
# ✅ Secure
deploy_production:
  stage: deploy
  script:
    - ./deploy-to-prod.sh
  when: manual
  environment:
    name: production
```

Проверка понимает и GitLab CI (плоские top-level job'ы), и GitHub Actions (`jobs: <job_id>:` с отступом), и определяет «продакшн» не только по имени job'а, но и по `environment: name: production`, ссылкам на `main`/`master` в `rules`/`only`.

### Hard / Cross-File — Check 51: Cross-File Network Policy

**Severity:** HIGH. **Стандарт:** CIS-K8S-5.3.2.

```yaml
# ❌ Insecure — deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
# ...и НИ В ОДНОМ файле набора нет kind: NetworkPolicy
```

```yaml
# ✅ Secure — netpol.yaml (в том же наборе файлов, необязательно в том же файле)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
```

Это первая по-настоящему кросс-файловая проверка проекта: `Deployment` и `NetworkPolicy` могут (и обычно) лежат в разных файлах — проверка находит workload в текущем файле, а затем ищет `NetworkPolicy` по всему набору через `_CURRENT_BATCH_CONTENTS`.

**Осознанное ограничение:** полное сопоставление namespace/podSelector между workload'ом и политикой не выполняется (для этого нужен настоящий YAML-парсер с label-matching) — проверка консервативна и находит случаи, когда во всём наборе НЕТ НИ ОДНОЙ `NetworkPolicy`, а не то, что конкретный workload не покрыт конкретной политикой.

### Hard — Check 52: IAM Privilege Escalation Path

**Severity:** CRITICAL. **Стандарт:** CIS-AWS-1.18.

```json
// ❌ Insecure — два statement в одной IAM-политике
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::123456789012:role/AdminRole"
},
{
  "Effect": "Allow",
  "Action": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
  "Resource": "arn:aws:iam::123456789012:policy/SelfPolicy"
}
```

```json
// ✅ Secure — Condition сужает применимость PassRole, Deny блокирует изменение политик не-админами
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::123456789012:role/LimitedRole",
  "Condition": {
    "StringEquals": { "iam:PassedToService": "ec2.amazonaws.com" }
  }
}
```

Проверка сверяет собранное множество разрешённых действий с каталогом известных цепочек эскалации привилегий в AWS (PassRole+RunInstances, PassRole+Lambda, CreatePolicyVersion как самостоятельный вектор и т.д. — подмножество каталога, задокументированного Rhino Security Labs).

**Осознанное ограничение:** проверка не анализирует `Resource`/`Condition` — она смотрит только на множество разрешённых `Action`, поэтому возможны false positives там, где права сужены конкретным ARN или условием. Это сигнал для ручного review, а не окончательный вердикт.

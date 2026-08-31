<div align="center">

# 🛡️ InfraGuard — Static Security Auditor

### Автоматический аудит безопасности инфраструктуры: Kubernetes • Docker • AWS • GCP • Azure • CI/CD

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Checks](https://img.shields.io/badge/Checks-75-green.svg)
![Platforms](https://img.shields.io/badge/Platforms-6-orange.svg)
![Formats](https://img.shields.io/badge/Formats-YAML%20%7C%20JSON%20%7C%20HCL%20%7C%20Dockerfile-yellow.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![CIS](https://img.shields.io/badge/CIS-Benchmark%20aligned-blueviolet.svg)

[Быстрый старт](#-быстрый-старт) • [Проверки](#-проверки) • [Архитектура](#-архитектура) • [Примеры](#-примеры-вывода) • [Дорожная карта](#-дорожная-карта)

</div>

---

## 📋 Что это?

**InfraGuard** — статический анализатор конфигурационных файлов инфраструктуры, который находит уязвимости **до деплоя** (shift-left security).

Анализирует:
- ☸️ **Kubernetes** манифесты (Pod, Deployment, Service, RBAC, NetworkPolicy)
- 🐳 **Docker** (Compose, Dockerfile)
- ☁️ **AWS** (CloudFormation, Terraform)
- 🌐 **GCP** (IAM, GCS, GKE, Cloud Functions)
- 🔷 **Azure** (ARM templates, NSG, SQL Firewall)
- 🔄 **CI/CD** (GitLab CI, GitHub Actions, Jenkinsfile)

**75 проверок** в 3 уровнях сложности, основанных на стандартах:
- CIS Benchmarks (Kubernetes, AWS, Azure, GCP, Docker)
- NIST SP 800-53
- OWASP Top 10
- SLSA Supply Chain Levels

---

## 🎯 Зачем это нужно?

| Проблема | Решение InfraGuard |
|----------|-------------------|
| Секреты в git-истории | ✅ Обнаружение plaintext secrets в CI/CD, Terraform, K8s |
| Привилегированные контейнеры | ✅ Проверка privileged, hostPID, hostNetwork, capabilities |
| Открытые порты в интернет | ✅ SSH/RDP на 0.0.0.0/0, S3 public, RDS public |
| Отсутствие шифрования | ✅ EBS, RDS, KMS rotation, state files |
| Supply-chain атаки | ✅ Dockerfile анализ, image pinning, подпись образов |
| Lateral movement | ✅ Cross-file анализ NetworkPolicy, IAM цепочки |

---

## 🏗️ Архитектура

```
┌─────────────────────────────────────────────────────────────┐
│                    find_file.py                              │
│         Поиск файлов (.yaml, .json, .tf, Dockerfile)        │
│         Группировка по папкам, фильтрация                   │
└────────────────────────┬────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
┌─────────────────┐ ┌──────────────┐ ┌──────────────┐
│  Easy_Check.py  │ │Medium_Check.py│ │Hard_Check.py │
│  Проверки 01-25 │ │Проверки 26-50│ │Проверки 51-75│
│                 │ │              │ │              │
│ • Line regex    │ │ • Block parse│ │ • Cross-file │
│ • YAML parse    │ │ • Heuristics │ │ • Chain attack│
│ • JSON parse    │ │ • Context    │ │ • Compliance │
└────────┬────────┘ └──────┬───────┘ └──────┬───────┘
         │                 │                 │
         └─────────────────┼─────────────────┘
                           ▼
              ┌────────────────────────┐
              │found_files_need_check.py│
              │  Запись результатов    │
              │  в файл + stdout       │
              └────────────────────────┘
```

---

## 📦 Установка

```bash
# Клонировать репозиторий
git clone https://github.com/YOUR_USERNAME/infraguard.git
cd infraguard

# Установить зависимости
pip install -r requirements.txt

# Или без зависимостей (работает без PyYAML, но с ограниченным функционалом)
python find_file.py
```

### Зависимости

```txt
# requirements.txt
PyYAML>=6.0
```

> ⚠️ Проект работает и без PyYAML (fallback на regex-парсинг), но для полного покрытия рекомендуется установить.

---

## 🚀 Быстрый старт

```bash
# Аудит текущей директории
python find_file.py

# Аудит конкретного проекта
python find_file.py /path/to/project

# Результат сохраняется в found_files_need_check.txt
```

---

## 🔍 Проверки

### Уровень 1: Easy (01–25) — Базовые уязвимости

| ID | Название | Стандарт | Severity | Платформа |
|----|----------|----------|----------|-----------|
| E-01 | Privileged Container | CIS-K8S-5.2.1 | 🔴 CRITICAL | K8s |
| E-02 | Run as Root | CIS-K8S-5.2.6 | 🟠 HIGH | K8s |
| E-03 | Latest Tag | NIST-CM-2 | 🟡 MEDIUM | K8s |
| E-04 | Host Network | CIS-K8S-5.2.4 | 🟠 HIGH | K8s |
| E-05 | Host PID | CIS-K8S-5.2.2 | 🟠 HIGH | K8s |
| E-06 | Host IPC | CIS-K8S-5.2.3 | 🟠 HIGH | K8s |
| E-07 | Privilege Escalation | CIS-K8S-5.2.5 | 🟠 HIGH | K8s |
| E-08 | Docker Exposed Ports | CIS-Docker-5.4 | 🟠 HIGH | Docker |
| E-09 | Docker Privileged | CIS-Docker-5.2 | 🔴 CRITICAL | Docker |
| E-10 | Secrets in Env Vars | CIS-K8S-5.4.1 | 🟠 HIGH | K8s |
| E-11 | Missing Resource Limits | CIS-K8S-5.2.7 | 🟡 MEDIUM | K8s |
| E-12 | Missing Health Probes | CIS-K8S-5.2.8 | 🟡 MEDIUM | K8s |
| E-13 | Insecure Capabilities | CIS-K8S-5.2.9 | 🔴 CRITICAL | K8s |
| E-14 | Docker Latest Tag | CIS-Docker-4.1 | 🟡 MEDIUM | Docker |
| E-15 | S3 Public Read | CIS-AWS-1.13 | 🔴 CRITICAL | AWS |
| E-16 | S3 Public Write | CIS-AWS-1.14 | 🔴 CRITICAL | AWS |
| E-17 | Unencrypted EBS | CIS-AWS-2.1.1 | 🟠 HIGH | AWS |
| E-18 | RDP Open to Internet | CIS-AWS-5.2 | 🔴 CRITICAL | AWS |
| E-19 | SSH Open to Internet | CIS-AWS-5.1 | 🔴 CRITICAL | AWS |
| E-20 | GCS Public Access | CIS-GCP-6.2.1 | 🔴 CRITICAL | GCP |
| E-21 | Azure Storage Public | CIS-Azure-9.1 | 🔴 CRITICAL | Azure |
| E-22 | K8s Dashboard Exposed | CIS-K8S-5.1.1 | 🔴 CRITICAL | K8s |
| E-23 | Etcd Client Cert Auth | CIS-K8S-4.1.1 | 🔴 CRITICAL | K8s |
| E-24 | Anonymous Auth | CIS-K8S-5.1.3 | 🔴 CRITICAL | K8s |
| E-25 | CI/CD Plaintext Secrets | NIST-IA-5 | 🔴 CRITICAL | CI/CD |

### Уровень 2: Medium (26–50) — Контекстные проверки

| ID | Название | Стандарт | Severity | Платформа |
|----|----------|----------|----------|-----------|
| M-26 | Network Policy Missing | CIS-K8S-5.3.2 | 🟠 HIGH | K8s |
| M-27 | SA Token Mount | CIS-K8S-5.2.10 | 🟠 HIGH | K8s |
| M-28 | Untrusted Registry | NIST-SI-2 | 🟡 MEDIUM | K8s |
| M-29 | Ingress Without TLS | CIS-K8S-5.1.7 | 🟠 HIGH | K8s |
| M-30 | LoadBalancer Internal | CIS-AWS-5.4 | 🟡 MEDIUM | AWS |
| M-31 | SG Overly Permissive | CIS-AWS-5.3 | 🟠 HIGH | AWS |
| M-32 | IAM Wildcard | CIS-AWS-1.17 | 🟠 HIGH | AWS |
| M-33 | KMS Rotation Disabled | CIS-AWS-2.1.4 | 🟡 MEDIUM | AWS |
| M-34 | CloudTrail Disabled | CIS-AWS-3.1 | 🟠 HIGH | AWS |
| M-35 | VPC Flow Logs Disabled | CIS-AWS-3.4 | 🟡 MEDIUM | AWS |
| M-36 | RDS Publicly Accessible | CIS-AWS-2.3.1 | 🔴 CRITICAL | AWS |
| M-37 | RDS Encryption Disabled | CIS-AWS-2.3.2 | 🟠 HIGH | AWS |
| M-38 | Redis Without Password | CIS-DB-4.1 | 🔴 CRITICAL | DB |
| M-39 | MongoDB Without Auth | CIS-DB-4.2 | 🔴 CRITICAL | DB |
| M-40 | Elasticsearch Public | CIS-AWS-2.4.1 | 🟠 HIGH | AWS |
| M-41 | Lambda Public Trigger | CIS-AWS-2.5.1 | 🟠 HIGH | AWS |
| M-42 | Cloud Function No Auth | CIS-GCP-6.6.1 | 🟠 HIGH | GCP |
| M-43 | Azure NSG Any-Any | CIS-Azure-7.1 | 🔴 CRITICAL | Azure |
| M-44 | Azure SQL Firewall Open | CIS-Azure-9.4 | 🔴 CRITICAL | Azure |
| M-45 | Pipeline Without Approval | NIST-AC-3 | 🟠 HIGH | CI/CD |
| M-46 | Actions Without Pin | CIS-GitHub-5.1 | 🟡 MEDIUM | CI/CD |
| M-47 | Docker Socket Mounted | CIS-Docker-5.31 | 🔴 CRITICAL | Docker |
| M-48 | Pod Security Policy | CIS-K8S-5.2.13 | 🟠 HIGH | K8s |
| M-49 | Helm Without Validation | NIST-CM-6 | 🟡 MEDIUM | K8s |
| M-50 | Terraform State No Lock | CIS-TF-2.1 | 🟠 HIGH | IaC |

### Уровень 3: Hard (51–75) — Продвинутые атаки

| ID | Название | Стандарт | Severity | Платформа |
|----|----------|----------|----------|-----------|
| H-51 | Cross-File NetworkPolicy | CIS-K8S-5.3.2 | 🟠 HIGH | K8s |
| H-52 | IAM Privilege Escalation | CIS-AWS-1.18 | 🔴 CRITICAL | AWS |
| H-53 | SA Token Abuse | CIS-K8S-5.2.11 | 🟠 HIGH | K8s |
| H-54 | Lateral Movement Path | NIST-AC-4 | 🔴 CRITICAL | Multi |
| H-55 | Secret Rotation Compliance | NIST-IA-5.1 | 🟠 HIGH | Cloud |
| H-56 | Unused IAM Credentials | CIS-AWS-1.15 | 🟡 MEDIUM | AWS |
| H-57 | RBAC Overprivileged | CIS-K8S-5.1.8 | 🔴 CRITICAL | K8s |
| H-58 | Role Binding to Default SA | CIS-K8S-5.1.9 | 🟠 HIGH | K8s |
| H-59 | Admission Controller Disabled | CIS-K8S-5.1.4 | 🟠 HIGH | K8s |
| H-60 | Container Breakout | CIS-K8S-5.2.14 | 🔴 CRITICAL | K8s |
| H-61 | Terraform Hardcoded Secrets | CIS-TF-1.1 | 🔴 CRITICAL | IaC |
| H-62 | State File Public Access | CIS-TF-2.2 | 🔴 CRITICAL | IaC |
| H-63 | CI/CD Secret Exfiltration | NIST-SI-10 | 🔴 CRITICAL | CI/CD |
| H-64 | Dependency Chain Vuln | NIST-SI-2 | 🟠 HIGH | Docker |
| H-65 | Supply Chain Attack | SLSA-3 | 🔴 CRITICAL | K8s |
| H-66 | Tagging Compliance | NIST-CM-2.1 | 🟡 MEDIUM | Cloud |
| H-67 | KMS Cross-Account Access | CIS-AWS-2.1.6 | 🟠 HIGH | AWS |
| H-68 | VPC Peering Gap | CIS-AWS-5.7 | 🟠 HIGH | AWS |
| H-69 | Azure AAD PIM | CIS-Azure-1.1 | 🔴 CRITICAL | Azure |
| H-70 | GCP SA Key Leakage | CIS-GCP-1.1.5 | 🔴 CRITICAL | GCP |
| H-71 | Audit Log Tampering | CIS-K8S-3.2.1 | 🟠 HIGH | K8s |
| H-72 | Registry Public Push | CIS-Docker-4.3 | 🔴 CRITICAL | Docker |
| H-73 | Serverless Chain Exploit | NIST-AC-4 | 🔴 CRITICAL | Cloud |
| H-74 | Multi-Cloud Federation | NIST-IA-3 | 🟠 HIGH | Multi |
| H-75 | Drift Detection | NIST-CM-3.2 | 🟠 HIGH | IaC |

---

## 📊 Примеры вывода

```
╔════════════════════════════════════════════════════════════════╗
║  🔐 Security Auditor — Easy Level Report                      ║
║  📁 Файл: k8s/deployment.yaml                                 ║
╚════════════════════════════════════════════════════════════════╝

🔴 [CRITICAL] Privileged Container
   📍 Строка 15: privileged: true
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

🟠 [HIGH] Run as Root
   📍 Строка 12: runAsUser: 0
   💥 Issue: Процессы внутри контейнера выполняются от имени root.
   🎯 Risk: При уязвимости в приложении злоумышленник получит права root.
   ...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Итого: 2 находки (1 CRITICAL, 1 HIGH)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 📁 Структура проекта

```
infraguard/
├── find_file.py              # Точка входа: поиск и маршрутизация файлов
├── Easy_Check.py             # 25 базовых проверок (regex + YAML parse)
├── Medium_Check.py           # 25 контекстных проверок (block analysis)
├── Hard_Check.py             # 25 продвинутых проверок (cross-file, chains)
├── found_files_need_check.py # Модуль записи результатов
├── requirements.txt          # Зависимости
├── README.md                 # Этот файл
├── test_files/               # Тестовые уязвимые конфигурации
│   ├── k8s/
│   │   ├── 01_privileged.yaml
│   │   ├── 02_run_as_root.yaml
│   │   └── ...
│   ├── docker/
│   ├── aws/
│   ├── gcp/
│   ├── azure/
│   └── cicd/
└── docs/
    ├── methodology.md        # Методология аудита
    ├── standards.md          # Маппинг на стандарты
    └── architecture.md       # Описание архитектуры
```

---

## 🗺️ Дорожная карта

- [x] Easy level: 25 проверок
- [x] Medium level: 25 проверок
- [ ] Hard level: реализация логики (сейчас заглушки)
- [ ] SARIF output формат
- [ ] HTML отчёт
- [ ] Интеграция с GitHub Actions
- [ ] Dockerfile парсинг
- [ ] OPA/Rego интеграция
- [ ] Severity scoring (CVSS-like)
- [ ] False-positive suppression (.auditignore)
- [ ] Unit tests (pytest)

---

## 📚 Стандарты и источники

- [CIS Kubernetes Benchmark v1.8.0](https://www.cisecurity.org/benchmark/kubernetes)
- [CIS AWS Foundations Benchmark v1.5.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [CIS Docker Benchmark v1.6.0](https://www.cisecurity.org/benchmark/docker)
- [NIST SP 800-53 Rev.5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [SLSA Supply Chain Levels](https://slsa.dev/)

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Сделано с ❤️ для безопасности вашей инфраструктуры**

⭐ Star this repo if you find it useful!

</div>
```

---

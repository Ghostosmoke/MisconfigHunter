from found_files_need_check import write_to_file
"""
╔════════════════════════════════════════════════════════════════╗
║  🔐 Security Auditor — Easy Level Checks (01–25)              ║
║  CIS Kubernetes | Docker | AWS | GCP | Azure | CI/CD          ║
╚════════════════════════════════════════════════════════════════╝

❗ ВНИМАНИЕ: Все проверки — ЗАГЛУШКИ (stubs).
   Функции НЕ анализируют файлы, а демонстрируют формат отчёта.
   Реальную логику проверки нужно добавить позже.
"""

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
def check_privileged_container_01(file_path,file):
    """
    Проверяет наличие privileged: true в securityContext.
    При нахождении уязвимости выводит детальный отчёт.
    """
    if 'privileged: true' in  file:
        write_to_file(str(file_path)+file)
        print("⚠️  [CRITICAL] Privileged Container")
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
def check_run_as_root_02():
    """
    Проверяет запуск контейнера от root или отсутствие runAsNonRoot.
    """
    print("⚠️  [HIGH] Run as Root")
    print("  💥 Issue: Процессы внутри контейнера выполняются от имени root.")
    print("  🎯 Risk: При уязвимости в приложении злоумышленник получит права root внутри контейнера, что облегчает выход за пределы контейнера.")
    print("  ❌ Insecure:")
    print("        securityContext:\n          runAsUser: 0")
    print("        # или отсутствие runAsNonRoot")
    print("  ✅ Secure:")
    print("        securityContext:\n          runAsNonRoot: true\n          runAsUser: 1000\n          runAsGroup: 1000")
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
# │ 📝 Описание:   Использование плавающего тега 'latest'      │
# └─────────────────────────────────────────────────────────────┘
def check_latest_tag_03():
    """
    Проверяет использование тега :latest в образах контейнеров.
    """
    print("⚠️  [MEDIUM] Latest Tag")
    print("  💥 Issue: Использование плавающего тега latest в образах.")
    print("  🎯 Risk: Непредсказуемые обновления, поломка совместимости, тихое внедрение уязвимостей в новую версию образа.")
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
def check_host_network_04():
    """
    Проверяет использование сетевого стека хоста контейнером.
    """
    print("⚠️  [HIGH] Host Network")
    print("  💥 Issue: Контейнер использует сетевой стек хоста.")
    print("  🎯 Risk: Доступ ко всем сетевым интерфейсам хоста, возможность сниффинга трафика, обход NetworkPolicies Kubernetes, доступ к сервисам на localhost хоста.")
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
def check_host_pid_05():
    """
    Проверяет использование пространства процессов хоста.
    """
    print("⚠️  [HIGH] Host PID")
    print("  💥 Issue: Контейнер видит пространство процессов хоста.")
    print("  🎯 Risk: Возможность видеть все процессы на узле, отправлять сигналы (kill) процессам хоста, анализировать работу других приложений.")
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
def check_host_ipc_06():
    """
    Проверяет использование IPC-пространства хоста.
    """
    print("⚠️  [HIGH] Host IPC")
    print("  💥 Issue: Контейнер использует пространство IPC хоста.")
    print("  🎯 Risk: Доступ к shared memory хоста, возможность перехвата данных между процессами на узле, атаки типа race condition.")
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
def check_allow_privilege_escalation_07():
    """
    Проверяет allowPrivilegeEscalation: true в securityContext.
    """
    print("⚠️  [HIGH] Allow Privilege Escalation")
    print("  💥 Issue: Разрешено повышение привилегий процесса.")
    print("  🎯 Risk: Процесс может получить больше прав, чем у родительского процесса (например, через setuid бинарники), что ведёт к правам root.")
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
def check_docker_exposed_ports_08():
    """
    Проверяет проброс портов Docker на все интерфейсы.
    """
    print("⚠️  [HIGH] Docker Exposed Ports")
    print("  💥 Issue: Порт проброшен на все интерфейсы (0.0.0.0).")
    print("  🎯 Risk: Сервис становится доступным из внешней сети, увеличение поверхности атаки, доступ без авторизации.")
    print("  ❌ Insecure:")
    print('        ports:\n          "0.0.0.0:80:80"\n        # Или без указания IP (подразумевается 0.0.0.0)\n        "80:80"')
    print("  ✅ Secure:")
    print('        ports:\n          "127.0.0.1:80:80"  # Только localhost\n        # Или использование overlay сети без публикации')
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
def check_docker_privileged_09():
    """
    Проверяет запуск Docker-контейнера в привилегированном режиме.
    """
    print("⚠️  [CRITICAL] Docker Privileged")
    print("  💥 Issue: Контейнер запущен в привилегированном режиме Docker.")
    print("  🎯 Risk: Полный доступ к устройствам хоста, возможность загрузки модулей ядра, обход изоляции, container escape.")
    print("  ❌ Insecure:")
    print("        services:\n          app:\n            image: myapp\n            privileged: true  # ❌ Опасно!")
    print("  ✅ Secure:")
    print("        services:\n          app:\n            image: myapp\n            privileged: false\n            cap_add:\n              - NET_BIND_SERVICE\n            security_opt:\n              - no-new-privileges:true\n            read_only: true")
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
def check_secrets_in_env_vars_10():
    """
    Проверяет хранение секретов в env-переменных в открытом виде.
    """
    print("⚠️  [HIGH] Secrets in Env Vars")
    print("  💥 Issue: Секреты хранятся в переменных окружения в открытом виде.")
    print("  🎯 Risk: Секреты видны через kubectl describe, docker inspect, могут попасть в логи систем мониторинга или отладки.")
    print("  ❌ Insecure:")
    print("        env:\n          - name: DB_PASSWORD\n            value: \"super_secret_password\"\n          - name: API_KEY\n            value: \"sk-1234567890abcdef\"")
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
def check_missing_resource_limits_11():
    """
    Проверяет наличие resource limits у контейнеров.
    """
    print("⚠️  [MEDIUM] Missing Resource Limits")
    print("  💥 Issue: Не ограничены ресурсы CPU/Memory для контейнера.")
    print("  🎯 Risk: Один контейнер может занять все ресурсы узла (DoS), падение других приложений на узле, нестабильность кластера.")
    print("  ❌ Insecure:")
    print("        resources:\n          requests:\n            memory: \"64Mi\"\n          # limits отсутствуют")
    print("  ✅ Secure:")
    print("        resources:\n          limits:\n            cpu: \"500m\"\n            memory: \"128Mi\"\n          requests:\n            cpu: \"250m\"\n            memory: \"64Mi\"")
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
def check_missing_health_probes_12():
    """
    Проверяет наличие health checks у контейнеров.
    """
    print("⚠️  [MEDIUM] Missing Health Probes")
    print("  💥 Issue: Отсутствуют проверки здоровья (livenessProbe/readinessProbe).")
    print("  🎯 Risk: Трафик направляется на неработающие поды, зависшие контейнеры не перезапускаются автоматически.")
    print("  ❌ Insecure:")
    print("        containers:\n          - name: app\n            # livenessProbe отсутствует\n            # readinessProbe отсутствует")
    print("  ✅ Secure:")
    print("        containers:\n          - name: app\n            livenessProbe:\n              httpGet:\n                path: /healthz\n                port: 8080\n              initialDelaySeconds: 15\n              periodSeconds: 10\n            readinessProbe:\n              httpGet:\n                path: /ready\n                port: 8080\n              initialDelaySeconds: 5\n              periodSeconds: 5")
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
def check_insecure_capabilities_add_13():
    """
    Проверяет добавление опасных Linux capabilities (SYS_ADMIN и др.).
    """
    print("⚠️  [CRITICAL] Insecure Capabilities Add")
    print("  💥 Issue: Добавлены опасные Linux capabilities (SYS_ADMIN, NET_ADMIN).")
    print("  🎯 Risk: SYS_ADMIN позволяет монтировать ФС, менять настройки ядра. Фактически даёт права, близкие к root.")
    print("  ❌ Insecure:")
    print("        securityContext:\n          capabilities:\n            add:\n              - SYS_ADMIN\n              - NET_ADMIN")
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
def check_docker_latest_tag_14():
    """
    Проверяет использование тега :latest в Docker Compose.
    """
    print("⚠️  [MEDIUM] Docker Latest Tag")
    print("  💥 Issue: Использование тега latest в Docker Compose.")
    print("  🎯 Risk: Невозможность воспроизведения окружения, риск получения битой или уязвимой версии при пересоздании.")
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
def check_s3_public_read_15():
    """Проверяет публичный доступ на чтение к S3 bucket."""
    print("⚠️  [CRITICAL] S3 Public Read")
    print("  💥 Issue: S3 bucket доступен для публичного чтения.")
    print("  🎯 Risk: Утечка конфиденциальных данных, логинов, ключей, персональной информации пользователей.")
    print("  ❌ Insecure:")
    print("        BucketPolicy:\n          Effect: Allow\n          Principal: \"*\"\n          Action: \"s3:GetObject\"\n          Resource: \"arn:aws:s3:::my-bucket/*\"")
    print("  ✅ Secure:")
    print("        PublicAccessBlockConfiguration:\n          BlockPublicAcls: true\n          BlockPublicPolicy: true\n          IgnorePublicAcls: true\n          RestrictPublicBuckets: true")
    print("  🛠️ Remediation:")
    print("      • Включите S3 Block Public Access")
    print("      • Удалите политики с Principal: *")
    print("      • Используйте CloudFront с signed URLs")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 16: S3 Public Write                             │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-1.14                                 │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   S3 bucket доступен для публичной записи     │
# └─────────────────────────────────────────────────────────────┘
def check_s3_public_write_16():
    """Проверяет публичный доступ на запись к S3 bucket."""
    print("⚠️  [CRITICAL] S3 Public Write")
    print("  💥 Issue: S3 bucket доступен для публичной записи.")
    print("  🎯 Risk: Злоумышленники могут загрузить вредоносное ПО, удалить данные, использовать бакет для хостинга нелегального контента.")
    print("  ❌ Insecure:")
    print("        BucketPolicy:\n          Effect: Allow\n          Principal: \"*\"\n          Action: \"s3:PutObject\"\n          Resource: \"arn:aws:s3:::my-bucket/*\"")
    print("  ✅ Secure:")
    print("        PublicAccessBlockConfiguration:\n          BlockPublicAcls: true\n          BlockPublicPolicy: true\n          IgnorePublicAcls: true\n          RestrictPublicBuckets: true")
    print("  🛠️ Remediation:")
    print("      • Немедленно удалите политику с публичной записью")
    print("      • Включите S3 Block Public Access")
    print("      • Настройте CloudTrail для мониторинга S3 API calls")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 17: Unencrypted EBS                             │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-2.1.1                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   EBS volume не зашифрован                    │
# └─────────────────────────────────────────────────────────────┘
def check_unencrypted_ebs_17():
    """Проверяет шифрование EBS volumes."""
    print("⚠️  [HIGH] Unencrypted EBS")
    print("  💥 Issue: EBS volume не зашифрован.")
    print("  🎯 Risk: При физическом доступе к диску или снимке снапшота данные могут быть прочитаны в открытом виде.")
    print("  ❌ Insecure:")
    print("        Type: AWS::EC2::Volume\n        Properties:\n          Size: 100\n          Encrypted: false")
    print("  ✅ Secure:")
    print("        Type: AWS::EC2::Volume\n        Properties:\n          Size: 100\n          Encrypted: true\n          KmsKeyId: arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012")
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
def check_rdp_open_to_internet_18():
    """Проверяет открытие порта RDP для всего интернета."""
    print("⚠️  [CRITICAL] RDP Open to Internet")
    print("  💥 Issue: Порт RDP (3389) открыт для всего интернета.")
    print("  🎯 Risk: Брутфорс паролей, уязвимости типа BlueKeep, шифровальщики (ransomware), полный доступ к серверу.")
    print("  ❌ Insecure:")
    print("        SecurityGroupIngress:\n          IpProtocol: tcp\n          FromPort: 3389\n          ToPort: 3389\n          CidrIp: 0.0.0.0/0")
    print("  ✅ Secure:")
    print("        SecurityGroupIngress:\n          IpProtocol: tcp\n          FromPort: 3389\n          ToPort: 3389\n          CidrIp: 10.0.0.0/8")
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
def check_ssh_open_to_internet_19():
    """Проверяет открытие порта SSH для всего интернета."""
    print("⚠️  [CRITICAL] SSH Open to Internet")
    print("  💥 Issue: Порт SSH (22) открыт для всего интернета.")
    print("  🎯 Risk: Постоянная атака ботнетов, брутфорс, утечка ключей, несанкционированный доступ.")
    print("  ❌ Insecure:")
    print("        SecurityGroupIngress:\n          IpProtocol: tcp\n          FromPort: 22\n          ToPort: 22\n          CidrIp: 0.0.0.0/0")
    print("  ✅ Secure:")
    print("        SecurityGroupIngress:\n          IpProtocol: tcp\n          FromPort: 22\n          ToPort: 22\n          CidrIp: 10.0.0.0/8")
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
def check_cloud_storage_public_20():
    """Проверяет публичный доступ к Google Cloud Storage bucket."""
    print("⚠️  [CRITICAL] Cloud Storage Public (GCP)")
    print("  💥 Issue: GCS bucket доступен всем пользователям (allUsers).")
    print("  🎯 Risk: Публичный доступ к файлам, утечка данных, несанкционированное чтение конфиденциальной информации.")
    print("  ❌ Insecure:")
    print("        bindings:\n          - role: roles/storage.objectViewer\n            members:\n              - allUsers")
    print("  ✅ Secure:")
    print("        bindings:\n          - role: roles/storage.objectViewer\n            members:\n              - user:specific@example.com")
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
def check_azure_storage_public_21():
    """Проверяет публичный доступ к Azure Storage container."""
    print("⚠️  [CRITICAL] Azure Storage Public")
    print("  💥 Issue: Уровень доступа Azure Storage установлен в публичный.")
    print("  🎯 Risk: Чтение данных любым пользователем интернета, утечка конфиденциальной информации, compliance violations.")
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
def check_kubernetes_dashboard_exposed_22():
    """Проверяет экспонирование Kubernetes Dashboard наружу."""
    print("⚠️  [CRITICAL] Kubernetes Dashboard Exposed")
    print("  💥 Issue: Панель управления K8s доступна извне через LoadBalancer.")
    print("  🎯 Risk: Если авторизация слабая, злоумышленник получит полный контроль над кластером.")
    print("  ❌ Insecure:")
    print("        apiVersion: v1\n        kind: Service\n        metadata:\n          name: kubernetes-dashboard\n        spec:\n          type: LoadBalancer")
    print("  ✅ Secure:")
    print("        apiVersion: v1\n        kind: Service\n        metadata:\n          name: kubernetes-dashboard\n        spec:\n          type: ClusterIP")
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
def check_etcd_client_cert_auth_23():
    """Проверяет требование клиентских сертификатов для etcd."""
    print("⚠️  [CRITICAL] Etcd Client Cert Auth")
    print("  💥 Issue: Etcd не требует клиентские сертификаты для аутентификации.")
    print("  🎯 Risk: Любой, кто имеет доступ к порту etcd, может читать/писать все данные кластера.")
    print("  ❌ Insecure:")
    print("        etcd:\n          client-cert-auth: false")
    print("  ✅ Secure:")
    print("        etcd:\n          client-cert-auth: true\n          cert-file: /etc/kubernetes/pki/etcd/server.crt\n          key-file: /etc/kubernetes/pki/etcd/server.key")
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
def check_anonymous_auth_enabled_24():
    """Проверяет включение анонимной аутентификации Kubernetes API."""
    print("⚠️  [CRITICAL] Anonymous Auth Enabled")
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
def check_cicd_plaintext_secrets_25():
    """Проверяет хранение секретов в открытом виде в CI/CD конфигах."""

    print("⚠️  [CRITICAL] CI/CD Plain Text Secrets")
    print("  💥 Issue: Секреты зашиты в код конфигурации CI/CD в открытом виде.")
    print("  🎯 Risk: Попадание секретов в git-историю, доступ к секретам у всех разработчиков с доступом к репозиторию.")
    print("  ❌ Insecure:")
    print("        # .gitlab-ci.yml\n        variables:\n          DB_PASSWORD: \"hardcoded_password\"  # ❌\n          API_KEY: \"sk-1234567890abcdef\"     # ❌")
    print("  ✅ Secure:")
    print("        # GitLab CI:\n        variables:\n          DB_PASSWORD: $SECURE_DB_PASSWORD  # ✅ Из CI/CD Variables\n        # GitHub Actions:\n        env:\n          PASSWORD: ${{ secrets.DB_PASSWORD }}  # ✅ Из Repository Secrets")
    print("  🛠️ Remediation:")
    print("      • Немедленно удалите все hardcoded secrets из кода")
    print("      • Используйте CI/CD platform secrets")
    print("      • Включите secret masking в логах")
    print("      • Ротируйте все скомпрометированные секреты")
    print()


def all_easy_check(all_files):
    """
    ╔════════════════════════════════════════════════════════════════╗
    ║  🔐 ЗАПУСК ВСЕХ ПРОВЕРОК EASY LEVEL (01–25)                   ║
    ╚════════════════════════════════════════════════════════════════╝
    """
    # for i in files:
    #     with open(i , 'r' , encoding='utf-8') as f:
    #         all_medium_check(f.read())
    #         all_hard_check(f.read)


    # print("\n" + "=" * 70)
    # print("🔐 Security Auditor — Easy Level Checks (01–25)")
    # print("=" * 70 + "\n")
    #
    # # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # # 🔹 РАЗДЕЛ 1: KUBERNETES SECURITY CHECKS (01–14)
    # # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # print("📦 РАЗДЕЛ 1: Kubernetes Security Checks (01–14)\n")
    # print("─" * 70)
    # files_path=all_files
    # print(type(files_path))
    # count = 0

    with open(all_files, 'r') as f:

        # print(f.read())
        # print(file)
        check_privileged_container_01(all_files,f.read())  # 01

    #     check_run_as_root_02()  # 02
    #     check_latest_tag_03()  # 03
    #     check_host_network_04()  # 04
    #     check_host_pid_05()  # 05
    #     check_host_ipc_06()  # 06
    #     check_allow_privilege_escalation_07()  # 07
    #     check_docker_exposed_ports_08()  # 08
    #     check_docker_privileged_09()  # 09
    #     check_secrets_in_env_vars_10()  # 10
    #     check_missing_resource_limits_11()  # 11
    #     check_missing_health_probes_12()  # 12
    #     check_insecure_capabilities_add_13()  # 13
    #     check_docker_latest_tag_14()  # 14
    #
    #     # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #     # 🔹 РАЗДЕЛ 2: AWS SECURITY CHECKS (15–19)
    #     # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #     print("\n📦 РАЗДЕЛ 2: AWS Security Checks (15–19)\n")
    #     print("─" * 70)
    #
    #     check_s3_public_read_15()  # 15
    #     check_s3_public_write_16()  # 16
    #     check_unencrypted_ebs_17()  # 17
    #     check_rdp_open_to_internet_18()  # 18
    #     check_ssh_open_to_internet_19()  # 19
    #
    #     # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #     # 🔹 РАЗДЕЛ 3: CLOUD STORAGE CHECKS (20–21)
    #     # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #     print("\n📦 РАЗДЕЛ 3: Cloud Storage Checks (20–21)\n")
    #     print("─" * 70)
    #
    #     check_cloud_storage_public_20()  # 20
    #     check_azure_storage_public_21()  # 21
    #
    #     # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #     # 🔹 РАЗДЕЛ 4: KUBERNETES ADMIN CHECKS (22–24)
    #     # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #     print("\n📦 РАЗДЕЛ 4: Kubernetes Admin Checks (22–24)\n")
    #     print("─" * 70)
    #
    #     check_kubernetes_dashboard_exposed_22()  # 22
    #     check_etcd_client_cert_auth_23()  # 23
    #     check_anonymous_auth_enabled_24()  # 24
    #
    #     # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #     # 🔹 РАЗДЕЛ 5: CI/CD SECURITY CHECKS (25)
    #     # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #     print("\n📦 РАЗДЕЛ 5: CI/CD Security Checks (25)\n")
    #     print("─" * 70)
    #
    #     check_cicd_plaintext_secrets_25()  # 25
#
#     # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#     # 🔹 ИТОГОВЫЙ ОТЧЁТ
#     # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#     print("\n" + "=" * 70)
#     print("✅ ВСЕ ПРОВЕРКИ EASY LEVEL ЗАВЕРШЕНЫ")
#     print("=" * 70)
#     print("""
# 📊 Сводка:
#     • Всего проверок: 25
#     • Kubernetes:     14 (01–14)
#     • AWS:            5  (15–19)
#     • Cloud Storage:  2  (20–21)
#     • K8s Admin:      3  (22–24)
#     • CI/CD:          1  (25)
#
# 💡 Запуск отдельных проверок:
#     python Easy_Check.py privileged_container_01
#     python Easy_Check.py run_as_root_02
#     python Easy_Check.py --list  (показать все доступные проверки)
#     """)

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


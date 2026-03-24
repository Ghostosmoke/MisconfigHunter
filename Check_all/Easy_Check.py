"""
🔐 Security Auditor — Easy Level Checks (01-25)
CIS Kubernetes | Docker | AWS | GCP | Azure | CI/CD
"""

from core import BaseCheck , SecurityReport , Severity , CheckRegistry


# =============================================================================
# 🔹 KUBERNETES SECURITY CHECKS (01-13)
# =============================================================================

@CheckRegistry.register
class Privileged_Container_01(BaseCheck):
    """Проверка 01: Privileged Container"""
    RULE_NAME = "Privileged Container"
    STANDARD = "CIS-K8S-5.2.1"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "privileged_container_01"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/01_privileged_container.yaml"]

        # 🔍 ПРОВЕРКА: если найдена уязвимость - выводим отчёт
        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Контейнер имеет почти полный доступ к хост-системе." ,
                risk="Злоумышленник может получить полный контроль над узлом, "
                     "читать файлы хоста, загружать модули ядра и обходить изоляцию." ,
                insecure="""securityContext:
  privileged: true""" ,
                secure="""securityContext:
  allowPrivilegeEscalation: false
  privileged: false
  runAsNonRoot: true
  runAsUser: 1000
  capabilities:
    drop:
      - ALL
  readOnlyRootFilesystem: true""" ,
                remediation=[
                    "Установите privileged: false" ,
                    "Добавьте runAsNonRoot: true" ,
                    "Ограничьте capabilities через drop: ALL" ,
                    "Включите readOnlyRootFilesystem: true"
                ]
            )
        return None  # ✅ Уязвимость не найдена - отчёт не выводим


@CheckRegistry.register
class Run_as_Root_02(BaseCheck):
    """Проверка 02: Run as Root"""
    RULE_NAME = "Run as Root"
    STANDARD = "CIS-K8S-5.2.6"
    SEVERITY = Severity.HIGH
    CHECK_ID = "run_as_root_02"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/02_run_as_root.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Процессы внутри контейнера выполняются от имени root." ,
                risk="При уязвимости в приложении злоумышленник получит права root "
                     "внутри контейнера, что облегчает выход за пределы контейнера." ,
                insecure="""securityContext:
  runAsUser: 0
  # или отсутствие runAsNonRoot""" ,
                secure="""securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000""" ,
                remediation=[
                    "Установите runAsNonRoot: true" ,
                    "Укажите конкретного пользователя runAsUser: 1000" ,
                    "Добавьте runAsGroup для групповых разрешений"
                ]
            )
        return None


@CheckRegistry.register
class Latest_Tag_03(BaseCheck):
    """Проверка 03: Latest Tag"""
    RULE_NAME = "Latest Tag"
    STANDARD = "NIST-CM-2"
    SEVERITY = Severity.MEDIUM
    CHECK_ID = "latest_tag_03"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/03_latest_tag.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Использование плавающего тега latest в образах." ,
                risk="Непредсказуемые обновления, поломка совместимости, "
                     "тихое внедрение уязвимостей в новую версию образа." ,
                insecure="""containers:
  - image: nginx:latest
  # или просто image: nginx""" ,
                secure="""containers:
  - image: nginx:1.21.0
  # или image: nginx@sha256:abc123...""" ,
                remediation=[
                    "Всегда указывайте конкретную версию образа" ,
                    "Используйте SHA-хеш для максимальной воспроизводимости" ,
                    "Настройте автоматическое обновление через Dependabot/Renovate"
                ]
            )
        return None


@CheckRegistry.register
class Host_Network_04(BaseCheck):
    """Проверка 04: Host Network"""
    RULE_NAME = "Host Network"
    STANDARD = "CIS-K8S-5.2.4"
    SEVERITY = Severity.HIGH
    CHECK_ID = "host_network_04"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/04_host_network.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Контейнер использует сетевой стек хоста." ,
                risk="Доступ ко всем сетевым интерфейсам хоста, возможность сниффинга трафика, "
                     "обход NetworkPolicies Kubernetes, доступ к сервисам на localhost хоста." ,
                insecure="""spec:
  hostNetwork: true""" ,
                secure="""spec:
  hostNetwork: false""" ,
                remediation=[
                    "Установите hostNetwork: false" ,
                    "Используйте стандартную сеть Kubernetes" ,
                    "Настройте NetworkPolicy для контроля трафика"
                ]
            )
        return None


@CheckRegistry.register
class Host_PID_05(BaseCheck):
    """Проверка 05: Host PID"""
    RULE_NAME = "Host PID"
    STANDARD = "CIS-K8S-5.2.2"
    SEVERITY = Severity.HIGH
    CHECK_ID = "host_pid_05"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/05_host_pid.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Контейнер видит пространство процессов хоста." ,
                risk="Возможность видеть все процессы на узле, отправлять сигналы (kill) "
                     "процессам хоста, анализировать работу других приложений." ,
                insecure="""spec:
  hostPID: true""" ,
                secure="""spec:
  hostPID: false""" ,
                remediation=[
                    "Установите hostPID: false" ,
                    "Изолируйте пространство процессов контейнера" ,
                    "Используйте стандартные механизмы мониторинга Kubernetes"
                ]
            )
        return None


@CheckRegistry.register
class Host_IPC_06(BaseCheck):
    """Проверка 06: Host IPC"""
    RULE_NAME = "Host IPC"
    STANDARD = "CIS-K8S-5.2.3"
    SEVERITY = Severity.HIGH
    CHECK_ID = "host_ipc_06"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/06_host_ipc.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Контейнер использует пространство IPC хоста." ,
                risk="Доступ к shared memory хоста, возможность перехвата данных "
                     "между процессами на узле, атаки типа race condition." ,
                insecure="""spec:
  hostIPC: true""" ,
                secure="""spec:
  hostIPC: false""" ,
                remediation=[
                    "Установите hostIPC: false" ,
                    "Изолируйте межпроцессное взаимодействие" ,
                    "Используйте стандартные механизмы IPC Kubernetes"
                ]
            )
        return None


@CheckRegistry.register
class Allow_Privilege_Escalation_07(BaseCheck):
    """Проверка 07: Allow Privilege Escalation"""
    RULE_NAME = "Allow Privilege Escalation"
    STANDARD = "CIS-K8S-5.2.5"
    SEVERITY = Severity.HIGH
    CHECK_ID = "allow_privilege_escalation_07"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/07_allow_privilege_escalation.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Разрешено повышение привилегий процесса." ,
                risk="Процесс может получить больше прав, чем у родительского процесса "
                     "(например, через setuid бинарники), что ведёт к правам root." ,
                insecure="""securityContext:
  allowPrivilegeEscalation: true""" ,
                secure="""securityContext:
  allowPrivilegeEscalation: false""" ,
                remediation=[
                    "Установите allowPrivilegeEscalation: false" ,
                    "Проверьте все контейнеры в workload" ,
                    "Добавьте в PodSecurityPolicy/PodSecurity Admission"
                ]
            )
        return None


@CheckRegistry.register
class Docker_Exposed_Ports_08(BaseCheck):
    """Проверка 08: Docker Exposed Ports"""
    RULE_NAME = "Docker Exposed Ports"
    STANDARD = "CIS-Docker-5.4"
    SEVERITY = Severity.HIGH
    CHECK_ID = "docker_exposed_ports_08"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/08_docker_exposed_ports.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Порт проброшен на все интерфейсы (0.0.0.0)." ,
                risk="Сервис становится доступным из внешней сети, "
                     "увеличение поверхности атаки, доступ без авторизации." ,
                insecure="""ports:
  - "0.0.0.0:80:80"
  # Или без указания IP (подразумевается 0.0.0.0)
  - "80:80" """ ,
                secure="""ports:
  - "127.0.0.1:80:80"  # Только localhost
# Или использование overlay сети без публикации:
networks:
  - app-network""" ,
                remediation=[
                    "Укажите конкретный IP для binding (127.0.0.1)" ,
                    "Используйте Docker networks для внутренней коммуникации" ,
                    "Настройте reverse proxy для внешнего доступа"
                ]
            )
        return None


@CheckRegistry.register
class Docker_Privileged_09(BaseCheck):
    """Проверка 09: Docker Privileged"""
    RULE_NAME = "Docker Privileged"
    STANDARD = "CIS-Docker-5.2"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "docker_privileged_09"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/09_docker_privileged.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Контейнер запущен в привилегированном режиме Docker." ,
                risk="Полный доступ к устройствам хоста, возможность загрузки "
                     "модулей ядра, обход изоляции, container escape." ,
                insecure="""services:
  app:
    image: myapp
    privileged: true  # ❌ Опасно!""" ,
                secure="""services:
  app:
    image: myapp
    privileged: false
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges:true
    read_only: true""" ,
                remediation=[
                    "Установите privileged: false" ,
                    "Используйте cap_add только для необходимых capabilities" ,
                    "Добавьте security_opt: no-new-privileges:true"
                ]
            )
        return None


@CheckRegistry.register
class Secrets_in_Env_Vars_10(BaseCheck):
    """Проверка 10: Secrets in Env Vars"""
    RULE_NAME = "Secrets in Env Vars"
    STANDARD = "CIS-K8S-5.4.1"
    SEVERITY = Severity.HIGH
    CHECK_ID = "secrets_in_env_vars_10"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/10_secrets_in_env.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Секреты хранятся в переменных окружения в открытом виде." ,
                risk="Секреты видны через kubectl describe, docker inspect, "
                     "могут попасть в логи систем мониторинга или отладки." ,
                insecure="""env:
  - name: DB_PASSWORD
    value: "super_secret_password"
  - name: API_KEY
    value: "sk-1234567890abcdef" """ ,
                secure="""envFrom:
  - secretRef:
      name: app-secrets""" ,
                remediation=[
                    "Используйте Kubernetes Secrets вместо plaintext values" ,
                    "Монтируйте секреты как файлы с readOnly: true" ,
                    "Включите encryption at rest для etcd"
                ]
            )
        return None


@CheckRegistry.register
class Missing_Resource_Limits_11(BaseCheck):
    """Проверка 11: Missing Resource Limits"""
    RULE_NAME = "Missing Resource Limits"
    STANDARD = "CIS-K8S-5.2.7"
    SEVERITY = Severity.MEDIUM
    CHECK_ID = "missing_resource_limits_11"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/11_missing_resource_limits.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Не ограничены ресурсы CPU/Memory для контейнера." ,
                risk="Один контейнер может занять все ресурсы узла (DoS), "
                     "падение других приложений на узле, нестабильность кластера." ,
                insecure="""resources:
  requests:
    memory: "64Mi"
  # limits отсутствуют""" ,
                secure="""resources:
  limits:
    cpu: "500m"
    memory: "128Mi"
  requests:
    cpu: "250m"
    memory: "64Mi" """ ,
                remediation=[
                    "Укажите limits.cpu и limits.memory" ,
                    "Настройте LimitRange для namespace" ,
                    "Используйте ResourceQuota для контроля"
                ]
            )
        return None


@CheckRegistry.register
class Missing_Health_Probes_12(BaseCheck):
    """Проверка 12: Missing Health Probes"""
    RULE_NAME = "Missing Health Probes"
    STANDARD = "CIS-K8S-5.2.8"
    SEVERITY = Severity.MEDIUM
    CHECK_ID = "missing_health_probes_12"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/12_missing_health_probes.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Отсутствуют проверки здоровья (livenessProbe/readinessProbe)." ,
                risk="Трафик направляется на неработающие поды, "
                     "зависшие контейнеры не перезапускаются автоматически." ,
                insecure="""containers:
  - name: app
    # livenessProbe отсутствует
    # readinessProbe отсутствует""" ,
                secure="""containers:
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
      periodSeconds: 5""" ,
                remediation=[
                    "Добавьте livenessProbe для перезапуска зависших контейнеров" ,
                    "Добавьте readinessProbe для контроля готовности" ,
                    "Настройте startupProbe для медленно стартующих приложений"
                ]
            )
        return None


@CheckRegistry.register
class Insecure_Capabilities_Add_13(BaseCheck):
    """Проверка 13: Insecure Capabilities Add"""
    RULE_NAME = "Insecure Capabilities Add"
    STANDARD = "CIS-K8S-5.2.9"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "insecure_capabilities_13"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/13_insecure_capabilities.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Добавлены опасные Linux capabilities (SYS_ADMIN, NET_ADMIN)." ,
                risk="SYS_ADMIN позволяет монтировать ФС, менять настройки ядра. "
                     "Фактически даёт права, близкие к root." ,
                insecure="""securityContext:
  capabilities:
    add:
      - SYS_ADMIN
      - NET_ADMIN""" ,
                secure="""securityContext:
  capabilities:
    drop:
      - ALL""" ,
                remediation=[
                    "Удалите все dangerous capabilities из add" ,
                    "Используйте drop: ALL по умолчанию" ,
                    "Добавляйте только минимально необходимые capabilities"
                ]
            )
        return None


@CheckRegistry.register
class Docker_Latest_Tag_14(BaseCheck):
    """Проверка 14: Docker Latest Tag"""
    RULE_NAME = "Docker Latest Tag"
    STANDARD = "CIS-Docker-4.1"
    SEVERITY = Severity.MEDIUM
    CHECK_ID = "docker_latest_tag_14"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/14_docker_latest_tag.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Использование тега latest в Docker Compose." ,
                risk="Невозможность воспроизведения окружения, "
                     "риск получения битой или уязвимой версии при пересоздании." ,
                insecure="""services:
  web:
    image: nginx
    # или image: nginx:latest""" ,
                secure="""services:
  web:
    image: nginx:1.21.0""" ,
                remediation=[
                    "Всегда указывайте конкретную версию образа" ,
                    "Используйте SHA-хеш для production" ,
                    "Настройте Dependabot для обновления образов"
                ]
            )
        return None


# =============================================================================
# 🔹 AWS SECURITY CHECKS (15-19)
# =============================================================================

@CheckRegistry.register
class S3_Public_Read_15(BaseCheck):
    """Проверка 15: S3 Public Read"""
    RULE_NAME = "S3 Public Read"
    STANDARD = "CIS-AWS-1.13"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "s3_public_read_15"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/15_s3_public_read.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="S3 bucket доступен для публичного чтения." ,
                risk="Утечка конфиденциальных данных, логинов, ключей, "
                     "персональной информации пользователей." ,
                insecure="""BucketPolicy:
  Effect: Allow
  Principal: "*"
  Action: "s3:GetObject"
  Resource: "arn:aws:s3:::my-bucket/*" """ ,
                secure="""PublicAccessBlockConfiguration:
  BlockPublicAcls: true
  BlockPublicPolicy: true
  IgnorePublicAcls: true
  RestrictPublicBuckets: true""" ,
                remediation=[
                    "Включите S3 Block Public Access" ,
                    "Удалите политики с Principal: *" ,
                    "Используйте CloudFront с signed URLs"
                ]
            )
        return None


@CheckRegistry.register
class S3_Public_Write_16(BaseCheck):
    """Проверка 16: S3 Public Write"""
    RULE_NAME = "S3 Public Write"
    STANDARD = "CIS-AWS-1.14"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "s3_public_write_16"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/16_s3_public_write.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="S3 bucket доступен для публичной записи." ,
                risk="Злоумышленники могут загрузить вредоносное ПО, "
                     "удалить данные, использовать бакет для хостинга нелегального контента." ,
                insecure="""BucketPolicy:
  Effect: Allow
  Principal: "*"
  Action: "s3:PutObject"
  Resource: "arn:aws:s3:::my-bucket/*" """ ,
                secure="""PublicAccessBlockConfiguration:
  BlockPublicAcls: true
  BlockPublicPolicy: true
  IgnorePublicAcls: true
  RestrictPublicBuckets: true""" ,
                remediation=[
                    "Немедленно удалите политику с публичной записью" ,
                    "Включите S3 Block Public Access" ,
                    "Настройте CloudTrail для мониторинга S3 API calls"
                ]
            )
        return None


@CheckRegistry.register
class Unencrypted_EBS_17(BaseCheck):
    """Проверка 17: Unencrypted EBS"""
    RULE_NAME = "Unencrypted EBS"
    STANDARD = "CIS-AWS-2.1.1"
    SEVERITY = Severity.HIGH
    CHECK_ID = "unencrypted_ebs_17"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/17_unencrypted_ebs.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="EBS volume не зашифрован." ,
                risk="При физическом доступе к диску или снимке снапшота "
                     "данные могут быть прочитаны в открытом виде." ,
                insecure="""Type: AWS::EC2::Volume
Properties:
  Size: 100
  Encrypted: false""" ,
                secure="""Type: AWS::EC2::Volume
Properties:
  Size: 100
  Encrypted: true
  KmsKeyId: arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012""" ,
                remediation=[
                    "Включите шифрование для всех новых EBS volumes" ,
                    "Настройте default encryption для региона" ,
                    "Зашифруйте существующие volumes через snapshot copy"
                ]
            )
        return None


@CheckRegistry.register
class RDP_Open_to_Internet_18(BaseCheck):
    """Проверка 18: RDP Open to Internet"""
    RULE_NAME = "RDP Open to Internet"
    STANDARD = "CIS-AWS-5.2"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "rdp_open_to_internet_18"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/18_rdp_open_internet.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Порт RDP (3389) открыт для всего интернета." ,
                risk="Брутфорс паролей, уязвимости типа BlueKeep, "
                     "шифровальщики (ransomware), полный доступ к серверу." ,
                insecure="""SecurityGroupIngress:
  - IpProtocol: tcp
    FromPort: 3389
    ToPort: 3389
    CidrIp: 0.0.0.0/0""" ,
                secure="""SecurityGroupIngress:
  - IpProtocol: tcp
    FromPort: 3389
    ToPort: 3389
    CidrIp: 10.0.0.0/8""" ,
                remediation=[
                    "Немедленно ограничьте CIDR до доверенных IP" ,
                    "Используйте AWS Systems Manager Session Manager" ,
                    "Настройте VPN для удалённого доступа"
                ]
            )
        return None


@CheckRegistry.register
class SSH_Open_to_Internet_19(BaseCheck):
    """Проверка 19: SSH Open to Internet"""
    RULE_NAME = "SSH Open to Internet"
    STANDARD = "CIS-AWS-5.1"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "ssh_open_to_internet_19"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/19_ssh_open_internet.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Порт SSH (22) открыт для всего интернета." ,
                risk="Постоянная атака ботнетов, брутфорс, "
                     "утечка ключей, несанкционированный доступ." ,
                insecure="""SecurityGroupIngress:
  - IpProtocol: tcp
    FromPort: 22
    ToPort: 22
    CidrIp: 0.0.0.0/0""" ,
                secure="""SecurityGroupIngress:
  - IpProtocol: tcp
    FromPort: 22
    ToPort: 22
    CidrIp: 10.0.0.0/8""" ,
                remediation=[
                    "Используйте AWS Systems Manager Session Manager (без SSH)" ,
                    "Ограничьте Security Group до конкретных IP" ,
                    "Включите ключевую аутентификацию, отключите password auth"
                ]
            )
        return None


# =============================================================================
# 🔹 CLOUD STORAGE CHECKS (20-21)
# =============================================================================

@CheckRegistry.register
class Cloud_Storage_Public_20(BaseCheck):
    """Проверка 20: Cloud Storage Public (GCP)"""
    RULE_NAME = "Cloud Storage Public"
    STANDARD = "CIS-GCP-6.2.1"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "cloud_storage_public_20"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/20_gcs_public.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="GCS bucket доступен всем пользователям (allUsers)." ,
                risk="Публичный доступ к файлам, утечка данных, "
                     "несанкционированное чтение конфиденциальной информации." ,
                insecure="""bindings:
  - role: roles/storage.objectViewer
    members:
      - allUsers""" ,
                secure="""bindings:
  - role: roles/storage.objectViewer
    members:
      - user:specific@example.com""" ,
                remediation=[
                    "Удалите allUsers и allAuthenticatedUsers из IAM policies" ,
                    "Используйте Uniform bucket-level access" ,
                    "Настройте VPC Service Controls"
                ]
            )
        return None


@CheckRegistry.register
class Azure_Storage_Public_21(BaseCheck):
    """Проверка 21: Azure Storage Public"""
    RULE_NAME = "Azure Storage Public"
    STANDARD = "CIS-Azure-9.1"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "azure_storage_public_21"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/21_azure_storage_public.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Уровень доступа Azure Storage установлен в публичный." ,
                risk="Чтение данных любым пользователем интернета, "
                     "утечка конфиденциальной информации, compliance violations." ,
                insecure="""properties:
  publicAccess: Blob""" ,
                secure="""properties:
  publicAccess: None""" ,
                remediation=[
                    "Установите publicAccess: None" ,
                    "Включите 'Allow Blob anonymous access' = Disabled" ,
                    "Используйте SAS tokens с ограниченным временем жизни"
                ]
            )
        return None


# =============================================================================
# 🔹 KUBERNETES ADMIN CHECKS (22-24)
# =============================================================================

@CheckRegistry.register
class Kubernetes_Dashboard_Exposed_22(BaseCheck):
    """Проверка 22: Kubernetes Dashboard Exposed"""
    RULE_NAME = "Kubernetes Dashboard Exposed"
    STANDARD = "CIS-K8S-5.1.1"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "kubernetes_dashboard_exposed_22"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/22_dashboard_exposed.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Панель управления K8s доступна извне через LoadBalancer." ,
                risk="Если авторизация слабая, злоумышленник получит "
                     "полный контроль над кластером." ,
                insecure="""apiVersion: v1
kind: Service
metadata:
  name: kubernetes-dashboard
spec:
  type: LoadBalancer""" ,
                secure="""apiVersion: v1
kind: Service
metadata:
  name: kubernetes-dashboard
spec:
  type: ClusterIP""" ,
                remediation=[
                    "Измените тип Service на ClusterIP" ,
                    "Настройте доступ через kubectl proxy" ,
                    "Или используйте Ingress с OAuth/OIDC"
                ]
            )
        return None


@CheckRegistry.register
class Etcd_Client_Cert_Auth_23(BaseCheck):
    """Проверка 23: Etcd Client Cert Auth"""
    RULE_NAME = "Etcd Client Cert Auth"
    STANDARD = "CIS-K8S-4.1.1"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "etcd_client_cert_auth_23"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/23_etcd_client_cert.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Etcd не требует клиентские сертификаты для аутентификации." ,
                risk="Любой, кто имеет доступ к порту etcd, может "
                     "читать/писать все данные кластера." ,
                insecure="""etcd:
  client-cert-auth: false""" ,
                secure="""etcd:
  client-cert-auth: true
  cert-file: /etc/kubernetes/pki/etcd/server.crt
  key-file: /etc/kubernetes/pki/etcd/server.key""" ,
                remediation=[
                    "Включите client-cert-auth: true" ,
                    "Настройте peer-client-cert-auth для etcd cluster" ,
                    "Ограничьте доступ к порту etcd firewall"
                ]
            )
        return None


@CheckRegistry.register
class Anonymous_Auth_Enabled_24(BaseCheck):
    """Проверка 24: Anonymous Auth Enabled"""
    RULE_NAME = "Anonymous Auth Enabled"
    STANDARD = "CIS-K8S-5.1.3"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "anonymous_auth_enabled_24"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/24_anonymous_auth.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Разрешена анонимная аутентификация Kubernetes API Server." ,
                risk="Неаутентифицированные запросы к API, "
                     "возможность разведки кластера или эксплуатации уязвимостей." ,
                insecure="""kube-apiserver:
  --anonymous-auth=true""" ,
                secure="""kube-apiserver:
  --anonymous-auth=false
  --authorization-mode=Node,RBAC""" ,
                remediation=[
                    "Установите --anonymous-auth=false" ,
                    "Проверьте все API Server конфигурации" ,
                    "Включите RBAC authorization mode"
                ]
            )
        return None


# =============================================================================
# 🔹 CI/CD SECURITY CHECKS (25)
# =============================================================================

@CheckRegistry.register
class CI_CD_Plain_Text_Secrets_25(BaseCheck):
    """Проверка 25: CI/CD Plain Text Secrets"""
    RULE_NAME = "CI/CD Plain Text Secrets"
    STANDARD = "NIST-IA-5"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "cicd_plaintext_secrets_25"

    def check(self) -> SecurityReport:
        self.files_checked = ["1_Easy_test/25_cicd_plaintext_secrets.yaml"]

        if 1 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Секреты зашиты в код конфигурации CI/CD в открытом виде." ,
                risk="Попадание секретов в git-историю, "
                     "доступ к секретам у всех разработчиков с доступом к репозиторию." ,
                insecure="""# .gitlab-ci.yml
variables:
  DB_PASSWORD: "hardcoded_password"  # ❌
  API_KEY: "sk-1234567890abcdef"     # ❌""" ,
                secure="""# GitLab CI:
variables:
  DB_PASSWORD: $SECURE_DB_PASSWORD  # ✅ Из CI/CD Variables

# GitHub Actions:
env:
  PASSWORD: ${{ secrets.DB_PASSWORD }}  # ✅ Из Repository Secrets""" ,
                remediation=[
                    "Немедленно удалите все hardcoded secrets из кода" ,
                    "Используйте CI/CD platform secrets" ,
                    "Включите secret masking в логах" ,
                    "Ротируйте все скомпрометированные секреты"
                ]
            )
        return None


# =============================================================================
# 🔹 CLI ЗАПУСК
# =============================================================================

if __name__ == "__main__":
    import sys

    print("🔐 Security Auditor — Easy Level Checks\n")

    if len(sys.argv) > 1:
        if sys.argv[1] == "--list":
            print("📋 Доступные проверки Easy уровня:\n")
            for check_name , check_class in CheckRegistry.get_checks_by_level('easy').items():
                print(f"  {check_class.CHECK_ID:40} [{check_class.SEVERITY.value}]")
        else:
            check_name = sys.argv[1]
            check_class = CheckRegistry.get_check(check_name)
            if check_class:
                check = check_class()
                report = check.check()
                if report:  # ✅ Выводим только если найдена уязвимость
                    report.print_report()
                else:
                    print(f"✅ Проверка '{check_name}' пройдена — уязвимостей не найдено")
            else:
                print(f"❌ Проверка '{check_name}' не найдена!")
    else:
        reports = []
        for check_class in CheckRegistry.get_checks_by_level('easy'):
            check = check_class()
            report = check.check()
            if report:  # ✅ Собираем только отчёты с уязвимостями
                reports.append(report)
                report.print_report()

        if reports:
            CheckRegistry.print_summary(reports)
        else:
            print("\n✅ Все проверки Easy уровня пройдены — уязвимостей не найдено!\n")
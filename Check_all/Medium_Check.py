"""
🔐 Security Auditor — Medium Level Checks (26-50)
CIS Kubernetes | Docker | AWS | GCP | Azure | CI/CD
"""
from core import BaseCheck, SecurityReport, Severity, CheckRegistry

# =============================================================================
# 🔹 KUBERNETES SECURITY CHECKS (26-29)
# =============================================================================
@CheckRegistry.register
class Network_Policy_Missing_26(BaseCheck):
    """Проверка 26: Network Policy Missing"""
    RULE_NAME = "Network Policy Missing"
    STANDARD = "CIS-K8S-5.3.2"
    SEVERITY = Severity.HIGH
    CHECK_ID = "network_policy_missing_26"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-01/02-01a_pod_without_networkpolicy.yaml",
                              "2_Medium_test/02-01/02-01b_empty_networkpolicy.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Pod без соответствующего NetworkPolicy в namespace",
                risk="Отсутствие сегментации сети. Атакующий может сканировать и атаковать "
                     "другие сервисы изнутри кластера (lateral movement).",
                insecure="""# Pod без соответствующего NetworkPolicy
apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-pod
# В namespace нет NetworkPolicy, селектирующей этот под""",
                secure="""# Явный NetworkPolicy, разрешающий только необходимый трафик
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
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432""",
                remediation=[
                    "Создайте NetworkPolicy для каждого namespace",
                    "Используйте default-deny политику по умолчанию",
                    "Разрешайте только необходимый трафик между подами"
                ]
            )
        return None

@CheckRegistry.register
class Service_Account_Token_Mount_27(BaseCheck):
    """Проверка 27: Service Account Token Mount"""
    RULE_NAME = "Service Account Token Mount"
    STANDARD = "CIS-K8S-5.2.10"
    SEVERITY = Severity.HIGH
    CHECK_ID = "service_account_token_mount_27"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-02/02-02a_pod_with_sa.yaml",
                              "2_Medium_test/02-02/02-02b_serviceaccount.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Токен ServiceAccount автоматически монтируется в под (automountServiceAccountToken: true)",
                risk="Утечка токена = доступ к Kubernetes API. Возможность создания/удаления "
                     "ресурсов в кластере в зависимости от RBAC.",
                insecure="""# Токен монтируется по умолчанию
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
spec:
  serviceAccountName: default
# automountServiceAccountToken не указан (true по умолчанию)""",
                secure="""# Явное отключение авто-монтирования токена
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
automountServiceAccountToken: false
---
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
spec:
  serviceAccountName: app-sa
  automountServiceAccountToken: false  # Переопределение на уровне пода""",
                remediation=[
                    "Установите automountServiceAccountToken: false на ServiceAccount",
                    "Переопределите на уровне Pod если нужно",
                    "Используйте отдельные SA для каждого приложения"
                ]
            )
        return None

@CheckRegistry.register
class Image_from_Untrusted_Registry_28(BaseCheck):
    """Проверка 28: Image from Untrusted Registry"""
    RULE_NAME = "Image from Untrusted Registry"
    STANDARD = "NIST-SI-2"
    SEVERITY = Severity.MEDIUM
    CHECK_ID = "image_from_untrusted_registry_28"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-03/02-03a_pod_with_images.yaml",
                              "2_Medium_test/02-03/02-03b_registry_allowlist.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Используются образы из публичных/недоверенных реестров (docker.io вместо private)",
                risk="Запуск непроверенного кода. Риск supply-chain атаки. "
                     "Отсутствие аудита и сканирования уязвимостей.",
                insecure="""containers:
- name: app
  image: docker.io/randomuser/suspicious-app:latest
# Или без указания реестра (подразумевается docker.io)""",
                secure="""# Использование только доверенного приватного реестра
containers:
- name: app
  image: registry.company.internal/team/app:v1.2.3
# Дополнительно: imagePullSecrets для аутентификации
spec:
  imagePullSecrets:
  - name: registry-credentials""",
                remediation=[
                    "Используйте только доверенные приватные реестры",
                    "Настройте imagePullSecrets для аутентификации",
                    "Внедрите сканирование образов на уязвимости"
                ]
            )
        return None

@CheckRegistry.register
class Ingress_Without_TLS_29(BaseCheck):
    """Проверка 29: Ingress Without TLS"""
    RULE_NAME = "Ingress Without TLS"
    STANDARD = "CIS-K8S-5.1.7"
    SEVERITY = Severity.HIGH
    CHECK_ID = "ingress_without_tls_29"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-04/02-04_ingress_without_tls.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Ingress без tls: секции (входящий трафик не шифруется)",
                risk="Трафик передаётся в открытом виде. Перехват данных в публичных сетях. "
                     "Утечка чувствительной информации, сессионных токенов.",
                insecure="""apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: insecure-ingress
spec:
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app-svc
            port:
              number: 80
# Секция tls: отсутствует!""",
                secure="""apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secure-ingress
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - app.example.com
    secretName: app-tls-secret
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app-svc
            port:
              number: 443""",
                remediation=[
                    "Добавьте tls: секцию во все Ingress ресурсы",
                    "Используйте cert-manager для автоматических сертификатов",
                    "Настройте редирект HTTP → HTTPS"
                ]
            )
        return None

# =============================================================================
# 🔹 AWS SECURITY CHECKS (30-38)
# =============================================================================
@CheckRegistry.register
class LoadBalancer_Internal_30(BaseCheck):
    """Проверка 30: LoadBalancer Internal"""
    RULE_NAME = "LoadBalancer Internal"
    STANDARD = "CIS-AWS-5.4"
    SEVERITY = Severity.MEDIUM
    CHECK_ID = "loadbalancer_internal_30"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-05/02-05_loadbalancer_internal.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Публичный облачный LoadBalancer создан без необходимости (нет internal: true)",
                risk="Внутренний сервис доступен из интернета. Прямая атака на приложение "
                     "без необходимости обхода периметра.",
                insecure="""apiVersion: v1
kind: Service
metadata:
  name: internal-app
# Аннотация service.beta.kubernetes.io/aws-load-balancer-internal отсутствует
spec:
  type: LoadBalancer
  ports:
  - port: 443
    targetPort: 8080""",
                secure="""apiVersion: v1
kind: Service
metadata:
  name: internal-app
  annotations:
    # AWS: делаем балансировщик внутренним
    service.beta.kubernetes.io/aws-load-balancer-internal: "true"
    # GCP: internal: true
    # networking.gke.io/load-balancer-type: "Internal"
spec:
  type: LoadBalancer
  ports:
  - port: 443
    targetPort: 8080""",
                remediation=[
                    "Добавьте аннотацию для внутреннего LB",
                    "Используйте PrivateLink для доступа из других VPC",
                    "Проверьте все Service типа LoadBalancer"
                ]
            )
        return None

@CheckRegistry.register
class Security_Group_Overly_Permissive_31(BaseCheck):
    """Проверка 31: Security Group Overly Permissive"""
    RULE_NAME = "Security Group Overly Permissive"
    STANDARD = "CIS-AWS-5.3"
    SEVERITY = Severity.HIGH
    CHECK_ID = "security_group_overly_permissive_31"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-06/02-06_security_group_permissive.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Правила безопасности разрешают доступ из слишком широкой сети (CIDR /16 или шире)",
                risk="Чрезмерный доступ к ресурсу. Увеличение поверхности атаки. "
                     "Сложность контроля и аудита входящих соединений.",
                insecure="""SecurityGroupIngress:
- IpProtocol: tcp
  FromPort: 443
  ToPort: 443
  CidrIp: 10.0.0.0/16  # Слишком широкий диапазон!
# Или хуже: 0.0.0.0/0""",
                secure="""SecurityGroupIngress:
- IpProtocol: tcp
  FromPort: 443
  ToPort: 443
  CidrIp: 10.0.1.0/24  # Только нужная подсеть
# Или ссылка на другой SecurityGroup:
- IpProtocol: tcp
  FromPort: 443
  ToPort: 443
  SourceSecurityGroupId: sg-frontend""",
                remediation=[
                    "Ограничьте CIDR до конкретных подсетей",
                    "Используйте SourceSecurityGroupId вместо CIDR",
                    "Применяйте принцип наименьших привилегий"
                ]
            )
        return None

@CheckRegistry.register
class IAM_Policy_Wildcard_Service_32(BaseCheck):
    """Проверка 32: IAM Policy Wildcard Service"""
    RULE_NAME = "IAM Policy Wildcard Service"
    STANDARD = "CIS-AWS-1.17"
    SEVERITY = Severity.HIGH
    CHECK_ID = "iam_policy_wildcard_service_32"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-07/02-07_iam_policy_wildcard.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="IAM политика использует wildcard (*) в действиях (например s3:* или ec2:*)",
                risk="Избыточные права. Компрометация роли = полный доступ к сервису. "
                     "Возможность удаления данных или создания дорогих ресурсов.",
                insecure="""PolicyDocument:
  Statement:
  - Effect: Allow
    Action:
    - "s3:*"  # Все действия над S3!
    - "ec2:RunInstances"
    Resource: "*" """,
                secure="""PolicyDocument:
  Statement:
  - Effect: Allow
    Action:
    - "s3:GetObject"
    - "s3:PutObject"
    # Только необходимые действия
    Resource: "arn:aws:s3:::my-bucket/prefix/*" """,
                remediation=[
                    "Замените wildcard на конкретные действия",
                    "Ограничьте Resource до конкретных ARN",
                    "Используйте IAM Access Analyzer для аудита"
                ]
            )
        return None

@CheckRegistry.register
class KMS_Key_Rotation_Disabled_33(BaseCheck):
    """Проверка 33: KMS Key Rotation Disabled"""
    RULE_NAME = "KMS Key Rotation Disabled"
    STANDARD = "CIS-AWS-2.1.4"
    SEVERITY = Severity.MEDIUM
    CHECK_ID = "kms_key_rotation_disabled_33"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-08/02-08_kms_key_rotation.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Отключена автоматическая ротация ключей KMS (enableKeyRotation: false)",
                risk="Длительная жизнь ключа = больший ущерб при утечке. "
                     "Несоответствие требованиям безопасности (PCI-DSS, HIPAA, etc).",
                insecure="""Type: AWS::KMS::Key
Properties:
  Enabled: true
  EnableKeyRotation: false (по умолчанию)
# Или явно выключено:
  EnableKeyRotation: false""",
                secure="""Type: AWS::KMS::Key
Properties:
  Enabled: true
  EnableKeyRotation: true  # Автоматическая ротация раз в год
  Description: "Key with rotation enabled" """,
                remediation=[
                    "Включите EnableKeyRotation: true для всех ключей",
                    "Настройте мониторинг использования ключей",
                    "Регулярно аудируйте KMS ключи"
                ]
            )
        return None

@CheckRegistry.register
class CloudTrail_Logging_Disabled_34(BaseCheck):
    """Проверка 34: CloudTrail Logging Disabled"""
    RULE_NAME = "CloudTrail Logging Disabled"
    STANDARD = "CIS-AWS-3.1"
    SEVERITY = Severity.HIGH
    CHECK_ID = "cloudtrail_logging_disabled_34"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-09/02-09_cloudtrail_logging.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Логирование действий в AWS отключено или ограничено одним регионом (IsMultiRegionTrail: false)",
                risk="Невозможно отследить действия злоумышленника в других регионах. "
                     "Отсутствие аудита = нарушение требований безопасности.",
                insecure="""Type: AWS::CloudTrail::Trail
Properties:
  IsMultiRegionTrail: false  # Только один регион!
  EnableLogFileValidation: false
# S3BucketName может отсутствовать""",
                secure="""Type: AWS::CloudTrail::Trail
Properties:
  IsMultiRegionTrail: true   # Логирование всех регионов
  EnableLogFileValidation: true
  S3BucketName: !Ref CloudTrailLogsBucket
  KMSKeyId: !Ref TrailKMSKey
  IncludeGlobalServiceEvents: true
  IsOrganizationTrail: true  # Если используется AWS Organizations""",
                remediation=[
                    "Включите multi-region trail для всех аккаунтов",
                    "Включите валидацию логов",
                    "Шифруйте логи через KMS"
                ]
            )
        return None

@CheckRegistry.register
class VPC_Flow_Logs_Disabled_35(BaseCheck):
    """Проверка 35: VPC Flow Logs Disabled"""
    RULE_NAME = "VPC Flow Logs Disabled"
    STANDARD = "CIS-AWS-3.4"
    SEVERITY = Severity.MEDIUM
    CHECK_ID = "vpc_flow_logs_disabled_35"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-10/02-10a_vpc_without_flowlogs.yaml",
                              "2_Medium_test/02-10/02-10b_flowlog_resource.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Не включены Flow Logs для мониторинга сетевого трафика VPC",
                risk="Слепая зона в мониторинге сети. Невозможно выявить сканирование, "
                     "эксфильтрацию данных или C2-трафик.",
                insecure="""Type: AWS::EC2::VPC
Properties:
  CidrBlock: 10.0.0.0/16
# Нет связанного ресурса AWS::EC2::FlowLog""",
                secure="""# VPC с включёнными Flow Logs
Type: AWS::EC2::VPC
Properties:
  CidrBlock: 10.0.0.0/16
---
Type: AWS::EC2::FlowLog
Properties:
  ResourceId: !Ref MyVPC
  ResourceType: VPC
  TrafficType: ALL  # Или REJECT для экономии
  LogDestinationType: cloud-watch-logs  # или s3
  LogDestination: !Ref LogGroupArn
# Опционально: фильтрация трафика""",
                remediation=[
                    "Включите Flow Logs для всех VPC",
                    "Настройте отправку в CloudWatch Logs или S3",
                    "Создайте алерты на аномальный трафик"
                ]
            )
        return None

@CheckRegistry.register
class RDS_Publicly_Accessible_36(BaseCheck):
    """Проверка 36: RDS Publicly Accessible"""
    RULE_NAME = "RDS Publicly Accessible"
    STANDARD = "CIS-AWS-2.3.1"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "rds_publicly_accessible_36"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-11/02-11_rds_publicly_accessible.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="База данных RDS доступна из публичной сети (PubliclyAccessible: true)",
                risk="Прямой доступ к базе данных из интернета. Риск взлома, "
                     "утечки данных, атак типа SQL injection и ransomware.",
                insecure="""Type: AWS::RDS::DBInstance
Properties:
  PubliclyAccessible: true  # БД видна из интернета!
  DBInstanceClass: db.t3.micro""",
                secure="""Type: AWS::RDS::DBInstance
Properties:
  PubliclyAccessible: false  # Только внутри VPC
  DBSubnetGroupName: !Ref PrivateSubnets
  VpcSecurityGroups:
  - !Ref DatabaseSecurityGroup""",
                remediation=[
                    "Установите PubliclyAccessible: false",
                    "Разместите БД в приватных подсетях",
                    "Используйте bastion host или Systems Manager для доступа"
                ]
            )
        return None

@CheckRegistry.register
class RDS_Encryption_Disabled_37(BaseCheck):
    """Проверка 37: RDS Encryption Disabled"""
    RULE_NAME = "RDS Encryption Disabled"
    STANDARD = "CIS-AWS-2.3.2"
    SEVERITY = Severity.HIGH
    CHECK_ID = "rds_encryption_disabled_37"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-12/02-12_rds_encryption.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Данные на диске RDS не зашифрованы (StorageEncrypted: false)",
                risk="Раскрытие данных при доступе к хранилищу (data at rest). "
                     "Нарушение требований комплаенса (GDPR, PCI-DSS).",
                insecure="""Type: AWS::RDS::DBInstance
Properties:
  StorageEncrypted: false  # Данные не шифруются!
# Или поле отсутствует (по умолчанию false)""",
                secure="""Type: AWS::RDS::DBInstance
Properties:
  StorageEncrypted: true
  KmsKeyId: !Ref DatabaseKMSKey  # CMK для управления ключом
# Шифруются: данные, логи, снапшоты, реплики""",
                remediation=[
                    "Включите шифрование для всех RDS инстансов",
                    "Используйте KMS ключи для управления",
                    "Зашифруйте существующие БД через snapshot copy"
                ]
            )
        return None

# =============================================================================
# 🔹 DATABASE SECURITY CHECKS (38-40)
# =============================================================================
@CheckRegistry.register
class Redis_Without_Password_38(BaseCheck):
    """Проверка 38: Redis Without Password"""
    RULE_NAME = "Redis Without Password"
    STANDARD = "CIS-Database-4.1"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "redis_without_password_38"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-13/02-13_redis_config.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Redis работает без аутентификации (requirepass не установлен)",
                risk="Неавторизованный доступ к кэшу/данным. Возможность "
                     "выполнения LUA-скриптов, очистки данных, использования "
                     "Redis для атак на другие системы.",
                insecure="""# redis.conf
port 6379
bind 0.0.0.0
# requirepass не установлен!
# Любой клиент может подключиться без пароля""",
                secure="""# redis.conf
port 6379
bind 127.0.0.1  # Или приватный интерфейс
requirepass ${REDIS_PASSWORD}  # Сложный пароль из секретов
# Дополнительно:
rename-command FLUSHALL ""
rename-command CONFIG "" """,
                remediation=[
                    "Установите requirepass с сложным паролем",
                    "Ограничьте bind до приватных интерфейсов",
                    "Отключите опасные команды через rename-command"
                ]
            )
        return None

@CheckRegistry.register
class MongoDB_Without_Auth_39(BaseCheck):
    """Проверка 39: MongoDB Without Auth"""
    RULE_NAME = "MongoDB Without Auth"
    STANDARD = "CIS-Database-4.2"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "mongodb_without_auth_39"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-14/02-14_mongodb_config.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="MongoDB работает без включения авторизации (security.authorization: disabled)",
                risk="Любой клиент может получить полный доступ к БД. "
                     "Утечка данных, модификация, удаление, ransomware-атаки.",
                insecure="""# mongod.conf
security:
  authorization: disabled  # Аутентификация выключена!
# Или поле отсутствует (по умолчанию disabled)""",
                secure="""# mongod.conf
security:
  authorization: enabled  # Включаем аутентификацию
# Создаём пользователя с необходимыми правами:
# db.createUser({user: "app", pwd: "...", roles: ["readWrite"]})
net:
  bindIp: 127.0.0.1,10.0.1.5  # Ограничиваем интерфейсы""",
                remediation=[
                    "Включите authorization: enabled",
                    "Создайте пользователей с минимальными правами",
                    "Ограничьте bindIp до приватных адресов"
                ]
            )
        return None

@CheckRegistry.register
class Elasticsearch_Public_Access_40(BaseCheck):
    """Проверка 40: Elasticsearch Public Access"""
    RULE_NAME = "Elasticsearch Public Access"
    STANDARD = "CIS-AWS-2.4.1"
    SEVERITY = Severity.HIGH
    CHECK_ID = "elasticsearch_public_access_40"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-15/02-15_elasticsearch_access.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Кластер Elasticsearch доступен публично (accessPolicies позволяют * principal)",
                risk="Публичный доступ к поисковому кластеру. Утечка логов, "
                     "содержащих персональные данные, токены, ключи.",
                insecure="""accessPolicies:
  Version: "2012-10-17"
  Statement:
  - Effect: Allow
    Principal: "*"  # Любой пользователь!
    Action: "es:*"
    Resource: "arn:aws:es:region:account:domain/logs/*" """,
                secure="""accessPolicies:
  Version: "2012-10-17"
  Statement:
  - Effect: Allow
    Principal:
      AWS: "arn:aws:iam::account:role/app-role"  # Только доверенная роль
    Action:
    - "es:ESHttpGet"
    - "es:ESHttpPost"
    Resource: "arn:aws:es:region:account:domain/logs/*"
# Дополнительно: VPC endpoint, IAM auth, Cognito""",
                remediation=[
                    "Ограничьте Principal до конкретных IAM ролей",
                    "Используйте VPC endpoint для доступа",
                    "Включите IAM auth или Cognito"
                ]
            )
        return None

# =============================================================================
# 🔹 SERVERLESS & CLOUD FUNCTIONS (41-42)
# =============================================================================
@CheckRegistry.register
class Lambda_Function_Public_Trigger_41(BaseCheck):
    """Проверка 41: Lambda Function Public Trigger"""
    RULE_NAME = "Lambda Function Public Trigger"
    STANDARD = "CIS-AWS-2.5.1"
    SEVERITY = Severity.HIGH
    CHECK_ID = "lambda_function_public_trigger_41"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-16/02-16a_lambda_function.yaml",
                              "2_Medium_test/02-16/02-16b_lambda_permission.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Lambda-функция вызывается публично без авторизации (Principal: *)",
                risk="Неавторизованный вызов функции. Риск исчерпания квот, "
                     "выполнения вредоносных операций, утечки данных.",
                insecure="""# Lambda Permission для публичного API Gateway
Type: AWS::Lambda::Permission
Properties:
  FunctionName: !Ref MyFunction
  Action: lambda:InvokeFunction
  Principal: "*"  # Любой может вызвать!
  SourceArn: !GetAtt ApiGateway.StageArn""",
                secure="""# Ограничиваем вызов только конкретным API Gateway
Type: AWS::Lambda::Permission
Properties:
  FunctionName: !Ref MyFunction
  Action: lambda:InvokeFunction
  Principal: apigateway.amazonaws.com
  SourceArn: !Sub "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${ApiGateway}/*"
# Дополнительно: авторизация на уровне API Gateway (IAM, Cognito, Lambda Authorizer)""",
                remediation=[
                    "Ограничьте Principal до конкретного сервиса",
                    "Добавьте SourceArn для ограничения источника",
                    "Включите авторизацию на уровне API Gateway"
                ]
            )
        return None

@CheckRegistry.register
class Cloud_Function_HTTP_Without_Auth_42(BaseCheck):
    """Проверка 42: Cloud Function HTTP Without Auth"""
    RULE_NAME = "Cloud Function HTTP Without Auth"
    STANDARD = "CIS-GCP-6.6.1"
    SEVERITY = Severity.HIGH
    CHECK_ID = "cloud_function_http_without_auth_42"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-17/02-17a_cloud_function.yaml",
                              "2_Medium_test/02-17/02-17b_function_iam.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="HTTP Cloud Function доступна без аутентификации (allUsers имеет роль cloudfunctions.invoker)",
                risk="Функция доступна любому пользователю интернета. "
                     "Риск атак, утечки данных, финансовых потерь.",
                insecure="""# Cloud Function с публичным триггером
type: google.cloud.functions.v1.Function
properties:
  httpsTrigger: {}
# Нет ограничения IAM: allUsers имеет роль cloudfunctions.invoker""",
                secure="""# Убираем публичный доступ и настраиваем IAM
# 1. Удаляем binding для allUsers:
# gcloud functions remove-iam-policy-binding FUNC \\
#   --member="allUsers" --role="roles/cloudfunctions.invoker"
# 2. Добавляем только доверенные сервис-аккаунты:
- role: roles/cloudfunctions.invoker
  members:
  - serviceAccount:backend-sa@project.iam.gserviceaccount.com""",
                remediation=[
                    "Удалите allUsers из IAM policy",
                    "Добавьте только доверенные service accounts",
                    "Используйте IAM авторизацию для всех функций"
                ]
            )
        return None

# =============================================================================
# 🔹 AZURE SECURITY CHECKS (43-44)
# =============================================================================
@CheckRegistry.register
class Azure_NSG_Any_Any_Rule_43(BaseCheck):
    """Проверка 43: Azure NSG Any-Any Rule"""
    RULE_NAME = "Azure NSG Any-Any Rule"
    STANDARD = "CIS-Azure-7.1"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "azure_nsg_any_any_rule_43"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-18/02-18_azure_nsg.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Правило NSG разрешает весь трафик отовсюду (source: *, dest: *, port: *)",
                risk="Полное отсутствие контроля сетевого трафика. "
                     "Любой хост может подключиться к любому сервису.",
                insecure="""securityRules:
- name: AllowAll
  properties:
    protocol: "*"
    sourceAddressPrefix: "*"      # Любой источник
    destinationAddressPrefix: "*" # Любое назначение
    sourcePortRange: "*"
    destinationPortRange: "*"     # Любой порт
    access: Allow
    direction: Inbound""",
                secure="""securityRules:
- name: AllowHTTPS
  properties:
    protocol: Tcp
    sourceAddressPrefix: "10.0.0.0/8"  # Только доверенная сеть
    destinationAddressPrefix: "*"
    sourcePortRange: "*"
    destinationPortRange: "443"        # Только HTTPS
    access: Allow
    direction: Inbound
# Принцип: по умолчанию Deny, разрешать только необходимое""",
                remediation=[
                    "Удалите правила Any-Any",
                    "Разрешайте только необходимые порты и IP",
                    "Используйте принцип default deny"
                ]
            )
        return None

@CheckRegistry.register
class Azure_SQL_Firewall_Open_44(BaseCheck):
    """Проверка 44: Azure SQL Firewall Open"""
    RULE_NAME = "Azure SQL Firewall Open"
    STANDARD = "CIS-Azure-9.4"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "azure_sql_firewall_open_44"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-19/02-19_azure_sql_firewall.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Брандмауэр Azure SQL разрешает подключения отовсюду (0.0.0.0 - 255.255.255.255)",
                risk="База данных доступна из любой точки мира. "
                     "Высокий риск взлома и утечки данных.",
                insecure="""Type: Microsoft.Sql/servers/firewallRules
Properties:
  startIpAddress: "0.0.0.0"
  endIpAddress: "255.255.255.255"  # Разрешён весь интернет!""",
                secure="""Type: Microsoft.Sql/servers/firewallRules
Properties:
  startIpAddress: "10.0.1.0"   # Только доверенный диапазон
  endIpAddress: "10.0.1.255"
# Или использование Private Endpoint для доступа из VNet:
Type: Microsoft.Sql/servers/privateEndpointConnections
Properties:
  privateLinkServiceConnectionState:
    status: Approved""",
                remediation=[
                    "Ограничьте firewall rules до конкретных IP",
                    "Используйте Private Endpoint для доступа",
                    "Включите Advanced Threat Protection"
                ]
            )
        return None

# =============================================================================
# 🔹 CI/CD SECURITY CHECKS (45-46)
# =============================================================================
@CheckRegistry.register
class CI_CD_Pipeline_Without_Approval_45(BaseCheck):
    """Проверка 45: CI/CD Pipeline Without Approval"""
    RULE_NAME = "CI/CD Pipeline Without Approval"
    STANDARD = "NIST-AC-3"
    SEVERITY = Severity.HIGH
    CHECK_ID = "ci_cd_pipeline_without_approval_45"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-20/02-20_gitlab_pipeline.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Развёртывание в production происходит автоматически (нет when: manual или approval)",
                risk="Отсутствие человеческого контроля перед продакшеном. "
                     "Риск инцидентов, уязвимостей, несанкционированных изменений.",
                insecure="""# .gitlab-ci.yml
deploy-production:
  stage: deploy
  script:
  - ./deploy.sh production
# Нет when: manual или approval rule!
# Изменение в main сразу деплоится в prod""",
                secure="""# .gitlab-ci.yml
deploy-production:
  stage: deploy
  script:
  - ./deploy.sh production
  when: manual  # Требуется ручной запуск
# Или с approval:
  rules:
  - if: $CI_COMMIT_BRANCH == "main"
    when: manual
  environment:
    name: production
# Дополнительно: защита ветки main, required approvals в MR""",
                remediation=[
                    "Добавьте when: manual для production деплоя",
                    "Настройте required approvals в merge requests",
                    "Защитите main ветку от прямых пушей"
                ]
            )
        return None

@CheckRegistry.register
class GitHub_Actions_Without_Pin_46(BaseCheck):
    """Проверка 46: GitHub Actions Without Pin"""
    RULE_NAME = "GitHub Actions Without Pin"
    STANDARD = "CIS-GitHub-5.1"
    SEVERITY = Severity.MEDIUM
    CHECK_ID = "github_actions_without_pin_46"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-21/02-21_github_actions.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Actions используются по тегу/ветке, а не по хешу (uses: actions/checkout@v2 вместо SHA)",
                risk="Supply-chain атака через компрометацию action. "
                     "Непредсказуемое поведение пайплайна при обновлении тега.",
                insecure="""# .github/workflows/ci.yml
jobs:
  build:
    steps:
    - uses: actions/checkout@v2        # Тег может измениться!
    - uses: some/user-action@main      # Ветка может быть обновлена""",
                secure="""# .github/workflows/ci.yml
jobs:
  build:
    steps:
    # Фиксируем action по полному хешу коммита
    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
    - uses: some/user-action@abc123def456...  # Полный SHA
# Дополнительно: Dependabot для обновления actions, аудит зависимостей""",
                remediation=[
                    "Используйте полные SHA хеши для всех actions",
                    "Настройте Dependabot для обновления зависимостей",
                    "Аудируйте используемые actions регулярно"
                ]
            )
        return None

# =============================================================================
# 🔹 CONTAINER & KUBERNETES CHECKS (47-48)
# =============================================================================
@CheckRegistry.register
class Docker_Socket_Mounted_47(BaseCheck):
    """Проверка 47: Docker Socket Mounted"""
    RULE_NAME = "Docker Socket Mounted"
    STANDARD = "CIS-Docker-5.31"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "docker_socket_mounted_47"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-22/02-22_docker_socket.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="В контейнер примонтирован Docker socket (/var/run/docker.sock)",
                risk="Полный контроль над хостом через Docker API. "
                     "Container escape, запуск майнеров, кража данных.",
                insecure="""services:
  app:
    image: myapp
    volumes:
    - /var/run/docker.sock:/var/run/docker.sock  # Опасно!
# Или в Kubernetes:
volumes:
- name: docker-sock
  hostPath:
    path: /var/run/docker.sock""",
                secure="""# Избегать монтирования docker.sock
# Альтернативы:
# 1. Использовать Kaniko/Buildah для сборки образов в K8s
# 2. Использовать Docker-in-Docker с осторожностью (не для прода)
# 3. Вынести сборку в отдельный CI-раннер с изоляцией
services:
  app:
    image: myapp
    # volumes: без docker.sock""",
                remediation=[
                    "Удалите монтирование docker.sock",
                    "Используйте Kaniko/Buildah для сборки в K8s",
                    "Вынесите сборку в изолированный CI-раннер"
                ]
            )
        return None

@CheckRegistry.register
class Kubernetes_Pod_Security_Policy_48(BaseCheck):
    """Проверка 48: Kubernetes Pod Security Policy"""
    RULE_NAME = "Kubernetes Pod Security Policy"
    STANDARD = "CIS-K8S-5.2.13"
    SEVERITY = Severity.HIGH
    CHECK_ID = "kubernetes_pod_security_policy_48"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-23/02-23a_pod.yaml",
                              "2_Medium_test/02-23/02-23b_podsecuritypolicy.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Не применяются политики безопасности подов (отсутствие PSP или PodSecurityStandard)",
                risk="Отсутствие контроля за настройками безопасности подов. "
                     "Риск запуска привилегированных контейнеров, escape на хост.",
                insecure="""# В кластере нет PodSecurityPolicy / PodSecurity Admission
# Или под создаётся без ограничений:
apiVersion: v1
kind: Pod
metadata:
  name: unrestricted-pod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true  # Нет PSP, который бы это запретил""",
                secure="""# Включить Pod Security Admission (K8s 1.23+)
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
# Или использовать OPA/Gatekeeper для сложных политик
# Или (устарело, но ещё работает) PodSecurityPolicy ресурс""",
                remediation=[
                    "Включите Pod Security Admission на namespace",
                    "Используйте OPA/Gatekeeper для кастомных политик",
                    "Аудируйте все поды на нарушения security context"
                ]
            )
        return None

# =============================================================================
# 🔹 INFRASTRUCTURE AS CODE CHECKS (49-50)
# =============================================================================
@CheckRegistry.register
class Helm_Chart_Without_Values_Validation_49(BaseCheck):
    """Проверка 49: Helm Chart Without Values Validation"""
    RULE_NAME = "Helm Chart Without Values Validation"
    STANDARD = "NIST-CM-6"
    SEVERITY = Severity.MEDIUM
    CHECK_ID = "helm_chart_without_values_validation_49"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-24/02-24a_values.yaml",
                              "2_Medium_test/02-24/02-24b_values_schema.json"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Отсутствует валидация значений Helm chart (нет values.schema.json)",
                risk="Ошибки конфигурации, уязвимые настройки, сложность "
                     "аудита и контроля за параметрами чарта.",
                insecure="""# values.yaml без schema validation
replicaCount: 3
image:
  repository: nginx
  tag: latest  # Опасный тег, но нет валидации!
security:
  runAsRoot: true  # Не проверяется, что должно быть false""",
                secure="""# values.schema.json для валидации
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "properties": {
    "image": {
      "properties": {
        "tag": {
          "type": "string",
          "pattern": "^v?\\d+\\.\\d+\\.\\d+$",  # Только семантические версии
          "not": { "pattern": "latest" }
        }
      }
    },
    "security": {
      "properties": {
        "runAsRoot": { "const": false }
      }
    }
  }
}
# Helm автоматически валидирует values.yaml при установке""",
                remediation=[
                    "Добавьте values.schema.json в chart",
                    "Валидируйте критические параметры безопасности",
                    "Блокируйте опасные значения через schema"
                ]
            )
        return None

@CheckRegistry.register
class Terraform_State_Remote_Without_Lock_50(BaseCheck):
    """Проверка 50: Terraform State Remote Without Lock"""
    RULE_NAME = "Terraform State Remote Without Lock"
    STANDARD = "CIS-TF-2.1"
    SEVERITY = Severity.HIGH
    CHECK_ID = "terraform_state_remote_without_lock_50"

    def check(self) -> SecurityReport:
        self.files_checked = ["2_Medium_test/02-25/02-25a_backend.tf",
                              "2_Medium_test/02-25/02-25b_dynamodb.tf"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Удалённый state Terraform без блокировки (S3 backend без dynamodb_table)",
                risk="Повреждение state при параллельном запуске terraform apply. "
                     "Потеря управления ресурсами, дублирование, удаление.",
                insecure="""# backend.tf
terraform {
  backend "s3" {
    bucket = "my-terraform-state"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
    # dynamodb_table не указан = нет locking!
  }
}""",
                secure="""# backend.tf с блокировкой через DynamoDB
terraform {
  backend "s3" {
    bucket         = "my-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-locks"  # Включает state locking
    encrypt        = true
  }
}
# DynamoDB таблица должна иметь partition key: LockID (String)""",
                remediation=[
                    "Добавьте dynamodb_table для state locking",
                    "Включите шифрование state файла",
                    "Настройте версионирование S3 bucket"
                ]
            )
        return None

# =============================================================================
# 🔹 CLI ЗАПУСК
# =============================================================================
if __name__ == "__main__":
    import sys
    print("🔐 Security Auditor — Medium Level Checks\n")

    if len(sys.argv) > 1:
        if sys.argv[1] == "--list":
            print("📋 Доступные проверки Medium уровня:\n")
            for check_name, check_class in CheckRegistry.get_checks_by_level('medium').items():
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
        for check_class in CheckRegistry.get_checks_by_level('medium'):
            check = check_class()
            report = check.check()
            if report:  # ✅ Собираем только отчёты с уязвимостями
                reports.append(report)
                report.print_report()

        if reports:
            CheckRegistry.print_summary(reports)
        else:
            print("\n✅ Все проверки Medium уровня пройдены — уязвимостей не найдено!\n")
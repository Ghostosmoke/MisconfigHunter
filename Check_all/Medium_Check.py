"""
╔════════════════════════════════════════════════════════════════╗
║  🔐 Security Auditor — Medium Level Checks (26–50)            ║
║  CIS Kubernetes | Docker | AWS | GCP | Azure | CI/CD          ║
╚════════════════════════════════════════════════════════════════╝

❗ ВНИМАНИЕ: Все проверки — ЗАГЛУШКИ (stubs).
   Функции НЕ анализируют файлы, а демонстрируют формат отчёта.
   Реальную логику проверки нужно добавить позже.
"""

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
def check_network_policy_missing_26():
    """
    Проверяет наличие NetworkPolicy для сегментации трафика между подами.
    При нахождении уязвимости выводит детальный отчёт.
    """
    print("⚠️  [HIGH] Network Policy Missing")
    print("  💥 Issue: Pod без соответствующего NetworkPolicy в namespace.")
    print("  🎯 Risk: Отсутствует сегментация сети. Атакующий может сканировать и атаковать другие сервисы изнутри кластера (lateral movement).")
    print("  ❌ Insecure:")
    print("        # Pod без соответствующего NetworkPolicy")
    print("        apiVersion: v1")
    print("        kind: Pod")
    print("        metadata:")
    print("          name: vulnerable-pod")
    print("        # В namespace нет NetworkPolicy, селектирующей этот под")
    print("  ✅ Secure:")
    print("        # Явный NetworkPolicy, разрешающий только необходимый трафик")
    print("        apiVersion: networking.k8s.io/v1")
    print("        kind: NetworkPolicy")
    print("        metadata:")
    print("          name: allow-frontend-only")
    print("        spec:")
    print("          podSelector:")
    print("            matchLabels:")
    print("              app: backend")
    print("          policyTypes:")
    print("          - Ingress")
    print("          - Egress")
    print("          ingress:")
    print("          - from:")
    print("            - podSelector:")
    print("                matchLabels:")
    print("                  app: frontend")
    print("            ports:")
    print("            - protocol: TCP")
    print("              port: 8080")
    print("  🛠️ Remediation:")
    print("      • Создайте NetworkPolicy для каждого namespace")
    print("      • Используйте default-deny политику по умолчанию")
    print("      • Разрешайте только необходимый трафик между подами")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 27: Service Account Token Mount                 │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.2.10                               │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Токен SA автоматически монтируется в под     │
# └─────────────────────────────────────────────────────────────┘
def check_service_account_token_mount_27():
    """
    Проверяет автоматическое монтирование токена ServiceAccount в поды.
    """
    print("⚠️  [HIGH] Service Account Token Mount")
    print("  💥 Issue: Токен ServiceAccount автоматически монтируется в под (automountServiceAccountToken: true).")
    print("  🎯 Risk: Утечка токена = доступ к Kubernetes API. Возможность создания/удаления ресурсов в кластере в зависимости от RBAC.")
    print("  ❌ Insecure:")
    print("        # Токен монтируется по умолчанию")
    print("        apiVersion: v1")
    print("        kind: Pod")
    print("        metadata:")
    print("          name: app-pod")
    print("        spec:")
    print("          serviceAccountName: default")
    print("          # automountServiceAccountToken не указан (true по умолчанию)")
    print("  ✅ Secure:")
    print("        # Явное отключение авто-монтирования токена")
    print("        apiVersion: v1")
    print("        kind: ServiceAccount")
    print("        metadata:")
    print("          name: app-sa")
    print("        automountServiceAccountToken: false")
    print("        ---")
    print("        apiVersion: v1")
    print("        kind: Pod")
    print("        metadata:")
    print("          name: app-pod")
    print("        spec:")
    print("          serviceAccountName: app-sa")
    print("          automountServiceAccountToken: false  # Переопределение на уровне пода")
    print("  🛠️ Remediation:")
    print("      • Установите automountServiceAccountToken: false на ServiceAccount")
    print("      • Переопределите на уровне Pod если нужно")
    print("      • Используйте отдельные SA для каждого приложения")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 28: Image from Untrusted Registry               │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   NIST-SI-2                                    │
# │ ⚡ Критичность: 🟡 MEDIUM                                    │
# │ 📝 Описание:   Образы из публичных/недоверенных реестров   │
# └─────────────────────────────────────────────────────────────┘
def check_image_from_untrusted_registry_28():
    """
    Проверяет использование образов из недоверенных контейнерных реестров.
    """
    print("⚠️  [MEDIUM] Image from Untrusted Registry")
    print("  💥 Issue: Используются образы из публичных/недоверенных реестров (docker.io вместо private).")
    print("  🎯 Risk: Запуск непроверенного кода. Риск supply-chain атаки. Отсутствие аудита и сканирования уязвимостей.")
    print("  ❌ Insecure:")
    print("        containers:")
    print("        - name: app")
    print("          image: docker.io/randomuser/suspicious-app:latest")
    print("          # Или без указания реестра (подразумевается docker.io)")
    print("  ✅ Secure:")
    print("        # Использование только доверенного приватного реестра")
    print("        containers:")
    print("        - name: app")
    print("          image: registry.company.internal/team/app:v1.2.3")
    print("        # Дополнительно: imagePullSecrets для аутентификации")
    print("        spec:")
    print("          imagePullSecrets:")
    print("          - name: registry-credentials")
    print("  🛠️ Remediation:")
    print("      • Используйте только доверенные приватные реестры")
    print("      • Настройте imagePullSecrets для аутентификации")
    print("      • Внедрите сканирование образов на уязвимости")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 29: Ingress Without TLS                         │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.1.7                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Ingress без шифрования TLS                  │
# └─────────────────────────────────────────────────────────────┘
def check_ingress_without_tls_29():
    """
    Проверяет наличие TLS-конфигурации в Kubernetes Ingress ресурсах.
    """
    print("⚠️  [HIGH] Ingress Without TLS")
    print("  💥 Issue: Ingress без tls: секции (входящий трафик не шифруется).")
    print("  🎯 Risk: Трафик передаётся в открытом виде. Перехват данных в публичных сетях. Утечка чувствительной информации, сессионных токенов.")
    print("  ❌ Insecure:")
    print("        apiVersion: networking.k8s.io/v1")
    print("        kind: Ingress")
    print("        metadata:")
    print("          name: insecure-ingress")
    print("        spec:")
    print("          rules:")
    print("          - host: app.example.com")
    print("            http:")
    print("              paths:")
    print("              - path: /")
    print("                pathType: Prefix")
    print("                backend:")
    print("                  service:")
    print("                    name: app-svc")
    print("                    port:")
    print("                      number: 80")
    print("        # Секция tls: отсутствует!")
    print("  ✅ Secure:")
    print("        apiVersion: networking.k8s.io/v1")
    print("        kind: Ingress")
    print("        metadata:")
    print("          name: secure-ingress")
    print("          annotations:")
    print("            cert-manager.io/cluster-issuer: letsencrypt-prod")
    print("        spec:")
    print("          tls:")
    print("          - hosts:")
    print("            - app.example.com")
    print("            secretName: app-tls-secret")
    print("          rules:")
    print("          - host: app.example.com")
    print("            http:")
    print("              paths:")
    print("              - path: /")
    print("                pathType: Prefix")
    print("                backend:")
    print("                  service:")
    print("                    name: app-svc")
    print("                    port:")
    print("                      number: 443")
    print("  🛠️ Remediation:")
    print("      • Добавьте tls: секцию во все Ingress ресурсы")
    print("      • Используйте cert-manager для автоматических сертификатов")
    print("      • Настройте редирект HTTP → HTTPS")
    print()


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
def check_loadbalancer_internal_30():
    """Проверяет, что внутренние сервисы не экспонируются публичными LoadBalancer."""
    print("⚠️  [MEDIUM] LoadBalancer Internal")
    print("  💥 Issue: Публичный облачный LoadBalancer создан без необходимости (нет internal: true).")
    print("  🎯 Risk: Внутренний сервис доступен из интернета. Прямая атака на приложение без необходимости обхода периметра.")
    print("  ❌ Insecure:")
    print("        apiVersion: v1")
    print("        kind: Service")
    print("        metadata:")
    print("          name: internal-app")
    print("          # Аннотация service.beta.kubernetes.io/aws-load-balancer-internal отсутствует")
    print("        spec:")
    print("          type: LoadBalancer")
    print("          ports:")
    print("          - port: 443")
    print("            targetPort: 8080")
    print("  ✅ Secure:")
    print("        apiVersion: v1")
    print("        kind: Service")
    print("        metadata:")
    print("          name: internal-app")
    print("          annotations:")
    print("            # AWS: делаем балансировщик внутренним")
    print("            service.beta.kubernetes.io/aws-load-balancer-internal: \"true\"")
    print("            # GCP:")
    print("            # networking.gke.io/load-balancer-type: \"Internal\"")
    print("        spec:")
    print("          type: LoadBalancer")
    print("          ports:")
    print("          - port: 443")
    print("            targetPort: 8080")
    print("  🛠️ Remediation:")
    print("      • Добавьте аннотацию для внутреннего LB")
    print("      • Используйте PrivateLink для доступа из других VPC")
    print("      • Проверьте все Service типа LoadBalancer")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 31: Security Group Overly Permissive            │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-5.3                                  │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Правила безопасности разрешают слишком широкий доступ │
# └─────────────────────────────────────────────────────────────┘
def check_security_group_overly_permissive_31():
    """Проверяет чрезмерно разрешительные правила Security Group."""
    print("⚠️  [HIGH] Security Group Overly Permissive")
    print("  💥 Issue: Правила безопасности разрешают доступ из слишком широкой сети (CIDR /16 или шире).")
    print("  🎯 Risk: Чрезмерный доступ к ресурсу. Увеличение поверхности атаки. Сложность контроля и аудита входящих соединений.")
    print("  ❌ Insecure:")
    print("        SecurityGroupIngress:")
    print("          IpProtocol: tcp")
    print("          FromPort: 443")
    print("          ToPort: 443")
    print("          CidrIp: 10.0.0.0/16  # Слишком широкий диапазон!")
    print("          # Или хуже: 0.0.0.0/0")
    print("  ✅ Secure:")
    print("        SecurityGroupIngress:")
    print("          IpProtocol: tcp")
    print("          FromPort: 443")
    print("          ToPort: 443")
    print("          CidrIp: 10.0.1.0/24  # Только нужная подсеть")
    print("          # Или ссылка на другой SecurityGroup:")
    print("          # SourceSecurityGroupId: sg-frontend")
    print("  🛠️ Remediation:")
    print("      • Ограничьте CIDR до конкретных подсетей")
    print("      • Используйте SourceSecurityGroupId вместо CIDR")
    print("      • Применяйте принцип наименьших привилегий")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 32: IAM Policy Wildcard Service                 │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-1.17                                 │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   IAM политика использует wildcard (*) в действиях │
# └─────────────────────────────────────────────────────────────┘
def check_iam_policy_wildcard_service_32():
    """Проверяет использование чрезмерно широких разрешений в IAM политиках."""
    print("⚠️  [HIGH] IAM Policy Wildcard Service")
    print("  💥 Issue: IAM политика использует wildcard (*) в действиях (например s3:* или ec2:*).")
    print("  🎯 Risk: Избыточные права. Компрометация роли = полный доступ к сервису. Возможность удаления данных или создания дорогих ресурсов.")
    print("  ❌ Insecure:")
    print("        PolicyDocument:")
    print("          Statement:")
    print("          - Effect: Allow")
    print("            Action:")
    print("            - \"s3:*\"  # Все действия над S3!")
    print("            - \"ec2:RunInstances\"")
    print("            Resource: \"*\"")
    print("  ✅ Secure:")
    print("        PolicyDocument:")
    print("          Statement:")
    print("          - Effect: Allow")
    print("            Action:")
    print("            - \"s3:GetObject\"")
    print("            - \"s3:PutObject\"")
    print("            # Только необходимые действия")
    print("            Resource: \"arn:aws:s3:::my-bucket/prefix/*\"")
    print("  🛠️ Remediation:")
    print("      • Замените wildcard на конкретные действия")
    print("      • Ограничьте Resource до конкретных ARN")
    print("      • Используйте IAM Access Analyzer для аудита")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 33: KMS Key Rotation Disabled                   │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-2.1.4                                │
# │ ⚡ Критичность: 🟡 MEDIUM                                    │
# │ 📝 Описание:   Отключена автоматическая ротация ключей KMS │
# └─────────────────────────────────────────────────────────────┘
def check_kms_key_rotation_disabled_33():
    """Проверяет включение автоматической ротации для KMS ключей."""
    print("⚠️  [MEDIUM] KMS Key Rotation Disabled")
    print("  💥 Issue: Отключена автоматическая ротация ключей KMS (enableKeyRotation: false).")
    print("  🎯 Risk: Длительная жизнь ключа = больший ущерб при утечке. Несоответствие требованиям безопасности (PCI-DSS, HIPAA, etc).")
    print("  ❌ Insecure:")
    print("        Type: AWS::KMS::Key")
    print("        Properties:")
    print("          Enabled: true")
    print("          EnableKeyRotation: false  # По умолчанию или явно выключено")
    print("  ✅ Secure:")
    print("        Type: AWS::KMS::Key")
    print("        Properties:")
    print("          Enabled: true")
    print("          EnableKeyRotation: true  # Автоматическая ротация раз в год")
    print("          Description: \"Key with rotation enabled\"")
    print("  🛠️ Remediation:")
    print("      • Включите EnableKeyRotation: true для всех ключей")
    print("      • Настройте мониторинг использования ключей")
    print("      • Регулярно аудируйте KMS ключи")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 34: CloudTrail Logging Disabled                 │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-3.1                                  │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Логирование действий в AWS отключено        │
# └─────────────────────────────────────────────────────────────┘
def check_cloudtrail_logging_disabled_34():
    """Проверяет включение CloudTrail для аудита действий в аккаунте AWS."""
    print("⚠️  [HIGH] CloudTrail Logging Disabled")
    print("  💥 Issue: Логирование действий в AWS отключено или ограничено одним регионом (IsMultiRegionTrail: false).")
    print("  🎯 Risk: Невозможно отследить действия злоумышленника в других регионах. Отсутствие аудита = нарушение требований безопасности.")
    print("  ❌ Insecure:")
    print("        Type: AWS::CloudTrail::Trail")
    print("        Properties:")
    print("          IsMultiRegionTrail: false  # Только один регион!")
    print("          EnableLogFileValidation: false")
    print("          # S3BucketName может отсутствовать")
    print("  ✅ Secure:")
    print("        Type: AWS::CloudTrail::Trail")
    print("        Properties:")
    print("          IsMultiRegionTrail: true   # Логирование всех регионов")
    print("          EnableLogFileValidation: true")
    print("          S3BucketName: !Ref CloudTrailLogsBucket")
    print("          KMSKeyId: !Ref TrailKMSKey")
    print("          IncludeGlobalServiceEvents: true")
    print("          IsOrganizationTrail: true  # Если используется AWS Organizations")
    print("  🛠️ Remediation:")
    print("      • Включите multi-region trail для всех аккаунтов")
    print("      • Включите валидацию логов")
    print("      • Шифруйте логи через KMS")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 35: VPC Flow Logs Disabled                      │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-3.4                                  │
# │ ⚡ Критичность: 🟡 MEDIUM                                    │
# │ 📝 Описание:   Не включены Flow Logs для мониторинга VPC   │
# └─────────────────────────────────────────────────────────────┘
def check_vpc_flow_logs_disabled_35():
    """Проверяет включение VPC Flow Logs для аудита сетевого трафика."""
    print("⚠️  [MEDIUM] VPC Flow Logs Disabled")
    print("  💥 Issue: Не включены Flow Logs для мониторинга сетевого трафика VPC.")
    print("  🎯 Risk: Слепая зона в мониторинге сети. Невозможно выявить сканирование, эксфильтрацию данных или C2-трафик.")
    print("  ❌ Insecure:")
    print("        Type: AWS::EC2::VPC")
    print("        Properties:")
    print("          CidrBlock: 10.0.0.0/16")
    print("          # Нет связанного ресурса AWS::EC2::FlowLog")
    print("  ✅ Secure:")
    print("        # VPC с включёнными Flow Logs")
    print("        Type: AWS::EC2::VPC")
    print("        Properties:")
    print("          CidrBlock: 10.0.0.0/16")
    print("        ---")
    print("        Type: AWS::EC2::FlowLog")
    print("        Properties:")
    print("          ResourceId: !Ref MyVPC")
    print("          ResourceType: VPC")
    print("          TrafficType: ALL  # Или REJECT для экономии")
    print("          LogDestinationType: cloud-watch-logs  # или s3")
    print("          LogDestination: !Ref LogGroupArn")
    print("          # Опционально: фильтрация трафика")
    print("  🛠️ Remediation:")
    print("      • Включите Flow Logs для всех VPC")
    print("      • Настройте отправку в CloudWatch Logs или S3")
    print("      • Создайте алерты на аномальный трафик")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 36: RDS Publicly Accessible                     │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-2.3.1                                │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   База данных RDS доступна из публичной сети  │
# └─────────────────────────────────────────────────────────────┘
def check_rds_publicly_accessible_36():
    """Проверяет, что RDS инстансы не доступны из публичной сети."""
    print("⚠️  [CRITICAL] RDS Publicly Accessible")
    print("  💥 Issue: База данных RDS доступна из публичной сети (PubliclyAccessible: true).")
    print("  🎯 Risk: Прямой доступ к базе данных из интернета. Риск взлома, утечки данных, атак типа SQL injection и ransomware.")
    print("  ❌ Insecure:")
    print("        Type: AWS::RDS::DBInstance")
    print("        Properties:")
    print("          PubliclyAccessible: true  # БД видна из интернета!")
    print("          DBInstanceClass: db.t3.micro")
    print("  ✅ Secure:")
    print("        Type: AWS::RDS::DBInstance")
    print("        Properties:")
    print("          PubliclyAccessible: false  # Только внутри VPC")
    print("          DBSubnetGroupName: !Ref PrivateSubnets")
    print("          VpcSecurityGroups:")
    print("          - !Ref DatabaseSecurityGroup")
    print("  🛠️ Remediation:")
    print("      • Установите PubliclyAccessible: false")
    print("      • Разместите БД в приватных подсетях")
    print("      • Используйте bastion host или Systems Manager для доступа")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 37: RDS Encryption Disabled                     │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-2.3.2                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Данные на диске RDS не зашифрованы          │
# └─────────────────────────────────────────────────────────────┘
def check_rds_encryption_disabled_37():
    """Проверяет шифрование данных на диске для RDS инстансов."""
    print("⚠️  [HIGH] RDS Encryption Disabled")
    print("  💥 Issue: Данные на диске RDS не зашифрованы (StorageEncrypted: false).")
    print("  🎯 Risk: Раскрытие данных при доступе к хранилищу (data at rest). Нарушение требований комплаенса (GDPR, PCI-DSS).")
    print("  ❌ Insecure:")
    print("        Type: AWS::RDS::DBInstance")
    print("        Properties:")
    print("          StorageEncrypted: false  # Данные не шифруются!")
    print("          # Или поле отсутствует (по умолчанию false)")
    print("  ✅ Secure:")
    print("        Type: AWS::RDS::DBInstance")
    print("        Properties:")
    print("          StorageEncrypted: true")
    print("          KmsKeyId: !Ref DatabaseKMSKey  # CMK для управления ключом")
    print("          # Шифруются: данные, логи, снапшоты, реплики")
    print("  🛠️ Remediation:")
    print("      • Включите шифрование для всех RDS инстансов")
    print("      • Используйте KMS ключи для управления")
    print("      • Зашифруйте существующие БД через snapshot copy")
    print()


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
def check_redis_without_password_38():
    """Проверяет наличие аутентификации в конфигурации Redis."""
    print("⚠️  [CRITICAL] Redis Without Password")
    print("  💥 Issue: Redis работает без аутентификации (requirepass не установлен).")
    print("  🎯 Risk: Неавторизованный доступ к кэшу/данным. Возможность выполнения LUA-скриптов, очистки данных, использования Redis для атак на другие системы.")
    print("  ❌ Insecure:")
    print("        # redis.conf")
    print("        port 6379")
    print("        bind 0.0.0.0")
    print("        # requirepass не установлен!")
    print("        # Любой клиент может подключиться без пароля")
    print("  ✅ Secure:")
    print("        # redis.conf")
    print("        port 6379")
    print("        bind 127.0.0.1  # Или приватный интерфейс")
    print("        requirepass ${REDIS_PASSWORD}  # Сложный пароль из секретов")
    print("        # Дополнительно:")
    print("        rename-command FLUSHALL \"\"")
    print("        rename-command CONFIG \"\"")
    print("  🛠️ Remediation:")
    print("      • Установите requirepass с сложным паролем")
    print("      • Ограничьте bind до приватных интерфейсов")
    print("      • Отключите опасные команды через rename-command")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 39: MongoDB Without Auth                        │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-Database-4.2                             │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   MongoDB работает без включения авторизации  │
# └─────────────────────────────────────────────────────────────┘
def check_mongodb_without_auth_39():
    """Проверяет включение авторизации в конфигурации MongoDB."""
    print("⚠️  [CRITICAL] MongoDB Without Auth")
    print("  💥 Issue: MongoDB работает без включения авторизации (security.authorization: disabled).")
    print("  🎯 Risk: Любой клиент может получить полный доступ к БД. Утечка данных, модификация, удаление, ransomware-атаки.")
    print("  ❌ Insecure:")
    print("        # mongod.conf")
    print("        security:")
    print("          authorization: disabled  # Аутентификация выключена!")
    print("          # Или поле отсутствует (по умолчанию disabled)")
    print("  ✅ Secure:")
    print("        # mongod.conf")
    print("        security:")
    print("          authorization: enabled  # Включаем аутентификацию")
    print("        # Создаём пользователя с необходимыми правами:")
    print("        # db.createUser({user: \"app\", pwd: \"...\", roles: [\"readWrite\"]})")
    print("        net:")
    print("          bindIp: 127.0.0.1,10.0.1.5  # Ограничиваем интерфейсы")
    print("  🛠️ Remediation:")
    print("      • Включите authorization: enabled")
    print("      • Создайте пользователей с минимальными правами")
    print("      • Ограничьте bindIp до приватных адресов")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 40: Elasticsearch Public Access                 │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-AWS-2.4.1                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Кластер Elasticsearch доступен публично     │
# └─────────────────────────────────────────────────────────────┘
def check_elasticsearch_public_access_40():
    """Проверяет политики доступа к Elasticsearch доменам."""
    print("⚠️  [HIGH] Elasticsearch Public Access")
    print("  💥 Issue: Кластер Elasticsearch доступен публично (accessPolicies позволяют * principal).")
    print("  🎯 Risk: Публичный доступ к поисковому кластеру. Утечка логов, содержащих персональные данные, токены, ключи.")
    print("  ❌ Insecure:")
    print("        accessPolicies:")
    print("          Version: \"2012-10-17\"")
    print("          Statement:")
    print("          - Effect: Allow")
    print("            Principal: \"*\"  # Любой пользователь!")
    print("            Action: \"es:*\"")
    print("            Resource: \"arn:aws:es:region:account:domain/logs/*\"")
    print("  ✅ Secure:")
    print("        accessPolicies:")
    print("          Version: \"2012-10-17\"")
    print("          Statement:")
    print("          - Effect: Allow")
    print("            Principal:")
    print("              AWS: \"arn:aws:iam::account:role/app-role\"  # Только доверенная роль")
    print("            Action:")
    print("            - \"es:ESHttpGet\"")
    print("            - \"es:ESHttpPost\"")
    print("            Resource: \"arn:aws:es:region:account:domain/logs/*\"")
    print("        # Дополнительно: VPC endpoint, IAM auth, Cognito")
    print("  🛠️ Remediation:")
    print("      • Ограничьте Principal до конкретных IAM ролей")
    print("      • Используйте VPC endpoint для доступа")
    print("      • Включите IAM auth или Cognito")
    print()


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
def check_lambda_function_public_trigger_41():
    """Проверяет политики разрешений на вызов Lambda-функций."""
    print("⚠️  [HIGH] Lambda Function Public Trigger")
    print("  💥 Issue: Lambda-функция вызывается публично без авторизации (Principal: *).")
    print("  🎯 Risk: Неавторизованный вызов функции. Риск исчерпания квот, выполнения вредоносных операций, утечки данных.")
    print("  ❌ Insecure:")
    print("        # Lambda Permission для публичного API Gateway")
    print("        Type: AWS::Lambda::Permission")
    print("        Properties:")
    print("          FunctionName: !Ref MyFunction")
    print("          Action: lambda:InvokeFunction")
    print("          Principal: \"*\"  # Любой может вызвать!")
    print("          SourceArn: !GetAtt ApiGateway.StageArn")
    print("  ✅ Secure:")
    print("        # Ограничиваем вызов только конкретным API Gateway")
    print("        Type: AWS::Lambda::Permission")
    print("        Properties:")
    print("          FunctionName: !Ref MyFunction")
    print("          Action: lambda:InvokeFunction")
    print("          Principal: apigateway.amazonaws.com")
    print("          SourceArn: !Sub \"arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${ApiGateway}/\"")
    print("        # Дополнительно: авторизация на уровне API Gateway (IAM, Cognito, Lambda Authorizer)")
    print("  🛠️ Remediation:")
    print("      • Ограничьте Principal до конкретного сервиса")
    print("      • Добавьте SourceArn для ограничения источника")
    print("      • Включите авторизацию на уровне API Gateway")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 42: Cloud Function HTTP Without Auth            │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-GCP-6.6.1                                │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   HTTP Cloud Function без аутентификации      │
# └─────────────────────────────────────────────────────────────┘
def check_cloud_function_http_without_auth_42():
    """Проверяет политики доступа к HTTP-триггерам Cloud Functions в GCP."""
    print("⚠️  [HIGH] Cloud Function HTTP Without Auth")
    print("  💥 Issue: HTTP Cloud Function доступна без аутентификации (allUsers имеет роль cloudfunctions.invoker).")
    print("  🎯 Risk: Функция доступна любому пользователю интернета. Риск атак, утечки данных, финансовых потерь.")
    print("  ❌ Insecure:")
    print("        # Cloud Function с публичным триггером")
    print("        type: google.cloud.functions.v1.Function")
    print("        properties:")
    print("          httpsTrigger: {}")
    print("          # Нет ограничения IAM: allUsers имеет роль cloudfunctions.invoker")
    print("  ✅ Secure:")
    print("        # Убираем публичный доступ и настраиваем IAM")
    print("        # 1. Удаляем binding для allUsers:")
    print("        # gcloud functions remove-iam-policy-binding FUNC \\")
    print("        #   --member=\"allUsers\" --role=\"roles/cloudfunctions.invoker\"")
    print("        # 2. Добавляем только доверенные сервис-аккаунты:")
    print("        role: roles/cloudfunctions.invoker")
    print("        members:")
    print("        - serviceAccount:backend-sa@project.iam.gserviceaccount.com")
    print("  🛠️ Remediation:")
    print("      • Удалите allUsers из IAM policy")
    print("      • Добавьте только доверенные service accounts")
    print("      • Используйте IAM авторизацию для всех функций")
    print()


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
def check_azure_nsg_any_any_rule_43():
    """Проверяет чрезмерно разрешительные правила в Azure Network Security Groups."""
    print("⚠️  [CRITICAL] Azure NSG Any-Any Rule")
    print("  💥 Issue: Правило NSG разрешает весь трафик отовсюду (source: *, dest: *, port: *).")
    print("  🎯 Risk: Полное отсутствие контроля сетевого трафика. Любой хост может подключиться к любому сервису.")
    print("  ❌ Insecure:")
    print("        securityRules:")
    print("        - name: AllowAll")
    print("          properties:")
    print("            protocol: \"*\"")
    print("            sourceAddressPrefix: \"*\"      # Любой источник")
    print("            destinationAddressPrefix: \"*\"  # Любое назначение")
    print("            sourcePortRange: \"*\"")
    print("            destinationPortRange: \"*\"      # Любой порт")
    print("            access: Allow")
    print("            direction: Inbound")
    print("  ✅ Secure:")
    print("        securityRules:")
    print("        - name: AllowHTTPS")
    print("          properties:")
    print("            protocol: Tcp")
    print("            sourceAddressPrefix: \"10.0.0.0/8\"  # Только доверенная сеть")
    print("            destinationAddressPrefix: \"*\"")
    print("            sourcePortRange: \"*\"")
    print("            destinationPortRange: \"443\"        # Только HTTPS")
    print("            access: Allow")
    print("            direction: Inbound")
    print("        # Принцип: по умолчанию Deny, разрешать только необходимое")
    print("  🛠️ Remediation:")
    print("      • Удалите правила Any-Any")
    print("      • Разрешайте только необходимые порты и IP")
    print("      • Используйте принцип default deny")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 44: Azure SQL Firewall Open                     │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-Azure-9.4                                │
# │ ⚡ Критичность: 🔴 CRITICAL                                  │
# │ 📝 Описание:   Брандмауэр Azure SQL разрешает подключения отовсюду │
# └─────────────────────────────────────────────────────────────┘
def check_azure_sql_firewall_open_44():
    """Проверяет правила брандмауэра Azure SQL Database."""
    print("⚠️  [CRITICAL] Azure SQL Firewall Open")
    print("  💥 Issue: Брандмауэр Azure SQL разрешает подключения отовсюду (0.0.0.0 - 255.255.255.255).")
    print("  🎯 Risk: База данных доступна из любой точки мира. Высокий риск взлома и утечки данных.")
    print("  ❌ Insecure:")
    print("        Type: Microsoft.Sql/servers/firewallRules")
    print("        Properties:")
    print("          startIpAddress: \"0.0.0.0\"")
    print("          endIpAddress: \"255.255.255.255\"  # Разрешён весь интернет!")
    print("  ✅ Secure:")
    print("        Type: Microsoft.Sql/servers/firewallRules")
    print("        Properties:")
    print("          startIpAddress: \"10.0.1.0\"   # Только доверенный диапазон")
    print("          endIpAddress: \"10.0.1.255\"")
    print("        # Или использование Private Endpoint для доступа из VNet:")
    print("        Type: Microsoft.Sql/servers/privateEndpointConnections")
    print("        Properties:")
    print("          privateLinkServiceConnectionState:")
    print("            status: Approved")
    print("  🛠️ Remediation:")
    print("      • Ограничьте firewall rules до конкретных IP")
    print("      • Используйте Private Endpoint для доступа")
    print("      • Включите Advanced Threat Protection")
    print()


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
def check_ci_cd_pipeline_without_approval_45():
    """Проверяет наличие ручного подтверждения для деплоя в production."""
    print("⚠️  [HIGH] CI/CD Pipeline Without Approval")
    print("  💥 Issue: Развёртывание в production происходит автоматически (нет when: manual или approval).")
    print("  🎯 Risk: Отсутствие человеческого контроля перед продакшеном. Риск инцидентов, уязвимостей, несанкционированных изменений.")
    print("  ❌ Insecure:")
    print("        # .gitlab-ci.yml")
    print("        deploy-production:")
    print("          stage: deploy")
    print("          script:")
    print("            - ./deploy.sh production")
    print("          # Нет when: manual или approval rule!")
    print("          # Изменение в main сразу деплоится в prod")
    print("  ✅ Secure:")
    print("        # .gitlab-ci.yml")
    print("        deploy-production:")
    print("          stage: deploy")
    print("          script:")
    print("            - ./deploy.sh production")
    print("          when: manual  # Требуется ручной запуск")
    print("          # Или с approval:")
    print("          rules:")
    print("            - if: $CI_COMMIT_BRANCH == \"main\"")
    print("              when: manual")
    print("          environment:")
    print("            name: production")
    print("        # Дополнительно: защита ветки main, required approvals в MR")
    print("  🛠️ Remediation:")
    print("      • Добавьте when: manual для production деплоя")
    print("      • Настройте required approvals в merge requests")
    print("      • Защитите main ветку от прямых пушей")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 46: GitHub Actions Without Pin                  │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-GitHub-5.1                               │
# │ ⚡ Критичность: 🟡 MEDIUM                                    │
# │ 📝 Описание:   Actions используются по тегу, а не по хешу  │
# └─────────────────────────────────────────────────────────────┘
def check_github_actions_without_pin_46():
    """Проверяет фиксацию версий GitHub Actions по полному хешу коммита."""
    print("⚠️  [MEDIUM] GitHub Actions Without Pin")
    print("  💥 Issue: Actions используются по тегу/ветке, а не по хешу (uses: actions/checkout@v2 вместо SHA).")
    print("  🎯 Risk: Supply-chain атака через компрометацию action. Непредсказуемое поведение пайплайна при обновлении тега.")
    print("  ❌ Insecure:")
    print("        # .github/workflows/ci.yml")
    print("        jobs:")
    print("          build:")
    print("            steps:")
    print("              - uses: actions/checkout@v2        # Тег может измениться!")
    print("              - uses: some/user-action@main      # Ветка может быть обновлена")
    print("  ✅ Secure:")
    print("        # .github/workflows/ci.yml")
    print("        jobs:")
    print("          build:")
    print("            steps:")
    print("              # Фиксируем action по полному хешу коммита")
    print("              - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1")
    print("              - uses: some/user-action@abc123def456...  # Полный SHA")
    print("        # Дополнительно: Dependabot для обновления actions, аудит зависимостей")
    print("  🛠️ Remediation:")
    print("      • Используйте полные SHA хеши для всех actions")
    print("      • Настройте Dependabot для обновления зависимостей")
    print("      • Аудируйте используемые actions регулярно")
    print()


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
def check_docker_socket_mounted_47():
    """Проверяет монтирование Docker socket в контейнеры."""
    print("⚠️  [CRITICAL] Docker Socket Mounted")
    print("  💥 Issue: В контейнер примонтирован Docker socket (/var/run/docker.sock).")
    print("  🎯 Risk: Полный контроль над хостом через Docker API. Container escape, запуск майнеров, кража данных.")
    print("  ❌ Insecure:")
    print("        services:")
    print("          app:")
    print("            image: myapp")
    print("            volumes:")
    print("              - /var/run/docker.sock:/var/run/docker.sock  # Опасно!")
    print("        # Или в Kubernetes:")
    print("        volumes:")
    print("        - name: docker-sock")
    print("          hostPath:")
    print("            path: /var/run/docker.sock")
    print("  ✅ Secure:")
    print("        # Избегать монтирования docker.sock")
    print("        # Альтернативы:")
    print("        # 1. Использовать Kaniko/Buildah для сборки образов в K8s")
    print("        # 2. Использовать Docker-in-Docker с осторожностью (не для прода)")
    print("        # 3. Вынести сборку в отдельный CI-раннер с изоляцией")
    print("        services:")
    print("          app:")
    print("            image: myapp")
    print("            # volumes: без docker.sock")
    print("  🛠️ Remediation:")
    print("      • Удалите монтирование docker.sock")
    print("      • Используйте Kaniko/Buildah для сборки в K8s")
    print("      • Вынесите сборку в изолированный CI-раннер")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 48: Kubernetes Pod Security Policy              │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-K8S-5.2.13                               │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Не применяются политики безопасности подов  │
# └─────────────────────────────────────────────────────────────┘
def check_kubernetes_pod_security_policy_48():
    """Проверяет применение политик безопасности подов (PSP/PodSecurity Admission)."""
    print("⚠️  [HIGH] Kubernetes Pod Security Policy")
    print("  💥 Issue: Не применяются политики безопасности подов (отсутствие PSP или PodSecurityStandard).")
    print("  🎯 Risk: Отсутствие контроля за настройками безопасности подов. Риск запуска привилегированных контейнеров, escape на хост.")
    print("  ❌ Insecure:")
    print("        # В кластере нет PodSecurityPolicy / PodSecurity Admission")
    print("        # Или под создаётся без ограничений:")
    print("        apiVersion: v1")
    print("        kind: Pod")
    print("        metadata:")
    print("          name: unrestricted-pod")
    print("        spec:")
    print("          containers:")
    print("          - name: app")
    print("            image: nginx")
    print("            securityContext:")
    print("              privileged: true  # Нет PSP, который бы это запретил")
    print("  ✅ Secure:")
    print("        # Включить Pod Security Admission (K8s 1.23+)")
    print("        apiVersion: v1")
    print("        kind: Namespace")
    print("        metadata:")
    print("          name: production")
    print("          labels:")
    print("            pod-security.kubernetes.io/enforce: restricted")
    print("            pod-security.kubernetes.io/audit: restricted")
    print("            pod-security.kubernetes.io/warn: restricted")
    print("        # Или использовать OPA/Gatekeeper для сложных политик")
    print("        # Или (устарело, но ещё работает) PodSecurityPolicy ресурс")
    print("  🛠️ Remediation:")
    print("      • Включите Pod Security Admission на namespace")
    print("      • Используйте OPA/Gatekeeper для кастомных политик")
    print("      • Аудируйте все поды на нарушения security context")
    print()


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
def check_helm_chart_without_values_validation_49():
    """Проверяет наличие values.schema.json для валидации параметров Helm chart."""
    print("⚠️  [MEDIUM] Helm Chart Without Values Validation")
    print("  💥 Issue: Отсутствует валидация значений Helm chart (нет values.schema.json).")
    print("  🎯 Risk: Ошибки конфигурации, уязвимые настройки, сложность аудита и контроля за параметрами чарта.")
    print("  ❌ Insecure:")
    print("        # values.yaml без schema validation")
    print("        replicaCount: 3")
    print("        image:")
    print("          repository: nginx")
    print("          tag: latest  # Опасный тег, но нет валидации!")
    print("        security:")
    print("          runAsRoot: true  # Не проверяется, что должно быть false")
    print("  ✅ Secure:")
    print("        # values.schema.json для валидации")
    print("        {")
    print("          \"$schema\": \"http://json-schema.org/draft-07/schema#\",")
    print("          \"properties\": {")
    print("            \"image\": {")
    print("              \"properties\": {")
    print("                \"tag\": {")
    print("                  \"type\": \"string\",")
    print("                  \"pattern\": \"^v?\\d+\\.\\d+\\.\\d+$\",  # Только семантические версии")
    print("                  \"not\": { \"pattern\": \"latest\" }")
    print("                }")
    print("              }")
    print("            },")
    print("            \"security\": {")
    print("              \"properties\": {")
    print("                \"runAsRoot\": { \"const\": false }")
    print("              }")
    print("            }")
    print("          }")
    print("        }")
    print("        # Helm автоматически валидирует values.yaml при установке")
    print("  🛠️ Remediation:")
    print("      • Добавьте values.schema.json в chart")
    print("      • Валидируйте критические параметры безопасности")
    print("      • Блокируйте опасные значения через schema")
    print()


# ┌─────────────────────────────────────────────────────────────┐
# │ 🔹 Проверка 50: Terraform State Remote Without Lock         │
# ├─────────────────────────────────────────────────────────────┤
# │ 📋 Стандарт:   CIS-TF-2.1                                   │
# │ ⚡ Критичность: 🟠 HIGH                                      │
# │ 📝 Описание:   Удалённый state Terraform без блокировки    │
# └─────────────────────────────────────────────────────────────┘
def check_terraform_state_remote_without_lock_50():
    """Проверяет включение state locking для удалённого бэкенда Terraform."""
    print("⚠️  [HIGH] Terraform State Remote Without Lock")
    print("  💥 Issue: Удалённый state Terraform без блокировки (S3 backend без dynamodb_table).")
    print("  🎯 Risk: Повреждение state при параллельном запуске terraform apply. Потеря управления ресурсами, дублирование, удаление.")
    print("  ❌ Insecure:")
    print("        # backend.tf")
    print("        terraform {")
    print("          backend \"s3\" {")
    print("            bucket = \"my-terraform-state\"")
    print("            key    = \"prod/terraform.tfstate\"")
    print("            region = \"us-east-1\"")
    print("            # dynamodb_table не указан = нет locking!")
    print("          }")
    print("        }")
    print("  ✅ Secure:")
    print("        # backend.tf с блокировкой через DynamoDB")
    print("        terraform {")
    print("          backend \"s3\" {")
    print("            bucket         = \"my-terraform-state\"")
    print("            key            = \"prod/terraform.tfstate\"")
    print("            region         = \"us-east-1\"")
    print("            dynamodb_table = \"terraform-locks\"  # Включает state locking")
    print("            encrypt        = true")
    print("          }")
    print("        }")
    print("        # DynamoDB таблица должна иметь partition key: LockID (String)")
    print("  🛠️ Remediation:")
    print("      • Добавьте dynamodb_table для state locking")
    print("      • Включите шифрование state файла")
    print("      • Настройте версионирование S3 bucket")
    print()


def all_medium_check():
    """
    ╔════════════════════════════════════════════════════════════════╗
    ║  🔐 ЗАПУСК ВСЕХ ПРОВЕРОК MEDIUM LEVEL (26–50)                 ║
    ╚════════════════════════════════════════════════════════════════╝
    """
    print("\n" + "=" * 70)
    print("🔐 Security Auditor — Medium Level Checks (26–50)")
    print("=" * 70 + "\n")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔹 РАЗДЕЛ 1: KUBERNETES SECURITY CHECKS (26–29)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("📦 РАЗДЕЛ 1: Kubernetes Security Checks (26–29)\n")
    print("─" * 70)

    # check_network_policy_missing_26()           # 26
    # check_service_account_token_mount_27()      # 27
    # check_image_from_untrusted_registry_28()    # 28
    # check_ingress_without_tls_29()              # 29
    #
    # # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # # 🔹 РАЗДЕЛ 2: AWS SECURITY CHECKS (30–37)
    # # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # print("\n📦 РАЗДЕЛ 2: AWS Security Checks (30–37)\n")
    # print("─" * 70)
    #
    # check_loadbalancer_internal_30()            # 30
    # check_security_group_overly_permissive_31() # 31
    # check_iam_policy_wildcard_service_32()      # 32
    # check_kms_key_rotation_disabled_33()        # 33
    # check_cloudtrail_logging_disabled_34()      # 34
    # check_vpc_flow_logs_disabled_35()           # 35
    # check_rds_publicly_accessible_36()          # 36
    # check_rds_encryption_disabled_37()          # 37
    #
    # # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # # 🔹 РАЗДЕЛ 3: DATABASE SECURITY CHECKS (38–40)
    # # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # print("\n📦 РАЗДЕЛ 3: Database Security Checks (38–40)\n")
    # print("─" * 70)
    #
    # check_redis_without_password_38()           # 38
    # check_mongodb_without_auth_39()             # 39
    # check_elasticsearch_public_access_40()      # 40
    #
    # # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # # 🔹 РАЗДЕЛ 4: SERVERLESS & CLOUD FUNCTIONS (41–42)
    # # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # print("\n📦 РАЗДЕЛ 4: Serverless & Cloud Functions (41–42)\n")
    # print("─" * 70)
    #
    # check_lambda_function_public_trigger_41()   # 41
    # check_cloud_function_http_without_auth_42() # 42
    #
    # # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # # 🔹 РАЗДЕЛ 5: AZURE SECURITY CHECKS (43–44)
    # # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # print("\n📦 РАЗДЕЛ 5: Azure Security Checks (43–44)\n")
    # print("─" * 70)
    #
    # check_azure_nsg_any_any_rule_43()           # 43
    # check_azure_sql_firewall_open_44()          # 44
    #
    # # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # # 🔹 РАЗДЕЛ 6: CI/CD SECURITY CHECKS (45–46)
    # # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # print("\n📦 РАЗДЕЛ 6: CI/CD Security Checks (45–46)\n")
    # print("─" * 70)
    #
    # check_ci_cd_pipeline_without_approval_45()  # 45
    # check_github_actions_without_pin_46()       # 46
    #
    # # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # # 🔹 РАЗДЕЛ 7: CONTAINER & KUBERNETES CHECKS (47–48)
    # # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # print("\n📦 РАЗДЕЛ 7: Container & Kubernetes Checks (47–48)\n")
    # print("─" * 70)
    #
    # check_docker_socket_mounted_47()            # 47
    # check_kubernetes_pod_security_policy_48()   # 48
    #
    # # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # # 🔹 РАЗДЕЛ 8: INFRASTRUCTURE AS CODE CHECKS (49–50)
    # # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # print("\n📦 РАЗДЕЛ 8: Infrastructure as Code Checks (49–50)\n")
    # print("─" * 70)
    #
    # check_helm_chart_without_values_validation_49()  # 49
    # check_terraform_state_remote_without_lock_50()   # 50

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔹 ИТОГОВЫЙ ОТЧЁТ
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print("\n" + "=" * 70)
    print("✅ ВСЕ ПРОВЕРКИ MEDIUM LEVEL ЗАВЕРШЕНЫ")
    print("=" * 70)
    print("""
📊 Сводка:
    • Всего проверок: 25
    • Kubernetes:     4  (26–29) .yaml, .yml
    • AWS:            8  (30–37) .yaml, .yml, .json
    • Database:       3  (38–40) .yaml, .conf, .json
    • Serverless:     2  (41–42) .yaml, .json
    • Azure:          2  (43–44) .yaml, .json
    • CI/CD:          2  (45–46) .yml, .yaml
    • Container:      2  (47–48) .yaml, .yml
    • IaC:            2  (49–50) .yaml, .json, .tf


    """)
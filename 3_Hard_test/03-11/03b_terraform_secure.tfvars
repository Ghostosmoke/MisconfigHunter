# ✅ SECURE: tfvars без секретов (использовать secrets manager)
# ⚠️ Этот файл должен быть в .gitignore
# ⚠️ Секреты загружаются через AWS Secrets Manager в runtime
db_username = "admin"
# db_password загружается через data source в main.tf
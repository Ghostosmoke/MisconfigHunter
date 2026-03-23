# ❌ VULNERABLE: Secret хардкод в .tf файле
# ⚠️ TRIGGER: пароль в коде
resource "aws_db_instance" "vulnerable" {
  identifier     = "production-db"
  engine         = "postgres"
  username       = "admin"
  password       = "SuperSecret123!"
  instance_class = "db.t3.medium"
}
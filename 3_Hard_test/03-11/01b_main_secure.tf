# ✅ SECURE: Secret через variables
# ⚠️ Требуется файл variables.tf с объявлением переменных
resource "aws_db_instance" "secure" {
  identifier     = "production-db"
  engine         = "postgres"
  username       = var.db_username
  password       = var.db_password
  instance_class = "db.t3.medium"
}
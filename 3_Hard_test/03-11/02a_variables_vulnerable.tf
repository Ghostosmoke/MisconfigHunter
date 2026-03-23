# ❌ VULNERABLE: Variables без sensitive флага
# ⚠️ TRIGGER: отсутствует sensitive = true
variable "db_password" {
  type        = string
  description = "Database password"
}

variable "db_username" {
  type        = string
  description = "Database username"
}
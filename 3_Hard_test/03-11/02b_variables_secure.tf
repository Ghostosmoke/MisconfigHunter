# ✅ SECURE: Variables с sensitive флагом
variable "db_password" {
  type        = string
  description = "Database password"
  sensitive   = true
}

variable "db_username" {
  type        = string
  description = "Database username"
}
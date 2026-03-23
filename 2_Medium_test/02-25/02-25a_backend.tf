# ❌ VULNERABLE: S3 backend без DynamoDB lock
# backend.tf
terraform {
  backend "s3" {
    bucket = "my-terraform-state"
    key    = "production/terraform.tfstate"
    region = "us-east-1"
    # ⚠️ TRIGGER: отсутствует dynamodb_table для lock
    encrypt = true
  }
}

---
# ✅ SECURE: S3 backend с DynamoDB lock
# backend.tf
terraform {
  backend "s3" {
    bucket         = "my-terraform-state"
    key            = "production/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-locks"  # ✅ OK: lock table указан
    encrypt        = true
  }
}
# ❌ VULNERABLE: Terraform state в публичном S3 bucket
terraform {
  backend "s3" {
    bucket = "terraform-state-public"  # ⚠️ Связан с bucket.tf
    key    = "production/terraform.tfstate"
    region = "us-east-1"
    encrypt = true
  }
}
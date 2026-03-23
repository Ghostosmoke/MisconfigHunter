# ❌ VULNERABLE: S3 bucket для state без блокировки публичного доступа
# ⚠️ TRIGGER: publicAccessBlockConfiguration отсутствует
resource "aws_s3_bucket" "vulnerable" {
  bucket = "terraform-state-public"
}
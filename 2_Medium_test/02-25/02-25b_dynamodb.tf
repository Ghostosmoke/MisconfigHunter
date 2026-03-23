# ❌ VULNERABLE: DynamoDB таблица не существует или без proper config
# (файл отсутствует - это нарушение)


# ✅ SECURE: DynamoDB таблица для lock существует
# dynamodb.tf
resource "aws_dynamodb_table" "terraform_locks" {
  name         = "terraform-locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    Name = "Terraform Lock Table"
  }
}
# ❌ VULNERABLE: Bucket policy разрешает публичный доступ
# ⚠️ TRIGGER: Principal = "*"
resource "aws_s3_bucket_policy" "vulnerable" {
  bucket = aws_s3_bucket.vulnerable.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.vulnerable.arn}/*"
    }]
  })
}
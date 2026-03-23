# ✅ SECURE: Bucket policy ограничивает доступ
resource "aws_s3_bucket_policy" "secure" {
  bucket = aws_s3_bucket.secure.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.secure.arn, "${aws_s3_bucket.secure.arn}/*"]
      Condition = {
        Bool = {
          aws:SecureTransport == "false"
        }
      }
    }]
  })
}
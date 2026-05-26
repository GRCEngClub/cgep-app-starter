# KMS Customer Managed Key
# SOC 2 CC6.1 — encryption at rest under customer custody
resource "aws_kms_key" "this" {
  description             = "CMK for ${var.bucket_name} S3 bucket"
  deletion_window_in_days = var.kms_deletion_window
  enable_key_rotation     = true

  tags = merge(var.tags, {
    Control     = "CC6.1"
    Gap         = "GAP-01"
    Environment = var.environment
  })
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.bucket_name}-${var.environment}"
  target_key_id = aws_kms_key.this.key_id
}

# S3 Bucket
resource "aws_s3_bucket" "this" {
  bucket = "${var.bucket_name}-${var.environment}"

  tags = merge(var.tags, {
    Environment = var.environment
  })
}

# GAP-01 fix: SSE-KMS encryption with customer CMK
# SOC 2 CC6.1
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
    bucket_key_enabled = true
  }
}

# GAP-03 fix: Deny all non-TLS requests
# SOC 2 CC6.7
resource "aws_s3_bucket_policy" "tls" {
  bucket = aws_s3_bucket.this.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyNonTLS"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [
        aws_s3_bucket.this.arn,
        "${aws_s3_bucket.this.arn}/*"
      ]
      Condition = {
        Bool = {
          "aws:SecureTransport" = "false"
        }
      }
    }]
  })
}

# GAP-04 fix: Enable versioning
# SOC 2 A1.2
resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Extra hardening: block public access
resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = false
}
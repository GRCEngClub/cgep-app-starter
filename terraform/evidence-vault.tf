# Lab 2.5 — Evidence Vault with Object Lock
# SOC 2 CC7.2 — system monitoring and evidence retention
# Object Lock ensures evidence cannot be deleted or tampered with

resource "aws_s3_bucket" "evidence" {
  bucket = "${local.name_prefix}-evidence-${local.suffix}"

  object_lock_enabled = true

  tags = {
    Control   = "CC7.2"
    Gap       = "GAP-06"
    ManagedBy = "terraform"
    Purpose   = "compliance-evidence-vault"
  }
}

# Enable Object Lock retention — COMPLIANCE mode means
# nobody (not even root) can delete evidence during retention period
resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 90
    }
  }
}

# Encrypt evidence bucket with KMS
resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.uploads.arn
    }
    bucket_key_enabled = true
  }
}

# Enable versioning on evidence bucket
resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Block all public access to evidence bucket
resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Deny non-TLS requests to evidence bucket
resource "aws_s3_bucket_policy" "evidence_tls" {
  bucket = aws_s3_bucket.evidence.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyNonTLS"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [
        aws_s3_bucket.evidence.arn,
        "${aws_s3_bucket.evidence.arn}/*"
      ]
      Condition = {
        Bool = {
          "aws:SecureTransport" = "false"
        }
      }
    }]
  })
}

# Output the evidence bucket details for use in the pipeline
output "evidence_bucket" {
  description = "Name of the evidence vault bucket"
  value       = aws_s3_bucket.evidence.id
}

output "evidence_bucket_arn" {
  description = "ARN of the evidence vault bucket"
  value       = aws_s3_bucket.evidence.arn
}

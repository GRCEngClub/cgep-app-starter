# Evidence vault with Object Lock for immutable compliance evidence
# CMMC AU.L2-3.3.1 - Audit and Accountability

resource "aws_s3_bucket" "evidence" {
  bucket              = "${local.name_prefix}-evidence-vault-${local.suffix}"
  object_lock_enabled = true

  tags = {
    Name       = "${local.name_prefix}-evidence-vault"
    ControlRef = "AU.L2-3.3.1"
  }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

output "evidence_vault_name" {
  value       = aws_s3_bucket.evidence.id
  description = "Evidence vault bucket name."
}
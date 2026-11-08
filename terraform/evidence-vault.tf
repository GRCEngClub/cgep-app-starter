######################################################################
# Evidence vault: where every pipeline run's signed bundle lands.
#
# Object Lock in GOVERNANCE mode with 30-day default retention.
# GOVERNANCE keeps objects tamper-resistant (normal users and the pipeline
# cannot delete or overwrite them) while a privileged caller can still
# clean up a sandbox. COMPLIANCE would be stronger for chain of custody
# but cannot be undone before retention expires.
#
# Versioned, encrypted with its own CMK (separate from the workload key so
# evidence custody is independent of the PHI data stores), TLS-only,
# no public access. CMMC SC.L2-3.13.11 / SC.L2-3.13.8 / MP.L2-3.8.9.
######################################################################

resource "aws_kms_key" "evidence" {
  description             = "Acme Health CMK for the evidence vault"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/${local.name_prefix}-evidence-${local.suffix}"
  target_key_id = aws_kms_key.evidence.key_id
}

resource "aws_s3_bucket" "evidence" {
  bucket              = "${local.name_prefix}-evidence-${local.suffix}"
  object_lock_enabled = true

  # Sandbox only: lets `terraform destroy` empty the vault (the provider
  # bypasses GOVERNANCE retention). Production would not set this.
  force_destroy = true
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
      days = 30
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

resource "aws_s3_bucket_policy" "evidence_tls_only" {
  bucket = aws_s3_bucket.evidence.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.evidence.arn,
        "${aws_s3_bucket.evidence.arn}/*"
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.evidence]
}

output "evidence_vault_name" {
  value       = aws_s3_bucket.evidence.id
  description = "Evidence vault bucket name (used by the pipeline and verify script)."
}

output "evidence_kms_key_arn" {
  value       = aws_kms_key.evidence.arn
  description = "CMK that encrypts the evidence vault."
}

######################################################################
# secure-bucket — the reusable PHI-bucket security floor
#
# Applies, to a bucket the caller already created, the four controls
# every PHI bucket in this system must have. Each S3 bucket allows only
# ONE of each of these resources, so a bucket must be hardened here OR
# inline — never both, or the two definitions fight on every apply.
######################################################################

# GAP-01 (SC.L2-3.13.11): default encryption with the customer-managed
# CMK, so new objects are SSE-KMS under a key we control rather than the
# AWS-managed SSE-S3 default. bucket_key_enabled cuts KMS costs by using a
# bucket-level data key instead of one call per object.

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = var.bucket_id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

# GAP-04 (MP.L2-3.8.9): versioning, so an overwrite or delete of a PHI
# object keeps the prior version and the data stays recoverable.
resource "aws_s3_bucket_versioning" "this" {
  bucket = var.bucket_id

  versioning_configuration {
    status = "Enabled"
  }
}

# Belt-and-braces: block all public access regardless of ACLs or policy.
# PHI buckets must never be public; this makes that non-negotiable.
resource "aws_s3_bucket_public_access_block" "this" {
  bucket = var.bucket_id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# GAP-03 (SC.L2-3.13.8): deny any request not made over TLS, forcing PHI
# in transit onto HTTPS. Depends on the public access block so, if a
# policy is ever (mis)judged "public", the block is already in force.
#
# S3 allows a single bucket policy, so any extra statements a caller needs
# (via additional_policy_json) are merged into this one document rather
# than applied as a second, conflicting aws_s3_bucket_policy.

locals {
  tls_deny_statement = {
    Sid       = "DenyNonTLSRequests"
    Effect    = "Deny"
    Principal = "*"
    Action    = "s3:*"
    Resource = [
      var.bucket_arn,
      "${var.bucket_arn}/*",
    ]
    Condition = {
      Bool = {
        "aws:SecureTransport" = "false"
      }
    }
  }

  additional_statements = var.additional_policy_json == null ? [] : jsondecode(var.additional_policy_json).Statement
}

resource "aws_s3_bucket_policy" "this" {
  bucket = var.bucket_id

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = concat([local.tls_deny_statement], local.additional_statements)
  })

  depends_on = [aws_s3_bucket_public_access_block.this]
}

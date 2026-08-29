######################################################################
# S3 Hardening for the starter's uploads bucket
# GAP-01: SSE-KMS with customer CMK  — HIPAA 164.312(a)(2)(iv)
# GAP-03: TLS-only bucket policy     — HIPAA 164.312(e)(1)
# GAP-04: Versioning enabled         — HIPAA 164.308(a)(7)
######################################################################

# GAP-01: Replace SSE-S3 with SSE-KMS using our CMK
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = data.terraform_remote_state.starter.outputs.uploads_bucket_id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

# GAP-04: Enable versioning so PHI overwrites are recoverable
resource "aws_s3_bucket_versioning" "uploads" {
  bucket = data.terraform_remote_state.starter.outputs.uploads_bucket_id

  versioning_configuration {
    status = "Enabled"
  }
}

# GAP-03: Deny all non-TLS requests to the PHI bucket
resource "aws_s3_bucket_policy" "uploads_tls_only" {
  bucket = data.terraform_remote_state.starter.outputs.uploads_bucket_id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "arn:aws:s3:::${data.terraform_remote_state.starter.outputs.uploads_bucket_id}",
          "arn:aws:s3:::${data.terraform_remote_state.starter.outputs.uploads_bucket_id}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

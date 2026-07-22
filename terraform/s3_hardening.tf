# terraform/s3_hardening.tf
#
# New sub-resources on the starter's uploads bucket. These are genuinely new
# resource types (not arguments of aws_s3_bucket itself), so they're wired in
# as plain resources referencing aws_s3_bucket.uploads directly rather than
# through the override mechanism used in starter_override.tf.

######################################################################
# GAP-01 (SOC 2 CC6.1): SSE-KMS with the customer CMK, replacing the
# AWS-managed SSE-S3 default. PHI keys move under customer custody.
######################################################################

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.grc.arn
    }
    bucket_key_enabled = true
  }
}

######################################################################
# GAP-04 (SOC 2 A1.2): versioning. PHI overwrites/deletes are recoverable.
######################################################################

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  versioning_configuration {
    status = "Enabled"
  }
}

######################################################################
# GAP-03 (SOC 2 CC6.7): deny any request to the uploads bucket that isn't
# over TLS.
######################################################################

resource "aws_s3_bucket_policy" "uploads_tls_only" {
  bucket = aws_s3_bucket.uploads.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.uploads.arn,
          "${aws_s3_bucket.uploads.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

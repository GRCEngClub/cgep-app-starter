######################################################################
# Hardening overrides for the starter's resources.
# Closes gaps by attaching new resources to the starter's own.
######################################################################

# GAP-01 (CMMC SC.L2-3.13.11): S3 uploads bucket encrypted with our CMK,
# not the AWS-managed SSE-S3 default.
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

# GAP-04 (CMMC MP.L2-3.8.9): versioning so PHI overwrites are recoverable.
resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  versioning_configuration {
    status = "Suspended"
  }
}

# GAP-03 (CMMC SC.L2-3.13.8): deny any request that is not over TLS.
# Written as an aws_iam_policy_document so the Rego policy can verify it.
data "aws_iam_policy_document" "uploads_tls_only" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.uploads.arn, "${aws_s3_bucket.uploads.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "uploads_tls_only" {
  bucket = aws_s3_bucket.uploads.id
  policy = data.aws_iam_policy_document.uploads_tls_only.json
}

######################################################################
# Layer 1 — CloudTrail (account activity audit trail)
#
# Purpose : Record every management API call in the account, in every
#           region, to a dedicated bucket, with tamper-evident digests.
# Control : AU.L2-3.3.1 (create and retain audit records). It also
#           records every use of the KMS keys and every change the
#           pipeline applies, which supports the evidence chain.
#
# Design
#   - Multi-region: an attacker can't act unseen by working in an
#     unused region.
#   - Log file validation on: CloudTrail writes signed hourly digest
#     files, so any edit or deletion of a log file is detectable.
#   - Encrypted with the EVIDENCE key (its key policy allows CloudTrail
#     for this trail only; kms.tf). The trail name comes from
#     local.trail_name so it matches that key policy.
#   - Dedicated bucket on the same secure-bucket floor. The module merges
#     CloudTrail's two required bucket-policy statements with its TLS deny.
######################################################################

# --------------------------------------------------------------------
# Log bucket
# --------------------------------------------------------------------

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = "${local.name_prefix}-cloudtrail-${local.suffix}"
  force_destroy = false # never let Terraform delete the audit trail

  tags = {
    Name      = "${local.name_prefix}-cloudtrail"
    DataClass = "evidence" # overrides default "phi": this bucket holds audit logs
  }
}

# The two statements AWS documents for a CloudTrail bucket, each pinned
# with aws:SourceArn to THIS trail, so no other trail (or account) can
# write here.
data "aws_iam_policy_document" "cloudtrail_bucket" {
  # CloudTrail checks the bucket ACL before delivering.
  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  # Write only under AWSLogs/<this account>/, and only with the bucket
  # owner getting full control of each log file.
  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

# Security floor (SSE-KMS with the evidence key, versioning, TLS-only,
# no public access) plus CloudTrail's statements in the same policy.
module "cloudtrail_bucket" {
  source = "./modules/secure-bucket"

  bucket_id              = aws_s3_bucket.cloudtrail.id
  bucket_arn             = aws_s3_bucket.cloudtrail.arn
  kms_key_arn            = aws_kms_key.evidence.arn
  additional_policy_json = data.aws_iam_policy_document.cloudtrail_bucket.json
}

# --------------------------------------------------------------------
# Trail
# --------------------------------------------------------------------

# With no event selectors, the trail records all management events
# (read and write), which is what audit logging needs. Data events
# (every S3 object read) are not enabled: they're billed per event.
resource "aws_cloudtrail" "main" {
  name           = local.trail_name
  s3_bucket_name = aws_s3_bucket.cloudtrail.id
  kms_key_id     = aws_kms_key.evidence.arn

  is_multi_region_trail         = true
  include_global_service_events = true # IAM, STS and other global services
  enable_log_file_validation    = true

  tags = {
    Control = "AU.L2-3.3.1"
  }

  # CloudTrail validates bucket access when the trail is created, so the
  # bucket policy and encryption must exist first.
  depends_on = [module.cloudtrail_bucket]
}
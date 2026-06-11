######################################################################
# Acme Health — GRC Baseline Module (Capstone Layer 1)
#
# This is a Terraform MODULE — it is called from terraform/main.tf
# via: module "baseline" { source = "./baseline" ... }
#
# It does NOT have a provider or terraform block — those are
# inherited from the root module (terraform/main.tf).
#
# New resources:
#   - KMS CMK with rotation (closes GAP-01, GAP-02)
#   - S3 evidence vault with Object Lock GOVERNANCE mode
#   - CloudTrail multi-region trail with log-file validation
#   - S3 uploads bucket: SSE-KMS (GAP-01), TLS deny (GAP-03), versioning (GAP-04)
#   - Security group for Lambda VPC placement (GAP-05)
#   - SQS DLQ for Lambda (GAP-06)
#   - CloudWatch log group for API Gateway (GAP-08)
######################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name_prefix = "acme-health-intake"
  suffix      = var.resource_suffix
}

######################################################################
# KMS CMK — customer-managed key for PHI at rest.
# Closes GAP-01 (S3) and GAP-02 (DynamoDB).
#
# enable_key_rotation = true satisfies CC6.1: key material is rotated
# annually by AWS KMS without interrupting existing ciphertext.
# key_deletion_window_in_days = 30 gives a recovery window; setting it
# lower risks accidental permanent data loss.
######################################################################

resource "aws_kms_key" "phi" {
  description             = "CMK for Acme Health PHI at rest — S3 and DynamoDB"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Lambda to use the key"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name_prefix}-lambda-${local.suffix}"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to use the key"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${local.name_prefix}-phi"
  target_key_id = aws_kms_key.phi.key_id
}

######################################################################
# S3 Evidence Vault — Object Lock (GOVERNANCE mode), versioning,
# encryption with the PHI CMK.
#
# This is where every pipeline run's signed evidence bundle lands.
# GOVERNANCE mode prevents deletion without a specific IAM permission.
# Design decision: GOVERNANCE over COMPLIANCE for lab environment
# (COMPLIANCE requires AWS support to override; see DESIGN.md).
######################################################################

resource "aws_s3_bucket" "vault" {
  bucket        = "${local.name_prefix}-evidence-vault-${local.suffix}"
  force_destroy = false

  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "vault" {
  bucket = aws_s3_bucket.vault.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 90
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "vault" {
  bucket                  = aws_s3_bucket.vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

######################################################################
# CloudTrail — multi-region trail with log-file validation.
# Closes GAP-08 partially (API calls recorded at AWS API level).
#
# is_multi_region_trail = true captures calls in all regions.
# enable_log_file_validation = true writes hourly SHA-256 digests,
# satisfying CC7.2 audit record integrity.
######################################################################

resource "aws_s3_bucket" "trail" {
  bucket        = "${local.name_prefix}-cloudtrail-${local.suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid     = "AWSCloudTrailAclCheck"
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${local.name_prefix}-mgmt"]
    }
  }
  statement {
    sid     = "AWSCloudTrailWrite"
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${local.name_prefix}-mgmt"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

resource "aws_cloudtrail" "mgmt" {
  name                          = "${local.name_prefix}-mgmt"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
  kms_key_id                    = aws_kms_key.phi.arn

  depends_on = [aws_s3_bucket_policy.trail]
}

######################################################################
# GAP-01: S3 uploads bucket — SSE-KMS with customer CMK.
# The starter bucket already exists; these resources configure it.
######################################################################

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = "${local.name_prefix}-uploads-${local.suffix}"
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

######################################################################
# GAP-03: S3 uploads bucket — deny non-TLS requests.
# aws:SecureTransport = false means the request arrived over HTTP.
######################################################################

data "aws_iam_policy_document" "uploads_tls" {
  statement {
    sid     = "DenyNonTLS"
    effect  = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [
      "arn:aws:s3:::${local.name_prefix}-uploads-${local.suffix}",
      "arn:aws:s3:::${local.name_prefix}-uploads-${local.suffix}/*"
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "uploads" {
  bucket = "${local.name_prefix}-uploads-${local.suffix}"
  policy = data.aws_iam_policy_document.uploads_tls.json
}

######################################################################
# GAP-04: S3 uploads bucket — enable versioning.
# Without versioning, a PUT overwrites PHI with no recovery path.
######################################################################

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = "${local.name_prefix}-uploads-${local.suffix}"
  versioning_configuration {
    status = "Enabled"
  }
}

######################################################################
# GAP-05: Security group for Lambda VPC placement.
# The Lambda is moved into the VPC in main.tf (vpc_config block).
# This security group restricts egress to HTTPS only — the Lambda
# only needs to call DynamoDB and S3, both reachable via VPC endpoints
# or HTTPS. No inbound rules needed (Lambda is invoked by API GW,
# not by network traffic).
######################################################################

resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-sg-${local.suffix}"
  description = "Lambda intake handler - HTTPS egress only"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS to AWS services (DynamoDB, S3, KMS)"
  }
}

######################################################################
# GAP-06: SQS DLQ for Lambda.
# Failed Lambda invocations are routed here instead of silently
# dropped. CC7.2 requires that processing failures are visible.
# max_message_size and message_retention_period ensure failed
# submissions are retained for investigation.
######################################################################

resource "aws_sqs_queue" "lambda_dlq" {
  name                      = "${local.name_prefix}-dlq-${local.suffix}"
  message_retention_seconds = 1209600
  kms_master_key_id         = aws_kms_key.phi.id
}

######################################################################
# GAP-08: CloudWatch log group for API Gateway access logs.
# The log group is created here; the stage access_log_settings
# in main.tf references its ARN via module output.
######################################################################

resource "aws_cloudwatch_log_group" "apigw" {
  name              = "/aws/apigateway/${local.name_prefix}-${local.suffix}"
  retention_in_days = 90
}

######################################################################
# Layer 1 — Customer-managed KMS keys
#
# Purpose : Put PHI and audit-evidence encryption under Acme's own keys.
# Closes  : GAP-01 (S3 uploads), GAP-02 (DynamoDB). hardening.tf points
#           the starter's bucket and table at aws_kms_key.data.
# Control : CMMC SC.L2-3.13.11 (FIPS-validated cryptography; KMS HSMs
#           are FIPS 140-3 Level 3).
#
# Design
#   - Two keys. "data" protects PHI; "evidence" protects the evidence
#     vault and CloudTrail. The workload role can never decrypt the
#     audit trail.
#   - Least privilege. No account-root kms:* statement. Each key policy
#     names exactly who can do what:
#       admins (var.kms_key_administrator_arns): manage only, never
#       encrypt or decrypt; services: pinned to one trail or log group.
#     Key users (Lambda, pipeline) are added when those roles exist.
#   - Rotation on, 30-day deletion window.
######################################################################

# --------------------------------------------------------------------
# Lookups and shared names (used by kms.tf, cloudtrail.tf, hardening.tf)
# --------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.name

  # Built from names (not resource attributes) to avoid a dependency
  # cycle: the key policy needs these ARNs, and the resources need the key.
  trail_name = "${local.name_prefix}-trail"
  trail_arn  = "arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"

  api_access_log_group_name = "/aws/apigateway/${local.name_prefix}-access-${local.suffix}"
  api_access_log_group_arn  = "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:${local.api_access_log_group_name}"

  # Key administrators: my aws sandbox (from terraform.tfvars) plus the pipeline role
  # (oidc-trust.tf), which must manage the keys when it applies on merge.
  kms_admin_arns = concat(var.kms_key_administrator_arns, [aws_iam_role.github_actions.arn])
}

# --------------------------------------------------------------------
# Key administrators (shared by both keys)
# --------------------------------------------------------------------

# Why kms_admin instead of AWS's default account-root kms:* statement:
#   - kms:* for the account root lets ANY IAM principal whose policy
#     allows kms:Decrypt use these keys, so the key policy would no
#     longer say who can read PHI or evidence. Naming admins here makes
#     the key policy the complete access list (least privilege).
#   - It is still required: with no statement allowing PutKeyPolicy, KMS
#     rejects the key (lockout safety check), or the key is unmanageable.
#   - Shared by both keys so the action list is written once.
# Management actions only. No Encrypt/Decrypt/GenerateDataKey, and no
# CreateGrant (an admin could use it to grant itself key use).

data "aws_iam_policy_document" "kms_admin" {
  statement {
    sid    = "KeyAdministration"
    effect = "Allow"
    actions = [
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListKeyRotations",
      "kms:ListResourceTags",
      "kms:ListGrants",
      "kms:PutKeyPolicy",
      "kms:UpdateKeyDescription",
      "kms:EnableKeyRotation",
      "kms:DisableKeyRotation",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:CreateAlias",
      "kms:UpdateAlias",
      "kms:DeleteAlias",
      "kms:EnableKey",
      "kms:DisableKey",
      "kms:RevokeGrant",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion",
    ]
    resources = ["*"] # in a key policy, "*" means this key only

    principals {
      type        = "AWS"
      identifiers = local.kms_admin_arns
    }
  }
}

# ====================================================================
# DATA KEY — PHI (S3 uploads, DynamoDB, DLQ, API access logs)
# ====================================================================

data "aws_iam_policy_document" "kms_data" {
  source_policy_documents = [data.aws_iam_policy_document.kms_admin.json]

  # CloudWatch Logs uses the key as itself, so it must be named here.
  # Limited to the API access log group (GAP-08) only.
  statement {
    sid    = "AllowCloudWatchLogsForApiAccessLogs"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = [local.api_access_log_group_arn]
    }
  }

  # GAP-07 / GAP-01: the Lambda role uploads attachments to the SSE-KMS
  # bucket. S3 documents kms:GenerateDataKey as the permission a single
  # PutObject needs (multipart uploads would also need kms:Decrypt; the
  # handler doesn't use them). ViaService: only through S3.

  statement {
    sid       = "AllowIntakeLambdaViaS3"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.lambda.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${local.region}.amazonaws.com"]
    }
  }

  # GAP-02 / GAP-07: DynamoDB uses the key on behalf of (1) the Lambda
  # role, which writes submissions, and (2) the key admins, because
  # whoever runs Terraform selects this key for the table and DynamoDB
  # acts as that principal. The six actions are the minimum AWS documents
  # for a DynamoDB customer managed key. kms:ViaService means none of
  # these principals can call KMS directly: only DynamoDB can, for them.
  # The Region wildcard is AWS's documented value (DynamoDB needs it to
  # be Region-independent).

  statement {
    sid    = "AllowTableUsersViaDynamoDB"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
      "kms:CreateGrant",
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = concat([aws_iam_role.lambda.arn], local.kms_admin_arns)
    }

    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["dynamodb.*.amazonaws.com"]
    }
  }

  # GAP-06: the Lambda role writes failed events to the encrypted DLQ.
  # SQS producers need GenerateDataKey and Decrypt on the queue's key.
  # kms:ViaService limits this to requests SQS makes for the role, so the
  # role can't call KMS directly to decrypt anything.

  statement {
    sid       = "AllowIntakeLambdaViaSqs"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.lambda.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["sqs.${local.region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "data" {
  description             = "${local.name_prefix}-data-key-PHI"
  deletion_window_in_days = var.kms_deletion_window_in_days
  enable_key_rotation     = true
  rotation_period_in_days = var.kms_rotation_period_in_days
  policy                  = data.aws_iam_policy_document.kms_data.json

  tags = {
    Name    = "${local.name_prefix}-data"
    Control = "SC.L2-3.13.11"
    Gap     = "GAP-01_and_GAP-02"
  }
}

resource "aws_kms_alias" "data" {
  name          = "alias/${local.name_prefix}-data"
  target_key_id = aws_kms_key.data.key_id
}

# ====================================================================
# EVIDENCE KEY — evidence vault + CloudTrail
# ====================================================================

data "aws_iam_policy_document" "kms_evidence" {
  source_policy_documents = [data.aws_iam_policy_document.kms_admin.json]

  # CloudTrail encrypts logs as itself. Pinned to this trail only
  # (aws:SourceArn) and to trails in this account (encryption context).
  statement {
    sid       = "AllowCloudTrailEncryptLogs"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"]
    }
  }

  # Pipeline (Phase 4): upload signed evidence bundles to the vault and
  # read them back to verify. GenerateDataKey to write, Decrypt to read
  # (and for multipart uploads). Only through S3.
  statement {
    sid       = "AllowPipelineEvidenceViaS3"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.github_actions.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${local.region}.amazonaws.com"]
    }
  }

  statement {
    sid       = "AllowCloudTrailDescribeKey"
    effect    = "Allow"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]

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
}

resource "aws_kms_key" "evidence" {
  description             = "${local.name_prefix} evidence key (vault + CloudTrail)"
  deletion_window_in_days = var.kms_deletion_window_in_days
  enable_key_rotation     = true
  rotation_period_in_days = var.kms_rotation_period_in_days
  policy                  = data.aws_iam_policy_document.kms_evidence.json

  tags = {
    Name      = "${local.name_prefix}-evidence"
    DataClass = "evidence" # overrides default "phi": this key holds audit data
    Control   = "SC.L2-3.13.11"
  }
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/${local.name_prefix}-evidence"
  target_key_id = aws_kms_key.evidence.key_id
}


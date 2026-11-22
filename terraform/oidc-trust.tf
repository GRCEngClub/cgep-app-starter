######################################################################
# Layer 1 — GitHub Actions OIDC trust (pipeline identity)
#
# Purpose : The pipeline gets short-lived AWS credentials for each run by
#           exchanging GitHub's OIDC token. No long-lived access keys are
#           stored in GitHub.
# Control : AC.L2-3.1.5 (least privilege) for the deploy identity; also
#           supports the evidence chain (it uploads to the vault).
#
# Design
#   - One role for both pull requests (plan) and main (apply), chosen for
#     simplicity. Trade-off: PR runs hold the same write credentials as
#     main. Deferred: split into a read-only PR role and a main-only
#     apply role.
#   - Trust is pinned to this repo by its IMMUTABLE subject (owner and
#     repo IDs, the GitHub format for repos created after 2026-07-15),
#     so a recycled repo or org name can't assume the role.
#   - Permissions are scoped to this stack's resources by name prefix
#     where AWS allows it, and to the specific actions Terraform needs.
#   - The pipeline can create and update, but cannot delete the data
#     stores or the audit trail, cannot remove Object Lock, cannot
#     schedule key deletion, and cannot change its own role (it can only
#     write IAM roles named acme-health-intake-lambda-*). Those actions
#     need a human admin.
######################################################################

# --------------------------------------------------------------------
# OIDC provider and role
# --------------------------------------------------------------------

# One provider per URL per account. If your account already has one
# (e.g. from Lab 4.3), see the note in the step instructions.
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # No thumbprint_list: for GitHub, AWS validates against its own trusted
  # CAs and ignores thumbprints.
}

data "aws_iam_policy_document" "github_actions_trust" {
  statement {
    sid     = "GitHubActionsThisRepoOnly"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Exact subjects only (StringEquals, no wildcards): runs on the main
    # branch, and pull-request runs, of this one repo.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "${var.github_oidc_subject_prefix}:ref:refs/heads/main",
        "${var.github_oidc_subject_prefix}:pull_request",
      ]
    }
  }
}

resource "aws_iam_role" "github_actions" {
  name                 = "${local.name_prefix}-github-actions"
  assume_role_policy   = data.aws_iam_policy_document.github_actions_trust.json
  max_session_duration = 3600 # one hour: long enough for a plan+apply run

  tags = {
    Control = "AC.L2-3.1.5"
    Gap     = "GAP-07"
  }
}

# --------------------------------------------------------------------
# Permissions
# --------------------------------------------------------------------

locals {
  arn_prefix = "arn:${local.partition}"
  # ARNs of this stack's resources, by the name prefix every resource uses.
  stack_buckets    = "${local.arn_prefix}:s3:::${local.name_prefix}-*"
  stack_lambda     = "${local.arn_prefix}:lambda:${local.region}:${local.account_id}:function:${local.name_prefix}-*"
  stack_table      = "${local.arn_prefix}:dynamodb:${local.region}:${local.account_id}:table/${local.name_prefix}-*"
  stack_queue      = "${local.arn_prefix}:sqs:${local.region}:${local.account_id}:${local.name_prefix}-*"
  stack_log_groups = "${local.arn_prefix}:logs:${local.region}:${local.account_id}:log-group:/aws/apigateway/${local.name_prefix}-*"
  lambda_role      = "${local.arn_prefix}:iam::${local.account_id}:role/${local.name_prefix}-lambda-*"
}

data "aws_iam_policy_document" "github_actions" {
  # ---- Terraform remote state (step 2.9) ----
  statement {
    sid       = "StateBucketList"
    actions   = ["s3:ListBucket"]
    resources = ["${local.arn_prefix}:s3:::${var.tf_state_bucket}"]
  }

  statement {
    sid       = "StateFileAndLock"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${local.arn_prefix}:s3:::${var.tf_state_bucket}/capstone/terraform.tfstate*"] # state + .tflock
  }

  # ---- Read access for terraform plan / refresh ----
  # Read-only actions across the services this stack uses. Reading
  # objects in the PHI bucket would still fail: the role isn't allowed to
  # decrypt with the data key through S3.
  statement {
    sid = "ReadForPlan"
    actions = [
      "ec2:Describe*",
      "s3:Get*",
      "s3:List*",
      "lambda:Get*",
      "lambda:List*",
      "iam:Get*",
      "iam:List*",
      "kms:ListAliases",
      "dynamodb:Describe*",
      "dynamodb:ListTagsOfResource",
      "logs:Describe*",
      "logs:ListTagsForResource",
      "logs:ListTagsLogGroup",
      "sqs:GetQueueAttributes",
      "sqs:ListQueueTags",
      "apigateway:GET",
      "cloudtrail:Describe*",
      "cloudtrail:Get*",
      "cloudtrail:List*",
    ]
    resources = ["*"]
  }

  # ---- S3: configure this stack's buckets (no DeleteBucket) ----
  statement {
    sid = "ConfigureStackBuckets"
    actions = [
      "s3:CreateBucket",
      "s3:PutBucketTagging",
      "s3:PutBucketPolicy",
      "s3:PutBucketVersioning",
      "s3:PutEncryptionConfiguration",
      "s3:PutBucketPublicAccessBlock",
      "s3:PutBucketObjectLockConfiguration",
    ]
    resources = [local.stack_buckets]
  }

  # ---- Evidence upload and verification (Phase 4) ----
  statement {
    sid       = "UploadAndVerifyEvidence"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:GetObjectRetention"]
    resources = ["${aws_s3_bucket.evidence.arn}/*"]
  }

  # ---- DynamoDB: the intake table (no DeleteTable) ----
  statement {
    sid       = "ManageStackTable"
    actions   = ["dynamodb:CreateTable", "dynamodb:UpdateTable", "dynamodb:TagResource", "dynamodb:UntagResource"]
    resources = [local.stack_table]
  }

  # ---- Lambda: the intake function ----
  statement {
    sid = "ManageStackFunction"
    actions = [
      "lambda:CreateFunction",
      "lambda:UpdateFunctionCode",
      "lambda:UpdateFunctionConfiguration",
      "lambda:DeleteFunction",
      "lambda:PutFunctionConcurrency",
      "lambda:DeleteFunctionConcurrency",
      "lambda:AddPermission",
      "lambda:RemovePermission",
      "lambda:TagResource",
      "lambda:UntagResource",
    ]
    resources = [local.stack_lambda]
  }

  # ---- IAM: ONLY the Lambda's role (never this pipeline role) ----
  statement {
    sid = "ManageLambdaRoleOnly"
    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:PutRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:DetachRolePolicy",
    ]
    resources = [local.lambda_role]
  }

  # Attach only the two AWS managed policies the Lambda role uses.
  statement {
    sid       = "AttachOnlyLambdaManagedPolicies"
    actions   = ["iam:AttachRolePolicy"]
    resources = [local.lambda_role]

    condition {
      test     = "ArnEquals"
      variable = "iam:PolicyARN"
      values = [
        "${local.arn_prefix}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        "${local.arn_prefix}:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole",
      ]
    }
  }

  # Pass the Lambda role to the Lambda service only.
  statement {
    sid       = "PassLambdaRoleToLambdaOnly"
    actions   = ["iam:PassRole"]
    resources = [local.lambda_role]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com"]
    }
  }

  # ---- KMS: create keys and manage this stack's aliases ----
  # Key-level management comes from the key policies, which name this
  # role as a key administrator (kms.tf).
  statement {
    sid       = "CreateKeys"
    actions   = ["kms:CreateKey", "kms:TagResource"]
    resources = ["*"] # a key doesn't have an ARN until it exists
  }

  statement {
    sid       = "ManageStackAliases"
    actions   = ["kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias"]
    resources = ["${local.arn_prefix}:kms:${local.region}:${local.account_id}:alias/${local.name_prefix}-*"]
  }

  # ---- VPC networking for GAP-05 (endpoints, route table, SGs) ----
  # EC2 IDs are random, so these can't be scoped by name; the actions are
  # limited to the networking pieces this stack manages (no instances).
  statement {
    sid = "ManageStackNetworking"
    actions = [
      "ec2:CreateRouteTable",
      "ec2:DeleteRouteTable",
      "ec2:AssociateRouteTable",
      "ec2:DisassociateRouteTable",
      "ec2:CreateVpcEndpoint",
      "ec2:ModifyVpcEndpoint",
      "ec2:DeleteVpcEndpoints",
      "ec2:CreateSecurityGroup",
      "ec2:DeleteSecurityGroup",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:CreateTags",
      "ec2:DeleteTags",
    ]
    resources = ["*"]
  }

  # ---- API Gateway HTTP API ----
  statement {
    sid     = "ManageHttpApi"
    actions = ["apigateway:POST", "apigateway:PATCH", "apigateway:PUT", "apigateway:DELETE"]
    resources = [
      "${local.arn_prefix}:apigateway:${local.region}::/apis",
      "${local.arn_prefix}:apigateway:${local.region}::/apis/*",
      "${local.arn_prefix}:apigateway:${local.region}::/tags/*",
    ]
  }

  # ---- CloudWatch Logs: API access log group (no DeleteLogGroup) ----
  statement {
    sid       = "ManageApiLogGroup"
    actions   = ["logs:CreateLogGroup", "logs:PutRetentionPolicy", "logs:AssociateKmsKey", "logs:TagResource", "logs:TagLogGroup"]
    resources = [local.stack_log_groups, "${local.stack_log_groups}:*"]
  }

  # AWS's documented permissions for whoever enables HTTP API access
  # logging. AWS lists them with Resource "*".
  statement {
    sid = "EnableApiAccessLogging"
    actions = [
      "logs:CreateLogDelivery",
      "logs:GetLogDelivery",
      "logs:UpdateLogDelivery",
      "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries",
      "logs:PutResourcePolicy",
      "logs:DescribeResourcePolicies",
    ]
    resources = ["*"]
  }

  # ---- SQS: the DLQ (no DeleteQueue) ----
  statement {
    sid       = "ManageStackQueue"
    actions   = ["sqs:CreateQueue", "sqs:SetQueueAttributes", "sqs:TagQueue", "sqs:UntagQueue"]
    resources = [local.stack_queue]
  }

  # ---- CloudTrail: this trail (no StopLogging / DeleteTrail) ----
  statement {
    sid       = "ManageStackTrail"
    actions   = ["cloudtrail:CreateTrail", "cloudtrail:UpdateTrail", "cloudtrail:StartLogging", "cloudtrail:AddTags", "cloudtrail:RemoveTags"]
    resources = [local.trail_arn]
  }

  # ---- Guardrails: explicit denies win over any Allow ----
  # Even if a future edit widens the Allows above, the pipeline can never
  # remove evidence locks, blind the audit trail, or destroy keys.
  statement {
    sid    = "DenyEvidenceAndAuditTampering"
    effect = "Deny"
    actions = [
      "s3:BypassGovernanceRetention",
      "s3:DeleteBucket",
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "kms:ScheduleKeyDeletion",
      "kms:DisableKey",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "github_actions" {
  name   = "terraform-pipeline"
  role   = aws_iam_role.github_actions.id
  policy = data.aws_iam_policy_document.github_actions.json
}
######################################################################
# GitHub OIDC trust + the two pipeline roles.
#
# plan role  : assumable only from pull_request runs. Reads the account,
#              can take the state lock, can write evidence to the vault.
#              Cannot change infrastructure.
# apply role : assumable only from the main branch. Can change the project's
#              infrastructure in one region, can write evidence, and can
#              never delete or un-lock evidence.
#
# Trust lists BOTH subject formats: repos created before 15 Jul 2026 use
# repo:OWNER/REPO:..., newer ones use repo:OWNER@ID/REPO@ID:... .
######################################################################

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://${local.oidc_host}"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

data "aws_iam_policy_document" "trust_plan" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "${local.oidc_host}:sub"
      values = [
        "repo:${var.github_org}/${var.github_repo}:pull_request",
        "repo:${var.github_org}@*/${var.github_repo}@*:pull_request",
      ]
    }
  }
}

data "aws_iam_policy_document" "trust_apply" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "${local.oidc_host}:sub"
      values = [
        "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main",
        "repo:${var.github_org}@*/${var.github_repo}@*:ref:refs/heads/main",
      ]
    }
  }
}

resource "aws_iam_role" "plan" {
  name               = "cgep-capstone-plan"
  assume_role_policy = data.aws_iam_policy_document.trust_plan.json
}

resource "aws_iam_role" "apply" {
  name               = "cgep-capstone-apply"
  assume_role_policy = data.aws_iam_policy_document.trust_apply.json
}

# Both roles can read the account to refresh state and plan.
resource "aws_iam_role_policy_attachment" "plan_readonly" {
  role       = aws_iam_role.plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "apply_readonly" {
  role       = aws_iam_role.apply.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

data "aws_kms_alias" "evidence" {
  name = local.evidence_alias
}

######################################################################
# Permissions shared by both roles: write evidence to the vault.
######################################################################

data "aws_iam_policy_document" "vault_write" {
  statement {
    sid       = "WriteEvidence"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion", "s3:GetBucketLocation", "s3:ListBucket"]
    resources = ["arn:aws:s3:::${local.vault_bucket}", "arn:aws:s3:::${local.vault_bucket}/*"]
  }

  statement {
    sid       = "UseEvidenceKey"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"]
    resources = [data.aws_kms_alias.evidence.target_key_arn]
  }
}

# Plan role: can take the state lock (a small .tflock file) and read state.
data "aws_iam_policy_document" "plan_inline" {
  source_policy_documents = [data.aws_iam_policy_document.vault_write.json]

  statement {
    sid       = "ListState"
    effect    = "Allow"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = [aws_s3_bucket.state.arn]
  }

  statement {
    sid       = "ReadState"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.state.arn}/${local.state_key}", "${aws_s3_bucket.state.arn}/${local.state_key}.tflock"]
  }

  statement {
    sid       = "TakeStateLock"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.state.arn}/${local.state_key}.tflock"]
  }
}

resource "aws_iam_role_policy" "plan" {
  name   = "plan-inline"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.plan_inline.json
}

# Apply role: change the project's infrastructure, in one region, nothing else.
data "aws_iam_policy_document" "apply_inline" {
  source_policy_documents = [data.aws_iam_policy_document.vault_write.json]

  statement {
    sid       = "ReadWriteState"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.state.arn}/${local.state_key}", "${aws_s3_bucket.state.arn}/${local.state_key}.tflock"]
  }

  statement {
    sid       = "ListState"
    effect    = "Allow"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = [aws_s3_bucket.state.arn]
  }

  # The services the workload uses, locked to ca-central-1. IAM is handled
  # separately below because it is global and is the escalation risk.
  statement {
    sid    = "ManageWorkloadServices"
    effect = "Allow"
    actions = [
      "ec2:*",
      "s3:*",
      "dynamodb:*",
      "kms:*",
      "lambda:*",
      "apigateway:*",
      "cloudtrail:*",
      "logs:*",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }

  # IAM only for roles named acme-health-intake-*, never the pipeline roles.
  statement {
    sid    = "ManageWorkloadRoles"
    effect = "Allow"
    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:PutRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:PassRole",
    ]
    resources = [local.role_name_arn]
  }

  # Evidence can be added but never removed, un-locked or reconfigured.
  statement {
    sid    = "ProtectEvidenceVault"
    effect = "Deny"
    actions = [
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
      "s3:BypassGovernanceRetention",
      "s3:PutObjectRetention",
      "s3:PutBucketObjectLockConfiguration",
      "s3:DeleteBucket",
    ]
    resources = ["arn:aws:s3:::${local.vault_bucket}", "arn:aws:s3:::${local.vault_bucket}/*"]
  }

  statement {
    sid       = "ProtectStateBucket"
    effect    = "Deny"
    actions   = ["s3:DeleteBucket", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy"]
    resources = [aws_s3_bucket.state.arn]
  }
}

resource "aws_iam_role_policy" "apply" {
  name   = "apply-inline"
  role   = aws_iam_role.apply.id
  policy = data.aws_iam_policy_document.apply_inline.json
}

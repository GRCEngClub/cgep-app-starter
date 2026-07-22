# oidc/main.tf
#
# Bootstrap module: the GitHub OIDC trust + IAM role the pipeline assumes,
# and the Terraform state bucket the main terraform/ config's backend
# points at. Applied once by hand, not by CI -- the pipeline can't create
# the very role it needs in order to authenticate, and terraform/ can't
# manage its own backend bucket before that backend exists. Kept in its
# own root module with its own (local) state for exactly that reason.
#
# The OIDC provider + trust-policy shape is adapted from
# cgep-labs/oidc/main.tf (CGE-P Lab 4.3's reference implementation). Two
# things are different here, both because this pipeline actually applies
# infrastructure changes, which the lab pipeline never did:
#   - the role gets a real scoped policy instead of the AWS-managed
#     ReadOnlyAccess (the lab's own troubleshooting notes call this out:
#     "For a real apply pipeline, you'd attach a more targeted policy.")
#   - this module also owns the Terraform state bucket, which the lab
#     never needed because it never ran `terraform apply` in CI.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "github_org" {
  type    = string
  default = "samruss824"
}

variable "github_repo" {
  type    = string
  default = "cgep-app-starter"
}

data "aws_caller_identity" "current" {}

######################################################################
# OIDC trust. The provider already existed in this account (created by
# earlier lab work) -- imported into this state rather than re-created;
# see README in this directory for the import command.
######################################################################

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "grc_gate" {
  name = "acme-health-intake-grc-gate"

  # StringLike with a trailing wildcard on `sub`, not StringEquals: PR runs
  # present `repo:OWNER/REPO:pull_request`, branch pushes present
  # `repo:OWNER/REPO:ref:refs/heads/BRANCH` -- this workflow triggers on
  # both, so it needs to match both shapes. The org/repo portion itself is
  # fixed, not wildcarded -- loosening that would trust every repo on
  # GitHub, not just this one.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike   = { "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*" }
      }
    }]
  })
}

######################################################################
# Terraform state bucket. AES256, not the workload CMK: this is a
# separate root module/state from terraform/, so it can't reference
# aws_kms_key.grc directly without a fragile cross-module lookup, and
# state files here don't carry PHI -- just resource IDs/ARNs/metadata.
# S3 native locking (use_lockfile in terraform/main.tf's backend block)
# needs no separate DynamoDB lock table.
######################################################################

resource "aws_s3_bucket" "tf_state" {
  bucket = "acme-health-intake-tfstate-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "tf_state" {
  bucket = aws_s3_bucket.tf_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tf_state" {
  bucket = aws_s3_bucket.tf_state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "tf_state" {
  bucket                  = aws_s3_bucket.tf_state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

######################################################################
# Permissions for the grc-gate role. Scoped by service and, where the
# AWS API supports it, by resource ARN pattern matching this workload's
# "acme-health-intake-*" naming convention -- broad within each service,
# not account-admin, but not down to individual actions/resources either.
# Tightening this to full least privilege is a "next sprint" item (see
# WRITEUP.md) -- EC2 network provisioning in particular doesn't support
# resource-level scoping for most create/delete actions, so that
# statement is necessarily Resource "*".
######################################################################

resource "aws_iam_role_policy" "grc_gate" {
  name = "acme-health-intake-grc-gate-policy"
  role = aws_iam_role.grc_gate.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TerraformStateBucket"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.tf_state.arn,
          "${aws_s3_bucket.tf_state.arn}/*",
        ]
      },
      {
        Sid    = "WorkloadAndEvidenceBuckets"
        Effect = "Allow"
        Action = "s3:*"
        Resource = [
          "arn:aws:s3:::acme-health-intake-*",
          "arn:aws:s3:::acme-health-intake-*/*",
        ]
      },
      {
        Sid      = "DynamoDB"
        Effect   = "Allow"
        Action   = "dynamodb:*"
        Resource = "arn:aws:dynamodb:*:${data.aws_caller_identity.current.account_id}:table/acme-health-intake-*"
      },
      {
        Sid      = "Lambda"
        Effect   = "Allow"
        Action   = "lambda:*"
        Resource = "arn:aws:lambda:*:${data.aws_caller_identity.current.account_id}:function:acme-health-intake-*"
      },
      {
        Sid    = "IamForLambdaExecutionRole"
        Effect = "Allow"
        Action = [
          "iam:GetRole", "iam:CreateRole", "iam:DeleteRole", "iam:TagRole",
          "iam:PassRole",
          "iam:PutRolePolicy", "iam:GetRolePolicy", "iam:DeleteRolePolicy", "iam:ListRolePolicies",
          "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:ListAttachedRolePolicies",
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/acme-health-intake-*"
      },
      {
        Sid    = "Ec2Networking"
        Effect = "Allow"
        # EC2 network-provisioning actions (VPC/subnet/route table/IGW/SG/
        # endpoint create+delete) mostly don't support resource-level ARNs
        # in IAM -- Resource "*" is the standard shape for this statement.
        Action = [
          "ec2:DescribeVpcs", "ec2:DescribeSubnets", "ec2:DescribeRouteTables",
          "ec2:DescribeInternetGateways", "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcEndpoints", "ec2:DescribeAvailabilityZones",
          "ec2:DescribeNetworkInterfaces",
          "ec2:CreateVpc", "ec2:DeleteVpc", "ec2:ModifyVpcAttribute",
          "ec2:CreateSubnet", "ec2:DeleteSubnet", "ec2:ModifySubnetAttribute",
          "ec2:CreateRouteTable", "ec2:DeleteRouteTable", "ec2:CreateRoute", "ec2:DeleteRoute",
          "ec2:AssociateRouteTable", "ec2:DisassociateRouteTable",
          "ec2:CreateInternetGateway", "ec2:DeleteInternetGateway",
          "ec2:AttachInternetGateway", "ec2:DetachInternetGateway",
          "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroupEgress", "ec2:RevokeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress",
          "ec2:CreateVpcEndpoint", "ec2:DeleteVpcEndpoints", "ec2:ModifyVpcEndpoint",
          "ec2:CreateTags", "ec2:DeleteTags",
        ]
        Resource = "*"
      },
      {
        Sid      = "Kms"
        Effect   = "Allow"
        Action   = ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListAliases", "kms:GenerateDataKey", "kms:Decrypt", "kms:TagResource"]
        Resource = "arn:aws:kms:*:${data.aws_caller_identity.current.account_id}:key/*"
      },
      {
        Sid      = "KmsAliases"
        Effect   = "Allow"
        Action   = ["kms:CreateAlias", "kms:DeleteAlias", "kms:UpdateAlias"]
        Resource = "arn:aws:kms:*:${data.aws_caller_identity.current.account_id}:alias/acme-health-intake-*"
      },
      {
        Sid    = "CloudTrailRead"
        Effect = "Allow"
        Action = ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:ListTags", "cloudtrail:GetEventSelectors"]
        Resource = "*"
      },
      {
        Sid      = "CloudTrailWrite"
        Effect   = "Allow"
        Action   = "cloudtrail:*"
        Resource = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/acme-health-intake-*"
      },
      {
        Sid      = "ApiGateway"
        Effect   = "Allow"
        Action   = "apigateway:*"
        Resource = "arn:aws:apigateway:*::/*"
      },
      {
        Sid      = "CloudWatchLogs"
        Effect   = "Allow"
        Action   = "logs:*"
        Resource = "arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/aws/apigateway/acme-health-intake-*"
      },
      {
        Sid      = "Sts"
        Effect   = "Allow"
        Action   = "sts:GetCallerIdentity"
        Resource = "*"
      },
    ]
  })
}

output "role_arn" {
  value = aws_iam_role.grc_gate.arn
}

output "tf_state_bucket" {
  value = aws_s3_bucket.tf_state.id
}

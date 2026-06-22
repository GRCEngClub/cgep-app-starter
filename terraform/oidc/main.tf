# GitHub Actions OIDC → IAM role for grc-gate pipeline (Phase 3).
# Apply separately: cd terraform/oidc && terraform init && terraform apply

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "github_org" {
  type        = string
  description = "GitHub username or org that owns the capstone repo"
}

variable "github_repo" {
  type        = string
  description = "GitHub repository name (capstone fork)"
}

variable "evidence_vault_name" {
  type        = string
  description = "Evidence vault bucket name (terraform output evidence_vault_name)"
}

variable "role_name" {
  type    = string
  default = "cgep-grc-gate"
}

data "aws_caller_identity" "current" {}

# Reuse account-wide GitHub OIDC provider (often created in Lab 4.x / prior apply).
data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_role" "grc_gate" {
  name = var.role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*"
        }
      }
    }]
  })
}

# Sandbox capstone: broad apply permissions. Tighten for production.
resource "aws_iam_role_policy_attachment" "terraform_apply" {
  role       = aws_iam_role.grc_gate.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Scoped write to evidence vault runs/ prefix (defense in depth; also in WRITEUP).
resource "aws_iam_role_policy" "vault_write" {
  name = "vault-write"
  role = aws_iam_role.grc_gate.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "VaultList"
        Effect = "Allow"
        Action = ["s3:ListBucket"]
        Resource = "arn:aws:s3:::${var.evidence_vault_name}"
        Condition = {
          StringLike = { "s3:prefix" = ["runs/*"] }
        }
      },
      {
        Sid    = "VaultPut"
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:GetObject", "s3:GetObjectRetention", "s3:GetObjectVersion"]
        Resource = "arn:aws:s3:::${var.evidence_vault_name}/runs/*"
      },
    ]
  })
}

output "role_arn" {
  description = "Set as GitHub repository variable AWS_ROLE_ARN"
  value       = aws_iam_role.grc_gate.arn
}

output "oidc_provider_arn" {
  value = data.aws_iam_openid_connect_provider.github.arn
}

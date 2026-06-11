######################################################################
# GitHub Actions OIDC — keyless IAM role for the GRC pipeline.
#
# This creates:
#   1. An OIDC identity provider trusting token.actions.githubusercontent.com
#   2. An IAM role that GitHub Actions can assume from the capstone repo
#   3. A policy granting the pipeline what it needs: Terraform apply,
#      S3 vault upload, CloudWatch, X-Ray, and Cosign (no extra AWS perms)
#
# The role ARN is exported as an output and stored as a GitHub secret
# AWS_ROLE_ARN so the workflow can reference it.
######################################################################

data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_role" "github_actions" {
  name = "${local.name_prefix}-github-actions-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = data.aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:davin1121/cgep-capstone:*"
        }
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "github_actions" {
  name = "grc-pipeline"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TerraformState"
        Effect = "Allow"
        Action = [
          "s3:GetObject", "s3:PutObject", "s3:ListBucket",
          "s3:DeleteObject", "s3:GetBucketVersioning"
        ]
        Resource = [
          "arn:aws:s3:::${local.name_prefix}-tfstate-*",
          "arn:aws:s3:::${local.name_prefix}-tfstate-*/*"
        ]
      },
      {
        Sid    = "EvidenceVaultUpload"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetObjectVersion"
        ]
        Resource = [
          "arn:aws:s3:::${local.name_prefix}-evidence-vault-${local.suffix}",
          "arn:aws:s3:::${local.name_prefix}-evidence-vault-${local.suffix}/*"
        ]
      },
      {
        Sid    = "TerraformWorkload"
        Effect = "Allow"
        Action = [
          "ec2:*", "lambda:*", "iam:*", "s3:*",
          "dynamodb:*", "kms:*", "sqs:*",
          "logs:*", "cloudtrail:*",
          "apigateway:*", "xray:*",
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      }
    ]
  })
}

output "github_actions_role_arn" {
  description = "ARN to set as AWS_ROLE_ARN GitHub secret."
  value       = aws_iam_role.github_actions.arn
}

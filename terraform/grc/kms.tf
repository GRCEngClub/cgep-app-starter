######################################################################
# HIPAA 164.312(a)(2)(iv) — Encryption and Decryption
# Customer Managed Key for PHI at rest.
# Closes GAP-01 (S3) and GAP-02 (DynamoDB).
######################################################################

resource "aws_kms_key" "phi" {
  description             = "CMK for Acme Health PHI — S3 uploads + DynamoDB submissions"
  deletion_window_in_days = 7
  enable_key_rotation     = true

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
        Sid    = "Allow S3 Service"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow DynamoDB Service"
        Effect = "Allow"
        Principal = {
          Service = "dynamodb.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name    = "acme-health-phi-cmk"
    Purpose = "phi-encryption"
  }
}

resource "aws_kms_alias" "phi" {
  name          = "alias/acme-health-phi"
  target_key_id = aws_kms_key.phi.key_id
}

resource "aws_kms_key" "evidence_vault" {
  description             = "CMK for GRC evidence vault"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name    = "acme-health-evidence-vault-cmk"
    Purpose = "evidence-vault"
  }
}

resource "aws_kms_alias" "evidence_vault" {
  name          = "alias/acme-health-evidence-vault"
  target_key_id = aws_kms_key.evidence_vault.key_id
}

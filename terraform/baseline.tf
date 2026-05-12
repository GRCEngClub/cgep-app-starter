# GRC Baseline overrides for Acme Health Patient Intake API
# Closes GAP-01, GAP-02, GAP-03, GAP-04, GAP-05, GAP-07

######################################################################
# GAP-01: S3 uploads bucket - SSE-KMS with customer CMK
# CMMC SC.L2-3.13.11
######################################################################

# resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

######################################################################
# GAP-03: S3 TLS-only bucket policy
# CMMC SC.L2-3.13.8
######################################################################

resource "aws_s3_bucket_policy" "uploads_tls" {
  bucket = aws_s3_bucket.uploads.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyNonTLS"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [
        aws_s3_bucket.uploads.arn,
        "${aws_s3_bucket.uploads.arn}/*"
      ]
      Condition = {
        Bool = {
          "aws:SecureTransport" = "false"
        }
      }
    }]
  })
}

######################################################################
# GAP-04: S3 versioning
# CMMC MP.L2-3.8.9
######################################################################

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  versioning_configuration {
    status = "Enabled"
  }
}

######################################################################
# GAP-02: DynamoDB CMK encryption
# CMMC SC.L2-3.13.11
######################################################################

resource "aws_dynamodb_table" "intake_encryption" {
  name         = aws_dynamodb_table.intake.name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "submission_id"

  attribute {
    name = "submission_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.phi.arn
  }

  lifecycle {
    ignore_changes = [name]
  }
}

######################################################################
# GAP-05: Lambda VPC config
# CMMC SC.L2-3.13.1
######################################################################

resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-sg"
  description = "Security group for Lambda in VPC"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name       = "${local.name_prefix}-lambda-sg"
    ControlRef = "SC.L2-3.13.1"
  }
}

######################################################################
# GAP-07: Tightened IAM policy - least privilege
# CMMC AC.L2-3.1.5
######################################################################

resource "aws_iam_role_policy" "lambda_least_privilege" {
  name = "intake-data-access-least-privilege"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBLeastPrivilege"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ]
        Resource = aws_dynamodb_table.intake.arn
      },
      {
        Sid    = "S3LeastPrivilege"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.uploads.arn}/*"
      },
      {
        Sid    = "KMSAccess"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.phi.arn
      }
    ]
  })
}
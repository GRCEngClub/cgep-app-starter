############################################
# GAP‑01 — Enforce SSE‑KMS on uploads bucket
############################################

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = module.starter.uploads_bucket_id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
     
    }
  }
}

############################################
# GAP‑04 — Enable versioning on uploads bucket
############################################

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = module.starter.uploads_bucket_id

  versioning_configuration {
    status = "Enabled"
  }
}

############################################
# GAP‑03 — Enforce TLS (deny insecure transport)
############################################

resource "aws_s3_bucket_policy" "uploads_tls" {
  bucket = module.starter.uploads_bucket_id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::${module.starter.uploads_bucket_id}",
        "arn:aws:s3:::${module.starter.uploads_bucket_id}/*"
      ],
      "Condition": {
        "Bool": { "aws:SecureTransport": "false" }
      }
    }
  ]
}
EOF
}

############################################
# GAP‑02 — DynamoDB must use CMK
############################################

resource "aws_dynamodb_table" "intake_override" {
  name         = module.starter.intake_table_name
  billing_mode = "PAY_PER_REQUEST"

  hash_key = "id"

  attribute {
    name = "id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.grc_cmk.arn
  }
}

############################################
# GAP‑07 — IAM least privilege (replace wildcards)
############################################

data "aws_iam_policy_document" "lambda_policy" {
  statement {
    sid    = "DynamoDBWrite"
    effect = "Allow"

    actions = [
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:GetItem"
    ]

    resources = [
      module.starter.intake_table_arn
    ]
  }

  statement {
    sid    = "S3Write"
    effect = "Allow"

    actions = [
      "s3:PutObject",
      "s3:GetObject"
    ]

    resources = [
      "${module.starter.uploads_bucket_arn}/*"
    ]
  }
}

resource "aws_iam_policy" "lambda_restricted" {
  name   = "acme-lambda-restricted"
  policy = data.aws_iam_policy_document.lambda_policy.json
}

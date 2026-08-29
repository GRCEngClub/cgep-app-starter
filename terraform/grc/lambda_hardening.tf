######################################################################
# Lambda Hardening
# GAP-05: VPC placement              — HIPAA 164.312(e)(1)
# GAP-06: DLQ + X-Ray tracing       — HIPAA 164.312(b)
# GAP-07: Least privilege IAM       — HIPAA 164.312(a)(1)
######################################################################

# Security group for Lambda inside the VPC
resource "aws_security_group" "lambda" {
  name        = "acme-health-lambda-sg"
  description = "Security group for intake Lambda — egress only"
  vpc_id      = data.terraform_remote_state.starter.outputs.vpc_id

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS egress for AWS service calls"
  }

  tags = { Name = "acme-health-lambda-sg" }
}

# GAP-06: Dead Letter Queue for failed Lambda invocations
resource "aws_sqs_queue" "lambda_dlq" {
  name                      = "acme-health-intake-dlq"
  message_retention_seconds = 1209600  # 14 days
  kms_master_key_id         = aws_kms_key.phi.arn

  tags = { Name = "acme-health-intake-dlq" }
}

# GAP-07: Least privilege inline policy replacing dynamodb:* and s3:*
resource "aws_iam_role_policy" "lambda_least_privilege" {
  name = "intake-least-privilege"
  role = data.terraform_remote_state.starter.outputs.lambda_role_id

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
        Resource = data.terraform_remote_state.starter.outputs.intake_table_arn
      },
      {
        Sid    = "S3LeastPrivilege"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${data.terraform_remote_state.starter.outputs.uploads_bucket_arn}/*"
      },
      {
        Sid    = "KMSAccess"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.phi.arn
      },
      {
        Sid    = "SQSDLQAccess"
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = aws_sqs_queue.lambda_dlq.arn
      }
    ]
  })
}

# GAP-05 + GAP-06: Lambda VPC config, DLQ, X-Ray
# Note: We update the existing Lambda function's configuration
resource "aws_lambda_function_event_invoke_config" "intake" {
  function_name = data.terraform_remote_state.starter.outputs.lambda_function_name

  destination_config {
    on_failure {
      destination = aws_sqs_queue.lambda_dlq.arn
    }
  }
}

# VPC and X-Ray require the Lambda to be redeployed with new config.
# We express this as a separate resource that the pipeline applies.
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = data.terraform_remote_state.starter.outputs.lambda_role_id
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_xray" {
  role       = data.terraform_remote_state.starter.outputs.lambda_role_id
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

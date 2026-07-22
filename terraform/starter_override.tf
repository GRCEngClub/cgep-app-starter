# terraform/starter_override.tf
#
# Terraform override file (name matches `*_override.tf`, so Terraform merges
# these blocks into the matching resources from main.tf rather than treating
# them as duplicate declarations). This is the mechanism for closing gaps
# that are *arguments of a resource the starter already declared* — SSE on
# aws_dynamodb_table, vpc_config on aws_lambda_function, the policy document
# on aws_iam_role_policy, access logging/throttling on aws_apigatewayv2_stage
# — none of which can be added as a standalone new resource the way the S3
# sub-resources in s3_hardening.tf can. main.tf itself stays byte-for-byte
# as forked from upstream; every gap-closing change to its resources lives
# here. See: https://developer.hashicorp.com/terraform/language/files/override

######################################################################
# GAP-02 (SOC 2 CC6.1): DynamoDB submissions table — SSE with the customer
# CMK, replacing the AWS-owned default key.
######################################################################

resource "aws_dynamodb_table" "intake" {
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.grc.arn
  }
}

######################################################################
# GAP-05 (SOC 2 CC6.6): Lambda into the starter's private subnets.
# GAP-06 (SOC 2 CC7.2), partial: reserved concurrency caps runaway scaling.
# No dead_letter_config — the Lambda's only trigger is the synchronous API
# Gateway proxy integration, and DLQs only capture failed *asynchronous*
# invocations, so one here would never receive anything. X-Ray is deferred.
######################################################################

resource "aws_lambda_function" "intake" {
  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  reserved_concurrent_executions = 5
}

######################################################################
# GAP-07 (SOC 2 CC6.3): least privilege. Replaces dynamodb:*/s3:* with
# exactly the actions terraform/lambda/handler.py performs (PutItem,
# PutObject), plus the KMS actions needed to write through the CMK from
# s3_hardening.tf / this file's DynamoDB override.
######################################################################

resource "aws_iam_role_policy" "lambda_inline" {
  name = "intake-data-access"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DynamoDBWriteOnly"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = aws_dynamodb_table.intake.arn
      },
      {
        Sid      = "S3UploadOnly"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.uploads.arn}/*"
      },
      {
        Sid      = "CMKForWrites"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.grc.arn
      }
    ]
  })
}

######################################################################
# GAP-08 (SOC 2 CC7.2), partial: access logging + throttling on the HTTP
# API stage. WAF is explicitly deferred (see WRITEUP.md).
######################################################################

resource "aws_apigatewayv2_stage" "default" {
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw_access.arn
    format = jsonencode({
      requestId               = "$context.requestId"
      ip                      = "$context.identity.sourceIp"
      requestTime             = "$context.requestTime"
      httpMethod              = "$context.httpMethod"
      routeKey                = "$context.routeKey"
      status                  = "$context.status"
      integrationErrorMessage = "$context.integrationErrorMessage"
    })
  }

  default_route_settings {
    throttling_burst_limit = 50
    throttling_rate_limit  = 25
  }
}

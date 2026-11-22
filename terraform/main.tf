######################################################################
# Acme Health — Patient Intake API (CGE-P Capstone Starter)
#
# This is the workload your capstone repo wraps with GRC controls.
# It is INTENTIONALLY non-compliant. See GAPS.md for the named flaws
# your Rego policies + Terraform overrides are expected to remediate.
######################################################################

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    random  = { source = "hashicorp/random", version = "~> 3.6" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
  backend "s3" {
    bucket       = "acme-health-intake-tfstate-ysd"
    key          = "capstone/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true # S3-native locking; no DynamoDB table
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "acme-health-intake"
      ManagedBy = "terraform"
      Workload  = "patient-intake-api"
      DataClass = "phi"
    }
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name_prefix = "acme-health-intake"
  suffix      = random_id.suffix.hex
}

######################################################################
# Networking — VPC the learner is expected to put the Lambda inside.
# Two public + two private subnets across two AZs.
######################################################################

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "main" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${local.name_prefix}-vpc" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.42.${count.index}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "${local.name_prefix}-public-${count.index}" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.42.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = { Name = "${local.name_prefix}-private-${count.index}" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${local.name_prefix}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${local.name_prefix}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private routing and VPC endpoints for the in-VPC Lambda (GAP-05) are in
# hardening.tf.

######################################################################
# DynamoDB — submissions table.
# GAP-02 : encryption uses AWS-owned default, not a CMK you control.
######################################################################

resource "aws_dynamodb_table" "intake" {
  name         = "${local.name_prefix}-submissions-${local.suffix}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "submission_id"

  attribute {
    name = "submission_id"
    type = "S"
  }

  # GAP-02 CLOSED: encrypt the table with the customer-managed CMK from
  # kms.tf instead of the AWS-owned default key, putting PHI keys under
  # customer custody.
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.data.arn
  }
}

######################################################################
# S3 — uploads bucket (PHI).
# GAP-01, GAP-03, GAP-04 are closed by module "uploads_bucket" in hardening.tf.
######################################################################

resource "aws_s3_bucket" "uploads" {
  bucket = "${local.name_prefix}-uploads-${local.suffix}"
}

######################################################################
# Lambda — the intake handler.
# GAP-05: not deployed inside the VPC.
# GAP-06: no reserved concurrency, no DLQ, no X-Ray.
# GAP-07: IAM role has dynamodb:* and s3:* on the resources (over-broad).
######################################################################

# GAP-07 CLOSED: least privilege. The handler makes exactly
# two AWS calls (lambda/handler.py): DynamoDB put_item on the intake table
# and S3 put_object under uploads/. The role gets those two actions on
# those two resources, nothing else: no reads, deletes, scans, or
# bucket-level actions. KMS use for the encrypted table and bucket is
# granted in the data key policy (kms.tf), which names this role.

resource "aws_iam_role_policy" "lambda_inline" {
  name = "intake-data-access"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteSubmissions"
        Effect   = "Allow"
        Action   = "dynamodb:PutItem"
        Resource = aws_dynamodb_table.intake.arn
      },
      {
        Sid      = "UploadAttachments"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.uploads.arn}/uploads/*"
      }
    ]
  })
}

data "archive_file" "handler" {
  type        = "zip"
  source_file = "${path.module}/lambda/handler.py"
  output_path = "${path.module}/lambda/handler.zip"
}

resource "aws_iam_role" "lambda" {
  name = "${local.name_prefix}-lambda-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "intake" {
  function_name    = "${local.name_prefix}-handler-${local.suffix}"
  role             = aws_iam_role.lambda.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256
  timeout          = 10

  environment {
    variables = {
      INTAKE_TABLE  = aws_dynamodb_table.intake.name
      UPLOAD_BUCKET = aws_s3_bucket.uploads.id
    }
  }

  # GAP-05 CLOSED: run the function inside the VPC's private subnets so it
  # has no public IP and its traffic stays within controlled network paths.
  # Its security group, ENI permissions, and VPC endpoints are in hardening.tf.
  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  # Gap-06 CLOSED: the function can now be monitored and cannot run away.
  # Its DLQ, IAM permissions, and X-Ray endpoint are in hardening.tf.
  # Cap concurrency so a flood of requests (abuse or bug) can't exhaust the
  # account's Lambda capacity or overwhelm DynamoDB.

  reserved_concurrent_executions = var.lambda_reserved_concurrency

  # Trace every request through X-Ray, so failures and latency are visible.
  tracing_config {
    mode = "Active"
  }

  # Keep events that fail all retries instead of dropping them. Applies to
  # asynchronous invocations only; API Gateway calls this function
  # synchronously, so API errors return to the caller instead.
  dead_letter_config {
    target_arn = aws_sqs_queue.intake_dlq.arn
  }
}

######################################################################
# API Gateway — HTTP API in front of the Lambda.
# GAP-08: no access logging, no throttling, no WAF.
######################################################################

resource "aws_apigatewayv2_api" "intake" {
  name          = "${local.name_prefix}-api-${local.suffix}"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.intake.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.intake.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "intake" {
  api_id    = aws_apigatewayv2_api.intake.id
  route_key = "POST /intake"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.intake.id
  name        = "$default"
  auto_deploy = true

  # GAP-08 CLOSED : every request is recorded, and traffic is
  # capped at the edge. The log group is in hardening.tf.
  # WAF is NOT closed: AWS WAF can't attach to an HTTP API. Documented as a
  # limitation; the fix is CloudFront + WAF in front, or a REST API.

  # Access logs: one JSON line per request (who, when, what, result).
  # Fields are API Gateway $context variables from AWS's HTTP API example.

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access.arn
    format = jsonencode({
      requestId         = "$context.requestId"
      extendedRequestId = "$context.extendedRequestId"
      sourceIp          = "$context.identity.sourceIp"
      requestTime       = "$context.requestTime"
      httpMethod        = "$context.httpMethod"
      routeKey          = "$context.routeKey"
      protocol          = "$context.protocol"
      status            = "$context.status"
      responseLength    = "$context.responseLength"
    })
  }


  # Throttling: excess requests get 429 at the API instead of recahing 
  # the lambda, sized to match its reserved cocurrency (GAP-06). 

  default_route_settings {
    throttling_rate_limit  = var.api_throttling_rate_limit
    throttling_burst_limit = var.api_throttling_burst_limit
  }
}


resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.intake.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.intake.execution_arn}/*/*"
}
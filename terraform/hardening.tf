######################################################################
# Layer 1 — Gap-closing overrides on the starter's resources
#
# Every standalone resource that closes a gap lives here. Fixes that are
# blocks INSIDE a starter resource cannot leave main.tf (a block can't
# exist outside its resource), so these stay there, marked "GAP-0X CLOSED"
# 
#   - GAP-02: aws_dynamodb_table.intake  server_side_encryption
#   - GAP-05: aws_lambda_function.intake vpc_config
#   - GAP-06 (Lambda), GAP-07 (IAM inline policy), GAP-08 (API stage)
######################################################################

######################################################################
# Private routing + VPC endpoints (supports GAP-05)
#
# Moving the Lambda into the private subnets (GAP-05) leaves it with no
# route off the VPC. Rather than a NAT gateway, which would send PHI
# traffic out over the public internet, we reach S3 and DynamoDB through
# gateway VPC endpoints. Traffic to those services then stays on the AWS
# network and never traverses the internet, which is what makes the
# in-VPC Lambda both functional and compliant.
#
# Gateway endpoints work by injecting prefix-list routes into a route
# table, so the private subnets need their own route table to attach to.
######################################################################

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  # No 0.0.0.0/0 route: these subnets have no internet path by design.
  tags = { Name = "${local.name_prefix}-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# S3 gateway endpoint — lets the Lambda read/write the uploads bucket
# without leaving the VPC.

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = { Name = "${local.name_prefix}-s3-endpoint" }
}

# DynamoDB gateway endpoint — lets the Lambda reach the submissions table
# without leaving the VPC.

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = { Name = "${local.name_prefix}-dynamodb-endpoint" }
}

# Security group for the interface endpoints (CloudWatch Logs).
# Interface endpoints are ENIs in the private subnets; they only need to
# accept HTTPS from the Lambda's security group.

resource "aws_security_group" "vpc_endpoints" {
  name        = "${local.name_prefix}-vpce-${local.suffix}"
  description = "Interface VPC endpoints: HTTPS in from the intake Lambda"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "HTTPS from the intake Lambda"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
  }

  tags = { Name = "${local.name_prefix}-vpce-sg" }
}

# CloudWatch Logs interface endpoint — the Lambda writes its logs via the
# Logs API, which (unlike S3/DynamoDB) has no gateway endpoint, so in the
# private subnets it needs this interface endpoint to log at all.

resource "aws_vpc_endpoint" "lambda_logs" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true # so the default logs.<region>.amazonaws.com name resolves here

  tags = { Name = "${local.name_prefix}-logs-endpoint" }
}

# No KMS interface endpoint, on purpose: the handler never calls KMS
# itself. S3 and DynamoDB call KMS on its behalf, from the service side,
# so an endpoint would be unused cost.

######################################################################
# Lambda networking and permissions (GAP-05)
######################################################################

# GAP-05: hardened security group for the Lambda ENIs. No inbound rules
# (the function is invoked by the Lambda service, not over the network),
# and egress restricted to HTTPS (443) so it can reach AWS APIs/endpoints.

resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-${local.suffix}"
  description = "Intake Lambda: no ingress, HTTPS egress only"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "HTTPS to AWS services / VPC endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name_prefix}-lambda-sg" }
}

# GAP-05: VPC-deployed Lambdas need ENI permissions (create/describe/delete
# network interfaces) to attach to the private subnets. Without this the
# function fails to initialize inside the VPC.

resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

######################################################################
# S3 uploads bucket (PHI) — GAP-01, GAP-03, GAP-04
######################################################################

# GAP-01 CLOSED : default SSE-KMS with the data CMK.
# GAP-03 CLOSED :  bucket policy denies non-TLS requests.
# GAP-04 CLOSED :  versioning, so PHI overwrites are recoverable.
# Plus the public access block. One reusable module, so the evidence
# vault and CloudTrail buckets get the identical floor. Do not add
# encryption, versioning, or a bucket policy for this bucket anywhere
# else: S3 allows one of each, and a second definition would fight it.

module "uploads_bucket" {
  source = "./modules/secure-bucket"

  bucket_id   = aws_s3_bucket.uploads.id
  bucket_arn  = aws_s3_bucket.uploads.arn
  kms_key_arn = aws_kms_key.data.arn
}

######################################################################
# Lambda resilience and monitoring — GAP-06
# The in-block settings (reserved concurrency, tracing, DLQ target) are
# on aws_lambda_function.intake in main.tf.
######################################################################

# Dead-letter queue (DLQ) for failed asynchronous invocations. Encrypted with
# the data CMK because a failed event can contain PHI. Retention is the
# SQS maximum (14 days) to give the most time to investigate.

resource "aws_sqs_queue" "intake_dlq" {
  name                      = "${local.name_prefix}-dlq-${local.suffix}"
  kms_master_key_id         = aws_kms_key.data.arn
  message_retention_seconds = 1209600 # 14 days

  tags = {
    Control = "SI.L2-3.14.6"
    Gap     = "GAP-06"
  }
}

# Least privilege for GAP-06: write to this one queue, and send traces.
# The X-Ray actions support no resource-level permissions, so "*" is the
# narrowest possible resource. Used instead of the AWSXRayDaemonWriteAccess
# managed policy, which grants more X-Ray actions than Lambda needs.
# The KMS permission for the encrypted queue is in the data key policy
# (kms.tf), because that key has no account-root delegation.

resource "aws_iam_role_policy" "lambda_gap06" {
  name = "intake-gap06-dlq-and-tracing"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SendFailedEventsToDlq"
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.intake_dlq.arn
      },
      {
        Sid    = "SendXRayTraces"
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords"
        ]
        Resource = "*"
      }
    ]
  })
}

# X-Ray interface endpoint. The private subnets have no internet route,
# and traces are not delivered if the X-Ray API isn't routable from the
# VPC. Reuses the endpoint security group (HTTPS from the Lambda only).

resource "aws_vpc_endpoint" "xray" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.xray"
  vpc_endpoint_type   = "Interface"
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  subnet_ids          = aws_subnet.private[*].id
  private_dns_enabled = true # so xray.<region>.amazonaws.com resolves here 

  tags = { Name = "${local.name_prefix}-xray-endpoint-${local.suffix}" }

}

######################################################################
# API Gateway access logging — GAP-08
# The stage settings (access_log_settings, throttling) are on
# aws_apigatewayv2_stage.default in main.tf.
######################################################################

# Destination for the API access logs. Encrypted with the data CMK; the
# key policy already allows CloudWatch Logs to use it for exactly this
# log group (kms.tf). Name comes from local.api_access_log_group_name so
# it matches the ARN in that key policy.

resource "aws_cloudwatch_log_group" "api_access" {
  name              = local.api_access_log_group_name
  kms_key_id        = aws_kms_key.data.arn
  retention_in_days = var.api_access_log_retention_days

  tags = {
    Control = "AU.L2-3.3.1"
    Gap     = "GAP-08"
  }
}
######################################################################
# API Gateway Hardening
# GAP-08: Access logging + throttling — HIPAA 164.312(b)
######################################################################

# CloudWatch log group for API Gateway access logs
resource "aws_cloudwatch_log_group" "apigw" {
  name              = "/aws/apigateway/acme-health-intake"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.phi.arn

  tags = { Name = "acme-health-apigw-logs" }
}

# IAM role allowing API Gateway to write to CloudWatch
resource "aws_iam_role" "apigw_logging" {
  name = "acme-health-apigw-logging"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "apigateway.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "apigw_logging" {
  role       = aws_iam_role.apigw_logging.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}

# Enable API Gateway account-level CloudWatch logging
resource "aws_api_gateway_account" "main" {
  cloudwatch_role_arn = aws_iam_role.apigw_logging.arn
}

# GAP-08: Update the stage with access logging and throttling
resource "aws_apigatewayv2_stage" "default_hardened" {
  api_id      = data.terraform_remote_state.starter.outputs.apigw_id
  name        = "hardened"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      responseLength = "$context.responseLength"
      errorMessage   = "$context.error.message"
    })
  }

  default_route_settings {
    throttling_burst_limit = 100
    throttling_rate_limit  = 50
  }

  tags = { Name = "acme-health-intake-hardened-stage" }
}

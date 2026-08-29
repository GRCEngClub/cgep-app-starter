output "api_url" {
  value       = "${aws_apigatewayv2_api.intake.api_endpoint}/intake"
  description = "POST /intake endpoint."
}

output "intake_table" {
  value       = aws_dynamodb_table.intake.name
  description = "DynamoDB table holding patient submissions."
}

output "uploads_bucket" {
  value       = aws_s3_bucket.uploads.id
  description = "S3 bucket where intake attachments land."
}

output "lambda_function_name" {
  value = aws_lambda_function.intake.function_name
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "uploads_bucket_id" {
  value       = aws_s3_bucket.uploads.id
  description = "S3 bucket ID for GRC layer reference."
}

output "uploads_bucket_arn" {
  value       = aws_s3_bucket.uploads.arn
  description = "S3 bucket ARN for GRC layer reference."
}

output "intake_table_arn" {
  value       = aws_dynamodb_table.intake.arn
  description = "DynamoDB table ARN for GRC layer reference."
}

output "lambda_role_id" {
  value       = aws_iam_role.lambda.id
  description = "Lambda IAM role ID for GRC layer reference."
}

output "lambda_function_arn" {
  value       = aws_lambda_function.intake.arn
  description = "Lambda function ARN for GRC layer reference."
}

output "apigw_id" {
  value       = aws_apigatewayv2_api.intake.id
  description = "API Gateway ID for GRC layer reference."
}

output "apigw_stage_id" {
  value       = aws_apigatewayv2_stage.default.id
  description = "API Gateway stage ID for GRC layer reference."
}

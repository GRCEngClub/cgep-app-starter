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

output "kms_data_key_arn" {
  description = "ARN of the PHI data key (SC.L2-3.13.11, GAP-01/GAP-02)."
  value       = aws_kms_key.data.arn
}

output "kms_evidence_key_arn" {
  description = "ARN of the evidence vault / CloudTrail key."
  value       = aws_kms_key.evidence.arn
}

output "evidence_vault_bucket" {
  value       = aws_s3_bucket.evidence.id
  description = "Object Lock (GOVERNANCE, 365-day) bucket where signed evidence bundles land."
}

output "cloudtrail_arn" {
  value       = aws_cloudtrail.main.arn
  description = "Multi-region trail with log file validation (AU.L2-3.3.1)."
}

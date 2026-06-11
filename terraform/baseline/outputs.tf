output "kms_key_arn" {
  description = "ARN of the PHI CMK — used by Lambda, DynamoDB, and S3."
  value       = aws_kms_key.phi.arn
}

output "kms_key_id" {
  description = "Key ID of the PHI CMK."
  value       = aws_kms_key.phi.key_id
}

output "vault_bucket_id" {
  description = "Name of the evidence vault bucket — pipeline uploads signed bundles here."
  value       = aws_s3_bucket.vault.id
}

output "lambda_sg_id" {
  description = "Security group ID for the Lambda VPC placement (GAP-05)."
  value       = aws_security_group.lambda.id
}

output "lambda_dlq_arn" {
  description = "ARN of the Lambda DLQ (GAP-06)."
  value       = aws_sqs_queue.lambda_dlq.arn
}

output "apigw_log_group_arn" {
  description = "ARN of the API Gateway CloudWatch log group (GAP-08)."
  value       = aws_cloudwatch_log_group.apigw.arn
}

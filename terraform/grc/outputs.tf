output "phi_kms_key_arn" {
  value       = aws_kms_key.phi.arn
  description = "ARN of the PHI CMK — SC-28/HIPAA 164.312(a)(2)(iv) attestation."
}

output "phi_kms_key_id" {
  value       = aws_kms_key.phi.key_id
  description = "Key ID of the PHI CMK."
}

output "evidence_vault_name" {
  value       = aws_s3_bucket.vault.id
  description = "Evidence vault bucket name. Feed to capture-evidence.sh --vault."
}

output "evidence_vault_arn" {
  value       = aws_s3_bucket.vault.arn
  description = "Evidence vault bucket ARN."
}

output "cloudtrail_arn" {
  value       = aws_cloudtrail.mgmt.arn
  description = "CloudTrail ARN — HIPAA 164.312(b) attestation."
}

output "lambda_dlq_arn" {
  value       = aws_sqs_queue.lambda_dlq.arn
  description = "Lambda DLQ ARN — GAP-06 remediation."
}

output "apigw_log_group" {
  value       = aws_cloudwatch_log_group.apigw.name
  description = "API Gateway log group — GAP-08 remediation."
}

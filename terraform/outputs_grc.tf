# terraform/outputs_grc.tf
#
# Outputs for the GRC baseline resources (kms.tf, evidence_vault.tf,
# cloudtrail.tf). Kept separate from the starter's outputs.tf rather than
# appended to it.

output "evidence_vault_bucket" {
  value       = aws_s3_bucket.evidence_vault.id
  description = "S3 bucket the pipeline uploads signed evidence bundles to."
}

output "grc_kms_key_arn" {
  value       = aws_kms_key.grc.arn
  description = "CMK protecting the uploads bucket, DynamoDB table, and evidence vault."
}

output "cloudtrail_name" {
  value       = aws_cloudtrail.main.name
  description = "Multi-region management-events trail."
}

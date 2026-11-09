output "plan_role_arn" {
  value       = aws_iam_role.plan.arn
  description = "Role for pull_request runs (GitHub variable AWS_PLAN_ROLE_ARN)."
}

output "apply_role_arn" {
  value       = aws_iam_role.apply.arn
  description = "Role for main-branch runs (GitHub variable AWS_APPLY_ROLE_ARN)."
}

output "state_bucket" {
  value       = aws_s3_bucket.state.id
  description = "Bucket holding the main stack's Terraform state."
}

output "evidence_vault" {
  value       = local.vault_bucket
  description = "Evidence vault bucket (GitHub variable EVIDENCE_VAULT)."
}

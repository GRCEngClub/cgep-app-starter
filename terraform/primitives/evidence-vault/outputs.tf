# outputs.tf
output "vault_name" {
  value       = aws_s3_bucket.vault.id
  description = "S3 bucket name of the evidence vault. Feed this to capture-evidence.sh --vault."
}
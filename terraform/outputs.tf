output "kms_key_arn" {
  description = "ARN de la llave CMK administrada para el cifrado SOC 2"
  value       = aws_kms_key.soc2_key.arn
}

output "evidence_vault_bucket_id" {
  description = "Nombre único del Bucket S3 protegido con Object Lock"
  value       = aws_s3_bucket.evidence_vault.id
}

output "cloudtrail_arn" {
  description = "ARN del CloudTrail multi-región configurado para auditoría continua"
  value       = aws_cloudtrail.multi_region_trail.arn
}

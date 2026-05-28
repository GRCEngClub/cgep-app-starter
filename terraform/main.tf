provider "aws" {
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true

  # Usamos credenciales falsas estáticas obligatorias para engañar al binario
  access_key = "mock_access_key"
  secret_key = "mock_secret_key"
}

# 1. Llave KMS administrada por el cliente (CMK)
resource "aws_kms_key" "soc2_key" {
  description             = "Llave CMK para cifrado de evidencias SOC 2"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

# 2. Bucket S3 de Evidencias con Object Lock Habilitado
resource "aws_s3_bucket" "evidence_vault" {
  bucket              = "acme-health-soc2-evidence-vault-2026"
  object_lock_enabled = true
}

# 3. Configuración de Cifrado con la llave KMS creada
resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_vault_encryption" {
  bucket = aws_s3_bucket.evidence_vault.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.soc2_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# 4. Habilitar Versionado en S3 (Exigido por GAP-04)
resource "aws_s3_bucket_versioning" "evidence_vault_versioning" {
  bucket = aws_s3_bucket.evidence_vault.id
  versioning_configuration {
    status = "Enabled"
  }
}

# 5. CloudTrail Multi-Región
resource "aws_cloudtrail" "multi_region_trail" {
  name                          = "acme-health-governance-trail"
  s3_bucket_name                = aws_s3_bucket.evidence_vault.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}
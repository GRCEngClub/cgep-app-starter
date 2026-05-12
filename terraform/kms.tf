# KMS Customer Managed Key for PHI data encryption
# Closes GAP-01 (S3) and GAP-02 (DynamoDB)
# CMMC SC.L2-3.13.11 - Employ FIPS-validated cryptography

resource "aws_kms_key" "phi" {
  description             = "CMK for Acme Health PHI data - S3 and DynamoDB"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name        = "${local.name_prefix}-phi-cmk"
    ControlRef  = "SC.L2-3.13.11"
    DataClass   = "phi"
  }
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${local.name_prefix}-phi-cmk"
  target_key_id = aws_kms_key.phi.key_id
}

resource "aws_kms_key" "evidence" {
  description             = "CMK for evidence vault encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name       = "${local.name_prefix}-evidence-cmk"
    ControlRef = "SC.L2-3.13.11"
  }
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/${local.name_prefix}-evidence-cmk"
  target_key_id = aws_kms_key.evidence.key_id
}
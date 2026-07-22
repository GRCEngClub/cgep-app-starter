# terraform/kms.tf
#
# Customer-managed key bringing the starter's PHI-bearing resources under
# customer key custody. Used by the uploads bucket (GAP-01), the DynamoDB
# table (GAP-02), and the evidence vault. SOC 2 CC6.1.

resource "aws_kms_key" "grc" {
  description             = "CMK for Acme Health intake PHI resources and the GRC evidence vault"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}

resource "aws_kms_alias" "grc" {
  name          = "alias/${local.name_prefix}-grc-${local.suffix}"
  target_key_id = aws_kms_key.grc.key_id
}

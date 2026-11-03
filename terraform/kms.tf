
resource "aws_kms_key" "grc" {
  description             = "Acme Health GRC customer-managed encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = {
    Name = "${local.name_prefix}-grc-key"
  }
}

resource "aws_kms_alias" "grc" {
  name          = "alias/${local.name_prefix}-grc-${local.suffix}"
  target_key_id = aws_kms_key.grc.key_id
}

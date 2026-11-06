######################################################################
# KMS: customer-managed key (CMK) for the PHI data stores.
# Closes the key-custody half of GAP-01 (S3 uploads) and GAP-02
# (DynamoDB intake table). CMMC SC.L2-3.13.11.
#
# The key is wired to the S3 bucket and DynamoDB table in later steps.
# Annual automatic rotation is on. With no explicit key policy, AWS
# applies the default policy, which lets the account's IAM policies
# grant access to the key (the Lambda role gets its permissions that way).
######################################################################

resource "aws_kms_key" "phi" {
  description             = "Acme Health CMK for PHI data stores (S3 uploads, DynamoDB intake)"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${local.name_prefix}-phi-${local.suffix}"
  target_key_id = aws_kms_key.phi.key_id
}

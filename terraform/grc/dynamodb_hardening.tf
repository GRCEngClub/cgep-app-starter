######################################################################
# DynamoDB Hardening
# GAP-02: SSE with customer CMK — HIPAA 164.312(a)(2)(iv)
######################################################################

resource "aws_dynamodb_table" "intake_hardened" {
  name         = "${data.terraform_remote_state.starter.outputs.intake_table}-hardened"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "submission_id"

  attribute {
    name = "submission_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.phi.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name    = "acme-health-intake-submissions-hardened"
    Purpose = "phi-storage"
  }
}

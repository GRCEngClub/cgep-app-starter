# METADATA
# title: HIPAA 164.312(a)(2)(iv) - CMK Encryption for PHI
# description: "S3 buckets and DynamoDB tables storing PHI must use customer-managed KMS keys, not AWS-managed keys."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm=aws:kms and a customer kms_master_key_id. Add server_side_encryption block to aws_dynamodb_table."
package compliance.hipaa.cmk_encryption

import rego.v1

# S3 buckets with PHI must use SSE-KMS with a CMK
deny contains msg if {
  some r in input.planned_values.root_module.resources
  r.type == "aws_s3_bucket"
  r.values.tags_all.DataClass == "phi"
  not has_kms_encryption(r.address)
  msg := sprintf(
    "[HIPAA 164.312(a)(2)(iv)] %s: PHI bucket uses AWS-managed encryption instead of a customer CMK. Remediation: add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm=aws:kms.",
    [r.address]
  )
}

# DynamoDB tables with PHI must use a CMK
deny contains msg if {
  some r in input.planned_values.root_module.resources
  r.type == "aws_dynamodb_table"
  r.values.tags_all.DataClass == "phi"
  not has_dynamodb_cmk(r)
  msg := sprintf(
    "[HIPAA 164.312(a)(2)(iv)] %s: PHI DynamoDB table uses AWS-managed encryption instead of a customer CMK. Remediation: add server_side_encryption block with kms_key_arn.",
    [r.address]
  )
}

has_kms_encryption(bucket_addr) if {
  some r in input.planned_values.root_module.resources
  r.type == "aws_s3_bucket_server_side_encryption_configuration"
  some rule in r.values.rule
  rule.apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
  some ref in input.configuration.root_module.resources[_].expressions.bucket.references
  contains(ref, split(bucket_addr, ".")[1])
}

has_dynamodb_cmk(resource) if {
  count(resource.values.server_side_encryption) > 0
  resource.values.server_side_encryption[0].enabled == true
  resource.values.server_side_encryption[0].kms_key_arn != null
  resource.values.server_side_encryption[0].kms_key_arn != ""
}

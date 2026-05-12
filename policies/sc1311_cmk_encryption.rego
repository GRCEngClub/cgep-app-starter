# METADATA
# title: SC.L2-3.13.11 - Cryptographic Protection (S3 CMK)
# description: "Every aws_s3_bucket must use SSE-KMS with a customer-managed key, not SSE-S3."
# custom:
#   control_id: SC.L2-3.13.11
#   framework: CMMC-L2
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = aws:kms and a kms_master_key_id referencing your CMK."
package compliance.cmmc.sc1311

import rego.v1

deny contains msg if {
  some r in input.configuration.root_module.resources
  r.type == "aws_s3_bucket_server_side_encryption_configuration"
  algo := r.expressions.rule[0].apply_server_side_encryption_by_default[0].sse_algorithm.constant_value
  algo != "aws:kms"
  msg := sprintf(
    "[SC.L2-3.13.11] %s: S3 bucket uses %s instead of aws:kms with a CMK. Remediation: set sse_algorithm = aws:kms and provide kms_master_key_id.",
    [r.address, algo]
  )
}

deny contains msg if {
  bucket := bucket_addresses[_]
  not has_kms_encryption(bucket)
  msg := sprintf(
    "[SC.L2-3.13.11] %s: S3 bucket has no SSE-KMS configuration. Remediation: add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = aws:kms.",
    [bucket]
  )
}

bucket_addresses contains addr if {
  some r in input.configuration.root_module.resources
  r.type == "aws_s3_bucket"
  addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_kms_encryption(bucket_addr) if {
  some r in input.configuration.root_module.resources
  r.type == "aws_s3_bucket_server_side_encryption_configuration"
  some ref in r.expressions.bucket.references
  ref == sprintf("%s.id", [bucket_addr])
}
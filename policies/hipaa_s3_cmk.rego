# METADATA
# title: GAP-01 S3 buckets must use SSE-KMS with a customer-managed key
# custom:
#   framework: hipaa
#   gap: GAP-01
#   controls:
#     - "164.312(a)(2)(iv)"
#   secondary:
#     - "SOC2 CC6.1"
#     - "CMMC SC.L2-3.13.11"
#   severity: high
package compliance.hipaa.s3_cmk

import data.lib.tf
import rego.v1

deny contains msg if {
    some bucket in tf.managed("aws_s3_bucket")
    not has_cmk_encryption(bucket.address)
    msg := sprintf("GAP-01 [HIPAA 164.312(a)(2)(iv)] %s is not encrypted with SSE-KMS using a customer-managed key", [bucket.address])
}

has_cmk_encryption(addr) if {
    some cfg in tf.managed("aws_s3_bucket_server_side_encryption_configuration")
    tf.references(cfg, "bucket", addr)
    default_enc := cfg.expressions.rule[0].apply_server_side_encryption_by_default[0]
    default_enc.sse_algorithm.constant_value == "aws:kms"
    default_enc.kms_master_key_id
}

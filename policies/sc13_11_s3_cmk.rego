# METADATA
# title: S3 buckets holding PHI must use SSE-KMS with a customer-managed key
# description: >
#   GAP-01. A bucket with only the AWS default (SSE-S3) leaves key custody with
#   AWS. Every non-audit-log bucket needs an encryption configuration using
#   aws:kms and a kms_master_key_id that points at a customer-managed key.
# custom:
#   control_id: SC.L2-3.13.11
#   framework: CMMC Level 2 (NIST SP 800-171)
#   gap: GAP-01
#   severity: high
#   remediation: >
#     Add an aws_s3_bucket_server_side_encryption_configuration for the bucket
#     with sse_algorithm = "aws:kms" and kms_master_key_id = aws_kms_key.<name>.arn.
package compliance.sc13_11_s3

import data.lib.tf
import rego.v1

buckets := {b | some b in tf.managed("aws_s3_bucket"); not b.address in tf.audit_log_buckets}

uses_cmk(b) if {
	some s in tf.managed("aws_s3_bucket_server_side_encryption_configuration")
	b.address in tf.refs(s.expressions.bucket)
	some rule in s.expressions.rule
	some d in rule.apply_server_side_encryption_by_default
	d.sse_algorithm.constant_value == "aws:kms"
	tf.is_cmk(d.kms_master_key_id)
}

deny contains msg if {
	some b in buckets
	not uses_cmk(b)
	msg := sprintf("[SC.L2-3.13.11] %s must be encrypted with SSE-KMS using a customer-managed key (GAP-01)", [b.address])
}

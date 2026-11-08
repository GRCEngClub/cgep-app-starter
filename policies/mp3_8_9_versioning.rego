# METADATA
# title: S3 buckets holding PHI must have versioning enabled
# description: >
#   GAP-04. Without versioning an overwrite or delete of PHI is unrecoverable.
#   Every non-audit-log bucket needs an aws_s3_bucket_versioning with status Enabled.
# custom:
#   control_id: MP.L2-3.8.9
#   framework: CMMC Level 2 (NIST SP 800-171)
#   gap: GAP-04
#   severity: medium
#   remediation: >
#     Add an aws_s3_bucket_versioning for the bucket with
#     versioning_configuration { status = "Enabled" }.
package compliance.mp3_8_9_versioning

import data.lib.tf
import rego.v1

buckets := {b | some b in tf.managed("aws_s3_bucket"); not b.address in tf.audit_log_buckets}

versioned(b) if {
	some v in tf.managed("aws_s3_bucket_versioning")
	b.address in tf.refs(v.expressions.bucket)
	some vc in v.expressions.versioning_configuration
	vc.status.constant_value == "Enabled"
}

deny contains msg if {
	some b in buckets
	not versioned(b)
	msg := sprintf("[MP.L2-3.8.9] %s must have versioning enabled so PHI overwrites are recoverable (GAP-04)", [b.address])
}

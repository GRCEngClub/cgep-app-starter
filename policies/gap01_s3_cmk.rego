# METADATA
# title: GAP-01 - S3 buckets must use SSE-KMS with a customer CMK
# description: >
#   SOC 2 CC6.1 requires logical access controls over encryption keys.
#   AWS-managed SSE-S3 encryption does not give the customer custody of
#   the key material. All S3 buckets storing PHI must use SSE-KMS with
#   a customer-managed key (CMK), not the AWS-managed default.
# custom:
#   framework: soc2
#   controls:
#     - CC6.1
#   gap: GAP-01
#   severity: high
package compliance.soc2.gap01_s3_cmk

import rego.v1

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_server_side_encryption_configuration"
	rule := resource.change.after.rule[_]
	rule.apply_server_side_encryption_by_default[_].sse_algorithm != "aws:kms"
	msg := sprintf(
		"[CC6.1][GAP-01] S3 bucket encryption config '%s' must use sse_algorithm = \"aws:kms\" with a customer CMK, not SSE-S3. PHI keys must be under customer custody.",
		[resource.address],
	)
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	resource.change.after != null
	not has_kms_encryption(resource.address)
	msg := sprintf(
		"[CC6.1][GAP-01] S3 bucket '%s' has no aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = \"aws:kms\". PHI buckets require a customer CMK.",
		[resource.address],
	)
}

has_kms_encryption(bucket_address) if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_server_side_encryption_configuration"
	resource.change.after != null
	resource.change.after.bucket == bucket_address
	rule := resource.change.after.rule[_]
	rule.apply_server_side_encryption_by_default[_].sse_algorithm == "aws:kms"
}

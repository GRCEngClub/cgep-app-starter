# METADATA
# title: GAP-03 - S3 buckets must deny non-TLS requests
# description: >
#   SOC 2 CC6.7 requires transmission security. An S3 bucket without a
#   bucket policy denying aws:SecureTransport=false will accept HTTP
#   requests, exposing PHI in transit. Every bucket storing PHI must
#   have an explicit Deny for non-TLS access.
# custom:
#   framework: soc2
#   controls:
#     - CC6.7
#   gap: GAP-03
#   severity: high
package compliance.soc2.gap03_s3_tls

import rego.v1

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	resource.change.after != null
	not has_tls_deny_policy(resource.change.after.bucket)
	msg := sprintf(
		"[CC6.7][GAP-03] S3 bucket '%s' has no bucket policy denying aws:SecureTransport=false. PHI buckets must refuse HTTP requests.",
		[resource.address],
	)
}

has_tls_deny_policy(bucket_name) if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_policy"
	resource.change.after != null
	resource.change.after.bucket == bucket_name
	policy := json.unmarshal(resource.change.after.policy)
	some statement in policy.Statement
	statement.Effect == "Deny"
	condition := statement.Condition
	condition.Bool["aws:SecureTransport"] == "false"
}

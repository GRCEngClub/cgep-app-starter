# METADATA
# title: GAP-02 - DynamoDB tables must use SSE with a customer CMK
# description: >
#   SOC 2 CC6.1 requires logical access controls over encryption keys.
#   DynamoDB tables using the AWS-owned default key do not give the
#   customer custody of the key material. Tables storing PHI must have
#   server_side_encryption enabled with a customer-managed KMS key ARN.
# custom:
#   framework: soc2
#   controls:
#     - CC6.1
#   gap: GAP-02
#   severity: high
package compliance.soc2.gap02_dynamodb_cmk

import rego.v1

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_dynamodb_table"
	resource.change.after != null
	not has_cmk_encryption(resource.change.after)
	msg := sprintf(
		"[CC6.1][GAP-02] DynamoDB table '%s' does not have server_side_encryption with a customer CMK. Tables storing PHI must use a customer-managed KMS key.",
		[resource.address],
	)
}

has_cmk_encryption(resource_after) if {
	sse := resource_after.server_side_encryption[_]
	sse.enabled == true
	sse.kms_key_arn != null
	sse.kms_key_arn != ""
}

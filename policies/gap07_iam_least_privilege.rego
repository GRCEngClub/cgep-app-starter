# METADATA
# title: GAP-07 - Lambda IAM role must not use wildcard actions on data stores
# description: >
#   SOC 2 CC6.3 requires that access is restricted to authorized users
#   with least privilege. An IAM policy granting dynamodb:* or s3:* on
#   workload resources violates the principle of least privilege. Lambda
#   functions must be granted only the specific actions they need.
# custom:
#   framework: soc2
#   controls:
#     - CC6.3
#   gap: GAP-07
#   severity: high
package compliance.soc2.gap07_iam_least_privilege

import rego.v1

wildcard_actions := {"dynamodb:*", "s3:*", "iam:*", "*"}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_iam_role_policy"
	resource.change.after != null
	policy := json.unmarshal(resource.change.after.policy)
	some statement in policy.Statement
	statement.Effect == "Allow"
	some action in to_array(statement.Action)
	action in wildcard_actions
	msg := sprintf(
		"[CC6.3][GAP-07] IAM role policy '%s' grants wildcard action '%s'. Use specific actions (e.g. dynamodb:PutItem) instead of %s to satisfy least-privilege.",
		[resource.address, action, action],
	)
}

to_array(x) := x if is_array(x)

to_array(x) := [x] if not is_array(x)

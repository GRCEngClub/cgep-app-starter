# policies/cc6_3_iam_least_privilege.rego
# METADATA
# title: CC6.3 - Lambda inline policy must not use wildcard actions
# description: >
#   Closes GAP-07: the intake Lambda's inline role policy must not grant
#   dynamodb:* or s3:* (or any other service-wide "service:*" / bare "*"
#   action) on the workload's data stores. Read via resource_changes for
#   the same reason as cc6_7_s3_tls_only: the policy document is built
#   with jsonencode(), so action strings aren't visible in the static
#   configuration representation. Also like cc6_7_s3_tls_only: an
#   unresolvable "after.policy" (key entirely absent, not null, when its
#   value depends on something not yet known) fails closed.
# custom:
#   framework: soc2
#   controls: ["CC6.3"]
#   severity: high
#   remediation: >
#     Replace wildcard Action entries with the exact actions the handler
#     performs (e.g. dynamodb:PutItem, s3:PutObject) scoped to specific
#     resource ARNs.
package compliance.soc2.cc6_3_iam_least_privilege

import rego.v1

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_role_policy"
	policy_value(rc) == null
	msg := sprintf(
		"[CC6.3] %s: policy value not resolvable in this plan. Failing closed -- re-run once referenced resources exist so the policy content can be verified.",
		[rc.address],
	)
}

policy_value(rc) := object.get(object.get(rc.change, "after", {}), "policy", null)

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_role_policy"
	policy_value(rc) != null
	doc := json.unmarshal(policy_value(rc))
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	action := wildcard_action(stmt.Action)
	msg := sprintf(
		"[CC6.3] %s: statement %q grants wildcard action %q. GAP-07. Remediation: scope to the specific actions the handler performs.",
		[rc.address, object.get(stmt, "Sid", "<no Sid>"), action],
	)
}

wildcard_action(actions) := action if {
	is_array(actions)
	some action in actions
	is_wildcard(action)
}

wildcard_action(action) := action if {
	is_string(action)
	is_wildcard(action)
}

is_wildcard(action) if action == "*"
is_wildcard(action) if endswith(action, ":*")

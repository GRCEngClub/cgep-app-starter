# policies/cc6_7_s3_tls_only.rego
# METADATA
# title: CC6.7 - uploads bucket must deny non-TLS requests
# description: >
#   Closes GAP-03: the uploads bucket must have a bucket policy that denies
#   any request where aws:SecureTransport is false. Read via
#   resource_changes (not configuration): the policy document is built with
#   jsonencode(), so the literal Condition/Effect values aren't visible in
#   the static configuration representation the way a plain literal would
#   be -- they only appear in the plan's rendered "after" value. When a
#   value depends on something not yet known (e.g. a from-scratch plan
#   where the bucket ARN doesn't exist yet), Terraform omits the key from
#   "after" entirely rather than setting it to null -- so this checks for
#   both, and fails closed rather than passing silently either way.
# custom:
#   framework: soc2
#   controls: ["CC6.7"]
#   severity: high
#   remediation: >
#     Add an aws_s3_bucket_policy for the uploads bucket with a Deny
#     statement, Principal "*", any s3:* action, and a
#     Condition.Bool["aws:SecureTransport"] == "false".
package compliance.soc2.cc6_7_s3_tls_only

import rego.v1

deny contains msg if {
	not any_policy_denies_insecure_transport
	msg := "[CC6.7] no aws_s3_bucket_policy resource change found denying insecure transport on the uploads bucket. GAP-03. Remediation: add a Deny statement with Condition.Bool[\"aws:SecureTransport\"] == \"false\"."
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_policy"
	policy_value(rc) == null
	msg := sprintf(
		"[CC6.7] %s: bucket policy value not resolvable in this plan (likely a from-scratch apply). Failing closed -- re-run after the referenced bucket/CMK exist so the policy content can be verified.",
		[rc.address],
	)
}

policy_value(rc) := object.get(object.get(rc.change, "after", {}), "policy", null)

any_policy_denies_insecure_transport if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_policy"
	policy_value(rc) != null
	doc := json.unmarshal(policy_value(rc))
	some stmt in doc.Statement
	stmt.Effect == "Deny"
	stmt.Condition.Bool["aws:SecureTransport"] == "false"
}

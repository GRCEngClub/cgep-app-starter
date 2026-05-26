# Policy: IAM policies must not use wildcard actions
# Framework: SOC 2
# Control ID: CC6.3
# Severity: HIGH
# Remediation: Replace dynamodb:* and s3:* with specific actions needed

package policies.iam_no_wildcard

import rego.v1

# Metadata
metadata := {
    "id":          "SOC2-CC6.3-IAM-NO-WILDCARD",
    "framework":   "SOC 2",
    "control":     "CC6.3",
    "severity":    "HIGH",
    "remediation": "Replace wildcard actions (e.g. s3:*, dynamodb:*) with least-privilege specific actions",
}

# Deny when Action is an array containing a wildcard
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_iam_role_policy"
    resource.change.actions[_] in ["create", "update"]
    policy := json.unmarshal(resource.change.after.policy)
    some statement in policy.Statement
    statement.Effect == "Allow"
    some action in statement.Action
    endswith(action, ":*")
    msg := sprintf(
        "[%s] %s: IAM policy '%s' uses wildcard action '%s' — must use least-privilege (SOC 2 CC6.3 — GAP-07)",
        [metadata.severity, metadata.control, resource.address, action]
    )
}

# Deny when Action is a single string wildcard
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_iam_role_policy"
    resource.change.actions[_] in ["create", "update"]
    policy := json.unmarshal(resource.change.after.policy)
    some statement in policy.Statement
    statement.Effect == "Allow"
    is_string(statement.Action)
    endswith(statement.Action, ":*")
    msg := sprintf(
        "[%s] %s: IAM policy '%s' uses wildcard action '%s' — must use least-privilege (SOC 2 CC6.3 — GAP-07)",
        [metadata.severity, metadata.control, resource.address, statement.Action]
    )
}
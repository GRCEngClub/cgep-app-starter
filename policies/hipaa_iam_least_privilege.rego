# METADATA
# title: GAP-07 IAM policies must be least-privilege (no wildcard actions)
# custom:
#   framework: hipaa
#   gap: GAP-07
#   controls:
#     - "164.312(a)(1)"
#     - "164.308(a)(4)"
#   secondary:
#     - "SOC2 CC6.3"
#     - "CMMC AC.L2-3.1.5"
#   severity: high
package compliance.hipaa.iam_least_privilege

import data.lib.tf
import rego.v1

policy_types := {"aws_iam_role_policy", "aws_iam_policy"}

deny contains msg if {
    some t in policy_types
    some pol in tf.managed(t)
    not tf.policy_doc(pol, "policy")
    msg := sprintf("GAP-07 [HIPAA 164.312(a)(1)] %s must be built with data.aws_iam_policy_document so its actions can be checked", [pol.address])
}

deny contains msg if {
    some t in policy_types
    some pol in tf.managed(t)
    doc := tf.policy_doc(pol, "policy")
    some stmt in doc.expressions.statement
    object.get(stmt, ["effect", "constant_value"], "Allow") == "Allow"
    some action in stmt.actions.constant_value
    wildcard(action)
    msg := sprintf("GAP-07 [HIPAA 164.312(a)(1)] %s allows wildcard action %q; list only the actions the workload needs", [pol.address, action])
}

wildcard(action) if action == "*"

wildcard(action) if endswith(action, ":*")

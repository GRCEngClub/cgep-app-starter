# METADATA
# title: AC.L2-3.1.5 - Least Privilege (IAM)
# description: "Lambda IAM roles must not use wildcard actions (dynamodb:* or s3:*) on PHI data stores."
# custom:
#   control_id: AC.L2-3.1.5
#   framework: CMMC-L2
#   severity: critical
#   remediation: "Replace dynamodb:* and s3:* with specific actions required by the function (e.g., dynamodb:PutItem, dynamodb:GetItem, s3:PutObject, s3:GetObject)."
package compliance.cmmc.ac315

import rego.v1

wildcard_actions := {"dynamodb:*", "s3:*", "*"}

deny contains msg if {
  some r in input.planned_values.root_module.resources
  r.type == "aws_iam_role_policy"
  policy := json.unmarshal(r.values.policy)
  some stmt in policy.Statement
  some action in to_array(stmt.Action)
  wildcard_actions[action]
  msg := sprintf(
    "[AC.L2-3.1.5] %s: IAM policy contains wildcard action '%s'. Remediation: replace with specific actions required by the function.",
    [r.address, action]
  )
}

to_array(x) := x if is_array(x)
to_array(x) := [x] if not is_array(x)
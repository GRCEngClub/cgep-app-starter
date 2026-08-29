package compliance.hipaa.least_privilege

import rego.v1

wildcard_actions := {"dynamodb:*", "s3:*", "*"}

# Handle Action as an array
deny contains msg if {
  some r in input.planned_values.root_module.resources
  r.type == "aws_iam_role_policy"
  policy := json.unmarshal(r.values.policy)
  some stmt in policy.Statement
  stmt.Effect == "Allow"
  some action in stmt.Action
  wildcard_actions[action]
  msg := sprintf(
    "[HIPAA 164.312(a)(1)] %s: IAM policy uses wildcard action '%s'. PHI systems require least privilege. Remediation: replace with specific actions.",
    [r.address, action]
  )
}

# Handle Action as a string
deny contains msg if {
  some r in input.planned_values.root_module.resources
  r.type == "aws_iam_role_policy"
  policy := json.unmarshal(r.values.policy)
  some stmt in policy.Statement
  stmt.Effect == "Allow"
  is_string(stmt.Action)
  wildcard_actions[stmt.Action]
  msg := sprintf(
    "[HIPAA 164.312(a)(1)] %s: IAM policy uses wildcard action '%s'. PHI systems require least privilege. Remediation: replace with specific actions.",
    [r.address, stmt.Action]
  )
}

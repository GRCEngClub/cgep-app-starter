package compliance.hipaa.audit_logging

import rego.v1

deny contains msg if {
  some r in input.planned_values.root_module.resources
  r.type == "aws_apigatewayv2_stage"
  not has_access_logging(r)
  msg := sprintf(
    "[HIPAA 164.312(b)] %s: API Gateway stage has no access logging configured. PHI systems must record and examine activity. Remediation: add access_log_settings with a CloudWatch destination_arn.",
    [r.address]
  )
}

has_access_logging(resource) if {
  count(resource.values.access_log_settings) > 0
  resource.values.access_log_settings[0].destination_arn != ""
  resource.values.access_log_settings[0].destination_arn != null
}

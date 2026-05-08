package compliance.cm6

import rego.v1

required := {"Project", "Environment", "ManagedBy", "ComplianceScope"}

deny contains msg if {
  some resource in input.planned_values.root_module.resources
  resource.type == "aws_s3_bucket"
  resource.values.tags
  provided := {k | resource.values.tags[k]}
  missing := required - provided
  count(missing) > 0
  msg := sprintf("[CM-6/CC6.8] %s: missing tags.", [resource.address])
}

deny contains msg if {
  some resource in input.planned_values.root_module.resources
  resource.type == "aws_s3_bucket"
  not resource.values.tags
  msg := sprintf("[CM-6/CC6.8] %s: no tags.", [resource.address])
}
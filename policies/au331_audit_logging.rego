# METADATA
# title: AU.L2-3.3.1 - Audit and Accountability (CloudTrail)
# description: "A multi-region CloudTrail trail with log file validation must exist."
# custom:
#   control_id: AU.L2-3.3.1
#   framework: CMMC-L2
#   severity: high
#   remediation: "Add aws_cloudtrail resource with is_multi_region_trail = true and enable_log_file_validation = true."
package compliance.cmmc.au331

import rego.v1

deny contains msg if {
  not has_cloudtrail
  msg := "[AU.L2-3.3.1] No CloudTrail trail found. Remediation: add aws_cloudtrail with is_multi_region_trail = true and enable_log_file_validation = true."
}

deny contains msg if {
  some r in input.planned_values.root_module.resources
  r.type == "aws_cloudtrail"
  r.values.is_multi_region_trail == false
  msg := sprintf(
    "[AU.L2-3.3.1] %s: CloudTrail is not multi-region. Remediation: set is_multi_region_trail = true.",
    [r.address]
  )
}

deny contains msg if {
  some r in input.planned_values.root_module.resources
  r.type == "aws_cloudtrail"
  r.values.enable_log_file_validation == false
  msg := sprintf(
    "[AU.L2-3.3.1] %s: CloudTrail log file validation is disabled. Remediation: set enable_log_file_validation = true.",
    [r.address]
  )
}

has_cloudtrail if {
  some r in input.planned_values.root_module.resources
  r.type == "aws_cloudtrail"
}
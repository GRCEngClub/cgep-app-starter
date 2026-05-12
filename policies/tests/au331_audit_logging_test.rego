package compliance.cmmc.au331_test

import rego.v1
import data.compliance.cmmc.au331

compliant_input := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_cloudtrail.mgmt",
    "type": "aws_cloudtrail",
    "values": {
      "is_multi_region_trail": true,
      "enable_log_file_validation": true
    }
  }
]}}}

noncompliant_input := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_cloudtrail.mgmt",
    "type": "aws_cloudtrail",
    "values": {
      "is_multi_region_trail": false,
      "enable_log_file_validation": false
    }
  }
]}}}

no_cloudtrail_input := {"planned_values": {"root_module": {"resources": []}}}

test_compliant_passes if { count(au331.deny) == 0 with input as compliant_input }

test_noncompliant_fails if {
  some msg in au331.deny with input as noncompliant_input
  contains(msg, "AU.L2-3.3.1")
}

test_no_cloudtrail_fails if {
  some msg in au331.deny with input as no_cloudtrail_input
  contains(msg, "AU.L2-3.3.1")
}
package compliance.cmmc.ac315_test

import rego.v1
import data.compliance.cmmc.ac315

compliant_input := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_iam_role_policy.lambda_least_privilege",
    "type": "aws_iam_role_policy",
    "values": {
      "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"dynamodb:PutItem\",\"dynamodb:GetItem\"],\"Resource\":\"*\"}]}"
    }
  }
]}}}

noncompliant_input := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_iam_role_policy.lambda_inline",
    "type": "aws_iam_role_policy",
    "values": {
      "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"dynamodb:*\",\"Resource\":\"*\"}]}"
    }
  }
]}}}

test_compliant_passes if { count(ac315.deny) == 0 with input as compliant_input }

test_noncompliant_fails if {
  some msg in ac315.deny with input as noncompliant_input
  contains(msg, "AC.L2-3.1.5")
}
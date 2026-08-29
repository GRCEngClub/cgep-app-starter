package compliance.hipaa.least_privilege_test

import rego.v1
import data.compliance.hipaa.least_privilege

compliant_input := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_iam_role_policy.lambda_inline",
    "type": "aws_iam_role_policy",
    "values": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"dynamodb:PutItem\",\"dynamodb:GetItem\"],\"Resource\":\"*\"}]}"}
  }
]}}}

noncompliant_input := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_iam_role_policy.lambda_inline",
    "type": "aws_iam_role_policy",
    "values": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"dynamodb:*\",\"Resource\":\"*\"}]}"}
  }
]}}}

test_compliant_passes if { count(least_privilege.deny) == 0 with input as compliant_input }

test_noncompliant_fails if {
  some msg in least_privilege.deny with input as noncompliant_input
  contains(msg, "164.312(a)(1)")
}

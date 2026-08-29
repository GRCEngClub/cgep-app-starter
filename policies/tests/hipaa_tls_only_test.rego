package compliance.hipaa.tls_only_test

import rego.v1
import data.compliance.hipaa.tls_only

compliant_input := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_s3_bucket.uploads",
    "type": "aws_s3_bucket",
    "values": {"tags_all": {"DataClass": "phi"}}
  },
  {
    "address": "aws_s3_bucket_policy.uploads",
    "type": "aws_s3_bucket_policy",
    "values": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"}
  }
]}}, "configuration": {"root_module": {"resources": [
  {"type": "aws_s3_bucket_policy", "expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id"]}}}
]}}}

noncompliant_input := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_s3_bucket.uploads",
    "type": "aws_s3_bucket",
    "values": {"tags_all": {"DataClass": "phi"}}
  }
]}}, "configuration": {"root_module": {"resources": []}}}

test_compliant_passes if { count(tls_only.deny) == 0 with input as compliant_input }

test_noncompliant_fails if {
  some msg in tls_only.deny with input as noncompliant_input
  contains(msg, "164.312(e)(1)")
}

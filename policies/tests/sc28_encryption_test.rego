package compliance.sc28_test

import rego.v1
import data.compliance.sc28

compliant_input := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_s3_bucket.good",
    "type": "aws_s3_bucket",
    "values": {"bucket": "my-good-bucket"}
  },
  {
    "address": "aws_s3_bucket_server_side_encryption_configuration.good",
    "type": "aws_s3_bucket_server_side_encryption_configuration",
    "values": {"bucket": "my-good-bucket"}
  }
]}}}

noncompliant_input := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_s3_bucket.bad",
    "type": "aws_s3_bucket",
    "values": {"bucket": "my-bad-bucket"}
  }
]}}}

test_compliant_passes if { count(sc28.deny) == 0 with input as compliant_input }

test_noncompliant_fails if {
  some msg in sc28.deny with input as noncompliant_input
  contains(msg, "SC-28")
  contains(msg, "aws_s3_bucket.bad")
}

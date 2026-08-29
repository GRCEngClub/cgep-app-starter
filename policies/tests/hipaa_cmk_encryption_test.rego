package compliance.hipaa.cmk_encryption_test

import rego.v1
import data.compliance.hipaa.cmk_encryption

compliant_input := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_s3_bucket.uploads",
    "type": "aws_s3_bucket",
    "values": {"tags_all": {"DataClass": "phi"}}
  },
  {
    "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
    "type": "aws_s3_bucket_server_side_encryption_configuration",
    "values": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms", "kms_master_key_id": "arn:aws:kms:us-east-1:123:key/abc"}]}]}
  }
]}}, "configuration": {"root_module": {"resources": [
  {"type": "aws_s3_bucket_server_side_encryption_configuration", "expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id"]}}}
]}}}

noncompliant_input := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_s3_bucket.uploads",
    "type": "aws_s3_bucket",
    "values": {"tags_all": {"DataClass": "phi"}}
  }
]}}, "configuration": {"root_module": {"resources": []}}}

test_compliant_passes if { count(cmk_encryption.deny) == 0 with input as compliant_input }

test_noncompliant_fails if {
  some msg in cmk_encryption.deny with input as noncompliant_input
  contains(msg, "164.312(a)(2)(iv)")
}

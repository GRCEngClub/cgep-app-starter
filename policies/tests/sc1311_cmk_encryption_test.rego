package compliance.cmmc.sc1311_test

import rego.v1
import data.compliance.cmmc.sc1311

compliant_input := {"configuration": {"root_module": {"resources": [
  {
    "address": "aws_s3_bucket.uploads",
    "type": "aws_s3_bucket",
    "name": "uploads"
  },
  {
    "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
    "type": "aws_s3_bucket_server_side_encryption_configuration",
    "name": "uploads",
    "expressions": {
      "bucket": {"references": ["aws_s3_bucket.uploads.id"]},
      "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": {"constant_value": "aws:kms"}, "kms_master_key_id": {"references": ["aws_kms_key.phi.arn"]}}]}]
    }
  }
]}}}

noncompliant_input := {"configuration": {"root_module": {"resources": [
  {
    "address": "aws_s3_bucket.uploads",
    "type": "aws_s3_bucket",
    "name": "uploads"
  }
]}}}

test_compliant_passes if { count(sc1311.deny) == 0 with input as compliant_input }

test_noncompliant_fails if {
  some msg in sc1311.deny with input as noncompliant_input
  contains(msg, "SC.L2-3.13.11")
}
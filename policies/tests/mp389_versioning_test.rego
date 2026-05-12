package compliance.cmmc.mp389_test

import rego.v1
import data.compliance.cmmc.mp389

compliant_input := {"configuration": {"root_module": {"resources": [
  {
    "address": "aws_s3_bucket.uploads",
    "type": "aws_s3_bucket",
    "name": "uploads"
  },
  {
    "address": "aws_s3_bucket_versioning.uploads",
    "type": "aws_s3_bucket_versioning",
    "name": "uploads",
    "expressions": {
      "bucket": {"references": ["aws_s3_bucket.uploads.id"]},
      "versioning_configuration": [{"status": {"constant_value": "Enabled"}}]
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

test_compliant_passes if { count(mp389.deny) == 0 with input as compliant_input }

test_noncompliant_fails if {
  some msg in mp389.deny with input as noncompliant_input
  contains(msg, "MP.L2-3.8.9")
}
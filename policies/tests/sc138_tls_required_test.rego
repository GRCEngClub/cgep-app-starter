package compliance.cmmc.sc138_test

import rego.v1
import data.compliance.cmmc.sc138

compliant_input := {"configuration": {"root_module": {"resources": [
  {
    "address": "aws_s3_bucket.uploads",
    "type": "aws_s3_bucket",
    "name": "uploads"
  },
  {
    "address": "aws_s3_bucket_policy.uploads_tls",
    "type": "aws_s3_bucket_policy",
    "name": "uploads_tls",
    "expressions": {
      "bucket": {"references": ["aws_s3_bucket.uploads.id"]}
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

test_compliant_passes if { count(sc138.deny) == 0 with input as compliant_input }

test_noncompliant_fails if {
  some msg in sc138.deny with input as noncompliant_input
  contains(msg, "SC.L2-3.13.8")
}
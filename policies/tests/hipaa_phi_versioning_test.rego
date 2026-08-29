package compliance.hipaa.phi_versioning_test

import rego.v1
import data.compliance.hipaa.phi_versioning

compliant_input := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_s3_bucket.uploads",
    "type": "aws_s3_bucket",
    "values": {"tags_all": {"DataClass": "phi"}}
  },
  {
    "address": "aws_s3_bucket_versioning.uploads",
    "type": "aws_s3_bucket_versioning",
    "values": {"versioning_configuration": [{"status": "Enabled"}]}
  }
]}}, "configuration": {"root_module": {"resources": [
  {"type": "aws_s3_bucket_versioning", "expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id"]}}}
]}}}

noncompliant_input := {"planned_values": {"root_module": {"resources": [
  {
    "address": "aws_s3_bucket.uploads",
    "type": "aws_s3_bucket",
    "values": {"tags_all": {"DataClass": "phi"}}
  }
]}}, "configuration": {"root_module": {"resources": []}}}

test_compliant_passes if { count(phi_versioning.deny) == 0 with input as compliant_input }

test_noncompliant_fails if {
  some msg in phi_versioning.deny with input as noncompliant_input
  contains(msg, "164.308(a)(7)")
}

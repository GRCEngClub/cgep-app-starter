package compliance.cm6_test

import rego.v1
import data.compliance.cm6

compliant_input := {"planned_values":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.good","type":"aws_s3_bucket","values":{"tags":{
    "Project":"x","Environment":"dev","ManagedBy":"terraform","ComplianceScope":"cge-p-lab"
  }}}
]}}}

noncompliant_input := {"planned_values":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.bad","type":"aws_s3_bucket","values":{"tags":{"Project":"x"}}}
]}}}

no_tags_input := {"planned_values":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.naked","type":"aws_s3_bucket","values":{}}
]}}}

test_compliant_passes if { count(cm6.deny) == 0 with input as compliant_input }
test_missing_tags_fails if { some msg in cm6.deny with input as noncompliant_input; contains(msg, "CM-6") }
test_no_tags_fails if { some msg in cm6.deny with input as no_tags_input; contains(msg, "CM-6") }
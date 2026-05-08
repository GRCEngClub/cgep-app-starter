package compliance.ac3_test

import rego.v1
import data.compliance.ac3

compliant_bucket := {"planned_values":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.good","type":"aws_s3_bucket","values":{"bucket":"good"}},
  {"address":"aws_s3_bucket_public_access_block.good","type":"aws_s3_bucket_public_access_block","values":{"bucket":"good","block_public_acls":true,"block_public_policy":true,"ignore_public_acls":true,"restrict_public_buckets":true}}
]}}}

noncompliant_bucket := {"planned_values":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.bad","type":"aws_s3_bucket","values":{"bucket":"bad"}}
]}}}

test_compliant_passes if { count(ac3.deny) == 0 with input as compliant_bucket }

test_noncompliant_fails if {
  some msg in ac3.deny with input as noncompliant_bucket
  contains(msg, "AC-3")
}
open_sg_input := {"planned_values":{"root_module":{"resources":[
  {"address":"aws_security_group.open","type":"aws_security_group","values":{
    "ingress":[{"from_port":22,"to_port":22,"protocol":"tcp","cidr_blocks":["0.0.0.0/0"]}]
  }}
]}}}

test_open_port_fails if {
  some msg in ac3.deny with input as open_sg_input
  contains(msg, "AC-3")
}
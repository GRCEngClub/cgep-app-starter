# METADATA
# title: Lambda functions must run inside a VPC
# description: >
#   GAP-05. A function without vpc_config runs on AWS-managed networking with no
#   boundary the customer controls. Every function needs vpc_config with
#   subnet_ids and security_group_ids.
# custom:
#   control_id: SC.L2-3.13.1
#   framework: CMMC Level 2 (NIST SP 800-171)
#   gap: GAP-05
#   severity: high
#   remediation: >
#     Add vpc_config { subnet_ids = [...], security_group_ids = [...] } to the
#     aws_lambda_function.
package compliance.sc13_1_lambda_vpc

import data.lib.tf
import rego.v1

in_vpc(f) if {
	some v in f.expressions.vpc_config
	tf.nonempty(v.subnet_ids)
	tf.nonempty(v.security_group_ids)
}

deny contains msg if {
	some f in tf.managed("aws_lambda_function")
	not in_vpc(f)
	msg := sprintf("[SC.L2-3.13.1] %s must be deployed in a VPC (vpc_config with subnets and security groups) (GAP-05)", [f.address])
}

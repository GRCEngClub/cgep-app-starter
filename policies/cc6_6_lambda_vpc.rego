# policies/cc6_6_lambda_vpc.rego
# METADATA
# title: CC6.6 - intake Lambda must run inside the VPC
# description: >
#   Closes GAP-05: the intake Lambda must not run in the default Lambda
#   environment. It must declare a vpc_config block.
# custom:
#   framework: soc2
#   controls: ["CC6.6"]
#   severity: medium
#   remediation: >
#     Add a vpc_config { subnet_ids = ..., security_group_ids = ... } block
#     referencing the starter's private subnets (directly, or via an
#     override file if the function is declared in a file you don't want
#     to edit).
package compliance.soc2.cc6_6_lambda_vpc

import rego.v1

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_lambda_function"
	count(object.get(r.expressions, "vpc_config", [])) == 0
	msg := sprintf(
		"[CC6.6] aws_lambda_function.%s: no vpc_config block. GAP-05. Remediation: add one referencing the private subnets and a security group.",
		[r.name],
	)
}

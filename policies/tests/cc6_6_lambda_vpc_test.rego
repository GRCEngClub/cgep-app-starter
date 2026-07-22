# policies/tests/cc6_6_lambda_vpc_test.rego
package compliance.soc2.cc6_6_lambda_vpc_test

import rego.v1
import data.compliance.soc2.cc6_6_lambda_vpc

compliant_input := {"configuration": {"root_module": {"resources": [{
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"name": "intake",
	"expressions": {"vpc_config": [{
		"subnet_ids": {"references": ["aws_subnet.private"]},
		"security_group_ids": {"references": ["aws_security_group.lambda.id"]},
	}]},
}]}}}

# GAP-05 re-introduced: no vpc_config block.
missing_vpc_config_input := {"configuration": {"root_module": {"resources": [{
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"name": "intake",
	"expressions": {},
}]}}}

test_compliant_passes if { count(cc6_6_lambda_vpc.deny) == 0 with input as compliant_input }

test_missing_vpc_config_fails if {
	some msg in cc6_6_lambda_vpc.deny with input as missing_vpc_config_input
	contains(msg, "CC6.6")
	contains(msg, "aws_lambda_function.intake")
}

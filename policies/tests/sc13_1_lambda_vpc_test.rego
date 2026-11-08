package compliance.sc13_1_lambda_vpc_test

import data.compliance.sc13_1_lambda_vpc
import data.fixtures
import rego.v1

test_compliant_passes if {
	p := fixtures.plan([fixtures.lambda_in_vpc("intake")])
	count(sc13_1_lambda_vpc.deny) == 0 with input as p
}

test_no_vpc_config_fails if {
	p := fixtures.plan([fixtures.lambda_no_vpc("intake")])
	count(sc13_1_lambda_vpc.deny) == 1 with input as p
}

test_empty_vpc_config_fails if {
	p := fixtures.plan([fixtures.lambda_empty_vpc("intake")])
	count(sc13_1_lambda_vpc.deny) == 1 with input as p
}

test_message_cites_control if {
	p := fixtures.plan([fixtures.lambda_no_vpc("intake")])
	some msg in sc13_1_lambda_vpc.deny with input as p
	contains(msg, "SC.L2-3.13.1")
}

package compliance.sc13_11_dynamodb_test

import data.compliance.sc13_11_dynamodb
import data.fixtures
import rego.v1

test_compliant_passes if {
	p := fixtures.plan([fixtures.dynamodb_cmk("intake")])
	count(sc13_11_dynamodb.deny) == 0 with input as p
}

test_default_encryption_fails if {
	p := fixtures.plan([fixtures.dynamodb_default("intake")])
	count(sc13_11_dynamodb.deny) == 1 with input as p
}

test_aws_managed_key_fails if {
	p := fixtures.plan([fixtures.dynamodb_aws_managed("intake")])
	count(sc13_11_dynamodb.deny) == 1 with input as p
}

test_message_cites_control if {
	p := fixtures.plan([fixtures.dynamodb_default("intake")])
	some msg in sc13_11_dynamodb.deny with input as p
	contains(msg, "SC.L2-3.13.11")
}

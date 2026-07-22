# policies/tests/cc6_3_iam_least_privilege_test.rego
package compliance.soc2.cc6_3_iam_least_privilege_test

import rego.v1
import data.compliance.soc2.cc6_3_iam_least_privilege

compliant_policy := `{"Version":"2012-10-17","Statement":[{"Sid":"DynamoDBWriteOnly","Effect":"Allow","Action":["dynamodb:PutItem"],"Resource":"arn:aws:dynamodb:x"},{"Sid":"S3UploadOnly","Effect":"Allow","Action":["s3:PutObject"],"Resource":"arn:aws:s3:::x/*"}]}`

compliant_input := {"resource_changes": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"change": {"after": {"policy": compliant_policy}},
}]}

# GAP-07 re-introduced exactly as GAPS.md describes: dynamodb:* and s3:*.
wildcard_policy := `{"Version":"2012-10-17","Statement":[{"Sid":"DynamoDBFull","Effect":"Allow","Action":"dynamodb:*","Resource":"arn:aws:dynamodb:x"},{"Sid":"S3Full","Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::x/*"}]}`

wildcard_input := {"resource_changes": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"change": {"after": {"policy": wildcard_policy}},
}]}

# Bare "*" action, array form.
bare_star_policy := `{"Version":"2012-10-17","Statement":[{"Sid":"TooBroad","Effect":"Allow","Action":["*"],"Resource":"*"}]}`

bare_star_input := {"resource_changes": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"change": {"after": {"policy": bare_star_policy}},
}]}

unresolvable_input := {"resource_changes": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"change": {"after": {"policy": null}},
}]}

# Terraform's actual shape for an unresolved value: the key is absent from
# "after" entirely, not set to a literal null.
unresolvable_absent_key_input := {"resource_changes": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"change": {"after": {"name": "intake-data-access"}},
}]}

test_compliant_passes if { count(cc6_3_iam_least_privilege.deny) == 0 with input as compliant_input }

test_wildcard_service_actions_fail if {
	msgs := {msg | some msg in cc6_3_iam_least_privilege.deny} with input as wildcard_input
	count(msgs) == 2
	some msg in msgs
	contains(msg, "CC6.3")
	contains(msg, "dynamodb:*")
}

test_bare_star_fails if {
	some msg in cc6_3_iam_least_privilege.deny with input as bare_star_input
	contains(msg, "CC6.3")
}

test_unresolvable_fails_closed if {
	some msg in cc6_3_iam_least_privilege.deny with input as unresolvable_input
	contains(msg, "not resolvable")
}

test_unresolvable_absent_key_fails_closed if {
	some msg in cc6_3_iam_least_privilege.deny with input as unresolvable_absent_key_input
	contains(msg, "not resolvable")
}

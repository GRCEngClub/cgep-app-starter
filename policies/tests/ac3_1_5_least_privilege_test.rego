package compliance.ac3_1_5_least_privilege_test

import data.compliance.ac3_1_5_least_privilege as lp
import data.fixtures
import rego.v1

scoped := fixtures.allow_statement("WriteIntake", ["dynamodb:PutItem"], {"references": ["aws_dynamodb_table.intake.arn", "aws_dynamodb_table.intake"]})

kms_actions := fixtures.allow_statement("UseDataCmk", ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"], {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]})

test_compliant_passes if {
	p := fixtures.plan([
		fixtures.role_policy("lambda_inline", "lambda_inline"),
		fixtures.doc("lambda_inline", [scoped, kms_actions]),
	])
	count(lp.deny) == 0 with input as p
}

test_service_wildcard_fails if {
	wide := fixtures.allow_statement("Wide", ["dynamodb:*"], {"references": ["aws_dynamodb_table.intake.arn"]})
	p := fixtures.plan([
		fixtures.role_policy("lambda_inline", "lambda_inline"),
		fixtures.doc("lambda_inline", [wide]),
	])
	count(lp.deny) == 1 with input as p
}

test_full_wildcard_fails if {
	wide := fixtures.allow_statement("Wide", ["*"], {"references": ["aws_dynamodb_table.intake.arn"]})
	p := fixtures.plan([fixtures.doc("lambda_inline", [wide])])
	count(lp.deny) == 1 with input as p
}

test_wildcard_resource_fails if {
	wide := fixtures.allow_statement("Wide", ["s3:PutObject"], {"constant_value": ["*"]})
	p := fixtures.plan([fixtures.doc("lambda_inline", [wide])])
	count(lp.deny) == 1 with input as p
}

test_deny_statement_with_wildcard_is_allowed if {
	p := fixtures.plan([fixtures.doc("tls", [fixtures.tls_statement])])
	count(lp.deny) == 0 with input as p
}

test_jsonencode_policy_is_unverifiable_and_fails if {
	p := fixtures.plan([fixtures.role_policy_jsonencode("lambda_inline")])
	count(lp.deny) == 1 with input as p
}

test_admin_managed_policy_fails if {
	p := fixtures.plan([fixtures.role_attachment("admin", "arn:aws:iam::aws:policy/AdministratorAccess")])
	count(lp.deny) == 1 with input as p
}

test_service_role_managed_policy_passes if {
	p := fixtures.plan([fixtures.role_attachment("basic", "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")])
	count(lp.deny) == 0 with input as p
}

test_message_cites_control if {
	wide := fixtures.allow_statement("Wide", ["dynamodb:*"], {"references": ["aws_dynamodb_table.intake.arn"]})
	p := fixtures.plan([fixtures.doc("lambda_inline", [wide])])
	some msg in lp.deny with input as p
	contains(msg, "AC.L2-3.1.5")
}

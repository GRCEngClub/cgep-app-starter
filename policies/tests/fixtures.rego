# Test fixtures: small builders that mimic the `configuration` section of
# `terraform show -json` for the resources the policies inspect.
package fixtures

import rego.v1

plan(resources) := {"configuration": {"root_module": {"resources": resources}}}

res(type, name, expressions) := {
	"address": sprintf("%s.%s", [type, name]),
	"mode": "managed",
	"type": type,
	"name": name,
	"expressions": expressions,
}

ref_pair(addr) := [sprintf("%s.id", [addr]), addr]

bucket(name) := res("aws_s3_bucket", name, {"bucket": {"constant_value": name}})

sse_kms(name, key) := res("aws_s3_bucket_server_side_encryption_configuration", name, {
	"bucket": {"references": ref_pair(sprintf("aws_s3_bucket.%s", [name]))},
	"rule": [{
		"apply_server_side_encryption_by_default": [{
			"sse_algorithm": {"constant_value": "aws:kms"},
			"kms_master_key_id": {"references": [sprintf("%s.arn", [key]), key]},
		}],
		"bucket_key_enabled": {"constant_value": true},
	}],
})

sse_kms_no_key(name) := res("aws_s3_bucket_server_side_encryption_configuration", name, {
	"bucket": {"references": ref_pair(sprintf("aws_s3_bucket.%s", [name]))},
	"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": {"constant_value": "aws:kms"}}]}],
})

sse_s3(name) := res("aws_s3_bucket_server_side_encryption_configuration", name, {
	"bucket": {"references": ref_pair(sprintf("aws_s3_bucket.%s", [name]))},
	"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": {"constant_value": "AES256"}}]}],
})

versioning(name, status) := res("aws_s3_bucket_versioning", name, {
	"bucket": {"references": ref_pair(sprintf("aws_s3_bucket.%s", [name]))},
	"versioning_configuration": [{"status": {"constant_value": status}}],
})

# aws_iam_policy_document data source.
doc(name, statements) := {
	"address": sprintf("data.aws_iam_policy_document.%s", [name]),
	"mode": "data",
	"type": "aws_iam_policy_document",
	"name": name,
	"expressions": {"statement": statements},
}

tls_statement := {
	"sid": {"constant_value": "DenyInsecureTransport"},
	"effect": {"constant_value": "Deny"},
	"actions": {"constant_value": ["s3:*"]},
	"resources": {"references": ["aws_s3_bucket.x.arn", "aws_s3_bucket.x"]},
	"principals": [{"type": {"constant_value": "*"}, "identifiers": {"constant_value": ["*"]}}],
	"condition": [{
		"test": {"constant_value": "Bool"},
		"variable": {"constant_value": "aws:SecureTransport"},
		"values": {"constant_value": ["false"]},
	}],
}

# A Deny statement that does NOT test SecureTransport (wrong condition).
wrong_condition_statement := object.union(tls_statement, {"condition": [{
	"test": {"constant_value": "StringEquals"},
	"variable": {"constant_value": "aws:SourceVpce"},
	"values": {"constant_value": ["vpce-123"]},
}]})

bucket_policy(name, doc_name) := res("aws_s3_bucket_policy", name, {
	"bucket": {"references": ref_pair(sprintf("aws_s3_bucket.%s", [name]))},
	"policy": {"references": [
		sprintf("data.aws_iam_policy_document.%s.json", [doc_name]),
		sprintf("data.aws_iam_policy_document.%s", [doc_name]),
	]},
})

# Bucket policy written as jsonencode(): config keeps only the references.
bucket_policy_jsonencode(name) := res("aws_s3_bucket_policy", name, {
	"bucket": {"references": ref_pair(sprintf("aws_s3_bucket.%s", [name]))},
	"policy": {"references": [sprintf("aws_s3_bucket.%s.arn", [name]), sprintf("aws_s3_bucket.%s", [name])]},
})

dynamodb_cmk(name) := res("aws_dynamodb_table", name, {"server_side_encryption": [{
	"enabled": {"constant_value": true},
	"kms_key_arn": {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]},
}]})

dynamodb_aws_managed(name) := res("aws_dynamodb_table", name, {"server_side_encryption": [{"enabled": {"constant_value": true}}]})

dynamodb_default(name) := res("aws_dynamodb_table", name, {"hash_key": {"constant_value": "id"}})

lambda_in_vpc(name) := res("aws_lambda_function", name, {"vpc_config": [{
	"subnet_ids": {"references": ["aws_subnet.private"]},
	"security_group_ids": {"references": ["aws_security_group.lambda.id", "aws_security_group.lambda"]},
}]})

lambda_no_vpc(name) := res("aws_lambda_function", name, {"timeout": {"constant_value": 10}})

lambda_empty_vpc(name) := res("aws_lambda_function", name, {"vpc_config": [{
	"subnet_ids": {"constant_value": []},
	"security_group_ids": {"constant_value": []},
}]})

allow_statement(sid, actions, resources) := {
	"sid": {"constant_value": sid},
	"effect": {"constant_value": "Allow"},
	"actions": {"constant_value": actions},
	"resources": resources,
}

role_policy(name, doc_name) := res("aws_iam_role_policy", name, {
	"role": {"references": ["aws_iam_role.lambda.id", "aws_iam_role.lambda"]},
	"policy": {"references": [
		sprintf("data.aws_iam_policy_document.%s.json", [doc_name]),
		sprintf("data.aws_iam_policy_document.%s", [doc_name]),
	]},
})

role_policy_jsonencode(name) := res("aws_iam_role_policy", name, {
	"role": {"references": ["aws_iam_role.lambda.id", "aws_iam_role.lambda"]},
	"policy": {"references": ["aws_dynamodb_table.intake.arn", "aws_dynamodb_table.intake"]},
})

role_attachment(name, arn) := res("aws_iam_role_policy_attachment", name, {
	"role": {"references": ["aws_iam_role.lambda.name", "aws_iam_role.lambda"]},
	"policy_arn": {"constant_value": arn},
})

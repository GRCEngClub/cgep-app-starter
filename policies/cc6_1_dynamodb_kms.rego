# policies/cc6_1_dynamodb_kms.rego
# METADATA
# title: CC6.1 - DynamoDB submissions table must use a customer CMK
# description: >
#   Closes GAP-02: the intake table must not rely on the AWS-owned default
#   key. It must declare server_side_encryption with a customer-managed
#   kms_key_arn.
# custom:
#   framework: soc2
#   controls: ["CC6.1"]
#   severity: high
#   remediation: >
#     Add a server_side_encryption { enabled = true, kms_key_arn = ... }
#     block referencing your own aws_kms_key (directly, or via an override
#     file if the table is declared in a file you don't want to edit).
package compliance.soc2.cc6_1_dynamodb_kms

import rego.v1

deny contains msg if {
	table := dynamodb_tables[_]
	not has_cmk_encryption(table)
	msg := sprintf(
		"[CC6.1] %s: no server_side_encryption block with a customer-managed kms_key_arn. GAP-02. Remediation: add server_side_encryption { enabled = true, kms_key_arn = <your CMK arn> }.",
		[table],
	)
}

dynamodb_tables contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_dynamodb_table"
	addr := sprintf("aws_dynamodb_table.%s", [r.name])
}

has_cmk_encryption(table_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_dynamodb_table"
	sprintf("aws_dynamodb_table.%s", [r.name]) == table_addr
	some sse in r.expressions.server_side_encryption
	sse.enabled.constant_value == true
	count(sse.kms_key_arn.references) > 0
}

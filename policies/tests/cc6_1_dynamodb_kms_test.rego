# policies/tests/cc6_1_dynamodb_kms_test.rego
package compliance.soc2.cc6_1_dynamodb_kms_test

import rego.v1
import data.compliance.soc2.cc6_1_dynamodb_kms

compliant_input := {"configuration": {"root_module": {"resources": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"name": "intake",
	"expressions": {"server_side_encryption": [{
		"enabled": {"constant_value": true},
		"kms_key_arn": {"references": ["aws_kms_key.grc.arn", "aws_kms_key.grc"]},
	}]},
}]}}}

# GAP-02 re-introduced: no server_side_encryption block at all (the
# starter's original shape).
missing_sse_input := {"configuration": {"root_module": {"resources": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"name": "intake",
	"expressions": {},
}]}}}

# Enabled but on the AWS-owned default key (no kms_key_arn reference) --
# still doesn't satisfy "under customer key custody".
default_key_input := {"configuration": {"root_module": {"resources": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"name": "intake",
	"expressions": {"server_side_encryption": [{"enabled": {"constant_value": true}}]},
}]}}}

test_compliant_passes if { count(cc6_1_dynamodb_kms.deny) == 0 with input as compliant_input }

test_missing_sse_fails if {
	some msg in cc6_1_dynamodb_kms.deny with input as missing_sse_input
	contains(msg, "CC6.1")
	contains(msg, "aws_dynamodb_table.intake")
}

test_default_key_fails if {
	some msg in cc6_1_dynamodb_kms.deny with input as default_key_input
	contains(msg, "CC6.1")
}

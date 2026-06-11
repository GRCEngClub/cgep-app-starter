package compliance.soc2.gap02_dynamodb_cmk

import rego.v1

# --- PASSING: DynamoDB table has CMK encryption ---
test_dynamodb_with_cmk_passes if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_dynamodb_table.intake_cmk",
			"type": "aws_dynamodb_table",
			"change": {"after": {"server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:us-east-1:123:key/abc"}]}},
		}],
	}
}

# --- FAILING: DynamoDB table has no server_side_encryption block ---
test_dynamodb_no_encryption_denied if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_dynamodb_table.intake",
			"type": "aws_dynamodb_table",
			"change": {"after": {"server_side_encryption": []}},
		}],
	}
}

# --- FAILING: DynamoDB table has SSE enabled but no CMK ARN ---
test_dynamodb_no_cmk_arn_denied if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_dynamodb_table.intake",
			"type": "aws_dynamodb_table",
			"change": {"after": {"server_side_encryption": [{"enabled": true, "kms_key_arn": null}]}},
		}],
	}
}

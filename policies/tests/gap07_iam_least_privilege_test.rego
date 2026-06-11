package compliance.soc2.gap07_iam_least_privilege

import rego.v1

# --- PASSING: specific actions only ---
test_specific_actions_pass if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_iam_role_policy.lambda_least_privilege",
			"type": "aws_iam_role_policy",
			"change": {"after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"dynamodb:PutItem\",\"dynamodb:GetItem\"],\"Resource\":\"*\"}]}"}},
		}],
	}
}

# --- FAILING: dynamodb:* wildcard ---
test_dynamodb_wildcard_denied if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_iam_role_policy.lambda_inline",
			"type": "aws_iam_role_policy",
			"change": {"after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"dynamodb:*\",\"Resource\":\"*\"}]}"}},
		}],
	}
}

# --- FAILING: s3:* wildcard ---
test_s3_wildcard_denied if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_iam_role_policy.lambda_inline",
			"type": "aws_iam_role_policy",
			"change": {"after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}"}},
		}],
	}
}

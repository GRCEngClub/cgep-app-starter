# Tests for iam_no_wildcard policy
package policies.iam_no_wildcard_test

import rego.v1
import data.policies.iam_no_wildcard

# --- PASSING TEST ---
# An IAM policy WITH specific actions should not trigger a deny
test_iam_with_specific_actions_passes if {
    count(iam_no_wildcard.deny) == 0 with input as {
        "resource_changes": [
            {
                "address": "aws_iam_role_policy.lambda_inline",
                "type": "aws_iam_role_policy",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"dynamodb:GetItem\",\"dynamodb:PutItem\",\"s3:GetObject\",\"s3:PutObject\"],\"Resource\":\"*\"}]}"
                    }
                }
            }
        ]
    }
}

# --- FAILING TEST ---
# An IAM policy WITH wildcard actions should trigger a deny
test_iam_with_wildcard_fails if {
    count(iam_no_wildcard.deny) > 0 with input as {
        "resource_changes": [
            {
                "address": "aws_iam_role_policy.lambda_inline",
                "type": "aws_iam_role_policy",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"dynamodb:*\",\"Resource\":\"*\"}]}"
                    }
                }
            }
        ]
    }
}
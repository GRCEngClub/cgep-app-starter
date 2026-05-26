# Tests for lambda_vpc policy
package policies.lambda_vpc_test

import rego.v1
import data.policies.lambda_vpc

# --- PASSING TEST ---
# A Lambda WITH vpc_config should not trigger a deny
test_lambda_with_vpc_passes if {
    count(lambda_vpc.deny) == 0 with input as {
        "resource_changes": [
            {
                "address": "aws_lambda_function.intake",
                "type": "aws_lambda_function",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "vpc_config": [
                            {
                                "subnet_ids": [
                                    "subnet-abc123",
                                    "subnet-def456"
                                ],
                                "security_group_ids": ["sg-abc123"]
                            }
                        ]
                    }
                }
            }
        ]
    }
}

# --- FAILING TEST ---
# A Lambda WITHOUT vpc_config should trigger a deny
test_lambda_without_vpc_fails if {
    count(lambda_vpc.deny) == 1 with input as {
        "resource_changes": [
            {
                "address": "aws_lambda_function.intake",
                "type": "aws_lambda_function",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "vpc_config": []
                    }
                }
            }
        ]
    }
}
# Tests for s3_tls_enforcement policy
package policies.s3_tls_enforcement_test

import rego.v1
import data.policies.s3_tls_enforcement

# --- PASSING TEST ---
# A bucket WITH a TLS-enforcing policy should not trigger a deny
test_s3_with_tls_passes if {
    count(s3_tls_enforcement.deny) == 0 with input as {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.uploads",
                "type": "aws_s3_bucket",
                "change": {
                    "actions": ["create"],
                    "after": {}
                }
            },
            {
                "address": "aws_s3_bucket_policy.uploads_tls",
                "type": "aws_s3_bucket_policy",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"
                    }
                }
            }
        ]
    }
}

# --- FAILING TEST ---
# A bucket WITHOUT a TLS policy should trigger a deny
test_s3_without_tls_fails if {
    count(s3_tls_enforcement.deny) == 1 with input as {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.uploads",
                "type": "aws_s3_bucket",
                "change": {
                    "actions": ["create"],
                    "after": {}
                }
            }
        ]
    }
}
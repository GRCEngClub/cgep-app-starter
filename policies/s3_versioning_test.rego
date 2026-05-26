# Tests for s3_versioning policy
package policies.s3_versioning_test

import rego.v1
import data.policies.s3_versioning

# --- PASSING TEST ---
# A bucket WITH versioning enabled should not trigger a deny
test_s3_with_versioning_passes if {
    count(s3_versioning.deny) == 0 with input as {
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
                "address": "aws_s3_bucket_versioning.uploads",
                "type": "aws_s3_bucket_versioning",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "versioning_configuration": [
                            {
                                "status": "Enabled"
                            }
                        ]
                    }
                }
            }
        ]
    }
}

# --- FAILING TEST ---
# A bucket WITHOUT versioning should trigger a deny
test_s3_without_versioning_fails if {
    count(s3_versioning.deny) == 1 with input as {
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
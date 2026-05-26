# Tests for s3_kms_encryption policy
package policies.s3_kms_encryption_test

import rego.v1
import data.policies.s3_kms_encryption

# --- PASSING TEST ---
# A bucket WITH KMS encryption should not trigger a deny
test_s3_with_kms_passes if {
    count(s3_kms_encryption.deny) == 0 with input as {
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
                "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
                "type": "aws_s3_bucket_server_side_encryption_configuration",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "rule": [
                            {
                                "apply_server_side_encryption_by_default": [
                                    {
                                        "sse_algorithm": "aws:kms",
                                        "kms_master_key_id": "arn:aws:kms:us-east-1:123456789:key/abc"
                                    }
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    }
}

# --- FAILING TEST ---
# A bucket WITHOUT KMS encryption should trigger a deny
test_s3_without_kms_fails if {
    count(s3_kms_encryption.deny) == 1 with input as {
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
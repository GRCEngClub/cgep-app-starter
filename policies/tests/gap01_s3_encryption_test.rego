

package compliance.gap01_test

import rego.v1
import data.compliance.gap01

# A compliant configuration with the correct bucket,
# customer-managed key, and SSE-KMS algorithm.
compliant_input := {
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
                    "type": "aws_s3_bucket_server_side_encryption_configuration",
                    "expressions": {
                        "bucket": {
                            "references": ["aws_s3_bucket.uploads.id"]
                        },
                        "rule": [{
                            "apply_server_side_encryption_by_default": [{
                                "sse_algorithm": {
                                    "constant_value": "aws:kms"
                                },
                                "kms_master_key_id": {
                                    "references": ["aws_kms_key.grc.arn"]
                                }
                            }]
                        }]
                    }
                },
                {
                    "address": "aws_kms_key.grc",
                    "type": "aws_kms_key"
                }
            ]
        }
    }
}

# Helper: remove the compliant encryption resource.
missing_input := {
    "configuration": {
        "root_module": {
            "resources": [{
                "address": "aws_kms_key.grc",
                "type": "aws_kms_key"
            }]
        }
    }
}

test_compliant_passes if {
    results := gap01.deny with input as compliant_input
    count(results) == 0
}

test_missing_encryption_fails if {
    results := gap01.deny with input as missing_input
    count(results) > 0
}

test_sse_s3_fails if {
    bad := object.union(
        compliant_input,
        {"configuration": {"root_module": {"resources": [
            {
                "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
                "type": "aws_s3_bucket_server_side_encryption_configuration",
                "expressions": {
                    "bucket": {"references": ["aws_s3_bucket.uploads.id"]},
                    "rule": [{
                        "apply_server_side_encryption_by_default": [{
                            "sse_algorithm": {"constant_value": "AES256"},
                            "kms_master_key_id": {"references": ["aws_kms_key.grc.arn"]}
                        }]
                    }]
                }
            }
        ]}}}
    )
    results := gap01.deny with input as bad
    count(results) > 0
}

test_wrong_kms_key_fails if {
    bad := {
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
                        "expressions": {
                            "bucket": {"references": ["aws_s3_bucket.uploads.id"]},
                            "rule": [{
                                "apply_server_side_encryption_by_default": [{
                                    "sse_algorithm": {"constant_value": "aws:kms"},
                                    "kms_master_key_id": {"references": ["aws_kms_key.other.arn"]}
                                }]
                            }]
                        }
                    },
                    {"address": "aws_kms_key.grc", "type": "aws_kms_key"}
                ]
            }
        }
    }
    results := gap01.deny with input as bad
    count(results) > 0
}

test_wrong_bucket_fails if {
    bad := {
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
                        "expressions": {
                            "bucket": {"references": ["aws_s3_bucket.other.id"]},
                            "rule": [{
                                "apply_server_side_encryption_by_default": [{
                                    "sse_algorithm": {"constant_value": "aws:kms"},
                                    "kms_master_key_id": {"references": ["aws_kms_key.grc.arn"]}
                                }]
                            }]
                        }
                    },
                    {"address": "aws_kms_key.grc", "type": "aws_kms_key"}
                ]
            }
        }
    }
    results := gap01.deny with input as bad
    count(results) > 0
}

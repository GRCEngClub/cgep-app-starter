
package compliance.gap02_test

import rego.v1
import data.compliance.gap02

# Correct DynamoDB encryption configuration
compliant_input := {
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_dynamodb_table.intake",
                    "type": "aws_dynamodb_table",
                    "expressions": {
                        "server_side_encryption": [{
                            "enabled": {
                                "constant_value": true
                            },
                            "kms_key_arn": {
                                "references": ["aws_kms_key.grc.arn"]
                            }
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

# DynamoDB without customer-managed encryption
missing_encryption_input := {
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_dynamodb_table.intake",
                    "type": "aws_dynamodb_table",
                    "expressions": {}
                },
                {
                    "address": "aws_kms_key.grc",
                    "type": "aws_kms_key"
                }
            ]
        }
    }
}

# DynamoDB referencing the wrong KMS key
wrong_key_input := {
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_dynamodb_table.intake",
                    "type": "aws_dynamodb_table",
                    "expressions": {
                        "server_side_encryption": [{
                            "enabled": {
                                "constant_value": true
                            },
                            "kms_key_arn": {
                                "references": ["aws_kms_key.other.arn"]
                            }
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

test_compliant_passes if {
    results := gap02.deny with input as compliant_input
    count(results) == 0
}

test_missing_encryption_fails if {
    results := gap02.deny with input as missing_encryption_input
    count(results) > 0
}

test_wrong_key_fails if {
    results := gap02.deny with input as wrong_key_input
    count(results) > 0
}

test_missing_intake_table_fails if {
    results := gap02.deny with input as {"configuration": {"root_module": {"resources": []}}}
    count(results) > 0
}


package compliance.gap03_test

import rego.v1
import data.compliance.gap03

bucket := {
    "address": "aws_s3_bucket.uploads",
    "values": {
        "arn": "arn:aws:s3:::acme-test-uploads"
    }
}

tls_statement := {
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
        "arn:aws:s3:::acme-test-uploads",
        "arn:aws:s3:::acme-test-uploads/*"
    ],
    "Condition": {
        "Bool": {
            "aws:SecureTransport": "false"
        }
    }
}

make_input(statement) := {
    "planned_values": {
        "root_module": {
            "resources": [
                bucket,
                {
                    "address": "aws_s3_bucket_policy.uploads_tls",
                    "values": {
                        "policy": json.marshal({
                            "Version": "2012-10-17",
                            "Statement": [statement]
                        })
                    }
                }
            ]
        }
    }
}

test_valid_tls_policy_passes if {
    results := gap03.deny with input as make_input(tls_statement)
    count(results) == 0
}

test_missing_bucket_policy_fails if {
    bad := {
        "planned_values": {
            "root_module": {
                "resources": [bucket]
            }
        }
    }
    results := gap03.deny with input as bad
    count(results) > 0
}

test_wrong_tls_condition_fails if {
    bad_statement := object.union(tls_statement, {
        "Condition": {
            "Bool": {
                "aws:SecureTransport": "true"
            }
        }
    })
    results := gap03.deny with input as make_input(bad_statement)
    count(results) > 0
}

test_allow_instead_of_deny_fails if {
    bad_statement := object.union(tls_statement, {
        "Effect": "Allow"
    })
    results := gap03.deny with input as make_input(bad_statement)
    count(results) > 0
}

test_wrong_bucket_fails if {
    bad_statement := object.union(tls_statement, {
        "Resource": [
            "arn:aws:s3:::different-bucket",
            "arn:aws:s3:::different-bucket/*"
        ]
    })
    results := gap03.deny with input as make_input(bad_statement)
    count(results) > 0
}

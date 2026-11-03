
package compliance.gap04_test

import rego.v1
import data.compliance.gap04

compliant_input := {
    "configuration": {
        "root_module": {
            "resources": [{
                "address": "aws_s3_bucket_versioning.uploads",
                "type": "aws_s3_bucket_versioning",
                "expressions": {
                    "bucket": {
                        "references": ["aws_s3_bucket.uploads.id"]
                    },
                    "versioning_configuration": [{
                        "status": {
                            "constant_value": "Enabled"
                        }
                    }]
                }
            }]
        }
    }
}

test_versioning_enabled_passes if {
    results := gap04.deny with input as compliant_input
    count(results) == 0
}

test_missing_versioning_fails if {
    bad := {
        "configuration": {
            "root_module": {
                "resources": []
            }
        }
    }
    results := gap04.deny with input as bad
    count(results) > 0
}

test_versioning_suspended_fails if {
    bad := {
        "configuration": {
            "root_module": {
                "resources": [{
                    "address": "aws_s3_bucket_versioning.uploads",
                    "type": "aws_s3_bucket_versioning",
                    "expressions": {
                        "bucket": {
                            "references": ["aws_s3_bucket.uploads.id"]
                        },
                        "versioning_configuration": [{
                            "status": {
                                "constant_value": "Suspended"
                            }
                        }]
                    }
                }]
            }
        }
    }
    results := gap04.deny with input as bad
    count(results) > 0
}

test_wrong_bucket_fails if {
    bad := {
        "configuration": {
            "root_module": {
                "resources": [{
                    "address": "aws_s3_bucket_versioning.uploads",
                    "type": "aws_s3_bucket_versioning",
                    "expressions": {
                        "bucket": {
                            "references": ["aws_s3_bucket.other.id"]
                        },
                        "versioning_configuration": [{
                            "status": {
                                "constant_value": "Enabled"
                            }
                        }]
                    }
                }]
            }
        }
    }
    results := gap04.deny with input as bad
    count(results) > 0
}

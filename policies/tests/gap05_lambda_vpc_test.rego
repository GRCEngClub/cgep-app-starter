
package compliance.gap05_test

import rego.v1
import data.compliance.gap05

# Correct Lambda VPC configuration
compliant_input := {
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_lambda_function.intake",
                    "type": "aws_lambda_function",
                    "expressions": {
                        "vpc_config": [{
                            "subnet_ids": {
                                "references": ["aws_subnet.private"]
                            },
                            "security_group_ids": {
                                "references": ["aws_security_group.lambda.id"]
                            }
                        }]
                    }
                },
                {
                    "address": "aws_subnet.private",
                    "type": "aws_subnet"
                },
                {
                    "address": "aws_security_group.lambda",
                    "type": "aws_security_group"
                }
            ]
        }
    }
}

test_compliant_passes if {
    results := gap05.deny with input as compliant_input
    count(results) == 0
}

test_missing_vpc_fails if {
    bad := {
        "configuration": {
            "root_module": {
                "resources": [{
                    "address": "aws_lambda_function.intake",
                    "type": "aws_lambda_function",
                    "expressions": {}
                }]
            }
        }
    }

    results := gap05.deny with input as bad
    count(results) > 0
}

test_missing_subnets_fails if {
    bad := {
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_lambda_function.intake",
                        "type": "aws_lambda_function",
                        "expressions": {
                            "vpc_config": [{
                                "subnet_ids": {
                                    "references": []
                                },
                                "security_group_ids": {
                                    "references": ["aws_security_group.lambda.id"]
                                }
                            }]
                        }
                    },
                    {"address": "aws_subnet.private", "type": "aws_subnet"},
                    {"address": "aws_security_group.lambda", "type": "aws_security_group"}
                ]
            }
        }
    }

    results := gap05.deny with input as bad
    count(results) > 0
}

test_wrong_security_group_fails if {
    bad := {
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_lambda_function.intake",
                        "type": "aws_lambda_function",
                        "expressions": {
                            "vpc_config": [{
                                "subnet_ids": {
                                    "references": ["aws_subnet.private"]
                                },
                                "security_group_ids": {
                                    "references": ["aws_security_group.other.id"]
                                }
                            }]
                        }
                    },
                    {"address": "aws_subnet.private", "type": "aws_subnet"},
                    {"address": "aws_security_group.lambda", "type": "aws_security_group"}
                ]
            }
        }
    }

    results := gap05.deny with input as bad
    count(results) > 0
}

test_missing_lambda_fails if {
    bad := {
        "configuration": {
            "root_module": {
                "resources": []
            }
        }
    }

    results := gap05.deny with input as bad
    count(results) > 0
}

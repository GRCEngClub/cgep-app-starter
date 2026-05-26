# Policy: Lambda functions must be deployed inside a VPC
# Framework: SOC 2
# Control ID: CC6.6
# Severity: HIGH
# Remediation: Add vpc_config block to aws_lambda_function referencing private subnets

package policies.lambda_vpc

import rego.v1

# Metadata
metadata := {
    "id":          "SOC2-CC6.6-LAMBDA-VPC",
    "framework":   "SOC 2",
    "control":     "CC6.6",
    "severity":    "HIGH",
    "remediation": "Add vpc_config block to Lambda function with private subnet IDs and security group",
}

# Deny any Lambda function that is not configured inside a VPC
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_lambda_function"
    resource.change.actions == ["create"]
    not lambda_has_vpc(resource)
    msg := sprintf(
        "[%s] %s: Lambda function '%s' must be deployed inside a VPC (SOC 2 CC6.6 — GAP-05)",
        [metadata.severity, metadata.control, resource.address]
    )
}

# Check if Lambda has a vpc_config block with at least one subnet
lambda_has_vpc(resource) if {
    count(resource.change.after.vpc_config) > 0
    count(resource.change.after.vpc_config[0].subnet_ids) > 0
}
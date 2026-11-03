
# METADATA
# title: GAP-05 - Lambda VPC Configuration
# description: Require intake Lambda to use the designated VPC networking resources.
# custom:
#   framework: cmmc-level-2
#   controls:
#     - "SC.L2-3.13.1"
#   severity: high
#   remediation: Attach Lambda to private subnets and the designated security group.

package compliance.gap05

import rego.v1

deny contains msg if {
    not lambda_vpc_compliant
    msg := "[SC.L2-3.13.1] GAP-05: intake Lambda must use the designated private subnets and security group."
}


lambda_vpc_compliant if {
    some r in input.configuration.root_module.resources
    r.address == "aws_lambda_function.intake"
    r.type == "aws_lambda_function"

    vpc := r.expressions.vpc_config[0]

    # Verify Lambda references the existing private subnets.
    "aws_subnet.private" in vpc.subnet_ids.references

    # Verify Lambda references the designated security group.
    "aws_security_group.lambda.id" in vpc.security_group_ids.references

    # Verify the security group exists.
    some sg in input.configuration.root_module.resources
    sg.address == "aws_security_group.lambda"
    sg.type == "aws_security_group"

    # Verify the private subnet resources exist.
    some subnet in input.configuration.root_module.resources
    subnet.address == "aws_subnet.private"
    subnet.type == "aws_subnet"
}

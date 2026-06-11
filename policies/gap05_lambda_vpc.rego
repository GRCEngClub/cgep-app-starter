# METADATA
# title: GAP-05 - Lambda functions must run inside the VPC
# description: >
#   SOC 2 CC6.6 requires boundary protection. A Lambda function running
#   outside the VPC can reach DynamoDB and S3 over the public internet,
#   bypassing network-level controls. Lambda functions processing PHI
#   must be deployed with a vpc_config referencing private subnets.
# custom:
#   framework: soc2
#   controls:
#     - CC6.6
#   gap: GAP-05
#   severity: high
package compliance.soc2.gap05_lambda_vpc

import rego.v1

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_lambda_function"
	resource.change.after != null
	not has_vpc_config(resource.change.after)
	msg := sprintf(
		"[CC6.6][GAP-05] Lambda function '%s' has no vpc_config block. Functions processing PHI must run in a VPC with private subnets for boundary protection.",
		[resource.address],
	)
}

has_vpc_config(resource_after) if {
	count(resource_after.vpc_config) > 0
	config := resource_after.vpc_config[0]
	count(config.subnet_ids) > 0
	count(config.security_group_ids) > 0
}

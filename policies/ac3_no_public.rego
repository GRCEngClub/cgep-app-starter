package compliance.ac3

import rego.v1

deny contains msg if {
  some resource in input.planned_values.root_module.resources
  resource.type == "aws_s3_bucket"
  not bucket_locked_down(resource)
  msg := sprintf(
    "[AC-3/CC6.6] %s: bucket allows public access. Remediation: set all four public access block flags to true.",
    [resource.address],
  )
}

bucket_locked_down(resource) if {
  some r in input.planned_values.root_module.resources
  r.type == "aws_s3_bucket_public_access_block"
  r.values.bucket == resource.values.bucket
  r.values.block_public_acls == true
  r.values.block_public_policy == true
  r.values.ignore_public_acls == true
  r.values.restrict_public_buckets == true
}

deny contains msg if {
  some resource in input.planned_values.root_module.resources
  resource.type == "aws_security_group"
  some ingress in resource.values.ingress
  some cidr in ingress.cidr_blocks
  cidr == "0.0.0.0/0"
  ingress.from_port <= 22
  ingress.to_port >= 22
  msg := sprintf(
    "[AC-3/CC6.6] %s: port 22 open to 0.0.0.0/0. Remediation: restrict ingress CIDR.",
    [resource.address],
  )
}
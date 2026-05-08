# policies/sc28_encryption.rego
# METADATA
# title: SC-28 - Encryption at Rest (S3)
# description: "Every aws_s3_bucket must have server-side encryption enabled."
# custom:
#   control_id: SC-28
#   framework: nist-800-53
#   soc2_control: CC6.1
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration with AES256 or aws:kms."
package compliance.sc28

import rego.v1

deny contains msg if {
some resource in input.planned_values.root_module.resources
resource.type == "aws_s3_bucket"
not has_encryption(resource)
msg := sprintf(
"[SC-28/CC6.1] %s: missing server-side encryption. Remediation: add aws_s3_bucket_server_side_encryption_configuration.",
[resource.address],
)
}

has_encryption(resource) if {
some r in input.planned_values.root_module.resources
r.type == "aws_s3_bucket_server_side_encryption_configuration"
r.values.bucket == resource.values.bucket
}

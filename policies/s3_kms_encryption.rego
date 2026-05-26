# Policy: S3 buckets must use KMS customer-managed key encryption
# Framework: SOC 2
# Control ID: CC6.1
# Severity: HIGH
# Remediation: Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm = "aws:kms"

package policies.s3_kms_encryption

import rego.v1

# Metadata
metadata := {
    "id":          "SOC2-CC6.1-S3-KMS",
    "framework":   "SOC 2",
    "control":     "CC6.1",
    "severity":    "HIGH",
    "remediation": "Configure S3 bucket with SSE-KMS using a customer-managed key",
}

# Deny any S3 bucket that does not have KMS encryption configured
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    resource.change.actions[_] in ["create", "update"]
    not s3_has_kms_encryption(resource.address)
    msg := sprintf(
        "[%s] %s: S3 bucket '%s' must use SSE-KMS encryption (SOC 2 CC6.1 — GAP-01)",
        [metadata.severity, metadata.control, resource.address]
    )
}

# Check if a corresponding encryption config exists for this bucket
s3_has_kms_encryption(bucket_address) if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.after.rule[_].apply_server_side_encryption_by_default[_].sse_algorithm == "aws:kms"
}

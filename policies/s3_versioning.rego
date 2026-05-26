# Policy: S3 buckets must have versioning enabled
# Framework: SOC 2
# Control ID: A1.2
# Severity: MEDIUM
# Remediation: Add aws_s3_bucket_versioning with status = "Enabled"

package policies.s3_versioning

import rego.v1

# Metadata
metadata := {
    "id":          "SOC2-A1.2-S3-VERSIONING",
    "framework":   "SOC 2",
    "control":     "A1.2",
    "severity":    "MEDIUM",
    "remediation": "Add aws_s3_bucket_versioning resource with status set to Enabled",
}

# Deny any S3 bucket that does not have versioning enabled
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    resource.change.actions[_] in ["create", "update"]
    not s3_has_versioning(resource.address)
    msg := sprintf(
        "[%s] %s: S3 bucket '%s' must have versioning enabled (SOC 2 A1.2 — GAP-04)",
        [metadata.severity, metadata.control, resource.address]
    )
}

# Check if versioning is enabled for this bucket
s3_has_versioning(bucket_address) if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_versioning"
    resource.change.after.versioning_configuration[_].status == "Enabled"
}

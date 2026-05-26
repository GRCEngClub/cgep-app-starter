# Policy: S3 buckets must deny non-TLS requests
# Framework: SOC 2
# Control ID: CC6.7
# Severity: HIGH
# Remediation: Add aws_s3_bucket_policy with aws:SecureTransport = false deny statement

package policies.s3_tls_enforcement

import rego.v1

# Metadata
metadata := {
    "id":          "SOC2-CC6.7-S3-TLS",
    "framework":   "SOC 2",
    "control":     "CC6.7",
    "severity":    "HIGH",
    "remediation": "Add a bucket policy denying requests where aws:SecureTransport is false",
}

# Only deny S3 buckets being created (not existing ones being updated)
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    resource.change.actions == ["create"]
    not s3_has_tls_policy(resource.address)
    msg := sprintf(
        "[%s] %s: S3 bucket '%s' must enforce TLS-only requests (SOC 2 CC6.7 — GAP-03)",
        [metadata.severity, metadata.control, resource.address]
    )
}

# Check if a TLS-enforcing bucket policy exists
s3_has_tls_policy(bucket_address) if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_policy"
    policy := json.unmarshal(resource.change.after.policy)
    some statement in policy.Statement
    statement.Effect == "Deny"
    statement.Condition.Bool["aws:SecureTransport"] == "false"
}

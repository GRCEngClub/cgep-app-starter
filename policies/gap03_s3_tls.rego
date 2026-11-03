
# METADATA
# title: GAP-03 - Enforce TLS for S3 Uploads
# description: Require an explicit S3 bucket policy denying insecure transport.
# custom:
#   framework: cmmc-level-2
#   controls:
#     - "SC.L2-3.13.8"
#   severity: high
#   remediation: Add an S3 bucket policy denying requests when aws:SecureTransport is false.

package compliance.gap03

import rego.v1

deny contains msg if {
    not secure_transport_enforced
    msg := "[SC.L2-3.13.8] GAP-03: uploads bucket must deny insecure S3 transport."
}

secure_transport_enforced if {
    some r in input.planned_values.root_module.resources
    r.address == "aws_s3_bucket_policy.uploads_tls"

    policy := json.unmarshal(r.values.policy)

    some statement in policy.Statement
    statement.Effect == "Deny"
    statement.Principal == "*"
    statement.Action == "s3:*"
    statement.Condition.Bool["aws:SecureTransport"] == "false"

    aws_bucket := input.planned_values.root_module.resources[_]
    aws_bucket.address == "aws_s3_bucket.uploads"

    bucket_arn := aws_bucket.values.arn
    bucket_arn in statement.Resource
    sprintf("%s/*", [bucket_arn]) in statement.Resource
}

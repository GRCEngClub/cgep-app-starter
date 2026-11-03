
# METADATA
# title: GAP-02 - DynamoDB Customer-Managed Encryption
# description: Require the intake table to use the capstone KMS key.
# custom:
#   framework: cmmc-level-2
#   controls:
#     - "SC.L2-3.13.11"
#   severity: high
#   remediation: Enable DynamoDB SSE using aws_kms_key.grc.

package compliance.gap02

import rego.v1

deny contains msg if {
    not intake_encrypted
    msg := "[SC.L2-3.13.11] GAP-02: DynamoDB intake table must use the customer-managed KMS key."
}

intake_encrypted if {
    some r in input.configuration.root_module.resources
    r.address == "aws_dynamodb_table.intake"
    r.type == "aws_dynamodb_table"

    sse := r.expressions.server_side_encryption[0]
    sse.enabled.constant_value == true

    some ref in sse.kms_key_arn.references
    ref == "aws_kms_key.grc.arn"

    some key in input.configuration.root_module.resources
    key.address == "aws_kms_key.grc"
    key.type == "aws_kms_key"
}

# METADATA
# title: GAP-02 DynamoDB tables must be encrypted with a customer-managed KMS key
# custom:
#   framework: hipaa
#   gap: GAP-02
#   controls:
#     - "164.312(a)(2)(iv)"
#   secondary:
#     - "SOC2 CC6.1"
#     - "CMMC SC.L2-3.13.11"
#   severity: high
package compliance.hipaa.dynamodb_cmk

import data.lib.tf
import rego.v1

deny contains msg if {
    some table in tf.managed("aws_dynamodb_table")
    not has_cmk(table)
    msg := sprintf("GAP-02 [HIPAA 164.312(a)(2)(iv)] %s uses the AWS-owned key; set server_side_encryption with kms_key_arn", [table.address])
}

has_cmk(table) if {
    sse := table.expressions.server_side_encryption[0]
    sse.enabled.constant_value == true
    sse.kms_key_arn
}

# METADATA
# title: DynamoDB tables must be encrypted with a customer-managed key
# description: >
#   GAP-02. Without a server_side_encryption block the table uses an AWS-owned
#   key; with enabled = true but no kms_key_arn it uses the AWS-managed key.
#   Neither is under customer control.
# custom:
#   control_id: SC.L2-3.13.11
#   framework: CMMC Level 2 (NIST SP 800-171)
#   gap: GAP-02
#   severity: high
#   remediation: >
#     Add server_side_encryption { enabled = true, kms_key_arn = aws_kms_key.<name>.arn }
#     to the aws_dynamodb_table.
package compliance.sc13_11_dynamodb

import data.lib.tf
import rego.v1

uses_cmk(t) if {
	some sse in t.expressions.server_side_encryption
	sse.enabled.constant_value == true
	tf.is_cmk(sse.kms_key_arn)
}

deny contains msg if {
	some t in tf.managed("aws_dynamodb_table")
	not uses_cmk(t)
	msg := sprintf("[SC.L2-3.13.11] %s must be encrypted with a customer-managed KMS key (GAP-02)", [t.address])
}

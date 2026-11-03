

# METADATA
# title: GAP-01 - S3 Customer-Managed KMS Encryption
# description: Require the uploads bucket to use the capstone customer-managed KMS key.
# custom:
#   framework: cmmc-level-2
#   controls:
#     - "SC.L2-3.13.11"
#   severity: high
#   remediation: Configure SSE-KMS referencing aws_kms_key.grc.

package compliance.gap01

import rego.v1

deny contains msg if {
    not uploads_encrypted
    msg := "[SC.L2-3.13.11] GAP-01: uploads bucket must use SSE-KMS with aws_kms_key.grc."
}

uploads_encrypted if {
    some r in input.configuration.root_module.resources

    r.address == "aws_s3_bucket_server_side_encryption_configuration.uploads"

    # Verify that encryption is attached to the correct S3 bucket.
    some bucket_ref in r.expressions.bucket.references
    bucket_ref == "aws_s3_bucket.uploads.id"

    # Verify SSE-KMS is explicitly configured.
    rule := r.expressions.rule[0]
    encryption := rule.apply_server_side_encryption_by_default[0]

    encryption.sse_algorithm.constant_value == "aws:kms"

    # Verify that the key is the capstone customer-managed key.
    some key_ref in encryption.kms_master_key_id.references
    key_ref == "aws_kms_key.grc.arn"

    # Verify that the referenced KMS key is defined in Terraform.
    some key in input.configuration.root_module.resources
    key.address == "aws_kms_key.grc"
    key.type == "aws_kms_key"
}


# METADATA
# title: GAP-04 - S3 Uploads Bucket Versioning
# description: Require versioning on the uploads bucket.
# custom:
#   framework: cmmc-level-2
#   controls:
#     - "MP.L2-3.8.9"
#   severity: medium
#   remediation: Enable S3 bucket versioning on the uploads bucket.

package compliance.gap04

import rego.v1

deny contains msg if {
    not versioning_enabled
    msg := "[MP.L2-3.8.9] GAP-04: S3 uploads bucket must have versioning enabled."
}

versioning_enabled if {
    some r in input.configuration.root_module.resources

    r.address == "aws_s3_bucket_versioning.uploads"
    r.type == "aws_s3_bucket_versioning"

    some bucket_ref in r.expressions.bucket.references
    bucket_ref == "aws_s3_bucket.uploads.id"

    r.expressions.versioning_configuration[0].status.constant_value == "Enabled"
}

# METADATA
# title: GAP-04 S3 buckets must have versioning enabled
# custom:
#   framework: hipaa
#   gap: GAP-04
#   controls:
#     - "164.308(a)(7)(ii)(A)"
#   secondary:
#     - "SOC2 A1.2"
#     - "CMMC MP.L2-3.8.9"
#   severity: medium
package compliance.hipaa.s3_versioning

import data.lib.tf
import rego.v1

deny contains msg if {
    some bucket in tf.managed("aws_s3_bucket")
    not versioning_enabled(bucket.address)
    msg := sprintf("GAP-04 [HIPAA 164.308(a)(7)(ii)(A)] %s does not have versioning enabled", [bucket.address])
}

versioning_enabled(addr) if {
    some cfg in tf.managed("aws_s3_bucket_versioning")
    tf.references(cfg, "bucket", addr)
    cfg.expressions.versioning_configuration[0].status.constant_value == "Enabled"
}

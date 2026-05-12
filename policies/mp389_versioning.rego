# METADATA
# title: MP.L2-3.8.9 - Media Protection (Versioning)
# description: "Every aws_s3_bucket storing PHI must have versioning enabled to prevent unrecoverable overwrites."
# custom:
#   control_id: MP.L2-3.8.9
#   framework: CMMC-L2
#   severity: high
#   remediation: "Add aws_s3_bucket_versioning with status = Enabled referencing the bucket."
package compliance.cmmc.mp389

import rego.v1

deny contains msg if {
  bucket := bucket_addresses[_]
  not has_versioning(bucket)
  msg := sprintf(
    "[MP.L2-3.8.9] %s: S3 bucket has no versioning enabled. PHI overwrites are unrecoverable. Remediation: add aws_s3_bucket_versioning with status = Enabled.",
    [bucket]
  )
}

bucket_addresses contains addr if {
  some r in input.configuration.root_module.resources
  r.type == "aws_s3_bucket"
  addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_versioning(bucket_addr) if {
  some r in input.configuration.root_module.resources
  r.type == "aws_s3_bucket_versioning"
  some ref in r.expressions.bucket.references
  ref == sprintf("%s.id", [bucket_addr])
}
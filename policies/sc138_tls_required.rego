# METADATA
# title: SC.L2-3.13.8 - Network Communications (TLS Required)
# description: "Every aws_s3_bucket must have a bucket policy denying non-TLS requests."
# custom:
#   control_id: SC.L2-3.13.8
#   framework: CMMC-L2
#   severity: high
#   remediation: "Add aws_s3_bucket_policy with a Deny statement on aws:SecureTransport = false."
package compliance.cmmc.sc138

import rego.v1

deny contains msg if {
  bucket := bucket_addresses[_]
  not has_tls_policy(bucket)
  msg := sprintf(
    "[SC.L2-3.13.8] %s: S3 bucket has no TLS-enforcing bucket policy. Remediation: add aws_s3_bucket_policy with Deny on aws:SecureTransport = false.",
    [bucket]
  )
}

bucket_addresses contains addr if {
  some r in input.configuration.root_module.resources
  r.type == "aws_s3_bucket"
  addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_tls_policy(bucket_addr) if {
  some r in input.configuration.root_module.resources
  r.type == "aws_s3_bucket_policy"
  some ref in r.expressions.bucket.references
  ref == sprintf("%s.id", [bucket_addr])
}
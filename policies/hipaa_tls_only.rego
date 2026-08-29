# METADATA
# title: HIPAA 164.312(e)(1) - Transmission Security
# description: "S3 buckets storing PHI must deny non-TLS requests via a bucket policy with aws:SecureTransport condition."
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(e)(1)"
#   severity: high
#   remediation: "Add aws_s3_bucket_policy with a Deny statement on aws:SecureTransport=false."
package compliance.hipaa.tls_only

import rego.v1

deny contains msg if {
  some r in input.planned_values.root_module.resources
  r.type == "aws_s3_bucket"
  r.values.tags_all.DataClass == "phi"
  not has_tls_policy(r.address)
  msg := sprintf(
    "[HIPAA 164.312(e)(1)] %s: PHI bucket has no bucket policy denying non-TLS requests. Remediation: add aws_s3_bucket_policy with Deny on aws:SecureTransport=false.",
    [r.address]
  )
}

has_tls_policy(bucket_addr) if {
  some r in input.planned_values.root_module.resources
  r.type == "aws_s3_bucket_policy"
  policy := json.unmarshal(r.values.policy)
  some stmt in policy.Statement
  stmt.Effect == "Deny"
  some condition_key in object.keys(stmt.Condition)
  lower(condition_key) == "bool"
  stmt.Condition[condition_key]["aws:SecureTransport"] == "false"
  some ref in input.configuration.root_module.resources[_].expressions.bucket.references
  contains(ref, split(bucket_addr, ".")[1])
}

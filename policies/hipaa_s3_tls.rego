# METADATA
# title: GAP-03 S3 bucket policies must deny non-TLS (aws:SecureTransport=false) requests
# custom:
#   framework: hipaa
#   gap: GAP-03
#   controls:
#     - "164.312(e)(1)"
#   secondary:
#     - "SOC2 CC6.7"
#     - "CMMC SC.L2-3.13.8"
#   severity: high
package compliance.hipaa.s3_tls

import data.lib.tf
import rego.v1

deny contains msg if {
    some bucket in tf.managed("aws_s3_bucket")
    not denies_insecure_transport(bucket.address)
    msg := sprintf("GAP-03 [HIPAA 164.312(e)(1)] %s has no bucket policy (built with aws_iam_policy_document) that denies aws:SecureTransport=false", [bucket.address])
}

denies_insecure_transport(addr) if {
    some pol in tf.managed("aws_s3_bucket_policy")
    tf.references(pol, "bucket", addr)
    doc := tf.policy_doc(pol, "policy")
    some stmt in doc.expressions.statement
    stmt.effect.constant_value == "Deny"
    some cond in stmt.condition
    cond.test.constant_value == "Bool"
    cond.variable.constant_value == "aws:SecureTransport"
    cond.values.constant_value == ["false"]
}

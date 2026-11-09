# METADATA
# title: S3 buckets must deny requests that do not use TLS
# description: >
#   GAP-03. Every bucket needs a bucket policy with a Deny statement for all
#   principals on s3:* when aws:SecureTransport is false. The policy must be
#   written with aws_iam_policy_document so it can be checked at plan time; a
#   hand-written JSON string cannot be verified and is treated as a failure.
# custom:
#   control_id: SC.L2-3.13.8
#   framework: CMMC Level 2 (NIST SP 800-171)
#   gap: GAP-03
#   severity: high
#   remediation: >
#     Add an aws_s3_bucket_policy whose policy is an aws_iam_policy_document with
#     a Deny / s3:* / Principal "*" statement conditioned on Bool aws:SecureTransport = false.
package compliance.sc13_8_tls

import data.lib.tf
import rego.v1

denies_insecure(st) if {
	st.effect.constant_value == "Deny"
	some a in st.actions.constant_value
	a in {"s3:*", "*"}
	some pr in st.principals
	"*" in pr.identifiers.constant_value
	some c in st.condition
	c.test.constant_value == "Bool"
	c.variable.constant_value == "aws:SecureTransport"
	"false" in c.values.constant_value
}

enforces_tls(b) if {
	some p in tf.managed("aws_s3_bucket_policy")
	b.address in tf.refs(p.expressions.bucket)
	some d in tf.docs_for(p.expressions.policy)
	some st in d.expressions.statement
	denies_insecure(st)
}

deny contains msg if {
	some b in tf.managed("aws_s3_bucket")
	not enforces_tls(b)
	msg := sprintf("[SC.L2-3.13.8] %s must have a bucket policy (aws_iam_policy_document) denying s3:* when aws:SecureTransport is false (GAP-03)", [b.address])
}

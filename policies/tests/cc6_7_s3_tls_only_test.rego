# policies/tests/cc6_7_s3_tls_only_test.rego
package compliance.soc2.cc6_7_s3_tls_only_test

import rego.v1
import data.compliance.soc2.cc6_7_s3_tls_only

compliant_policy := `{"Version":"2012-10-17","Statement":[{"Sid":"DenyInsecureTransport","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::x","arn:aws:s3:::x/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`

compliant_input := {"resource_changes": [{
	"address": "aws_s3_bucket_policy.uploads_tls_only",
	"type": "aws_s3_bucket_policy",
	"change": {"after": {"policy": compliant_policy}},
}]}

# GAP-03 re-introduced: the bucket policy resource is gone entirely.
missing_policy_input := {"resource_changes": []}

# Present, but doesn't actually deny insecure transport (e.g. an
# unrelated bucket policy someone left in its place).
irrelevant_policy := `{"Version":"2012-10-17","Statement":[{"Sid":"AllowSomething","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::x/*"}]}`

irrelevant_policy_input := {"resource_changes": [{
	"address": "aws_s3_bucket_policy.uploads_tls_only",
	"type": "aws_s3_bucket_policy",
	"change": {"after": {"policy": irrelevant_policy}},
}]}

# Referenced bucket ARN not yet known (from-scratch plan) -- fail closed.
# Terraform represents this by omitting the key from "after" entirely, not
# by setting it to a literal null; both shapes must fail closed.
unresolvable_input := {"resource_changes": [{
	"address": "aws_s3_bucket_policy.uploads_tls_only",
	"type": "aws_s3_bucket_policy",
	"change": {"after": {"policy": null}},
}]}

unresolvable_absent_key_input := {"resource_changes": [{
	"address": "aws_s3_bucket_policy.uploads_tls_only",
	"type": "aws_s3_bucket_policy",
	"change": {"after": {}},
}]}

test_compliant_passes if { count(cc6_7_s3_tls_only.deny) == 0 with input as compliant_input }

test_missing_policy_fails if {
	some msg in cc6_7_s3_tls_only.deny with input as missing_policy_input
	contains(msg, "CC6.7")
}

test_irrelevant_policy_fails if {
	some msg in cc6_7_s3_tls_only.deny with input as irrelevant_policy_input
	contains(msg, "CC6.7")
}

test_unresolvable_fails_closed if {
	some msg in cc6_7_s3_tls_only.deny with input as unresolvable_input
	contains(msg, "not resolvable")
}

test_unresolvable_absent_key_fails_closed if {
	some msg in cc6_7_s3_tls_only.deny with input as unresolvable_absent_key_input
	contains(msg, "not resolvable")
}

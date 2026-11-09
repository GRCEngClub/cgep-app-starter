package compliance.sc13_8_tls_test

import data.compliance.sc13_8_tls
import data.fixtures
import rego.v1

# Matches the real layout: bucket_policy.uploads_tls_only -> doc uploads_tls.
linked_plan := fixtures.plan([
	fixtures.bucket("uploads"),
	object.union(fixtures.bucket_policy("uploads", "uploads_tls"), {"address": "aws_s3_bucket_policy.uploads_tls_only"}),
	fixtures.doc("uploads_tls", [fixtures.tls_statement]),
])

test_compliant_passes if {
	count(sc13_8_tls.deny) == 0 with input as linked_plan
}

test_no_bucket_policy_fails if {
	p := fixtures.plan([fixtures.bucket("uploads")])
	count(sc13_8_tls.deny) == 1 with input as p
}

test_policy_without_tls_deny_fails if {
	p := fixtures.plan([
		fixtures.bucket("uploads"),
		fixtures.bucket_policy("uploads", "uploads_tls"),
		fixtures.doc("uploads_tls", [fixtures.wrong_condition_statement]),
	])
	count(sc13_8_tls.deny) == 1 with input as p
}

test_jsonencode_policy_is_unverifiable_and_fails if {
	p := fixtures.plan([fixtures.bucket("uploads"), fixtures.bucket_policy_jsonencode("uploads")])
	count(sc13_8_tls.deny) == 1 with input as p
}

test_every_bucket_is_checked if {
	p := fixtures.plan([
		fixtures.bucket("uploads"),
		fixtures.bucket("trail"),
		fixtures.bucket_policy("uploads", "uploads_tls"),
		fixtures.doc("uploads_tls", [fixtures.tls_statement]),
	])
	count(sc13_8_tls.deny) == 1 with input as p
}

test_message_cites_control if {
	p := fixtures.plan([fixtures.bucket("uploads")])
	some msg in sc13_8_tls.deny with input as p
	contains(msg, "SC.L2-3.13.8")
}

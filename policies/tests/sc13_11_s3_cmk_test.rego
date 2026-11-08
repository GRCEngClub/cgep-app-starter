package compliance.sc13_11_s3_test

import data.compliance.sc13_11_s3
import data.fixtures
import rego.v1

test_compliant_passes if {
	p := fixtures.plan([fixtures.bucket("uploads"), fixtures.sse_kms("uploads", "aws_kms_key.phi")])
	count(sc13_11_s3.deny) == 0 with input as p
}

test_no_encryption_config_fails if {
	p := fixtures.plan([fixtures.bucket("uploads")])
	count(sc13_11_s3.deny) == 1 with input as p
}

test_sse_s3_fails if {
	p := fixtures.plan([fixtures.bucket("uploads"), fixtures.sse_s3("uploads")])
	count(sc13_11_s3.deny) == 1 with input as p
}

test_kms_without_cmk_fails if {
	p := fixtures.plan([fixtures.bucket("uploads"), fixtures.sse_kms_no_key("uploads")])
	count(sc13_11_s3.deny) == 1 with input as p
}

test_encryption_config_for_other_bucket_does_not_count if {
	p := fixtures.plan([
		fixtures.bucket("uploads"),
		fixtures.bucket("other"),
		fixtures.sse_kms("other", "aws_kms_key.phi"),
	])
	count(sc13_11_s3.deny) == 1 with input as p
}

test_audit_log_bucket_is_exempt if {
	p := fixtures.plan([fixtures.bucket("trail"), fixtures.sse_s3("trail")])
	count(sc13_11_s3.deny) == 0 with input as p
}

test_message_cites_control if {
	p := fixtures.plan([fixtures.bucket("uploads")])
	some msg in sc13_11_s3.deny with input as p
	contains(msg, "SC.L2-3.13.11")
}

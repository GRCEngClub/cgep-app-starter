package compliance.mp3_8_9_versioning_test

import data.compliance.mp3_8_9_versioning
import data.fixtures
import rego.v1

test_compliant_passes if {
	p := fixtures.plan([fixtures.bucket("uploads"), fixtures.versioning("uploads", "Enabled")])
	count(mp3_8_9_versioning.deny) == 0 with input as p
}

test_no_versioning_fails if {
	p := fixtures.plan([fixtures.bucket("uploads")])
	count(mp3_8_9_versioning.deny) == 1 with input as p
}

test_suspended_versioning_fails if {
	p := fixtures.plan([fixtures.bucket("uploads"), fixtures.versioning("uploads", "Suspended")])
	count(mp3_8_9_versioning.deny) == 1 with input as p
}

test_audit_log_bucket_is_exempt if {
	p := fixtures.plan([fixtures.bucket("trail")])
	count(mp3_8_9_versioning.deny) == 0 with input as p
}

test_message_cites_control if {
	p := fixtures.plan([fixtures.bucket("uploads")])
	some msg in mp3_8_9_versioning.deny with input as p
	contains(msg, "MP.L2-3.8.9")
}

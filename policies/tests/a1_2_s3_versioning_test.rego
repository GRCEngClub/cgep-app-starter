# policies/tests/a1_2_s3_versioning_test.rego
package compliance.soc2.a1_2_s3_versioning_test

import rego.v1
import data.compliance.soc2.a1_2_s3_versioning

compliant_input := {"configuration": {"root_module": {"resources": [
	{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads", "expressions": {}},
	{
		"address": "aws_s3_bucket_versioning.uploads",
		"type": "aws_s3_bucket_versioning",
		"name": "uploads",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.uploads.id"]},
			"versioning_configuration": [{"status": {"constant_value": "Enabled"}}],
		},
	},
]}}}

# GAP-04 re-introduced: no versioning resource at all.
missing_versioning_input := {"configuration": {"root_module": {"resources": [
	{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads", "expressions": {}},
]}}}

# Present but suspended, not enabled.
suspended_input := {"configuration": {"root_module": {"resources": [
	{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads", "expressions": {}},
	{
		"address": "aws_s3_bucket_versioning.uploads",
		"type": "aws_s3_bucket_versioning",
		"name": "uploads",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.uploads.id"]},
			"versioning_configuration": [{"status": {"constant_value": "Suspended"}}],
		},
	},
]}}}

# A second bucket with no versioning at all must not be flagged -- GAP-04
# is specifically about the uploads bucket, not every bucket in the config.
compliant_with_other_bucket_input := {"configuration": {"root_module": {"resources": array.concat(
	compliant_input.configuration.root_module.resources,
	[{"address": "aws_s3_bucket.cloudtrail_logs", "type": "aws_s3_bucket", "name": "cloudtrail_logs", "expressions": {}}],
)}}}

test_compliant_passes if { count(a1_2_s3_versioning.deny) == 0 with input as compliant_input }

test_other_bucket_without_versioning_not_flagged if {
	count(a1_2_s3_versioning.deny) == 0 with input as compliant_with_other_bucket_input
}

test_missing_versioning_fails if {
	some msg in a1_2_s3_versioning.deny with input as missing_versioning_input
	contains(msg, "A1.2")
	contains(msg, "aws_s3_bucket.uploads")
}

test_suspended_fails if {
	some msg in a1_2_s3_versioning.deny with input as suspended_input
	contains(msg, "A1.2")
}

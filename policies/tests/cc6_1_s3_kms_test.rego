# policies/tests/cc6_1_s3_kms_test.rego
package compliance.soc2.cc6_1_s3_kms_test

import rego.v1
import data.compliance.soc2.cc6_1_s3_kms

compliant_input := {"configuration": {"root_module": {"resources": [
	{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads", "expressions": {}},
	{
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"name": "uploads",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
			"rule": [{"apply_server_side_encryption_by_default": [{
				"sse_algorithm": {"constant_value": "aws:kms"},
				"kms_master_key_id": {"references": ["aws_kms_key.grc.arn", "aws_kms_key.grc"]},
			}]}],
		},
	},
]}}}

# GAP-01 re-introduced: SSE resource removed entirely.
missing_encryption_input := {"configuration": {"root_module": {"resources": [
	{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads", "expressions": {}},
]}}}

# GAP-01 partially re-introduced: encryption resource present but back on
# the AWS-managed default (no customer CMK), the exact residual gap
# GAPS.md describes.
aes256_input := {"configuration": {"root_module": {"resources": [
	{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads", "expressions": {}},
	{
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"name": "uploads",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.uploads.id"]},
			"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": {"constant_value": "AES256"}}]}],
		},
	},
]}}}

# A second bucket with a deliberately different encryption choice (e.g.
# the CloudTrail log bucket, AES256 not KMS) must not be flagged -- GAP-01
# is specifically about the uploads bucket, not every bucket in the config.
compliant_with_other_bucket_input := {"configuration": {"root_module": {"resources": array.concat(
	compliant_input.configuration.root_module.resources,
	[
		{"address": "aws_s3_bucket.cloudtrail_logs", "type": "aws_s3_bucket", "name": "cloudtrail_logs", "expressions": {}},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.cloudtrail_logs",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "cloudtrail_logs",
			"expressions": {
				"bucket": {"references": ["aws_s3_bucket.cloudtrail_logs.id"]},
				"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": {"constant_value": "AES256"}}]}],
			},
		},
	],
)}}}

test_compliant_passes if { count(cc6_1_s3_kms.deny) == 0 with input as compliant_input }

test_other_bucket_with_different_encryption_not_flagged if {
	count(cc6_1_s3_kms.deny) == 0 with input as compliant_with_other_bucket_input
}

test_missing_encryption_fails if {
	some msg in cc6_1_s3_kms.deny with input as missing_encryption_input
	contains(msg, "CC6.1")
	contains(msg, "aws_s3_bucket.uploads")
}

test_aes256_without_cmk_fails if {
	some msg in cc6_1_s3_kms.deny with input as aes256_input
	contains(msg, "CC6.1")
}

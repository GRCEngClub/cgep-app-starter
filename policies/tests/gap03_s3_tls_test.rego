package compliance.soc2.gap03_s3_tls

import rego.v1

# --- PASSING: S3 bucket has TLS deny policy ---
test_s3_with_tls_deny_passes if {
	count(deny) == 0 with input as {
		"resource_changes": [
			{
				"address": "aws_s3_bucket.uploads",
				"type": "aws_s3_bucket",
				"change": {"after": {"bucket": "my-bucket"}},
			},
			{
				"address": "aws_s3_bucket_policy.uploads",
				"type": "aws_s3_bucket_policy",
				"change": {"after": {
					"bucket": "my-bucket",
					"policy": "{\"Statement\":[{\"Effect\":\"Deny\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}",
				}},
			},
		],
	}
}

# --- FAILING: S3 bucket has no bucket policy at all ---
test_s3_no_policy_denied if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket.uploads",
			"type": "aws_s3_bucket",
			"change": {"after": {"bucket": "my-bucket-no-policy"}},
		}],
	}
}

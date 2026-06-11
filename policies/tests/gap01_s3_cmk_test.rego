package compliance.soc2.gap01_s3_cmk

import rego.v1

# --- PASSING: SSE-KMS configured correctly ---
test_s3_with_kms_passes if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"change": {"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms", "kms_master_key_id": "arn:aws:kms:us-east-1:123:key/abc"}]}]}},
		}],
	}
}

# --- FAILING: SSE-S3 instead of SSE-KMS ---
test_s3_with_sse_s3_denied if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"change": {"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]}},
		}],
	}
}

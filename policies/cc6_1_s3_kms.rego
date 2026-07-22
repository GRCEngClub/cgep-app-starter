# policies/cc6_1_s3_kms.rego
# METADATA
# title: CC6.1 - S3 uploads bucket must use SSE-KMS with a customer CMK
# description: >
#   Closes GAP-01: the uploads bucket specifically (not every bucket in the
#   config -- the evidence vault and CloudTrail log bucket have their own,
#   separately-justified encryption choices) must not rely on the
#   AWS-managed SSE-S3 default. It must have a server-side encryption
#   configuration using aws:kms with a customer-managed key.
# custom:
#   framework: soc2
#   controls: ["CC6.1"]
#   severity: high
#   remediation: >
#     Add aws_s3_bucket_server_side_encryption_configuration for the bucket
#     with rule.apply_server_side_encryption_by_default.sse_algorithm =
#     "aws:kms" and kms_master_key_id referencing your own aws_kms_key.
package compliance.soc2.cc6_1_s3_kms

import rego.v1

deny contains msg if {
	bucket := s3_buckets[_]
	not has_kms_encryption(bucket)
	msg := sprintf(
		"[CC6.1] %s: no aws_s3_bucket_server_side_encryption_configuration using aws:kms with a customer CMK. GAP-01. Remediation: add one referencing this bucket with sse_algorithm = \"aws:kms\" and kms_master_key_id set to your aws_kms_key.",
		[bucket],
	)
}

s3_buckets contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	r.name == "uploads"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_kms_encryption(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	some rule in r.expressions.rule
	some default_cfg in rule.apply_server_side_encryption_by_default
	default_cfg.sse_algorithm.constant_value == "aws:kms"
	count(default_cfg.kms_master_key_id.references) > 0
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])

# policies/a1_2_s3_versioning.rego
# METADATA
# title: A1.2 - uploads bucket must have versioning enabled
# description: >
#   Closes GAP-04: without versioning, an overwritten or deleted PHI object
#   in the uploads bucket specifically is unrecoverable.
# custom:
#   framework: soc2
#   controls: ["A1.2"]
#   severity: medium
#   remediation: >
#     Add aws_s3_bucket_versioning for the bucket with
#     versioning_configuration.status = "Enabled".
package compliance.soc2.a1_2_s3_versioning

import rego.v1

deny contains msg if {
	bucket := s3_buckets[_]
	not has_versioning_enabled(bucket)
	msg := sprintf(
		"[A1.2] %s: no aws_s3_bucket_versioning resource with status \"Enabled\". GAP-04. Remediation: add one referencing this bucket.",
		[bucket],
	)
}

s3_buckets contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	r.name == "uploads"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_versioning_enabled(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_versioning"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	some cfg in r.expressions.versioning_configuration
	cfg.status.constant_value == "Enabled"
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])

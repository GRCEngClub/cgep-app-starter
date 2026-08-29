package compliance.hipaa.phi_versioning

import rego.v1

deny contains msg if {
  some r in input.planned_values.root_module.resources
  r.type == "aws_s3_bucket"
  r.values.tags_all.DataClass == "phi"
  not has_versioning(r.address)
  msg := sprintf(
    "[HIPAA 164.308(a)(7)] %s: PHI bucket has no versioning enabled. PHI overwrites are unrecoverable. Remediation: add aws_s3_bucket_versioning with status=Enabled.",
    [r.address]
  )
}

has_versioning(bucket_addr) if {
  some r in input.planned_values.root_module.resources
  r.type == "aws_s3_bucket_versioning"
  r.values.versioning_configuration[0].status == "Enabled"
  some ref in input.configuration.root_module.resources[_].expressions.bucket.references
  contains(ref, split(bucket_addr, ".")[1])
}

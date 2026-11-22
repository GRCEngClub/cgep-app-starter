######################################################################
# secure-bucket — inputs
#
# A caller passes an EXISTING aws_s3_bucket (its id + arn) and the CMK to
# encrypt it with. The module does not create the bucket itself, so the
# same floor can be layered onto any bucket (uploads, evidence vault,
# CloudTrail) without the module owning its name or lifecycle.
######################################################################

variable "bucket_id" {
  type        = string
  description = "ID (name) of the bucket to harden, e.g. aws_s3_bucket.uploads.id."
}

variable "bucket_arn" {
  type        = string
  description = "ARN of the same bucket, used to scope the bucket policy to it and its objects."
}

variable "kms_key_arn" {
  type        = string
  description = "ARN of the customer-managed KMS key used for default SSE-KMS encryption (GAP-01)."
}

variable "additional_policy_json" {
  type        = string
  default     = null
  description = <<-EOT
    Optional rendered IAM policy JSON (e.g. an aws_iam_policy_document .json)
    whose statements are merged into this bucket's policy alongside the
    built-in TLS-only deny. Used for buckets that need extra statements,
    such as a CloudTrail log bucket's AclCheck/Write grants. S3 allows only
    one bucket policy, so the statements must be merged here rather than in a
    second aws_s3_bucket_policy resource.
  EOT
}

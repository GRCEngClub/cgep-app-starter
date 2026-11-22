# secure-bucket

Applies the mandatory PHI-bucket security floor to an **existing** S3
bucket. The module does not create the bucket — the caller owns the
`aws_s3_bucket` and its name/lifecycle — so the identical floor can be
layered onto any bucket (uploads, evidence vault, CloudTrail logs).

## Controls applied

| Control | Resource | Gap closed |
|---------|----------|------------|
| Default SSE-KMS with a customer-managed CMK (bucket keys on) | `aws_s3_bucket_server_side_encryption_configuration` | GAP-01 — SC.L2-3.13.11 |
| Deny any request not over TLS (`aws:SecureTransport = false`) | `aws_s3_bucket_policy` | GAP-03 — SC.L2-3.13.8 |
| Versioning enabled (overwrites/deletes recoverable) | `aws_s3_bucket_versioning` | GAP-04 — MP.L2-3.8.9 |
| Block all public access | `aws_s3_bucket_public_access_block` | — (defense in depth) |

> **One per bucket.** S3 allows exactly one of each of these resources per
> bucket. Harden a bucket with this module **or** inline — never both, or
> the two definitions fight on every apply.

## Usage

```hcl
module "uploads_bucket" {
  source = "./modules/secure-bucket"

  bucket_id   = aws_s3_bucket.uploads.id
  bucket_arn  = aws_s3_bucket.uploads.arn
  kms_key_arn = aws_kms_key.data.arn
}
```

## Inputs

| Name | Type | Description | Required |
|------|------|-------------|----------|
| `bucket_id` | `string` | ID (name) of the bucket to harden. | yes |
| `bucket_arn` | `string` | ARN of the same bucket; scopes the bucket policy to it and its objects. | yes |
| `kms_key_arn` | `string` | ARN of the customer-managed KMS key used for default SSE-KMS encryption. | yes |

## Outputs

None. The caller already holds the bucket it passed in.

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.6 |
| aws | >= 5.0 |

Provider configuration (region, credentials) is **inherited from the root
module** — this module intentionally declares no `provider "aws"` block.

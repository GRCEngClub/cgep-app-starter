# terraform/backend.tf
#
# Remote state in the bucket created by oidc/main.tf's bootstrap module.
# Without this, a GitHub Actions checkout has no way to know the 42
# resources in main.tf/kms.tf/etc. already exist -- it would plan to
# create a second, parallel copy of everything. Backend blocks can't use
# variables/interpolation, so the bucket name is a literal, matching
# oidc/main.tf's tf_state_bucket output.
#
# use_lockfile (S3 native locking, Terraform >= 1.10) instead of a
# DynamoDB lock table -- one fewer resource to provision/pay for/manage
# for the same guarantee.

terraform {
  backend "s3" {
    bucket       = "acme-health-intake-tfstate-552353217556"
    key          = "acme-health-intake/terraform.tfstate"
    region       = "us-east-1"
    use_lockfile = true
  }
}

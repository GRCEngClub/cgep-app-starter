# Remote state: lives in S3 so GitHub Actions and your laptop see the same state.
# Bucket created by bootstrap/. Locking uses S3's native lock file.
terraform {
  backend "s3" {
    bucket       = "acme-health-intake-tfstate-08fa0596"
    key          = "capstone/terraform.tfstate"
    region       = "ca-central-1"
    encrypt      = true
    use_lockfile = true
  }
}

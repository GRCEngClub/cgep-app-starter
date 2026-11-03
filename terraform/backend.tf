
terraform {
  backend "s3" {
    bucket       = "cgep-terraform-state-804450520828"
    key          = "acme-health-intake/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}

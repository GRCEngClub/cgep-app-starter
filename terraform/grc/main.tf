######################################################################
# Acme Health — GRC Baseline Layer
# Wraps the cgep-app-starter workload with HIPAA-aligned controls.
# Primary framework: HIPAA Security Rule
######################################################################

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project         = "acme-health-intake"
      ManagedBy       = "terraform"
      ComplianceScope = "hipaa"
      DataClass       = "phi"
      GRCLayer        = "baseline"
    }
  }
}

# Reference the starter's state so we can wire our resources to theirs
data "terraform_remote_state" "starter" {
  backend = "local"
  config = {
    path = "${path.module}/../terraform.tfstate"
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

######################################################################
# Pipeline bootstrap: the pieces GitHub Actions needs BEFORE it can run.
#
#   1. S3 bucket that holds the Terraform state for the main stack
#   2. GitHub OIDC provider (no stored AWS keys anywhere)
#   3. Two IAM roles: a read-mostly "plan" role for pull requests and a
#      write-capable "apply" role that only the main branch can assume
#
# This is a separate Terraform root on purpose. The main stack's policy gate
# (AC.L2-3.1.5) would, correctly, flag the broad permissions a deploy role
# needs, and a pipeline should not be able to rewrite its own permissions.
# Apply this folder by hand, once, with your own admin credentials.
######################################################################

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "acme-health-intake"
      ManagedBy = "terraform"
      Purpose   = "pipeline-bootstrap"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "ca-central-1"
}

variable "github_org" {
  description = "GitHub user or org that owns the repo. Case matters."
  type        = string
  default     = "RookwoodRan"
}

variable "github_repo" {
  description = "Repository name. Case matters."
  type        = string
  default     = "rani-cgep-app-starter"
}

variable "name_prefix" {
  type    = string
  default = "acme-health-intake"
}

variable "suffix" {
  description = "Same random suffix the main stack uses, so names line up."
  type        = string
  default     = "08fa0596"
}

data "aws_caller_identity" "current" {}

locals {
  account_id      = data.aws_caller_identity.current.account_id
  state_bucket    = "${var.name_prefix}-tfstate-${var.suffix}"
  state_key       = "capstone/terraform.tfstate"
  vault_bucket    = "${var.name_prefix}-evidence-${var.suffix}"
  evidence_alias  = "alias/${var.name_prefix}-evidence-${var.suffix}"
  oidc_host       = "token.actions.githubusercontent.com"
  role_name_arn   = "arn:aws:iam::${local.account_id}:role/${var.name_prefix}-*"
}

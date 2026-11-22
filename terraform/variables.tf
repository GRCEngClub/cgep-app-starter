######################################################################
# Input variables — the single home for every variable in this root module
#
# Purpose
#   All inputs live here so a reviewer or assessor can see, in one file,
#   every value that changes how the system is configured. The default
#   on each security-relevant input IS the security floor; changing it
#   is a reviewable diff to this file, not a value hidden in another .tf.
#
# Layout
#   1. Starter workload (unchanged from cgep-app-starter)
#   2. KMS (kms.tf): CMK lifecycle (closes GAP-01/GAP-02, SC.L2-3.13.11)
#   Tags are not inputs: common tags are fixed in the provider's
#   default_tags in main.tf.
#
# Design rationale
#   Validation blocks reject out-of-policy values at plan time, before
#   the Conftest gate even runs, so a bad input fails fast with a clear
#   message instead of producing a weaker resource.
######################################################################

# 1. Starter workload

variable "aws_region" {
  type        = string
  description = "AWS region for the starter."
  default     = "us-east-1"
}

# 2. KMS customer-managed keys (kms.tf)

variable "kms_deletion_window_in_days" {
  type        = number
  description = "Waiting period before a scheduled key deletion completes. Maximum (30) gives the longest window to cancel an accidental or malicious deletion, which would make all PHI and evidence encrypted under the key unrecoverable."
  default     = 30

  validation {
    condition     = var.kms_deletion_window_in_days >= 7 && var.kms_deletion_window_in_days <= 30
    error_message = "kms_deletion_window_in_days must be between 7 and 30."
  }
}

variable "kms_rotation_period_in_days" {
  type        = number
  description = "Days between automatic key-material rotations. 365 matches the AWS default and an annual crypto-period; lower it if a policy requires a shorter one."
  default     = 365

  validation {
    condition     = var.kms_rotation_period_in_days >= 90 && var.kms_rotation_period_in_days <= 2560
    error_message = "kms_rotation_period_in_days must be between 90 and 2560."
  }
}

variable "kms_key_administrator_arns" {
  type        = list(string)
  description = "IAM principal ARNs allowed to administer the CMKs (manage the key lifecycle: policy, rotation, aliases, enable/disable, scheduled deletion) but NOT to use them for encrypt/decrypt. Keep this list short — ideally a break-glass role, not day-to-day operators — to preserve separation of duties between key administration and key use."

  validation {
    condition     = length(var.kms_key_administrator_arns) > 0
    error_message = "kms_key_administrator_arns must list at least one administrator ARN; an empty list would leave the key with no administrator."
  }

  validation {
    condition     = alltrue([for arn in var.kms_key_administrator_arns : can(regex("^arn:aws:iam::[0-9]{12}:(root|(user|role)/.+)$", arn))])
    error_message = "Each kms_key_administrator_arns entry must be a valid IAM principal ARN (arn:aws:iam::<account-id>:root, :user/<name>, or :role/<name>)."
  }
}

# --------------------------------------------------------------------
# Lambda (main.tf, GAP-06)
# --------------------------------------------------------------------

variable "lambda_reserved_concurrency" {
  type        = number
  description = "Maximum concurrent executions reserved for the intake Lambda (GAP-06). Your account must keep at least 100 unreserved, so it needs a concurrency limit of at least 100 + this value. -1 removes the cap."
  default     = 10
}

# --------------------------------------------------------------------
# API Gateway (main.tf + hardening.tf, GAP-08)
# --------------------------------------------------------------------

variable "api_access_log_retention_days" {
  type        = number
  description = "Days to keep API access logs (GAP-08). Must be a CloudWatch Logs allowed value, e.g. 90, 180, 365, 731."
  default     = 365
}

variable "api_throttling_rate_limit" {
  type        = number
  description = "Steady-state requests per second allowed on the API's default route (GAP-08). Keep it within what the Lambda's reserved concurrency can serve."
  default     = 50
}

variable "api_throttling_burst_limit" {
  type        = number
  description = "Maximum burst of requests on the API's default route before API Gateway returns 429 (GAP-08)."
  default     = 100
}

# --------------------------------------------------------------------
# Evidence vault (evidence-vault.tf)
# --------------------------------------------------------------------

variable "evidence_retention_days" {
  type        = number
  description = "Object Lock default retention for evidence bundles, in days. Locked decision: 365."
  default     = 365
}

# --------------------------------------------------------------------
# Pipeline identity (oidc-trust.tf)
# --------------------------------------------------------------------

variable "github_oidc_subject_prefix" {
  type        = string
  description = "Your repo's OIDC subject prefix in GitHub's immutable format, e.g. repo:OWNER@OWNER_ID/REPO@REPO_ID. Get it with: gh api /repos/OWNER/REPO/actions/oidc/customization/sub. Set in terraform.tfvars."
}

variable "tf_state_bucket" {
  type        = string
  description = "S3 bucket holding Terraform state (bootstrapped in step 2.9). Must match the backend block in main.tf."
  default     = "acme-health-intake-tfstate-ysd"
}
variable "aws_region" {
  type        = string
  description = "AWS region matching the starter deployment."
  default     = "us-east-1"
}

variable "aws_profile" {
  type        = string
  description = "AWS CLI profile."
  default     = "my-sandbox"
}

variable "environment" {
  type        = string
  description = "Deployment environment."
  default     = "dev"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging, or prod."
  }
}

variable "lock_mode" {
  type        = string
  description = "S3 Object Lock mode. GOVERNANCE for lab, COMPLIANCE for production."
  default     = "GOVERNANCE"
  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.lock_mode)
    error_message = "lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "retention_days" {
  type        = number
  description = "Evidence vault retention period in days."
  default     = 1
}

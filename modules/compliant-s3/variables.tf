variable "bucket_name" {
  description = "Name of the S3 bucket to create"
  type        = string
}

variable "environment" {
  description = "Environment name e.g. dev, prod"
  type        = string
}

variable "kms_deletion_window" {
  description = "Number of days before KMS key is deleted"
  type        = number
  default     = 7
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}
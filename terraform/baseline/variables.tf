variable "resource_suffix" {
  description = "Random suffix from the root module — keeps all resource names consistent."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID from the starter — Lambda security group is placed here."
  type        = string
}

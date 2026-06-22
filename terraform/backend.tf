terraform {
  backend "s3" {
    bucket         = "acme-health-tfstate-7ce7f7e1"
    key            = "acme-health-capstone/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "acme-health-tfstate-lock"
    encrypt        = true
  }
}

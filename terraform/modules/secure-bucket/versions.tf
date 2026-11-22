######################################################################
# secure-bucket — provider requirements
#
# A child module declares the providers and versions it is built against,
# so anyone reusing it gets a clear compatibility contract instead of
# silently inheriting whatever the caller happens to have. No provider
# "aws" block here: configuration (region, credentials) is inherited from
# the root — a reusable module must not pin its own provider config.
######################################################################

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# IAM roles and the reaper for the tls-bench fleet.
# A person applies this stack before infra/bench. No access key is created.

terraform {
  required_version = ">= 1.12"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.66"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.8"
    }
  }
}

variable "account_id" {
  description = "The AWS account ID. Set TF_VAR_account_id in the local environment."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be 12 digits."
  }
}

locals {
  project = "tls-bench"
  region  = "us-west-2"
}

provider "aws" {
  region              = local.region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = {
      Project   = local.project
      ManagedBy = "tofu"
    }
  }
}

module "bench" {
  source = "git::https://github.com/baskingspot/infra//modules/bench-iam?ref=cff88dc4c6f30a2ee314c60f55f49675bb4557f3"

  project           = local.project
  region            = local.region
  account_id        = var.account_id
  instance_families = ["c7i", "c7g"]
}

output "role_arn" {
  description = "ARN of the role for the tls-bench AWS profile"
  value       = module.bench.role_arn
}

output "instance_profile_name" {
  description = "Instance profile required by the base module"
  value       = module.bench.instance_profile_name
}

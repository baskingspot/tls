# Launch templates and the box image for the tls-bench fleet.
# A person applies this stack after infra/iam. The harness reads no state.

terraform {
  required_version = ">= 1.12"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.66"
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
  source = "git::https://github.com/baskingspot/infra//modules/bench-base?ref=653c441d3219bf5d532d5f7e60db367ed2d4a0e6"

  project = local.project

  # Official NixOS 25.11.12484.b6018f87da91 AMIs in us-west-2.
  amis = {
    x86_64 = "ami-0e78db03e0a4e1eb0"
    arm64  = "ami-0b1109b091092c6fe"
  }

  image_version = "1"
  nixos_module  = file("${path.module}/image.nix")

  # The bench-iam module names the profile <project>-box.
  instance_profile_name = "${local.project}-box"
}

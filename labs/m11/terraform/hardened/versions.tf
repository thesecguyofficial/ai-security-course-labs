# M11 lab: TSG Helpdesk on Amazon Bedrock, the HARDENED version.
# Deploy only into your own sandbox account (lesson 0.7). Cost and teardown: README, Step 7.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      project = "tsg-helpdesk"
      lab     = "m11"
    }
  }
}

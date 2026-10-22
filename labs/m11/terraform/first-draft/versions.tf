# M11 lab: TSG Helpdesk on Amazon Bedrock, the FIRST DRAFT ("it works, ship it").
# REVIEW ONLY. Do not deploy this version: it is here so the checker has something real to find.

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
}

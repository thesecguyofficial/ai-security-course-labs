# M12 lab, OPTIONAL cloud path: the reviewed TSG Helpdesk guardrail in YOUR sandbox account (lesson 0.7).
# Cost and teardown: README, Step 8. Nothing here is needed for Steps 1 to 7.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.70.0, < 7.0" # 6.70.0 added aws_bedrock_enforced_guardrail_configuration
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      project = "tsg-helpdesk"
      lab     = "m12"
    }
  }
}

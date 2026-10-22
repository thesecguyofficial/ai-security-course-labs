# Copied into a Terraform folder by `make twin` and deleted afterwards. It lets `terraform plan` run with NO AWS
# account and NO network calls, so the plan can be checked offline. Never use these settings for a real deploy.
provider "aws" {
  access_key                  = "mock_access_key"
  secret_key                  = "mock_secret_key"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}

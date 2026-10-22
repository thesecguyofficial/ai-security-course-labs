# AZ11 optional cloud path: the hardened TSG Helpdesk Foundry setup in YOUR OWN subscription.
# Works with Terraform 1.6+ or OpenTofu 1.6+. Read README Step 8 (cost, budget, teardown) before `make cloud-up`.
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.10"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.12"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      # The vault has purge protection on (Microsoft requires it for customer-managed keys), so Terraform
      # can't purge it on destroy anyway. It stays soft-deleted for soft_delete_retention_days (7 here).
      purge_soft_delete_on_destroy       = false
      purge_soft_deleted_keys_on_destroy = false
    }
    cognitive_account {
      # On destroy, purge the Foundry resource so its name is free again (otherwise it's held, see README).
      purge_soft_delete_on_destroy = true
    }
  }
}

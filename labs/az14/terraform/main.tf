# AZ14 in Terraform: the infrastructure half of lesson 14.8's build, in one file.
#
#   terraform init
#   terraform apply -var name=az14ab1234
#   AZ14_NAME=az14ab1234 bash ../cloud/deploy.sh content   # knowledge files, MCP server, toolbox, hosted agent, its role
#   AZ14_NAME=az14ab1234 bash ../cloud/deploy.sh test      # the same 5 checks as the script
#   AZ14_NAME=az14ab1234 bash ../cloud/deploy.sh down      # removes the content AND everything below
#
# Terraform builds G1 (video 1): a Foundry resource with keys off, its project "helpdesk" with its own identity, the
# model helpdesk-chat, a storage account with shared keys off, a Basic container registry, and the roles. The hosted
# agent, its toolbox and your MCP server need images built from the lab's code and an identity that only exists
# after the agent is created, so deploy.sh content makes them, exactly as the videos do. Destroy it today.

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.10"
    }
    azapi = {
      source  = "Azure/azapi"
      version = "~> 2.0"
    }
  }
}

provider "azurerm" {
  storage_use_azuread = true # the storage account has shared keys off
  features {
    cognitive_account {
      purge_soft_delete_on_destroy = true
    }
  }
}

variable "name" {
  description = "Globally unique, 3 to 20 lowercase letters and digits only, e.g. az14ab1234 (names st<name> and cr<name> too)"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9]{3,20}$", var.name))
    error_message = "Use 3 to 20 lowercase letters and digits, no hyphens."
  }
}

variable "region" {
  description = "A region with hosted agents and gpt-5-mini (our run: swedencentral)"
  type        = string
  default     = "swedencentral"
}

data "azurerm_client_config" "me" {}

resource "azurerm_resource_group" "lab" {
  name     = "rg-${var.name}"
  location = var.region
}

# ---------------------------------------------------------------- Foundry resource, project, model
resource "azurerm_cognitive_account" "foundry" {
  name                       = var.name
  resource_group_name        = azurerm_resource_group.lab.name
  location                   = azurerm_resource_group.lab.location
  kind                       = "AIServices"
  sku_name                   = "S0"
  custom_subdomain_name      = var.name
  project_management_enabled = true
  local_auth_enabled         = false # Entra ID only
  identity {
    type = "SystemAssigned"
  }
}

resource "azapi_resource" "project" {
  type      = "Microsoft.CognitiveServices/accounts/projects@2025-06-01"
  name      = "helpdesk"
  parent_id = azurerm_cognitive_account.foundry.id
  location  = var.region
  identity {
    type = "SystemAssigned"
  }
  body                   = { properties = {} }
  response_export_values = ["identity.principalId"]
}

resource "azurerm_cognitive_deployment" "chat" {
  name                 = "helpdesk-chat"
  cognitive_account_id = azurerm_cognitive_account.foundry.id
  model {
    format  = "OpenAI"
    name    = "gpt-5-mini"
    version = "2025-08-07"
  }
  sku {
    name     = "GlobalStandard"
    capacity = 200 # 1 = 1,000 tokens a minute: an agent gets 429s. Capacity is a rate limit, not a price
  }
}

resource "azurerm_role_assignment" "me_project_manager" { # Microsoft: needed "to deploy a hosted agent"
  scope                = azapi_resource.project.id
  role_definition_name = "Foundry Project Manager"
  principal_id         = data.azurerm_client_config.me.object_id
}

# ---------------------------------------------------------------- the knowledge store
resource "azurerm_storage_account" "kb" {
  name                            = "st${var.name}"
  resource_group_name             = azurerm_resource_group.lab.name
  location                        = azurerm_resource_group.lab.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = false # no anonymous blobs
  shared_access_key_enabled       = false # no account keys, no SAS signed with them: Entra ID only
  min_tls_version                 = "TLS1_2"
}

resource "azurerm_role_assignment" "me_blob" { # you upload the articles
  scope                = azurerm_storage_account.kb.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.me.object_id
}

# ---------------------------------------------------------------- the registry the agent's image lives in
resource "azurerm_container_registry" "cr" {
  name                = "cr${var.name}"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  sku                 = "Basic"
  admin_enabled       = false
}

resource "azurerm_role_assignment" "me_push" {
  scope                = azurerm_container_registry.cr.id
  role_definition_name = "Container Registry Repository Writer"
  principal_id         = data.azurerm_client_config.me.object_id
}

# The PROJECT identity pulls the image, not the agent identity. A registry in LegacyRegistryPermissions mode (our run)
# honors only AcrPull; one in ABAC repository mode needs Container Registry Repository Reader. Both, read-only.
resource "azurerm_role_assignment" "project_pull" {
  for_each             = toset(["AcrPull", "Container Registry Repository Reader"])
  scope                = azurerm_container_registry.cr.id
  role_definition_name = each.value
  principal_id         = azapi_resource.project.output.identity.principalId
  principal_type       = "ServicePrincipal"
}

output "next" {
  value = "Wait 2 minutes (roles), then: AZ14_NAME=${var.name} bash ../cloud/deploy.sh content"
}

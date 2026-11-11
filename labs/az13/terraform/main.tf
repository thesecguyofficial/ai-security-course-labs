# AZ13 in Terraform: the infrastructure half of lesson 13.3's build, in one file.
#
#   terraform init
#   terraform apply -var name=az13-ab1234
#   AZ13_NAME=az13-ab1234 bash ../cloud/deploy.sh content   # groups, index, knowledge base, agent (data plane)
#   AZ13_NAME=az13-ab1234 bash ../cloud/deploy.sh test      # the same 5 checks as the script
#   AZ13_NAME=az13-ab1234 bash ../cloud/deploy.sh down      # removes the content AND everything below
#
# Terraform builds what the portal builds in videos 1 and 2 (G1): Azure AI Search on the Free tier with keys off, a
# Foundry resource with keys off, its project "helpdesk" with its own identity, the model helpdesk-chat, and four
# role assignments. The index, knowledge base and agent are data-plane objects with no Terraform resource: deploy.sh
# content makes them, exactly as the videos do. Cost: a few US cents of tokens. Destroy it today.

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
  features {
    cognitive_account {
      purge_soft_delete_on_destroy = true
    }
  }
}

variable "name" {
  description = "Globally unique, lowercase letters, digits, hyphens, e.g. az13-ab1234 (<name>.services.ai.azure.com, srch-<name>)"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,18}[a-z0-9]$", var.name))
    error_message = "Use 3 to 20 lowercase letters, digits or hyphens."
  }
}

variable "region" {
  description = "A region with agentic retrieval and gpt-5-mini (our run: francecentral; Sweden Central refused a new search service)"
  type        = string
  default     = "francecentral"
}

data "azurerm_client_config" "me" {}

resource "azurerm_resource_group" "lab" {
  name     = "rg-${var.name}"
  location = var.region
}

# ---------------------------------------------------------------- AI Search, Free tier, keys off (video 1)
resource "azurerm_search_service" "search" {
  name                         = "srch-${var.name}"
  resource_group_name          = azurerm_resource_group.lab.name
  location                     = azurerm_resource_group.lab.location
  sku                          = "free" # one free service per subscription
  local_authentication_enabled = false  # Entra ID only: no admin or query keys
}

resource "azurerm_role_assignment" "me_search_service" { # create the index, knowledge source and knowledge base
  scope                = azurerm_search_service.search.id
  role_definition_name = "Search Service Contributor"
  principal_id         = data.azurerm_client_config.me.object_id
}

resource "azurerm_role_assignment" "me_search_data" { # upload the four documents
  scope                = azurerm_search_service.search.id
  role_definition_name = "Search Index Data Contributor"
  principal_id         = data.azurerm_client_config.me.object_id
}

# ---------------------------------------------------------------- Foundry resource, project, model (video 2)
resource "azurerm_cognitive_account" "foundry" {
  name                       = var.name
  resource_group_name        = azurerm_resource_group.lab.name
  location                   = azurerm_resource_group.lab.location
  kind                       = "AIServices"
  sku_name                   = "S0"
  custom_subdomain_name      = var.name
  project_management_enabled = true  # Foundry projects live under this resource
  local_auth_enabled         = false # keys off
  identity {
    type = "SystemAssigned"
  }
}

resource "azapi_resource" "project" { # the project the agent lives in, with its own managed identity
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
    capacity = 200 # a rate limit, not a price: capacity 1 gave 429 in our run
  }
}

resource "azurerm_role_assignment" "me_foundry_user" { # Foundry User (formerly Azure AI User), by ID during the rename
  scope              = azurerm_cognitive_account.foundry.id
  role_definition_id = "/subscriptions/${data.azurerm_client_config.me.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/53ca6127-db72-4b80-b1b0-d745d6d5456d"
  principal_id       = data.azurerm_client_config.me.object_id
}

resource "azurerm_role_assignment" "project_reads_index" { # the project's identity READS the index, nothing more
  scope                = azurerm_search_service.search.id
  role_definition_name = "Search Index Data Reader"
  principal_id         = azapi_resource.project.output.identity.principalId
  principal_type       = "ServicePrincipal"
}

output "next" {
  value = "Wait 2 minutes (roles), then: AZ13_NAME=${var.name} bash ../cloud/deploy.sh content"
}

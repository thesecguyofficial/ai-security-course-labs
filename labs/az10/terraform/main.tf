# AZ10 in Terraform: the LOCKED-DOWN Foundry estate from the guided build (lesson 10.5), in one file.
#
#   terraform init
#   terraform apply -var name=az10-ab1234 [-var budget_email=you@example.com]
#   AZ10_NAME=az10-ab1234 bash ../cloud/deploy.sh test     # the same 5 checks as the script
#   terraform destroy -var name=az10-ab1234
#
# Works with Terraform 1.6+ or OpenTofu 1.6+ (Azure Cloud Shell has Terraform). Signs in with your Azure CLI login.
# Builds the "after" state only: keys off, Foundry User on one resource (no Contributor), logs on, approved models on
# Deny, key access on Deny, a US$5 budget alarm. Cost: a few US cents. Destroy it today.

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.10"
    }
  }
}

provider "azurerm" {
  features {
    cognitive_account {
      purge_soft_delete_on_destroy = true # frees the name now, not in 48 hours
    }
  }
}

variable "name" {
  description = "Globally unique, lowercase letters, digits, hyphens, for example az10-ab1234"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,22}[a-z0-9]$", var.name))
    error_message = "Use 3 to 24 lowercase letters, digits or hyphens."
  }
}

variable "region" {
  description = "One region for everything"
  type        = string
  default     = "swedencentral"
}

variable "deployment_sku" {
  description = "DataZoneStandard keeps prompts in the EU data zone. Our free subscription had 0 quota for it, so the default is GlobalStandard: change it if your quota allows"
  type        = string
  default     = "GlobalStandard"
}

variable "budget_email" {
  description = "Where the budget alert goes. Empty = no budget"
  type        = string
  default     = ""
}

data "azurerm_subscription" "current" {}
data "azurerm_client_config" "current" {}

locals {
  foundry_user = "${data.azurerm_subscription.current.id}/providers/Microsoft.Authorization/roleDefinitions/53ca6127-db72-4b80-b1b0-d745d6d5456d"
  model        = "gpt-5-mini"
  model_ver    = "2025-08-07"
}

resource "azurerm_resource_group" "lab" {
  name     = "rg-${var.name}"
  location = var.region
}

# ---------------------------------------------------------------- 10.5: the budget alarm comes first
resource "azurerm_consumption_budget_resource_group" "lab" {
  count             = var.budget_email == "" ? 0 : 1
  name              = "az10-budget"
  resource_group_id = azurerm_resource_group.lab.id
  amount            = 5
  time_grain        = "Monthly"
  time_period {
    start_date = formatdate("YYYY-MM-01'T'00:00:00Z", timestamp())
  }
  notification {
    enabled        = true
    operator       = "GreaterThan"
    threshold      = 50
    threshold_type = "Actual"
    contact_emails = [var.budget_email]
  }
  notification {
    enabled        = true
    operator       = "GreaterThan"
    threshold      = 100
    threshold_type = "Forecasted"
    contact_emails = [var.budget_email]
  }
  lifecycle {
    ignore_changes = [time_period] # timestamp() changes every run
  }
}

# ---------------------------------------------------------------- 10.4: the Foundry resource, keys off
resource "azurerm_cognitive_account" "foundry" {
  name                       = var.name
  location                   = azurerm_resource_group.lab.location
  resource_group_name        = azurerm_resource_group.lab.name
  kind                       = "AIServices"
  sku_name                   = "S0"
  custom_subdomain_name      = var.name # needed for Entra ID tokens
  local_auth_enabled         = false    # provider default is true: keys on
  project_management_enabled = true
  identity {
    type = "SystemAssigned"
  }
  tags = {
    deployment-type-reason = var.deployment_sku == "GlobalStandard" ? "DataZoneStandard quota 0 in this subscription" : "EU data zone"
  }
  depends_on = [azurerm_resource_group_policy_assignment.deny_keys] # the guardrail exists before the resource
}

# ---------------------------------------------------------------- 10.2: the deployment type, on purpose
resource "azurerm_cognitive_deployment" "chat" {
  name                 = "chat"
  cognitive_account_id = azurerm_cognitive_account.foundry.id
  model {
    format  = "OpenAI"
    name    = local.model
    version = local.model_ver
  }
  sku {
    name     = var.deployment_sku
    capacity = 1 # 1,000 tokens per minute: a runaway script can't spend much
  }
  depends_on = [azurerm_resource_group_policy_assignment.approved_models]
}

# ---------------------------------------------------------------- 10.3: the app's identity, data role only
resource "azurerm_user_assigned_identity" "app" {
  name                = "id-az10-app"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
}

resource "azurerm_role_assignment" "app" { # Foundry User on ONE resource. Never Contributor: it can list keys
  scope              = azurerm_cognitive_account.foundry.id
  role_definition_id = local.foundry_user
  principal_id       = azurerm_user_assigned_identity.app.principal_id
}

resource "azurerm_role_assignment" "me" { # you, so the test can call the model. Owner alone has no data actions
  scope              = azurerm_cognitive_account.foundry.id
  role_definition_id = local.foundry_user
  principal_id       = data.azurerm_client_config.current.object_id
}

# ---------------------------------------------------------------- 10.5: logs on
resource "azurerm_log_analytics_workspace" "lab" {
  name                = "law-${var.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

resource "azurerm_monitor_diagnostic_setting" "foundry" {
  name                       = "to-law"
  target_resource_id         = azurerm_cognitive_account.foundry.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id
  enabled_log {
    category = "Audit"
  }
  enabled_log {
    category = "RequestResponse"
  }
  enabled_log {
    category = "Trace"
  }
}

# ---------------------------------------------------------------- 10.3 and 10.4: the two guardrails, on Deny
resource "azurerm_resource_group_policy_assignment" "approved_models" {
  name                 = "az10-approved-models"
  resource_group_id    = azurerm_resource_group.lab.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/aafe3651-cb78-4f68-9f81-e7e41509110f"
  parameters = jsonencode({
    effect            = { value = "Deny" }
    allowedPublishers = { value = [] } # a publisher here would approve EVERY model it publishes (lesson 10.3)
    allowedAssetIds   = { value = ["azureml://registries/azure-openai/models/${local.model}/"] }
  })
}

resource "azurerm_resource_group_policy_assignment" "deny_keys" {
  name                 = "az10-deny-key-access"
  resource_group_id    = azurerm_resource_group.lab.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/71ef260a-8f18-47b7-abcb-62d0673d94dc"
  parameters           = jsonencode({ effect = { value = "Deny" } })
}

output "name" {
  value = var.name
}

output "endpoint" {
  value = azurerm_cognitive_account.foundry.endpoint
}

output "next" {
  value = "Wait 15 minutes for the policies, then: AZ10_NAME=${var.name} AZ10_REGION=${var.region} bash ../cloud/deploy.sh test"
}

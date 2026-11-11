# AZ16 in Terraform: lesson 16.6's logged, Defender-watched Foundry model, in one file.
#
#   terraform init
#   terraform apply -var name=az16-ab1234
#   AZ16_NAME=az16-ab1234 bash ../cloud/deploy.sh test     # the same 5 checks as the script
#   terraform destroy -var name=az16-ab1234                # also sets Defender for AI services back to Free
#
# What it builds (Parts A, B and E of GUIDED-BUILD.md):
#   - a Foundry resource with keys off and gpt-5-mini as "chat", Foundry User for you
#   - Log Analytics law-<name>, with Audit, RequestResponse and Trace from the resource
#   - Defender for AI services (subscription-wide) with user prompt evidence
#   - continuous export of security alerts of EVERY severity to the workspace
#   - the subscription's Activity log to the workspace, and an alert rule on exported jailbreak alerts
# Defender for AI services is subscription-wide: if your subscription already uses it, import it instead of letting
# destroy turn it off. Cost: a few US cents of tokens, plus Defender's per-token price after any free trial.

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
      purge_soft_delete_on_destroy = true
    }
  }
}

variable "name" {
  description = "Globally unique, 3 to 20 lowercase letters, digits, hyphens, e.g. az16-ab1234"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,18}[a-z0-9]$", var.name))
    error_message = "Use 3 to 20 lowercase letters, digits or hyphens."
  }
}

variable "region" {
  type    = string
  default = "eastus"
}

data "azurerm_client_config" "me" {}
data "azurerm_subscription" "current" {}

resource "azurerm_resource_group" "lab" {
  name     = "rg-${var.name}"
  location = var.region
}

# ---------------------------------------------------------------- Part A: a Foundry resource that logs (16.1)
resource "azurerm_cognitive_account" "foundry" {
  name                       = var.name
  resource_group_name        = azurerm_resource_group.lab.name
  location                   = azurerm_resource_group.lab.location
  kind                       = "AIServices"
  sku_name                   = "S0"
  custom_subdomain_name      = var.name
  project_management_enabled = true
  local_auth_enabled         = false # keys off: our run left them on, and Part E's inventory flagged it
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_cognitive_deployment" "chat" {
  name                 = "chat"
  cognitive_account_id = azurerm_cognitive_account.foundry.id
  model {
    format  = "OpenAI"
    name    = "gpt-5-mini"
    version = "2025-08-07"
  }
  sku {
    name     = "GlobalStandard"
    capacity = 100 # 1 gave empty answers and 429s in our run; Global Standard bills per token, not per capacity
  }
}

resource "azurerm_role_assignment" "me_foundry_user" { # Foundry User, by ID during the rename
  scope              = azurerm_cognitive_account.foundry.id
  role_definition_id = "${data.azurerm_subscription.current.id}/providers/Microsoft.Authorization/roleDefinitions/53ca6127-db72-4b80-b1b0-d745d6d5456d"
  principal_id       = data.azurerm_client_config.me.object_id
}

resource "azurerm_log_analytics_workspace" "law" {
  name                = "law-${var.name}"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

resource "azurerm_monitor_diagnostic_setting" "foundry" { # prompts and completions are NOT in these logs (16.1)
  name                       = "to-law"
  target_resource_id         = azurerm_cognitive_account.foundry.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id
  dynamic "enabled_log" {
    for_each = ["Audit", "RequestResponse", "Trace"]
    content {
      category = enabled_log.value
    }
  }
}

# ---------------------------------------------------------------- Part B: Defender for AI services (16.2)
resource "azurerm_security_center_subscription_pricing" "ai" {
  resource_type = "AI"
  tier          = "Standard"
  extension {
    name = "AIPromptEvidence" # "Exposes the prompts passed between the user and the AI model as alert evidence"
  }
}

resource "azurerm_security_center_automation" "export" { # alerts live in Defender until you export them
  name                = "export-az16"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  scopes              = [data.azurerm_subscription.current.id]
  action {
    type        = "loganalytics"
    resource_id = azurerm_log_analytics_workspace.law.id
  }
  source {
    event_source = "Alerts" # no rule set: EVERY severity, not just High (the trap in lesson 16.2)
  }
}

resource "azurerm_monitor_diagnostic_setting" "activity" { # the subscription's Activity log (D03 needs it; free to ingest)
  name                       = "to-law-az16"
  target_resource_id         = data.azurerm_subscription.current.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id
  dynamic "enabled_log" {
    for_each = ["Administrative", "Security", "Policy"]
    content {
      category = enabled_log.value
    }
  }
}

# ---------------------------------------------------------------- Part E: an alert on the exported alert (16.3)
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "jailbreak" {
  name                 = "az16-jailbreak-alert"
  resource_group_name  = azurerm_resource_group.lab.name
  location             = azurerm_resource_group.lab.location
  scopes               = [azurerm_log_analytics_workspace.law.id]
  severity             = 3
  evaluation_frequency = "PT5M"
  window_duration      = "PT15M"
  criteria {
    query                   = "SecurityAlert | where AlertName has 'Jailbreak'"
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"
  }
}

output "next" {
  value = "Wait a few minutes (role), then: AZ16_NAME=${var.name} bash ../cloud/deploy.sh test"
}

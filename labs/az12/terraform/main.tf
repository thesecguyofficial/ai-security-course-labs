# AZ12 in Terraform: the finished guardrail build from lesson 12.5, in one file.
#
#   terraform init
#   terraform apply -var name=az12-ab1234
#   AZ12_NAME=az12-ab1234 bash ../cloud/deploy.sh test     # the same 5 checks as the script
#   terraform destroy -var name=az12-ab1234
#
# What it builds (all keys off, Entra ID only):
#   - a Content Safety resource <name> on the FREE tier (F0), and Cognitive Services User for you on it only (12.2, 12.5 G1)
#   - a Foundry resource with helpdesk-chat (gpt-5-mini), and Cognitive Services OpenAI User for you (12.5 G1)
#   - the contoso-codenames blocklist with one term, NIGHTJAR (12.3, G3)
#   - the contoso-helpdesk-v2 guardrail from fixes/rai-policies.json, assigned to helpdesk-chat (12.4, G4)
# Two controls of that guardrail are set in the portal in the videos (personal information and spotlighting); the
# provider has no field for them, so this build leaves them to the portal too. Cost: pennies (F0 is free; you pay
# tokens). Destroy it today.

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
      purge_soft_delete_on_destroy = true # frees both names now, not in 48 hours
    }
  }
}

variable "name" {
  description = "Globally unique prefix, lowercase letters, digits, hyphens, e.g. az12-ab1234 (the Content Safety resource; Foundry is <name>-fdy)"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,18}[a-z0-9]$", var.name))
    error_message = "Use 3 to 20 lowercase letters, digits or hyphens."
  }
}

variable "region" {
  description = "A region where Prompt Shields is available (our run: eastus)"
  type        = string
  default     = "eastus"
}

data "azurerm_client_config" "current" {}

locals {
  policy      = jsondecode(file("${path.module}/../fixes/rai-policies.json"))["policies"]["contoso-helpdesk-v2"]["properties"]
  portal_only = ["PII", "Indirect Attack Spotlighting"] # set in the portal (README Step 9, G3)
  filters     = [for f in local.policy.contentFilters : f if !contains(local.portal_only, f.name)]
}

resource "azurerm_resource_group" "lab" {
  name     = "rg-${var.name}"
  location = var.region
}

# ---------------------------------------------------------------- G1: Content Safety, free tier, keys off
resource "azurerm_cognitive_account" "cs" {
  name                  = var.name
  location              = azurerm_resource_group.lab.location
  resource_group_name   = azurerm_resource_group.lab.name
  kind                  = "ContentSafety"
  sku_name              = "F0"
  custom_subdomain_name = var.name # needed for Entra ID tokens
  local_auth_enabled    = false            # provider default is true: keys on
}

resource "azurerm_role_assignment" "me_cs" { # call the classifiers; can't change the resource
  scope                = azurerm_cognitive_account.cs.id
  role_definition_name = "Cognitive Services User"
  principal_id         = data.azurerm_client_config.current.object_id
}

# ---------------------------------------------------------------- G1: the model the guardrail protects
resource "azurerm_cognitive_account" "fdy" {
  name                  = "${var.name}-fdy"
  location              = azurerm_resource_group.lab.location
  resource_group_name   = azurerm_resource_group.lab.name
  kind                  = "AIServices"
  sku_name              = "S0"
  custom_subdomain_name = "${var.name}-fdy"
  local_auth_enabled    = false
}

resource "azurerm_role_assignment" "me_fdy" { # call the deployment with a token; can't read the keys
  scope                = azurerm_cognitive_account.fdy.id
  role_definition_name = "Cognitive Services OpenAI User"
  principal_id         = data.azurerm_client_config.current.object_id
}

# ---------------------------------------------------------------- G3: the blocklist
resource "azurerm_cognitive_account_rai_blocklist" "codenames" {
  name                 = "contoso-codenames"
  cognitive_account_id = azurerm_cognitive_account.fdy.id
  description          = "Contoso internal code names (lab AZ12)"
}

# One term, added with the blocklist's own batch action (POST addRaiBlocklistItems). Not azapi_resource on the item:
# its existence check (a GET before create) answers 400, not 404, and azapi stops there. The term goes when the
# blocklist does. Microsoft: new terms can take about 5 minutes to take effect.
resource "azapi_resource_action" "nightjar" {
  type        = "Microsoft.CognitiveServices/accounts/raiBlocklists@2024-10-01"
  resource_id = azurerm_cognitive_account_rai_blocklist.codenames.id
  action      = "addRaiBlocklistItems"
  method      = "POST"
  body        = [{ name = "nightjar", properties = { pattern = "NIGHTJAR", isRegex = false } }]
}

# ---------------------------------------------------------------- G4: the guardrail, from fixes/rai-policies.json
# The provider's own rai_policy resource has no field for custom blocklists, so the guardrail is written with azapi,
# in the same body cloud.sh sends (ARM schema 2024-10-01: contentFilters + customBlocklists).
resource "azapi_resource" "helpdesk_v2" {
  type      = "Microsoft.CognitiveServices/accounts/raiPolicies@2024-10-01"
  name      = "contoso-helpdesk-v2"
  parent_id = azurerm_cognitive_account.fdy.id
  body = {
    properties = {
      basePolicyName = local.policy.basePolicyName
      mode           = local.policy.mode
      contentFilters = [for f in local.filters : { for k, v in f : k => v if !startswith(k, "x-") }]
      customBlocklists = [{
        blocklistName = azurerm_cognitive_account_rai_blocklist.codenames.name
        blocking      = true
        source        = "Completion"
      }]
    }
  }
  depends_on = [azapi_resource_action.nightjar]
}

resource "azurerm_cognitive_deployment" "chat" {
  name                 = "helpdesk-chat"
  cognitive_account_id = azurerm_cognitive_account.fdy.id
  rai_policy_name      = azapi_resource.helpdesk_v2.name # starts on Microsoft.DefaultV2 otherwise
  model {
    format  = "OpenAI"
    name    = "gpt-5-mini"
    version = "2025-08-07"
  }
  sku {
    name     = "GlobalStandard"
    capacity = 50
  }
}

output "next" {
  value = "Wait 5 minutes (roles and the blocklist term), then: AZ12_NAME=${var.name} bash deploy.sh test"
}

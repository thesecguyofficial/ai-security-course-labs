# AZ11: TSG Helpdesk on Microsoft Foundry, hardened. Every control below is checked by `make test`
# (offline, on fixes/plan.json) and by `make cloud-check` (on YOUR real plan). Lesson numbers in brackets.

data "azurerm_client_config" "current" {}
data "azurerm_subscription" "current" {}

locals {
  # Microsoft's DNS zone table for a Foundry account private endpoint (lesson 11.2): all three, or one hostname breaks.
  foundry_zones = toset([
    "privatelink.cognitiveservices.azure.com",
    "privatelink.openai.azure.com",
    "privatelink.services.ai.azure.com",
  ])
  # Foundry User, by ID: Microsoft says to use the role definition ID (GUID), not the name, while the
  # Azure AI -> Foundry role rename rolls out.
  foundry_user_role_id = "${data.azurerm_subscription.current.id}/providers/Microsoft.Authorization/roleDefinitions/53ca6127-db72-4b80-b1b0-d745d6d5456d"
}

resource "azurerm_resource_group" "lab" {
  name     = "rg-${var.name}"
  location = var.location
}

# ------------------------------------------------------------------ network (11.2)
resource "azurerm_virtual_network" "lab" {
  name                = "vnet-helpdesk"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  address_space       = ["10.20.0.0/16"]
}

resource "azurerm_subnet" "app" { # reserved for the helpdesk app (not deployed by this lab)
  name                 = "snet-app"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.20.1.0/24"]
}

resource "azurerm_subnet" "pe" {
  name                 = "snet-pe"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.20.2.0/24"]
}

resource "azurerm_subnet" "jump" { # the test VM: no public IP, no internet route needed
  name                            = "snet-jump"
  resource_group_name             = azurerm_resource_group.lab.name
  virtual_network_name            = azurerm_virtual_network.lab.name
  address_prefixes                = ["10.20.3.0/24"]
  default_outbound_access_enabled = false
}

# ------------------------------------------------------------------ identities (11.1): one per job
resource "azurerm_user_assigned_identity" "cmk" { # used ONLY by the Foundry resource to reach its key
  name                = "id-${var.name}-cmk"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
}

resource "azurerm_user_assigned_identity" "helpdesk_app" { # for the helpdesk web app, and nothing else
  name                = "id-helpdesk-app"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
}

resource "azurerm_user_assigned_identity" "jump" { # for the test VM
  name                = "id-jump"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
}

# ------------------------------------------------------------------ customer-managed key (11.3)
resource "azurerm_key_vault" "cmk" {
  name                          = "kv-${var.name}"
  location                      = azurerm_resource_group.lab.location # same region as Foundry
  resource_group_name           = azurerm_resource_group.lab.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  rbac_authorization_enabled    = true # Azure RBAC, not access policies
  purge_protection_enabled      = true # required for CMK
  soft_delete_retention_days    = 7    # the minimum: the vault name is held 7 days after `make cloud-down`
  public_network_access_enabled = true
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices" # "Allow trusted Microsoft services"
    ip_rules       = [var.my_ip]     # only your laptop, to create the key
  }
}

resource "azurerm_role_assignment" "me_crypto_officer" { # you, to create the key
  scope                = azurerm_key_vault.cmk.id
  role_definition_name = "Key Vault Crypto Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "cmk_crypto_user" { # the Foundry resource's key identity: use the key, nothing else
  scope                = azurerm_key_vault.cmk.id
  role_definition_name = "Key Vault Crypto User"
  principal_id         = azurerm_user_assigned_identity.cmk.principal_id
}

resource "time_sleep" "rbac" { # role assignments "can take up to 5 minutes to propagate"
  depends_on      = [azurerm_role_assignment.me_crypto_officer, azurerm_role_assignment.cmk_crypto_user]
  create_duration = "120s"
}

resource "azurerm_key_vault_key" "cmk" {
  name         = "cmk-foundry"
  key_vault_id = azurerm_key_vault.cmk.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
  depends_on   = [time_sleep.rbac]
}

# ------------------------------------------------------------------ the Foundry resource (11.1 to 11.3)
resource "azurerm_cognitive_account" "foundry" {
  name                          = var.name
  location                      = azurerm_resource_group.lab.location
  resource_group_name           = azurerm_resource_group.lab.name
  kind                          = "AIServices"
  sku_name                      = "S0"
  custom_subdomain_name         = var.name # needed for Entra ID and for a private endpoint
  local_auth_enabled            = false    # provider default is true: keys on (lesson 10.4)
  public_network_access_enabled = false    # provider default is true: open to the internet (11.2)

  network_acls {
    default_action = "Deny"
    bypass         = "None"
  }

  identity {
    type         = "SystemAssigned, UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.cmk.id]
  }

  customer_managed_key {
    key_vault_key_id   = azurerm_key_vault_key.cmk.id
    identity_client_id = azurerm_user_assigned_identity.cmk.client_id
  }

  # Grant the identity access to the key BEFORE CMK is enabled, or the operation fails (Microsoft, 11.3).
  depends_on = [time_sleep.rbac]
}

resource "azurerm_cognitive_deployment" "chat" {
  name                 = "helpdesk-chat"
  cognitive_account_id = azurerm_cognitive_account.foundry.id
  model {
    format  = "OpenAI"
    name    = var.model_name
    version = var.model_version
  }
  sku {
    name     = var.deployment_sku # DataZoneStandard: processed only inside the data zone (11.5)
    capacity = 1                  # 1,000 tokens per minute
  }
}

# ------------------------------------------------------------------ private endpoint + DNS (11.2)
resource "azurerm_private_dns_zone" "foundry" {
  for_each            = local.foundry_zones
  name                = each.value
  resource_group_name = azurerm_resource_group.lab.name
}

resource "azurerm_private_dns_zone_virtual_network_link" "foundry" {
  for_each            = local.foundry_zones
  name                = "link-${replace(each.value, ".", "-")}"
  private_dns_zone_id = azurerm_private_dns_zone.foundry[each.value].id
  virtual_network_id  = azurerm_virtual_network.lab.id
}

resource "azurerm_private_endpoint" "foundry" {
  name                = "pe-${var.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  subnet_id           = azurerm_subnet.pe.id

  private_service_connection {
    name                           = "psc-${var.name}"
    private_connection_resource_id = azurerm_cognitive_account.foundry.id
    subresource_names              = ["account"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "foundry"
    private_dns_zone_ids = [for z in azurerm_private_dns_zone.foundry : z.id]
  }
}

# ------------------------------------------------------------------ logging (11.4)
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

resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  name                       = "to-law"
  target_resource_id         = azurerm_key_vault.cmk.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id

  enabled_log {
    category = "AuditEvent"
  }
}

# ------------------------------------------------------------------ RBAC for callers (11.1)
resource "azurerm_role_assignment" "helpdesk_app" {
  scope              = azurerm_cognitive_account.foundry.id # ONE resource, not the resource group
  role_definition_id = local.foundry_user_role_id
  principal_id       = azurerm_user_assigned_identity.helpdesk_app.principal_id
}

resource "azurerm_role_assignment" "jump" {
  scope              = azurerm_cognitive_account.foundry.id
  role_definition_id = local.foundry_user_role_id
  principal_id       = azurerm_user_assigned_identity.jump.principal_id
}

# ------------------------------------------------------------------ test VM inside the VNet (no public IP)
resource "tls_private_key" "jump" { # never used: the VM has no public IP and we use Run Command instead of SSH
  algorithm = "ED25519"
}

resource "azurerm_network_interface" "jump" {
  name                = "nic-jump"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.jump.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "jump" {
  name                  = "vm-jump"
  location              = azurerm_resource_group.lab.location
  resource_group_name   = azurerm_resource_group.lab.name
  size                  = var.jump_vm_size
  admin_username        = "labadmin"
  network_interface_ids = [azurerm_network_interface.jump.id]

  admin_ssh_key {
    username   = "labadmin"
    public_key = tls_private_key.jump.public_key_openssh
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.jump.id]
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }
}

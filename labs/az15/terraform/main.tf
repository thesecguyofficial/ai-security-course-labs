# AZ15 in Terraform: the infrastructure half of lesson 15.5's build, in one file.
#
#   terraform init
#   terraform apply -var name=az15-ab1234
#   AZ15_NAME=az15-ab1234 bash ../cloud/deploy.sh content   # timer, endpoint, deployment, scorer role, logs
#   AZ15_NAME=az15-ab1234 bash ../cloud/deploy.sh test      # the same 5 checks (within 60 minutes of content)
#   AZ15_NAME=az15-ab1234 bash ../cloud/deploy.sh down      # removes the endpoint AND everything below
#
# Terraform builds Part A and the egress review: a Machine Learning workspace whose managed network allows approved
# outbound only, the four FQDN rules our model's container needed, a client network with a private endpoint to the
# workspace and its DNS, a client VM with no public IP and its own identity, and a Log Analytics workspace. The online
# endpoint and its deployment are made by deploy.sh content (the Azure ML CLI, as in the videos), timer first.
# COST: the client VM and the managed firewall (the FQDN rules bring it in) bill by the hour. Destroy it today.

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
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
    machine_learning {
      purge_soft_deleted_workspace_on_destroy = true
    }
  }
}

variable "name" {
  description = "3 to 24 lowercase letters, digits, hyphens, starting with a letter, e.g. az15-ab1234 (the workspace name)"
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,23}$", var.name))
    error_message = "Use 3 to 24 lowercase letters, digits or hyphens, starting with a letter."
  }
}

variable "region" {
  type    = string
  default = "eastus"
}

variable "client_vm_size" {
  description = "Every B size was restricted in our East US run; Standard_D2as_v4 worked"
  type        = string
  default     = "Standard_D2as_v4"
}

data "azurerm_client_config" "me" {}

locals {
  short = substr(replace(var.name, "-", ""), 0, 18) # storage and Key Vault names: no hyphens, length limits
}

resource "azurerm_resource_group" "lab" {
  name     = "rg-${var.name}"
  location = var.region
  tags     = { purpose = "tsg-az15-lab" }
}

# ---------------------------------------------------------------- the workspace and what it needs (A2, A3)
resource "azurerm_storage_account" "ws" {
  name                            = "st${local.short}"
  resource_group_name             = azurerm_resource_group.lab.name
  location                        = azurerm_resource_group.lab.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = false
  min_tls_version                 = "TLS1_2"
}

resource "azurerm_key_vault" "ws" {
  name                      = "kv${local.short}"
  resource_group_name       = azurerm_resource_group.lab.name
  location                  = azurerm_resource_group.lab.location
  tenant_id                  = data.azurerm_client_config.me.tenant_id
  sku_name                   = "standard"
  rbac_authorization_enabled = true
}

resource "azurerm_log_analytics_workspace" "law" { # A6: the endpoint's logs land here (name as cloud.sh expects)
  name                = "log-tsg-az15"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

resource "azurerm_application_insights" "ws" {
  name                = "appi-${var.name}"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  workspace_id        = azurerm_log_analytics_workspace.law.id
  application_type    = "web"
}

resource "azurerm_machine_learning_workspace" "ws" {
  name                    = var.name
  resource_group_name     = azurerm_resource_group.lab.name
  location                = azurerm_resource_group.lab.location
  storage_account_id      = azurerm_storage_account.ws.id
  key_vault_id            = azurerm_key_vault.ws.id
  application_insights_id = azurerm_application_insights.ws.id
  identity {
    type = "SystemAssigned"
  }
  managed_network {
    isolation_mode = "AllowOnlyApprovedOutbound" # nothing leaves unless a rule names it
  }
}

# The egress review from lesson 15.2, done for real: the curated model's container installs conda packages when it
# starts. Four named hosts, nothing else. The first FQDN rule brings in the managed Azure Firewall (hourly).
resource "azurerm_machine_learning_workspace_network_outbound_rule_fqdn" "allow" {
  for_each         = toset(["conda.anaconda.org", "repo.anaconda.com", "pypi.org", "files.pythonhosted.org"])
  name             = "allow-${replace(each.value, ".", "-")}"
  workspace_id     = azurerm_machine_learning_workspace.ws.id
  destination_fqdn = each.value
}

# ---------------------------------------------------------------- the client network and its private door (A4)
resource "azurerm_virtual_network" "client" {
  name                = "vnet-tsg-az15"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  address_space       = ["10.15.0.0/16"]
}

resource "azurerm_subnet" "clients" {
  name                 = "clients"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.client.name
  address_prefixes     = ["10.15.1.0/24"]
}

resource "azurerm_private_dns_zone" "z" {
  for_each            = toset(["privatelink.api.azureml.ms", "privatelink.notebooks.azure.net"])
  name                = each.value
  resource_group_name = azurerm_resource_group.lab.name
}

resource "azurerm_private_dns_zone_virtual_network_link" "z" {
  for_each            = azurerm_private_dns_zone.z
  name                = "link-vnet-tsg-az15"
  private_dns_zone_id = each.value.id
  virtual_network_id  = azurerm_virtual_network.client.id
}

resource "azurerm_private_endpoint" "ws" {
  name                = "pe-${var.name}"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  subnet_id           = azurerm_subnet.clients.id
  private_service_connection {
    name                           = "pe-${var.name}"
    private_connection_resource_id = azurerm_machine_learning_workspace.ws.id
    subresource_names              = ["amlworkspace"]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = "default"
    private_dns_zone_ids = [for z in azurerm_private_dns_zone.z : z.id]
  }
}

# ---------------------------------------------------------------- the client VM: plays the Helpdesk app (A5)
resource "tls_private_key" "vm" { # nobody signs in to it: run-command does the work
  algorithm = "ED25519"
}

resource "azurerm_network_interface" "vm" {
  name                = "nic-vm-tsg-az15-client"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.clients.id
    private_ip_address_allocation = "Dynamic" # and no public IP
  }
}

resource "azurerm_linux_virtual_machine" "client" {
  name                  = "vm-tsg-az15-client" # the name cloud.sh ask uses
  resource_group_name   = azurerm_resource_group.lab.name
  location              = azurerm_resource_group.lab.location
  size                  = var.client_vm_size
  admin_username        = "labadmin"
  network_interface_ids = [azurerm_network_interface.vm.id]
  admin_ssh_key {
    username   = "labadmin"
    public_key = tls_private_key.vm.public_key_openssh
  }
  identity {
    type = "SystemAssigned" # it gets one custom role on the endpoint in deploy.sh content
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }
}

output "next" {
  value = "AZ15_NAME=${var.name} bash ../cloud/deploy.sh content   (then test within 60 minutes)"
}

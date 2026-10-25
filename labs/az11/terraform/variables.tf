variable "name" {
  description = "Globally unique name for the Foundry resource and its subdomain, e.g. az11-ab1234 (lowercase letters, digits, hyphens). Also used for the Key Vault name (kv-<name>, max 24 characters)."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.name))
    error_message = "Use 3-21 lowercase letters, digits or hyphens, starting with a letter (the Key Vault name kv-<name> must fit in 24 characters)."
  }
}

variable "location" {
  description = "Azure region for EVERYTHING (Microsoft: deploy the key store and the Foundry resource in the same region)."
  type        = string
  default     = "swedencentral"
}

variable "my_ip" {
  description = "Your laptop's public IPv4 address. Only this address may reach the Key Vault data plane (to create the key)."
  type        = string
}

variable "model_name" {
  description = "Model to deploy. Pick one your region offers as a Data Zone deployment (README Step 8)."
  type        = string
  default     = "gpt-5-mini" # GA; gpt-4.1-mini is Deprecated, "No longer available to new customers"
}

variable "model_version" {
  type    = string
  default = "2025-08-07"
}

variable "deployment_sku" {
  description = "Deployment type. Contoso's residency standard allows DataZoneStandard or Standard only (lesson 11.5)."
  type        = string
  default     = "DataZoneStandard"
  validation {
    condition     = contains(["DataZoneStandard", "Standard"], var.deployment_sku)
    error_message = "Contoso's standard: DataZoneStandard or Standard only. Global types may process prompts in any Azure region."
  }
}

variable "jump_vm_size" {
  description = "Size of the small test VM inside the VNet. Change it if your region has no capacity for this size."
  type        = string
  default     = "Standard_B1s"
}

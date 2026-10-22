output "foundry_name" {
  value = azurerm_cognitive_account.foundry.name
}

output "resource_group" {
  value = azurerm_resource_group.lab.name
}

output "hostnames" {
  description = "The three public names of the Foundry resource. Inside the VNet they must resolve to the private endpoint."
  value = [
    "${var.name}.openai.azure.com",
    "${var.name}.cognitiveservices.azure.com",
    "${var.name}.services.ai.azure.com",
  ]
}

output "deployment_name" {
  value = azurerm_cognitive_deployment.chat.name
}

output "jump_vm_name" {
  value = azurerm_linux_virtual_machine.jump.name
}

output "jump_identity_client_id" {
  value = azurerm_user_assigned_identity.jump.client_id
}

output "log_analytics_workspace_id" {
  value = azurerm_log_analytics_workspace.lab.workspace_id
}

output "key_vault_name" {
  value = azurerm_key_vault.cmk.name
}

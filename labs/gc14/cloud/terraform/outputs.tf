output "gateway" {
  description = "Pass to cloud/agent/deploy.py --gateway."
  value       = "projects/${var.project_id}/locations/${var.region}/agentGateways/${google_network_services_agent_gateway.egress.name}"
}

output "staging_bucket" {
  description = "Pass to cloud/agent/deploy.py --staging-bucket."
  value       = "gs://${google_storage_bucket.staging.name}"
}

output "enforcement" {
  value = var.enforcement
}

output "all_agents_principal_set" {
  description = "Every Agent Runtime agent in this project (used only by Step 7's deliberate mistake)."
  value       = local.all_ours
}

variable "project_id" {
  description = "Your sandbox project ID (never a work project)."
  type        = string
}

variable "region" {
  description = "Region for the gateway, the registry and the agent. The agent must be in the gateway's region."
  type        = string
  default     = "us-central1"
}

variable "bigquery_location" {
  description = "Location of the two BigQuery datasets."
  type        = string
  default     = "US"
}

variable "gateway_name" {
  type    = string
  default = "tsg-gc14-egress"
}

variable "enforcement" {
  description = "DRY_RUN: IAP logs what it would deny and blocks nothing. ENFORCE: denials are blocked."
  type        = string
  default     = "DRY_RUN"
  validation {
    condition     = contains(["DRY_RUN", "ENFORCE"], var.enforcement)
    error_message = "enforcement must be DRY_RUN or ENFORCE."
  }
}

variable "agent_principal" {
  description = "The deployed agent's effectiveIdentity (principal://...), printed by cloud/agent/deploy.py. Empty until Step 4."
  type        = string
  default     = ""
  validation {
    condition     = var.agent_principal == "" || startswith(var.agent_principal, "principal://agents.global.")
    error_message = "agent_principal must be the agent's principal://agents.global... identity."
  }
}

variable "deny_execute_sql" {
  description = "Step 4: the one DENY rule (execute_sql is the BigQuery MCP tool that isn't read-only)."
  type        = bool
  default     = true
}

variable "memory_data_access_logs" {
  description = "Step 6: Data Access audit logs (DATA_READ, DATA_WRITE) for aiplatform.googleapis.com."
  type        = bool
  default     = true
}

variable "grant_all_agents_project_data" {
  description = "Step 7 (the one-setting change): BigQuery Data Viewer on the WHOLE project for every agent in it."
  type        = bool
  default     = false
}

variable "google_endpoints" {
  description = "Google API hosts the agent needs, registered as Agent Registry endpoints (Google's routing page; matching is exact)."
  type        = list(string)
  default = [
    "agentregistry.googleapis.com",
    "logging.googleapis.com", "logging.mtls.googleapis.com",
    "telemetry.googleapis.com", "telemetry.mtls.googleapis.com",
    "cloudtrace.googleapis.com", "cloudtrace.mtls.googleapis.com",
    "monitoring.googleapis.com", "monitoring.mtls.googleapis.com",
    "secretmanager.googleapis.com", "secretmanager.mtls.googleapis.com",
    "cloudresourcemanager.googleapis.com", "cloudresourcemanager.mtls.googleapis.com",
    "iamcredentials.googleapis.com", "iamcredentials.mtls.googleapis.com",
    "aiplatform.googleapis.com", "aiplatform.mtls.googleapis.com",
    "oauth2.googleapis.com",
  ]
}

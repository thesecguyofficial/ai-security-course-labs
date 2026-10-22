variable "project_id" {
  description = "Your own sandbox project ID (not a work project)."
  type        = string
}

variable "region" {
  description = "Region for the VPC subnet, KMS key ring and BigQuery datasets. Check the model is offered here."
  type        = string
  default     = "europe-west4"
}

variable "model" {
  description = "Publisher model the Helpdesk calls."
  type        = string
  default     = "publishers/google/models/gemini-3.1-flash-lite"
}

variable "psc_ip" {
  description = "Internal IPv4 address for the Private Service Connect endpoint. Must be outside every subnet range."
  type        = string
  default     = "10.100.0.2"
}

variable "org_id" {
  description = "Organization ID. Leave empty if your project has no organization (personal Free Trial)."
  type        = string
  default     = ""
}

variable "prod_folder_id" {
  description = "Folder for the vertexai.allowedModels allow-list. Empty = skip (needs an organization)."
  type        = string
  default     = ""
}

variable "access_policy_id" {
  description = "Access Context Manager policy number. Empty = skip the VPC Service Controls perimeter."
  type        = string
  default     = ""
}

variable "incident_readers" {
  description = "Who may read the request-response log dataset, e.g. group:helpdesk-sre@your-domain.example."
  type        = string
  default     = ""
}

variable "create_test_vm" {
  description = "Create one small VM with no external IP to prove the private path. Billed while it exists."
  type        = bool
  default     = false
}

variable "deployers" {
  description = "Who may attach chatbot-runtime to a VM, e.g. group:helpdesk-deployers@your-domain.example."
  type        = string
  default     = ""
}

variable "office_ranges" {
  description = "Office egress CIDRs allowed into the perimeter for BigQuery (empty = none). Use your real ranges."
  type        = list(string)
  default     = []
}

variable "project_id" {
  description = "Your own sandbox project ID (not a work project). The GC11/GC12 project is fine."
  type        = string
}

variable "region" {
  description = "RAG Engine, Model Armor and the agent's region. europe-west4 is GA for RAG Engine (and billed)."
  type        = string
  default     = "europe-west4"
}

variable "kms_key" {
  description = "Optional CMEK key (projects/.../cryptoKeys/...) for both corpora. Fixed at creation. Empty = Google-managed."
  type        = string
  default     = ""
}

variable "create_model_armor_template" {
  description = "false if you kept GC12's helpdesk-guard template and want to reuse it."
  type        = bool
  default     = true
}

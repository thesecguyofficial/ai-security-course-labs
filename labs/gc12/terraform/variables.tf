variable "project_id" {
  description = "Your own sandbox project ID (not a work project). The GC11 project is fine."
  type        = string
}

variable "region" {
  description = "Model Armor location for the template and the Sensitive Data Protection inspect template."
  type        = string
  default     = "europe-west4"
}

variable "floor_mode" {
  description = "Agent Platform floor setting enforcement: start with INSPECT_ONLY for a week, then INSPECT_AND_BLOCK."
  type        = string
  default     = "INSPECT_ONLY"
  validation {
    condition     = contains(["INSPECT_ONLY", "INSPECT_AND_BLOCK"], var.floor_mode)
    error_message = "floor_mode must be INSPECT_ONLY or INSPECT_AND_BLOCK."
  }
}

variable "pi_confidence" {
  description = "Prompt injection and jailbreak confidence level. Pick it from your own `make sweep` results."
  type        = string
  default     = "MEDIUM_AND_ABOVE"
}

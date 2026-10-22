variable "account_id" {
  description = "Your sandbox AWS account ID (12 digits). Used to build ARNs that are readable at plan time."
  type        = string
  default     = "111122223333" # AWS documentation example value: `make cloud-up` passes your real one
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be 12 digits."
  }
}

variable "region" {
  description = "Source Region. The US guardrail profile routes guardrail evaluation from us-east-1 to us-east-1, us-east-2 and us-west-2 (AWS docs)."
  type        = string
  default     = "us-east-1"
}

variable "guardrail_profile_id" {
  description = "System-defined guardrail profile for cross-Region inference. Standard tier needs one. US only, to match the M11 residency rule."
  type        = string
  default     = "us.guardrail.v1:0"
}

variable "helpdesk_role_name" {
  description = "OPTIONAL. The M11 Helpdesk role (tsg-helpdesk-app) if it is deployed: adds the 'no model call without guardrail version N' deny to it. Empty = don't touch it."
  type        = string
  default     = ""
}

variable "enforce_account_wide" {
  description = "OPTIONAL. true = account-level enforcement in this Region: EVERY Bedrock model call in the account gets this guardrail, and callers without bedrock:ApplyGuardrail on it start getting AccessDenied. Sandbox accounts only."
  type        = bool
  default     = false
}

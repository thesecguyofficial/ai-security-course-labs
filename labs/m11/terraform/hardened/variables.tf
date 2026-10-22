variable "account_id" {
  description = "Your sandbox AWS account ID (12 digits). Policies are built from it so the plan can be checked offline."
  type        = string
  default     = "111122223333" # AWS documentation example value: replace it before `make up`
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be 12 digits."
  }
}

variable "region" {
  description = "Source Region. The us. profile below routes from us-east-1 to us-east-1, us-east-2 and us-west-2 (AWS model card)."
  type        = string
  default     = "us-east-1"
}

variable "availability_zones" {
  description = "One subnet (and one endpoint network interface, billed per hour) per zone. Use one zone to halve the endpoint cost."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "inference_profile_id" {
  description = "Geographic (us.) profile: requests stay in US Regions. Never a global. profile for this app (lesson 11.5)."
  type        = string
  default     = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
}

variable "foundation_model_id" {
  type    = string
  default = "anthropic.claude-haiku-4-5-20251001-v1:0"
}

variable "destination_regions" {
  description = "Where the profile may route a request from var.region. Check: aws bedrock get-inference-profile --inference-profile-identifier <id>"
  type        = list(string)
  default     = ["us-east-1", "us-east-2", "us-west-2"]
}

variable "prompt_log_retention_days" {
  description = "Prompts and answers are personal data in most helpdesks. Keep them only as long as investigations need them."
  type        = number
  default     = 30
}

variable "max_tokens" {
  description = "Output cap per request (cost safety, LLM06:2026)."
  type        = number
  default     = 300
}

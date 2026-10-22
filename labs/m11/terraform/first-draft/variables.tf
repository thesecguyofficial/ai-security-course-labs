variable "account_id" {
  type    = string
  default = "111122223333"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "availability_zones" {
  type    = list(string)
  default = ["us-east-1a", "us-east-1b"]
}

variable "inference_profile_id" {
  description = "Global profile: about 10% cheaper, and it worked first time."
  type        = string
  default     = "global.anthropic.claude-haiku-4-5-20251001-v1:0"
}

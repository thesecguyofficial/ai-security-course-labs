variable "project_id" {
  description = "Your sandbox project ID."
  type        = string
}

variable "region" {
  description = "Region for the endpoint, the key, the bucket, the image repository and the network."
  type        = string
  default     = "us-central1"
}

variable "endpoint_id" {
  description = "The endpoint's numeric ID (Agent Platform wants a number, at most 10 digits, no leading zero)."
  type        = string
  default     = "1501500001"
}

variable "request_response_logging" {
  description = "Part F: keep a copy of every request and answer in BigQuery. A PSC endpoint takes this only when it is created."
  type        = bool
  default     = false
}

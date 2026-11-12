variable "project_id" {
  description = "Your sandbox project ID."
  type        = string
}

variable "region" {
  description = "Region for the Model Armor template."
  type        = string
  default     = "europe-west4"
}

variable "alert_email" {
  description = "Where the three alerts send email (your own address)."
  type        = string
}

variable "my_ip" {
  description = "The address your own key calls come from; any other address raises the key alert."
  type        = string
  default     = "203.0.113.7"
}

variable "flood_threshold" {
  description = "Model calls in 5 minutes before the flood alert opens (Part E raises it to 100)."
  type        = number
  default     = 20
}

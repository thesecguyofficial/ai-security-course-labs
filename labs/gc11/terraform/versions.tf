# GC11 optional cloud path: the hardened TSG Helpdesk foundation on Gemini Enterprise Agent Platform.
# Read README.md Step 8 (cost, budget, teardown) BEFORE `terraform apply`. Use your own project only.
terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 8.0, < 9.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

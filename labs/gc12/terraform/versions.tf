# GC12 optional cloud path: Model Armor for the TSG Helpdesk (works on the GC11 project or any sandbox project).
# Read README.md Step 8 (cost, teardown) BEFORE `terraform apply`. Use your own project only.
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

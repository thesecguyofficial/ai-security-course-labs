# GC16 cloud path as code: the same pieces `cloud/deploy.sh up` makes (GUIDED-BUILD.md Parts A to C).
# Use your own sandbox project only; `terraform destroy` the same day.
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

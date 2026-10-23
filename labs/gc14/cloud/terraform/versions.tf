# GC14 guided build. Your own sandbox project only. Read GUIDED-BUILD.md before `terraform apply`.
# Agent Gateway and Agent Registry resources are in the google provider; the authz extension/policy and the IAM v3
# access policy and policy binding are used through google-beta here (Google's own Agent Gateway demo pins the
# authz resources to google-beta).
terraform {
  required_version = ">= 1.6"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 7.39.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 7.39.0"
    }
    time = {
      source  = "hashicorp/time"
      version = ">= 0.9"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

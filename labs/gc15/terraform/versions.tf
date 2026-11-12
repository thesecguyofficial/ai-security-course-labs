# GC15 cloud path as code: the pieces of GUIDED-BUILD.md Part A, the Private Service Connect endpoint (D1) and the
# Data Access logs (D6). The image build, the model upload, the auto-undeploy job, the deployment and the forwarding
# rule stay in cloud/deploy.sh: they depend on the image digest, the model and the endpoint's service attachment,
# which only exist once those steps have run. Use your own sandbox project only.
terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 8.0, < 9.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 8.0, < 9.0"
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

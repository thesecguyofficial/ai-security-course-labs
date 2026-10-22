# GC13 optional cloud path: RAG Engine corpora per audience, a dedicated agent service account, a Model Armor
# template for the ADK plugin. Read GUIDED-BUILD.md (cost, teardown) BEFORE `terraform apply`. Your own project only.
terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source = "hashicorp/google"
      # google_vertex_ai_rag_corpus arrived in 8.3.0; its vector_db_config block in 8.4.0.
      version = ">= 8.4, < 9.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

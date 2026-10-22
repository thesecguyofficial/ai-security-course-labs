data "google_project" "this" {}

locals {
  embedding = "projects/${data.google_project.this.number}/locations/${var.region}/publishers/google/models/text-embedding-005"
  docs      = jsondecode(file("${path.module}/../data/docs.json")).documents
  # Staff corpus: everything everyone may read, PLUS the poisoned refund update on purpose (GUIDED-BUILD request G3).
  staff_docs   = [for d in local.docs : d if d.team == "all"]
  finance_docs = [for d in local.docs : d if d.team == "finance"]
}

resource "google_project_service" "apis" {
  for_each           = toset(["aiplatform.googleapis.com", "modelarmor.googleapis.com", "storage.googleapis.com"])
  service            = each.value
  disable_on_destroy = false
}

# One bucket per audience. Only you write to them (no broad writer groups: lab rule GC13-06).
resource "google_storage_bucket" "kb" {
  for_each                    = toset(["staff", "finance"])
  name                        = "${var.project_id}-tsg-kb-${each.value}"
  location                    = upper(var.region)
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true
}

resource "google_storage_bucket_object" "staff" {
  for_each = { for d in local.staff_docs : d.id => d }
  bucket   = google_storage_bucket.kb["staff"].name
  name     = "${each.key}.txt"
  content  = each.value.text
}

resource "google_storage_bucket_object" "finance" {
  for_each = { for d in local.finance_docs : d.id => d }
  bucket   = google_storage_bucket.kb["finance"].name
  name     = "${each.key}.txt"
  content  = each.value.text
}

# One corpus per audience. RAG Engine has no per-document ACL and no IAM policy per corpus: which corpus a
# request may search is decided in the agent's tool code, from the user's verified groups (lesson 13.1).
resource "google_vertex_ai_rag_corpus" "kb" {
  for_each     = toset(["staff", "finance"])
  display_name = "kb-${each.value}"
  description  = "TSG Helpdesk knowledge base: ${each.value}"
  region       = var.region

  vector_db_config {
    rag_managed_db {
      knn {}
    }
    rag_embedding_model_config {
      vertex_prediction_endpoint {
        endpoint = local.embedding
      }
    }
  }

  dynamic "encryption_spec" {
    for_each = var.kms_key == "" ? [] : [var.kms_key]
    content {
      kms_key_name = encryption_spec.value
    }
  }
  depends_on = [google_project_service.apis]
}

# RAG Engine's service agent reads the buckets during import. It is created on first use of RAG Engine,
# so grant it after the corpora exist (as in the provider's own example).
resource "google_storage_bucket_iam_member" "rag_reads_kb" {
  for_each   = google_storage_bucket.kb
  bucket     = each.value.name
  role       = "roles/storage.objectViewer"
  member     = "serviceAccount:service-${data.google_project.this.number}@gcp-sa-vertex-rag.iam.gserviceaccount.com"
  depends_on = [google_vertex_ai_rag_corpus.kb]
}

# The agent's own identity: not the project-wide Reasoning Engine Service Agent (lab rule GC13-10).
resource "google_service_account" "agent" {
  account_id   = "helpdesk-agent"
  display_name = "TSG Helpdesk agent (GC13)"
}

resource "google_project_iam_member" "agent_aiplatform_user" {
  project = var.project_id
  role    = "roles/aiplatform.user" # Gemini calls and RAG Engine retrieval. Nothing else.
  member  = google_service_account.agent.member
}

resource "google_project_iam_member" "agent_model_armor_user" {
  project = var.project_id
  role    = "roles/modelarmor.user" # the ADK Model Armor plugin calls sanitize as the agent
  member  = google_service_account.agent.member
}

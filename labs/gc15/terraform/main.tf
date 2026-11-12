data "google_project" "this" {
  project_id = var.project_id
}

resource "google_project_service" "apis" {
  for_each = toset([
    "aiplatform.googleapis.com", "compute.googleapis.com", "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com", "cloudkms.googleapis.com", "cloudscheduler.googleapis.com",
    "storage.googleapis.com", "containerscanning.googleapis.com", "bigquery.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}

# ---- A2: three service accounts, each with one job -----------------------------------------------------------
resource "google_service_account" "lab" {
  for_each     = toset(["tsg-gc15-runtime", "tsg-gc15-app", "tsg-gc15-teardown"])
  account_id   = each.value
  display_name = "GC15 lab ${each.value}"
}

resource "google_project_iam_custom_role" "undeploy" {
  role_id     = "tsgGc15Undeploy"
  title       = "GC15 tsgGc15Undeploy"
  permissions = ["aiplatform.endpoints.undeploy", "aiplatform.endpoints.get"]
}

resource "google_project_iam_custom_role" "predict_only" {
  role_id     = "tsgGc15PredictOnly"
  title       = "GC15 tsgGc15PredictOnly"
  permissions = ["aiplatform.endpoints.predict"]
}

# The teardown account may only undeploy; the app account gets predict on the endpoint itself (deploy.sh, D4).
resource "google_project_iam_member" "teardown_undeploys" {
  project = var.project_id
  role    = google_project_iam_custom_role.undeploy.id
  member  = "serviceAccount:${google_service_account.lab["tsg-gc15-teardown"].email}"
}

# ---- A3: a Cloud KMS key the Agent Platform service agent may use ---------------------------------------------
resource "google_kms_key_ring" "gc15" {
  name       = "tsg-gc15" # key rings can't be deleted: deploy.sh adopts an existing one
  location   = var.region
  depends_on = [google_project_service.apis]
}

resource "google_kms_crypto_key" "ai" {
  name     = "tsg-gc15-ai"
  key_ring = google_kms_key_ring.gc15.id
  purpose  = "ENCRYPT_DECRYPT"
}

resource "google_project_service_identity" "aiplatform" {
  provider = google-beta
  project  = var.project_id
  service  = "aiplatform.googleapis.com"
}

resource "google_kms_crypto_key_iam_member" "aiplatform_uses_key" {
  crypto_key_id = google_kms_crypto_key.ai.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.this.number}@gcp-sa-aiplatform.iam.gserviceaccount.com"
  depends_on    = [google_project_service_identity.aiplatform]
}

# ---- A4: a private model bucket, an image repository, a network with no internet route ------------------------
resource "google_storage_bucket" "models" {
  name                        = "${var.project_id}-tsg-gc15-models"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true
  depends_on                  = [google_project_service.apis]
}

resource "google_artifact_registry_repository" "images" {
  repository_id = "tsg-gc15"
  location      = var.region
  format        = "DOCKER"
  depends_on    = [google_project_service.apis]
}

resource "google_compute_network" "vpc" {
  name                    = "tsg-gc15-vpc"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.apis]
}

resource "google_compute_subnetwork" "subnet" {
  name          = "tsg-gc15-subnet"
  network       = google_compute_network.vpc.id
  region        = var.region
  ip_cidr_range = "10.15.0.0/24"
}

# ---- D1: the Private Service Connect endpoint, encrypted with your key, open to this project only ---------------
resource "google_vertex_ai_endpoint" "summariser" {
  name         = var.endpoint_id
  display_name = "tsg-gc15-summariser"
  location     = var.region
  region       = var.region
  labels       = { course = "tsg-gc15" }
  private_service_connect_config {
    enable_private_service_connect = true
    project_allowlist              = [var.project_id]
  }
  encryption_spec {
    kms_key_name = google_kms_crypto_key.ai.id
  }
  depends_on = [google_kms_crypto_key_iam_member.aiplatform_uses_key]
}

# ---- D6: Data Access audit logs (Data Read) for Agent Platform: who called predict --------------------------------
resource "google_project_iam_audit_config" "aiplatform" {
  project = var.project_id
  service = "aiplatform.googleapis.com"
  audit_log_config { log_type = "DATA_READ" }
}

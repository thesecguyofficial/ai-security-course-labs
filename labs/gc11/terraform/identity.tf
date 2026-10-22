# Lesson 11.1: one service account per workload, no keys, a predict-only custom role.

locals {
  apis = ["aiplatform", "bigquery", "cloudkms", "compute", "dns", "iam", "servicedirectory"]
}

resource "google_project_service" "apis" {
  for_each           = toset(local.apis)
  service            = "${each.value}.googleapis.com"
  disable_on_destroy = false
}

data "google_project" "this" {}

resource "google_service_account" "chatbot_runtime" {
  account_id   = "chatbot-runtime"
  display_name = "TSG Helpdesk runtime"
}

resource "google_service_account" "ticket_summariser" {
  account_id   = "ticket-summariser"
  display_name = "Ticket summariser"
}

# No google_service_account_key anywhere: workloads get credentials from the attached service account (ADC).

resource "google_project_iam_custom_role" "model_caller" {
  role_id     = "helpdeskModelCaller"
  title       = "Helpdesk model caller"
  description = "Call Agent Platform models. Nothing else: no endpoint create or deploy."
  permissions = ["aiplatform.endpoints.predict"]
}

resource "google_project_iam_member" "chatbot_model_caller" {
  project = var.project_id
  role    = google_project_iam_custom_role.model_caller.id
  member  = "serviceAccount:${google_service_account.chatbot_runtime.email}"
}

resource "google_project_iam_member" "summariser_model_caller" {
  project = var.project_id
  role    = google_project_iam_custom_role.model_caller.id
  member  = "serviceAccount:${google_service_account.ticket_summariser.email}"
}

resource "google_bigquery_dataset_iam_member" "tickets_chatbot" {
  dataset_id = google_bigquery_dataset.helpdesk_tickets.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = "serviceAccount:${google_service_account.chatbot_runtime.email}"
}

resource "google_bigquery_dataset_iam_member" "tickets_summariser" {
  dataset_id = google_bigquery_dataset.helpdesk_tickets.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.ticket_summariser.email}"
}

resource "google_bigquery_dataset_iam_member" "ai_logs_readers" {
  count      = var.incident_readers == "" ? 0 : 1
  dataset_id = google_bigquery_dataset.ai_logs.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = var.incident_readers
}

# Who may attach chatbot-runtime to a VM (iam.serviceAccounts.actAs): granted on THIS service account only,
# never Token Creator or Service Account User on the whole project.
resource "google_service_account_iam_member" "deployer_can_attach" {
  count              = var.deployers == "" ? 0 : 1
  service_account_id = google_service_account.chatbot_runtime.name
  role               = "roles/iam.serviceAccountUser"
  member             = var.deployers
}

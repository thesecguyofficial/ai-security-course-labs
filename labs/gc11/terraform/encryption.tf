# Lesson 11.3: customer-managed keys for everything this project stores about tickets and prompts.

resource "google_kms_key_ring" "helpdesk_eu" {
  name       = "helpdesk-eu" # key rings can't be deleted: pick names you're happy to keep
  location   = var.region
  depends_on = [google_project_service.apis]
}

resource "google_kms_crypto_key" "helpdesk_data" {
  name            = "helpdesk-data"
  key_ring        = google_kms_key_ring.helpdesk_eu.id
  rotation_period = "7776000s" # 90 days
  purpose         = "ENCRYPT_DECRYPT"
}

data "google_bigquery_default_service_account" "bq" {
  depends_on = [google_project_service.apis]
}

resource "google_kms_crypto_key_iam_member" "bq_can_use_key" {
  crypto_key_id = google_kms_crypto_key.helpdesk_data.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_bigquery_default_service_account.bq.email}"
}

resource "google_bigquery_dataset" "helpdesk_tickets" {
  dataset_id                 = "helpdesk_tickets"
  location                   = var.region
  delete_contents_on_destroy = true # lab only: lets `make down` remove it
  labels     = { data_class = "customer" }
  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.helpdesk_data.id
  }
  depends_on = [google_kms_crypto_key_iam_member.bq_can_use_key]
}

# Request-response logging writes here (scripts/request_response_logging.sh). The dataset must exist;
# Agent Platform creates the table.
resource "google_bigquery_dataset" "ai_logs" {
  dataset_id                 = "ai_logs"
  location                   = var.region
  delete_contents_on_destroy = true # lab only
  labels     = { data_class = "customer" }
  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.helpdesk_data.id
  }
  depends_on = [google_kms_crypto_key_iam_member.bq_can_use_key]
}

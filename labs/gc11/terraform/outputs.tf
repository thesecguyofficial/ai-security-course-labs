output "runtime_service_account" {
  value = google_service_account.chatbot_runtime.email
}

output "psc_endpoint" {
  value = "${var.endpoint_ip} -> ${var.model_host} (locations/${var.model_location})"
}

output "kms_key" {
  value = google_kms_crypto_key.helpdesk_data.id
}

output "request_response_log_destination" {
  value = "bq://${var.project_id}.${google_bigquery_dataset.ai_logs.dataset_id}.request_response_logging"
}

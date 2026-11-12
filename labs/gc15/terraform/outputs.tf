output "endpoint_id" {
  value = google_vertex_ai_endpoint.summariser.name
}

output "kms_key" {
  value = google_kms_crypto_key.ai.id
}

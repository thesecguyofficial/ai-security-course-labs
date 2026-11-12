# The provider's `name` is only the corpus number; `id` is the full resource name the APIs and the agent need.
output "corpus_staff" {
  value = google_vertex_ai_rag_corpus.kb["staff"].id
}

output "corpus_finance" {
  value = google_vertex_ai_rag_corpus.kb["finance"].id
}

output "agent_service_account" {
  value = google_service_account.agent.email
}

output "model_armor_template" {
  value = var.create_model_armor_template ? google_model_armor_template.agent_guard[0].id : "projects/${var.project_id}/locations/${var.region}/templates/helpdesk-guard"
}

output "env_lines" {
  description = "Paste into adk_agent/tsg_helpdesk/.env (GUIDED-BUILD.md Step 4)."
  value = join("\n", [
    "TSG_MODE=cloud",
    "GOOGLE_GENAI_USE_VERTEXAI=TRUE",
    "GOOGLE_CLOUD_PROJECT=${var.project_id}",
    "GOOGLE_CLOUD_LOCATION=eu",
    "TSG_RAG_LOCATION=${var.region}",
    "TSG_CORPUS_STAFF=${google_vertex_ai_rag_corpus.kb["staff"].id}",
    "TSG_CORPUS_FINANCE=${google_vertex_ai_rag_corpus.kb["finance"].id}",
  ])
}

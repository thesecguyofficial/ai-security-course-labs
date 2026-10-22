# Lesson 11.4: Data Access audit logs for Agent Platform are off by default. Switch them on.
resource "google_project_iam_audit_config" "aiplatform_data_access" {
  project = var.project_id
  service = "aiplatform.googleapis.com"
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

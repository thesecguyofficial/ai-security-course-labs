resource "google_project_service" "apis" {
  for_each           = toset(["modelarmor.googleapis.com", "dlp.googleapis.com", "aiplatform.googleapis.com"])
  service            = each.value
  disable_on_destroy = false
}

data "google_project" "this" {}

# Agent Platform calls Model Armor as its service agent, which needs Model Armor User.
# The service agent exists once Agent Platform has been used in the project (e.g. GC11's smoke test).
resource "google_project_iam_member" "aiplatform_agent_modelarmor_user" {
  project    = var.project_id
  role       = "roles/modelarmor.user"
  member     = "serviceAccount:service-${data.google_project.this.number}@gcp-sa-aiplatform.iam.gserviceaccount.com"
  depends_on = [google_project_service.apis]
}

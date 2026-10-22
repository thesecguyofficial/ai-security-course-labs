# Lesson 11.1 / GC10 lesson 10.3: which models may be called at all. Needs an organization and a folder; skipped
# otherwise. Run it as dry_run_spec for a week first (lesson 10.3), then enforce with spec as below.
resource "google_org_policy_policy" "allowed_models" {
  count  = var.prod_folder_id == "" ? 0 : 1
  name   = "folders/${var.prod_folder_id}/policies/vertexai.allowedModels"
  parent = "folders/${var.prod_folder_id}"

  spec {
    inherit_from_parent = false
    rules {
      values {
        allowed_values = ["${var.model}:predict"]
      }
    }
  }
}

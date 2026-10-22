# Template for the ADK Model Armor plugin: user input, model output and tool output (lesson 13.2).
resource "google_model_armor_template" "agent_guard" {
  count       = var.create_model_armor_template ? 1 : 0
  location    = var.region
  template_id = "helpdesk-agent-guard"

  filter_config {
    rai_settings {
      dynamic "rai_filters" {
        for_each = ["DANGEROUS", "HARASSMENT", "HATE_SPEECH", "SEXUALLY_EXPLICIT"]
        content {
          filter_type      = rai_filters.value
          confidence_level = "MEDIUM_AND_ABOVE"
        }
      }
    }
    pi_and_jailbreak_filter_settings {
      filter_enforcement = "ENABLED"
      confidence_level   = "MEDIUM_AND_ABOVE"
    }
    malicious_uri_filter_settings {
      filter_enforcement = "ENABLED"
    }
  }

  template_metadata {
    log_sanitize_operations            = true
    ignore_partial_invocation_failures = false
  }
  depends_on = [google_project_service.apis]
}

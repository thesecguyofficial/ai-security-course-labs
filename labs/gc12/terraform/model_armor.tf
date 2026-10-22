# Your own info types for Sensitive Data Protection (advanced config), instead of basic's six US-centred ones.
resource "google_data_loss_prevention_inspect_template" "helpdesk" {
  parent       = "projects/${var.project_id}/locations/${var.region}"
  template_id  = "helpdesk-in-eu"
  display_name = "TSG Helpdesk info types"
  inspect_config {
    info_types { name = "CREDIT_CARD_NUMBER" }
    info_types { name = "EMAIL_ADDRESS" }
    info_types { name = "GCP_API_KEY" }
    info_types { name = "GCP_CREDENTIALS" }
    info_types { name = "IBAN_CODE" }
    info_types { name = "INDIA_AADHAAR_INDIVIDUAL" }
    info_types { name = "INDIA_PAN_INDIVIDUAL" }
    min_likelihood = "LIKELY"
  }
  depends_on = [google_project_service.apis]
}

locals {
  rai_types = ["DANGEROUS", "HARASSMENT", "HATE_SPEECH", "SEXUALLY_EXPLICIT"]
}

# Template for the self-hosted path (app_guard.py / run_suite.py --engine model-armor).
resource "google_model_armor_template" "helpdesk_guard" {
  location    = var.region
  template_id = "helpdesk-guard"

  filter_config {
    rai_settings {
      dynamic "rai_filters" {
        for_each = local.rai_types
        content {
          filter_type      = rai_filters.value
          confidence_level = "MEDIUM_AND_ABOVE"
        }
      }
    }
    pi_and_jailbreak_filter_settings {
      filter_enforcement = "ENABLED"
      confidence_level   = var.pi_confidence
    }
    malicious_uri_filter_settings {
      filter_enforcement = "ENABLED"
    }
    sdp_settings {
      advanced_config {
        inspect_template = google_data_loss_prevention_inspect_template.helpdesk.id
      }
    }
  }

  template_metadata {
    log_sanitize_operations            = true
    ignore_partial_invocation_failures = false
    enforcement_type                   = "INSPECT_AND_BLOCK"
  }
  depends_on = [google_project_service.apis]
}

# Project floor setting: applies to every Gemini generateContent call in the project, even without a template.
# deletion_policy ABANDON: `terraform destroy` leaves it alone; scripts/reset_floor.sh switches it off explicitly.
resource "google_model_armor_floorsetting" "project" {
  parent   = "projects/${var.project_id}"
  location = "global"

  filter_config {
    rai_settings {
      dynamic "rai_filters" {
        for_each = local.rai_types
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
    sdp_settings {
      advanced_config {
        inspect_template = google_data_loss_prevention_inspect_template.helpdesk.id
      }
    }
  }

  enable_floor_setting_enforcement = true
  integrated_services              = ["AI_PLATFORM"]

  ai_platform_floor_setting {
    inspect_only         = var.floor_mode == "INSPECT_ONLY" ? true : null
    inspect_and_block    = var.floor_mode == "INSPECT_AND_BLOCK" ? true : null
    enable_cloud_logging = true
  }

  deletion_policy = "ABANDON"
  depends_on      = [google_project_service.apis]
}

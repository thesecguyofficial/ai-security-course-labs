locals {
  rai_types = ["DANGEROUS", "HARASSMENT", "HATE_SPEECH", "SEXUALLY_EXPLICIT"]
}

resource "google_project_service" "apis" {
  for_each           = toset(["aiplatform.googleapis.com", "modelarmor.googleapis.com", "logging.googleapis.com", "monitoring.googleapis.com"])
  service            = each.value
  disable_on_destroy = false
}

# Part A: Data Access audit logs (Data Read + Data Write) for Agent Platform. Terraform owns this one service's
# audit config and leaves every other service and every IAM binding alone; destroy switches it off again.
resource "google_project_iam_audit_config" "aiplatform" {
  project = var.project_id
  service = "aiplatform.googleapis.com"
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}

# Part B: a Model Armor template that logs every sanitize call (raw text included: keep this log's access tight).
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
      confidence_level   = "MEDIUM_AND_ABOVE"
    }
    malicious_uri_filter_settings {
      filter_enforcement = "ENABLED"
    }
    sdp_settings {
      basic_config {
        filter_enforcement = "ENABLED"
      }
    }
  }

  template_metadata {
    log_sanitize_operations = true
  }
  depends_on = [google_project_service.apis]
}

# Part C: where alerts go, the metric that counts model calls, and the three alerts.
resource "google_monitoring_notification_channel" "email" {
  display_name = "GC16 lab email"
  type         = "email"
  labels       = { email_address = var.alert_email }
  depends_on   = [google_project_service.apis]
}

resource "google_logging_metric" "ai_calls" {
  name        = "gc16_ai_calls"
  description = "Agent Platform model calls (GC16 lab)"
  filter      = trimspace(file("${path.module}/../cloud/ai-calls-metric-filter.txt"))
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
  depends_on = [google_project_service.apis]
}

resource "google_monitoring_alert_policy" "armor_match" {
  display_name = "GC16 Model Armor match"
  combiner     = "OR"
  conditions {
    display_name = "A Model Armor sanitize operation found a match"
    condition_matched_log {
      filter = "jsonPayload.@type=\"type.googleapis.com/google.cloud.modelarmor.logging.v1.SanitizeOperationLogEntry\" AND jsonPayload.sanitizationResult.filterMatchState=\"MATCH_FOUND\""
    }
  }
  alert_strategy {
    notification_rate_limit { period = "300s" }
    auto_close = "1800s"
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}

resource "google_monitoring_alert_policy" "key_unknown_ip" {
  display_name = "GC16 service account key used from an unknown address"
  combiner     = "OR"
  conditions {
    display_name = "A call made with a downloaded key, from outside your addresses"
    condition_matched_log {
      filter = "logName:\"cloudaudit.googleapis.com\" AND protoPayload.authenticationInfo.serviceAccountKeyName:\"keys/\" AND NOT protoPayload.requestMetadata.callerIp=\"${var.my_ip}\""
    }
  }
  alert_strategy {
    notification_rate_limit { period = "300s" }
    auto_close = "1800s"
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}

resource "google_monitoring_alert_policy" "request_flood" {
  display_name = "GC16 request flood on Agent Platform"
  combiner     = "OR"
  conditions {
    display_name = "More than ${var.flood_threshold} model calls in 5 minutes"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.ai_calls.name}\" AND resource.type=\"audited_resource\""
      comparison      = "COMPARISON_GT"
      threshold_value = var.flood_threshold
      duration        = "0s"
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}

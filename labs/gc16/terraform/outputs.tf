output "template" {
  value = google_model_armor_template.helpdesk_guard.name
}

output "alerts" {
  value = [
    google_monitoring_alert_policy.armor_match.display_name,
    google_monitoring_alert_policy.key_unknown_ip.display_name,
    google_monitoring_alert_policy.request_flood.display_name,
  ]
}

output "template_name" {
  description = "Pass to run_suite.py --engine model-armor --template-name"
  value       = google_model_armor_template.helpdesk_guard.id
}

output "floor_mode" {
  value = var.floor_mode
}

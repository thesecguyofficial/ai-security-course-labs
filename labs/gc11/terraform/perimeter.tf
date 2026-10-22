# Lesson 11.2: VPC Service Controls perimeter, in DRY RUN. Needs an organization and an access policy.
# Dry run logs violations (metadata.dryRun = true) and blocks nothing. Enforce only after reading the logs.
resource "google_access_context_manager_service_perimeter" "helpdesk" {
  count          = var.access_policy_id == "" ? 0 : 1
  parent         = "accessPolicies/${var.access_policy_id}"
  name           = "accessPolicies/${var.access_policy_id}/servicePerimeters/helpdesk"
  title          = "helpdesk"
  perimeter_type = "PERIMETER_TYPE_REGULAR"

  spec {
    resources           = ["projects/${data.google_project.this.number}"]
    restricted_services = ["aiplatform.googleapis.com", "bigquery.googleapis.com", "storage.googleapis.com"]

    # Office analysts may query BigQuery from the office ranges (only if office_ranges is set).
    dynamic "ingress_policies" {
      for_each = length(var.office_ranges) == 0 ? [] : [1]
      content {
        ingress_from {
          identity_type = "ANY_USER_ACCOUNT"
          sources {
            access_level = google_access_context_manager_access_level.office[0].name
          }
        }
        ingress_to {
          resources = ["*"]
          operations {
            service_name = "bigquery.googleapis.com"
            method_selectors {
              method = "*"
            }
          }
        }
      }
    }
  }
  use_explicit_dry_run_spec = true
}

resource "google_access_context_manager_access_level" "office" {
  count  = var.access_policy_id == "" || length(var.office_ranges) == 0 ? 0 : 1
  parent = "accessPolicies/${var.access_policy_id}"
  name   = "accessPolicies/${var.access_policy_id}/accessLevels/office"
  title  = "office"
  basic {
    conditions {
      ip_subnetworks = var.office_ranges
    }
  }
}

# GC14 guided build: Agent Gateway (Agent-to-Anywhere) with a registry allow-list, an IAM Unified Access Policy
# (one DENY rule), BigQuery data for the Helpdesk agent, and Data Access audit logs for Memory Bank.
# Two applies: Step 2 creates everything that doesn't need the agent; Step 4 (agent_principal set) adds the policy,
# its binding and the agent's own IAM grants. Never applied by the course authors: see GUIDED-BUILD.md.

data "google_project" "this" {
  project_id = var.project_id
}

locals {
  number   = data.google_project.this.number
  org_id   = data.google_project.this.org_id
  trust    = local.org_id != "" ? "agents.global.org-${local.org_id}.system.id.goog" : "agents.global.proj-${local.number}.system.id.goog"
  all_ours = "principalSet://${local.trust}/attribute.platformContainer/aiplatform/projects/${local.number}"
  agent    = var.agent_principal != ""
  gateway  = "projects/${var.project_id}/locations/${var.region}/agentGateways/${var.gateway_name}"

  hosts = concat(var.google_endpoints, [
    "${var.region}-aiplatform.googleapis.com",
    "${var.region}-aiplatform.mtls.googleapis.com",
    "aiplatform.${var.region}.rep.googleapis.com",
  ])

  bigquery_tools     = ["list_dataset_ids", "list_table_ids", "get_dataset_info", "get_table_info", "execute_sql_readonly", "execute_sql"]
  bigquery_tool_list = join(", ", [for t in local.bigquery_tools : "'${t}'"])
}

# ---- APIs ----------------------------------------------------------------------------------------------------
resource "google_project_service" "apis" {
  for_each = toset([
    "aiplatform.googleapis.com", "agentregistry.googleapis.com", "networkservices.googleapis.com",
    "networksecurity.googleapis.com", "iap.googleapis.com", "iam.googleapis.com", "compute.googleapis.com",
    "bigquery.googleapis.com", "storage.googleapis.com", "logging.googleapis.com",
    "cloudresourcemanager.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}

# ---- data the agent works on (fake rows are inserted with `bq query` in Step 2) --------------------------------
resource "google_bigquery_dataset" "helpdesk" {
  dataset_id                 = "helpdesk"
  location                   = var.bigquery_location
  delete_contents_on_destroy = true
  depends_on                 = [google_project_service.apis]
}

resource "google_bigquery_table" "tickets" {
  dataset_id          = google_bigquery_dataset.helpdesk.dataset_id
  table_id            = "tickets"
  deletion_protection = false
  schema = jsonencode([
    { name = "ticket_id", type = "STRING" }, { name = "status", type = "STRING" }, { name = "summary", type = "STRING" },
  ])
}

resource "google_bigquery_dataset" "finance" {
  dataset_id                 = "finance_exports"
  location                   = var.bigquery_location
  delete_contents_on_destroy = true
  depends_on                 = [google_project_service.apis]
}

resource "google_bigquery_table" "payroll" {
  dataset_id          = google_bigquery_dataset.finance.dataset_id
  table_id            = "payroll"
  deletion_protection = false
  schema = jsonencode([
    { name = "employee", type = "STRING" }, { name = "band", type = "STRING" },
  ])
}

resource "google_storage_bucket" "staging" {
  name                        = "${var.project_id}-tsg-gc14-staging"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true
  depends_on                  = [google_project_service.apis]
}

# ---- Agent Registry: the Google endpoints the agent needs (exact hosts, no wildcards) ---------------------------
# Google's BigQuery MCP server is registered automatically (location "global") when the BigQuery API is enabled.
resource "google_agent_registry_service" "endpoints" {
  for_each     = toset(local.hosts)
  location     = var.region
  service_id   = replace(trimsuffix(each.value, ".googleapis.com"), ".", "-")
  display_name = each.value
  interfaces {
    url              = "https://${each.value}"
    protocol_binding = "JSONRPC"
  }
  endpoint_spec {
    type = "NO_SPEC"
  }
  depends_on = [google_project_service.apis]
}

# ---- Agent Gateway, Agent-to-Anywhere --------------------------------------------------------------------------
resource "google_network_services_agent_gateway" "egress" {
  name      = var.gateway_name
  location  = var.region
  protocols = ["MCP"]
  google_managed {
    governed_access_path = "AGENT_TO_ANYWHERE"
  }
  registries = [
    "//agentregistry.googleapis.com/projects/${var.project_id}/locations/${var.region}",
    "//agentregistry.googleapis.com/projects/${var.project_id}/locations/global",
  ]
  depends_on = [google_project_service.apis]
}

resource "time_sleep" "gateway_ready" {
  depends_on      = [google_network_services_agent_gateway.egress]
  create_duration = "30s"
}

# IAP decides every request with the Unified Access Policy (iapPolicyVersion V2). DRY_RUN = log, don't block.
resource "google_network_services_authz_extension" "iap" {
  provider  = google-beta
  name      = "tsg-gc14-iap"
  location  = var.region
  service   = "iap.googleapis.com"
  timeout   = "1s"
  fail_open = false
  metadata = merge(
    { iapPolicyVersion = "V2" },
    var.enforcement == "DRY_RUN" ? { iamEnforcementMode = "DRY_RUN" } : {},
  )
}

resource "google_network_security_authz_policy" "iap" {
  provider       = google-beta
  name           = "tsg-gc14-iap-policy"
  location       = var.region
  policy_profile = "REQUEST_AUTHZ"
  action         = "CUSTOM"
  target {
    resources = [google_network_services_agent_gateway.egress.id]
  }
  custom_provider {
    authz_extension {
      resources = [google_network_services_authz_extension.iap.id]
    }
  }
  depends_on = [time_sleep.gateway_ready]
}

# ---- Step 4: the Unified Access Policy for THIS agent, bound to the gateway --------------------------------------
resource "google_iam_project_access_policy" "egress" {
  count            = local.agent ? 1 : 0
  provider         = google-beta
  location         = "global"
  access_policy_id = "tsg-gc14-egress"
  display_name     = "TSG GC14 helpdesk egress"
  details {
    rules {
      description = "allow-google-endpoints"
      effect      = "ALLOW"
      principals  = [var.agent_principal]
      operation {
        permissions = ["iap.googleapis.com/resources.egressViaIAP"]
      }
      conditions {
        service    = "iap.googleapis.com"
        expression = "destination.agent_registry.resource_type == 'ENDPOINT'"
      }
    }
    rules {
      description = "allow-bigquery-tools"
      effect      = "ALLOW"
      principals  = [var.agent_principal]
      operation {
        permissions = ["iap.googleapis.com/resources.egressViaIAP"]
      }
      conditions {
        service    = "iap.googleapis.com"
        expression = "destination.agent_registry.resource_type == 'MCP_SERVER' && destination.agent_registry.mcp_server.tool.name in [${local.bigquery_tool_list}]"
      }
    }
    dynamic "rules" {
      for_each = var.deny_execute_sql ? [1] : []
      content {
        description = "deny-execute-sql"
        effect      = "DENY"
        principals  = [var.agent_principal]
        operation {
          permissions = ["iap.googleapis.com/resources.egressViaIAP"]
        }
        conditions {
          service    = "iap.googleapis.com"
          expression = "destination.agent_registry.mcp_server.tool.name == 'execute_sql'"
        }
      }
    }
  }
  depends_on = [google_project_service.apis]
}

resource "time_sleep" "policy_ready" {
  count           = local.agent ? 1 : 0
  depends_on      = [google_iam_project_access_policy.egress]
  create_duration = "60s"
}

resource "google_iam_projects_policy_binding" "egress" {
  count             = local.agent ? 1 : 0
  provider          = google-beta
  location          = "global"
  policy_binding_id = "tsg-gc14-egress"
  display_name      = "TSG GC14 egress policy on the gateway"
  policy_kind       = "ACCESS"
  policy            = "projects/${var.project_id}/locations/global/accessPolicies/tsg-gc14-egress"
  target {
    resource = "//networkservices.googleapis.com/${local.gateway}"
  }
  depends_on = [time_sleep.policy_ready, google_network_security_authz_policy.iap]
}

# ---- Step 4: the agent's own grants (its principal, not every agent in the project) ----------------------------
resource "google_project_iam_member" "agent" {
  for_each = local.agent ? toset([
    "roles/aiplatform.expressUser", "roles/serviceusage.serviceUsageConsumer",
    "roles/bigquery.jobUser", "roles/mcp.toolUser",
  ]) : toset([])
  project = var.project_id
  role    = each.value
  member  = var.agent_principal
}

resource "google_bigquery_dataset_iam_member" "agent_reads_helpdesk" {
  count      = local.agent ? 1 : 0
  dataset_id = google_bigquery_dataset.helpdesk.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = var.agent_principal
}

# ---- Step 6: Data Access audit logs for Agent Platform (memories.retrieve is a data read) ----------------------
resource "google_project_iam_audit_config" "aiplatform" {
  count   = var.memory_data_access_logs ? 1 : 0
  project = var.project_id
  service = "aiplatform.googleapis.com"
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# ---- Step 7: the one-setting change. Every agent in the project may read every table. --------------------------
resource "google_project_iam_member" "all_agents_read_all_data" {
  count   = var.grant_all_agents_project_data ? 1 : 0
  project = var.project_id
  role    = "roles/bigquery.dataViewer"
  member  = local.all_ours
}

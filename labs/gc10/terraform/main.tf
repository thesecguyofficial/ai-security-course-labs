# GC10 as Terraform: the locked-down AI footprint from lesson 10.6 (GUIDED-BUILD.md), in one apply.
#
#   cd labs/gc10/terraform
#   gcloud services enable cloudresourcemanager.googleapis.com cloudbilling.googleapis.com billingbudgets.googleapis.com
#   terraform init
#   terraform apply -var project=PROJECT_ID -var me=YOUR_EMAIL
#   bash ../cloud/deploy.sh test      # the same R1 to R5 checks as the script build
#   terraform destroy -var project=PROJECT_ID -var me=YOUR_EMAIL
#
# What it makes: a budget alert, the three APIs, gc10-caller (Agent Platform User) and gc10-nobody (no AI role), your
# Token Creator on each account (not on the project), Data Access logs for Agent Platform, the plain key gc10-build
# (Agent Platform refuses it: "API keys are not supported by this API") and the key Agent Platform accepts, gc10-bound,
# bound to gc10-caller. Both keys only work from 192.0.2.10. Prompt caching has no Terraform resource, so a
# terraform_data step sends the same PATCH the guide shows (and turns caching back on at destroy).
# Cloud Shell no longer ships Terraform (12 Nov 2026): `bash ../cloud/deploy.sh tf apply` installs it into ~/bin and
# runs this file with your project and account filled in.
# Cost: cents at most. Use a project you own, never your employer's.

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 7.0" }
  }
}

variable "project" { type = string }
variable "me" {
  type        = string
  description = "Your Google account email (gets Token Creator on the two test accounts so you can test as them)"
}
variable "budget_amount" {
  type        = string
  default     = "500"
  description = "In your billing account's currency (500 INR, or 5 for a USD account)"
}
variable "currency" {
  type    = string
  default = "INR"
}

provider "google" {
  project               = var.project
  billing_project       = var.project
  user_project_override = true
}

data "google_project" "this" {}
data "google_billing_account" "this" {
  billing_account = trimprefix(data.google_project.this.billing_account, "billingAccounts/")
}

resource "google_project_service" "apis" {
  for_each           = toset(["aiplatform.googleapis.com", "apikeys.googleapis.com", "cloudasset.googleapis.com", "billingbudgets.googleapis.com"])
  service            = each.value
  disable_on_destroy = false
}

# Step 0: a budget alert. It only emails you, hours late (lesson 10.5).
resource "google_billing_budget" "alerts" {
  billing_account = data.google_billing_account.this.id
  display_name    = "gc10-build alerts"
  budget_filter { projects = ["projects/${data.google_project.this.number}"] }
  amount {
    specified_amount {
      currency_code = var.currency
      units         = var.budget_amount
    }
  }
  threshold_rules { threshold_percent = 0.5 }
  threshold_rules { threshold_percent = 0.9 }
  threshold_rules { threshold_percent = 1.0 }
  depends_on = [google_project_service.apis]
}

# 2a: one identity that may call models, one that may not.
resource "google_service_account" "caller" {
  account_id   = "gc10-caller"
  display_name = "GC10 model caller"
}
resource "google_service_account" "nobody" {
  account_id   = "gc10-nobody"
  display_name = "GC10 no AI role"
}
resource "google_project_iam_member" "caller_ai_user" {
  project = var.project
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.caller.email}"
}
resource "google_service_account_iam_member" "me_token_creator" { # on each account, not on the project (lesson 11.1)
  for_each           = { caller = google_service_account.caller.name, nobody = google_service_account.nobody.name }
  service_account_id = each.value
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "user:${var.me}"
}

# 2b: Data Access logs for Agent Platform (off by default; without them R4 has nothing to find).
resource "google_project_iam_audit_config" "aiplatform" {
  project = var.project
  service = "aiplatform.googleapis.com"
  audit_log_config { log_type = "DATA_READ" }
}

# 2c: two keys, both Agent Platform only and only from 192.0.2.10 (a documentation address).
resource "google_apikeys_key" "plain" {
  name         = "gc10-build"
  display_name = "gc10-build"
  restrictions {
    api_targets { service = "aiplatform.googleapis.com" }
    server_key_restrictions { allowed_ips = ["192.0.2.10"] }
  }
  depends_on = [google_project_service.apis]
}
resource "google_apikeys_key" "bound" { # the kind Agent Platform accepts: bound to a service account (lesson 10.4)
  name                  = "gc10-bound"
  display_name          = "gc10-bound"
  service_account_email = google_service_account.caller.email
  restrictions {
    api_targets { service = "aiplatform.googleapis.com" }
    server_key_restrictions { allowed_ips = ["192.0.2.10"] }
  }
  depends_on = [google_project_service.apis]
}

# 2d: prompt caching off. No Terraform resource exists, so the guide's own PATCH (and back on at destroy).
resource "terraform_data" "cache_off" {
  input = var.project
  provisioner "local-exec" {
    command = <<-EOT
      curl -s -o /dev/null -w "cacheConfig PATCH: HTTP %%{http_code}\n" -X PATCH \
        -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \
        "https://us-central1-aiplatform.googleapis.com/v1/projects/${self.input}/cacheConfig" \
        -d '{"name": "projects/${self.input}/cacheConfig", "disableCache": true}'
    EOT
  }
  provisioner "local-exec" {
    when    = destroy
    command = <<-EOT
      curl -s -o /dev/null -w "cacheConfig PATCH: HTTP %%{http_code}\n" -X PATCH \
        -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \
        "https://us-central1-aiplatform.googleapis.com/v1/projects/${self.input}/cacheConfig" \
        -d '{"name": "projects/${self.input}/cacheConfig", "disableCache": false}'
    EOT
  }
  depends_on = [google_project_service.apis]
}

output "next" {
  value = "bash ../cloud/deploy.sh test   (IAM can take a few minutes; WAIT means run it again)"
}

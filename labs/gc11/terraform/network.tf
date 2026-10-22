# Lesson 11.2: no internet path; Google APIs through a Private Service Connect endpoint and a private DNS zone.

resource "google_compute_network" "helpdesk" {
  name                    = "helpdesk-vpc"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.apis]
}

resource "google_compute_subnetwork" "helpdesk_eu" {
  name                     = "helpdesk-eu"
  region                   = var.region
  network                  = google_compute_network.helpdesk.id
  ip_cidr_range            = "10.10.0.0/24"
  private_ip_google_access = true # fallback path; it doesn't support *.rep.googleapis.com endpoints
}

# No google_compute_router_nat and no external IPs: the only way out is the PSC endpoint below.

resource "google_compute_global_address" "psc_apis" {
  provider     = google-beta
  name         = "psc-google-apis"
  address_type = "INTERNAL"
  purpose      = "PRIVATE_SERVICE_CONNECT"
  network      = google_compute_network.helpdesk.id
  address      = var.psc_ip
}

resource "google_compute_global_forwarding_rule" "psc_apis" {
  provider              = google-beta
  name                  = "tsgapis" # 1-20 lowercase letters and digits, starting with a letter
  target                = "vpc-sc" # only APIs that support VPC Service Controls; use all-apis if you need others
  network               = google_compute_network.helpdesk.id
  ip_address            = google_compute_global_address.psc_apis.id
  load_balancing_scheme = ""
}

# Default API names (REGION-aiplatform.googleapis.com, bigquery.googleapis.com) resolve to the endpoint.
resource "google_dns_managed_zone" "googleapis" {
  name       = "googleapis-private"
  dns_name   = "googleapis.com."
  visibility = "private"
  private_visibility_config {
    networks {
      network_url = google_compute_network.helpdesk.id
    }
  }
  depends_on = [google_project_service.apis]
}

resource "google_dns_record_set" "googleapis_a" {
  managed_zone = google_dns_managed_zone.googleapis.name
  name         = "googleapis.com."
  type         = "A"
  ttl          = 300
  rrdatas      = [var.psc_ip]
}

resource "google_dns_record_set" "googleapis_cname" {
  managed_zone = google_dns_managed_zone.googleapis.name
  name         = "*.googleapis.com."
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["googleapis.com."]
}

resource "google_compute_firewall" "deny_all_egress" {
  name               = "deny-all-egress"
  network            = google_compute_network.helpdesk.id
  direction          = "EGRESS"
  priority           = 65000
  destination_ranges = ["0.0.0.0/0"]
  deny {
    protocol = "all"
  }
}

resource "google_compute_firewall" "allow_google_apis_egress" {
  name               = "allow-google-apis-egress"
  network            = google_compute_network.helpdesk.id
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = ["${var.psc_ip}/32"]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

# Lesson 11.2 + 11.5: no internet path. The one way out is a Private Service Connect endpoint for the EU Agent Platform
# host (aiplatform.eu.rep.googleapis.com), so the network itself holds the residency pin.
#
# Why not a PSC endpoint for global Google APIs (the earlier version of this lab): in our 12 Nov 2026 run
# gemini-3.1-flash-lite answered only on global, eu and us, never on a single region, so the Helpdesk calls location
# eu. Google's all-apis bundle "excludes *.rep.googleapis.com", and the vpc-sc bundle returned 503 "VPC network mapping
# unavailable" in a project with no organization. A regional endpoint targets exactly one host.

resource "google_compute_network" "helpdesk" {
  name                    = "helpdesk-vpc"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.apis]
}

resource "google_compute_subnetwork" "helpdesk_eu" {
  name          = "helpdesk-eu"
  region        = var.region
  network       = google_compute_network.helpdesk.id
  ip_cidr_range = "10.10.0.0/24"
  # no Private Google Access: it "doesn't support regional and multi-regional endpoints", and nothing here needs it
}

# No google_compute_router_nat and no external IPs: the only way out is the endpoint below.

resource "google_network_connectivity_regional_endpoint" "aiplatform_eu" {
  name              = "aiplatform-eu"
  location          = var.region
  target_google_api = var.model_host
  access_type       = "REGIONAL"
  address           = var.endpoint_ip
  network           = google_compute_network.helpdesk.id
  subnetwork        = google_compute_subnetwork.helpdesk_eu.id
  depends_on        = [google_project_service.apis]
}

# The model host resolves to the endpoint inside the VPC; every other name keeps resolving to public addresses,
# which the firewall then refuses.
resource "google_dns_managed_zone" "aiplatform_eu" {
  name        = "aiplatform-eu-rep"
  dns_name    = "${var.model_host}."
  description = "The EU Agent Platform host through its PSC endpoint"
  visibility  = "private"
  private_visibility_config {
    networks {
      network_url = google_compute_network.helpdesk.id
    }
  }
  depends_on = [google_project_service.apis]
}

resource "google_dns_record_set" "aiplatform_eu_a" {
  managed_zone = google_dns_managed_zone.aiplatform_eu.name
  name         = "${var.model_host}."
  type         = "A"
  ttl          = 300
  rrdatas      = [var.endpoint_ip]
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

resource "google_compute_firewall" "allow_aiplatform_eu_egress" {
  name               = "allow-aiplatform-eu-egress"
  network            = google_compute_network.helpdesk.id
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = ["${var.endpoint_ip}/32"]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

# Optional (create_test_vm = true): one small VM with NO external IP that calls Gemini once at boot through the
# private path and prints the result to its serial port. Billed per second while it exists; delete it after the test.
resource "google_compute_instance" "helpdesk_vm" {
  count        = var.create_test_vm ? 1 : 0
  name         = "helpdesk-vm"
  zone         = "${var.region}-a"
  machine_type = "e2-small"
  labels       = { app = "tsg-helpdesk", ai_workload = "true" }

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.helpdesk_eu.id
    # no access_config block = no external IP
  }

  service_account {
    email  = google_service_account.chatbot_runtime.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot = true
  }

  metadata = {
    startup-script = templatefile("${path.module}/scripts/smoke_call.sh.tftpl", {
      project = var.project_id
      region  = var.region
      model   = var.model
    })
  }
}

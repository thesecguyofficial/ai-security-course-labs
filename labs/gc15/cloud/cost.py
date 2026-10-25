"""
cost.py: what the guided build costs per hour, from the list prices we read on 25 Oct 2026 (us-central1).
Prices change: check the pages below before you start. `make cost` prints this table.

  Agent Platform inference node hour, e2-standard-4: $0.1541128   https://cloud.google.com/vertex-ai/pricing
  Private Service Connect endpoint (forwarding rule): $0.01 / hour   https://cloud.google.com/vpc/pricing
  Cloud KMS software key version: $0.06 / month       https://cloud.google.com/kms/pricing
  Cloud Scheduler: 3 jobs free per billing account     https://cloud.google.com/scheduler/pricing
"""

NODE_HOUR = 0.1541128      # e2-standard-4, one replica
PSC_HOUR = 0.01
KMS_MONTH = 0.06
HOURS_PER_MONTH = 730      # used only to turn the key's monthly price into an hourly one


def main():
    hourly = NODE_HOUR + PSC_HOUR + KMS_MONTH / HOURS_PER_MONTH
    print(f"{'item':<44}{'per hour':>10}")
    print(f"{'inference node, e2-standard-4 (1 replica)':<44}{NODE_HOUR:>10.4f}")
    print(f"{'Private Service Connect endpoint':<44}{PSC_HOUR:>10.4f}")
    print(f"{'Cloud KMS key version ($0.06 a month)':<44}{KMS_MONTH / HOURS_PER_MONTH:>10.4f}")
    print(f"{'total while the model is deployed':<44}{hourly:>10.4f}")
    print(f"\nThe auto-undeploy job runs 60 minutes after you deploy: about ${hourly:.2f} if you forget everything else.")
    print("Not included: Artifact Registry storage for the image, Cloud Build minutes, Cloud Storage for the model, BigQuery, logs.")


if __name__ == "__main__":
    main()

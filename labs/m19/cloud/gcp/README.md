# Capstone cloud part: Google Cloud stream

Status, 15 November 2026: **not built yet.** The Google Cloud modules (GC10 to GC16) are open, but the capstone's
Google Cloud file is not written. When it is, this folder gets a `deployment.json` and `cloud_check.py --stream gcp`
rules for the same Helpdesk on Google Cloud, and the rubric's cloud row accepts it exactly like the AWS one.

Until then, do the cloud part on AWS (`cloud/aws/`), which needs no AWS account, and leave `capstone.json` at `aws`.
Each finding names the setting and the AWS lesson that teaches it; the Google Cloud module with the same number
(GC11 for a finding that cites 11.x) covers the same topic. If you took the Google Cloud stream, you may describe your Google Cloud version in `report/FINDINGS.md`; the grader marks
the cloud row from the AWS check and treats your Google Cloud notes as extra evidence.

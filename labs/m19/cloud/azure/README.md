# Capstone cloud part: Azure stream

Status, 15 November 2026: **not built yet.** The Azure modules (Azure M1 to M7) are open, but the capstone's Azure
cloud file is not written. When it is, this folder gets a `deployment.json` and `cloud_check.py --stream azure` rules
for the same Helpdesk on Microsoft Foundry, and the rubric's cloud row accepts it exactly like the AWS one.

Until then, do the cloud part on AWS (`cloud/aws/`), which needs no AWS account, and leave `capstone.json` at `aws`.
Each finding names the setting and the AWS lesson that teaches it; the Azure module with the same number (Azure M2 for a
finding that cites 11.x) covers the same topic. If you took the Azure stream, you may describe your Azure version in `report/FINDINGS.md`; the grader marks the cloud row
from the AWS check and treats your Azure notes as extra evidence.

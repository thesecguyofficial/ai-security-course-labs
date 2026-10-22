#!/usr/bin/env bash
# Read-only checks of the deployed controls, from Cloud Shell or your laptop. Changes nothing.
#   scripts/check_live.sh PROJECT_ID REGION
set -uo pipefail
PROJECT=${1:?project id}; REGION=${2:?region}
echo "== 11.1 user-managed keys on chatbot-runtime (expect none)"
gcloud iam service-accounts keys list --iam-account="chatbot-runtime@${PROJECT}.iam.gserviceaccount.com" \
  --managed-by=user --project="$PROJECT"
echo "== 11.1 custom role permissions (expect only aiplatform.endpoints.predict)"
gcloud iam roles describe helpdeskModelCaller --project="$PROJECT" --format="value(includedPermissions)"
echo "== 11.2 PSC endpoint for Google APIs"
gcloud compute forwarding-rules describe tsgapis --global --project="$PROJECT" --format="value(target,IPAddress)"
echo "== 11.3 dataset default keys"
for ds in helpdesk_tickets ai_logs; do
  bq --project_id="$PROJECT" show --format=prettyjson "$ds" | grep -A2 -i "defaultEncryptionConfiguration" || echo "$ds: none"
done
echo "== 11.3 cache config"
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://${REGION}-aiplatform.googleapis.com/v1/projects/${PROJECT}/cacheConfig"; echo
echo "== 11.4 Data Access audit config for aiplatform.googleapis.com"
gcloud projects get-iam-policy "$PROJECT" --format=json | python3 -c \
  'import json,sys; p=json.load(sys.stdin); print([a for a in p.get("auditConfigs",[]) if a["service"]=="aiplatform.googleapis.com"])'

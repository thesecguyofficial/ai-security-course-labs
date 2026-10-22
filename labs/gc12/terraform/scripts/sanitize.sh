#!/usr/bin/env bash
# Call the sanitize API directly (the self-hosted path). Prints Model Armor's sanitizationResult.
#   scripts/sanitize.sh PROJECT_ID REGION "text to screen"
set -euo pipefail
PROJECT=${1:?project id}; REGION=${2:?region}; TEXT=${3:?text}
NAME="projects/${PROJECT}/locations/${REGION}/templates/helpdesk-guard"
BODY=$(python3 -c 'import json,sys; print(json.dumps({"userPromptData": {"text": sys.argv[1]}}))' "$TEXT")
curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \
  "https://modelarmor.${REGION}.rep.googleapis.com/v1/${NAME}:sanitizeUserPrompt" -d "$BODY"
echo

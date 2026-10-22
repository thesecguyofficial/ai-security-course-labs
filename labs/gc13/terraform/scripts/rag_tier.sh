#!/usr/bin/env bash
# Set the project's RAG Engine tier (RagEngineConfig.ragManagedDbConfig) in one region.
#   scripts/rag_tier.sh PROJECT_ID REGION basic          # the cheapest provisioned tier (100 processing units)
#   scripts/rag_tier.sh PROJECT_ID REGION unprovisioned  # TEARDOWN: deletes the managed database and its data,
#                                                        # and stops its billing. Can't be undone.
set -euo pipefail
PROJECT=${1:?project id}; REGION=${2:?region}; TIER=${3:?basic or unprovisioned}
case "$TIER" in basic|unprovisioned) ;; *) echo "tier must be basic or unprovisioned" >&2; exit 2;; esac
NAME="projects/${PROJECT}/locations/${REGION}/ragEngineConfig"
curl -s -X PATCH -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \
  "https://${REGION}-aiplatform.googleapis.com/v1/${NAME}" \
  -d "{\"name\": \"${NAME}\", \"ragManagedDbConfig\": {\"${TIER}\": {}}}"
echo
echo "Check it: curl -s -H \"Authorization: Bearer \$(gcloud auth print-access-token)\" https://${REGION}-aiplatform.googleapis.com/v1/${NAME}"

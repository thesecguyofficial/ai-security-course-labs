#!/usr/bin/env bash
# Lesson 11.4: switch request-response logging on (or off) for one publisher model in one project and region.
# It uses setPublisherModelConfig, which is in the v1beta1 API only (not v1): check its launch stage on Google's
# request-response logging page before you depend on it.
#
#   scripts/request_response_logging.sh on   PROJECT_ID REGION [MODEL]
#   scripts/request_response_logging.sh off  PROJECT_ID REGION [MODEL]
#   scripts/request_response_logging.sh show PROJECT_ID REGION [MODEL]
#
# Logged prompts and answers are customer data: the ai_logs dataset has a CMEK default key and narrow readers.
set -euo pipefail
ACTION=${1:?on|off|show}; PROJECT=${2:?project id}; REGION=${3:?region}
MODEL=${4:-publishers/google/models/gemini-3.1-flash-lite}
BASE="https://${REGION}-aiplatform.googleapis.com/v1beta1/projects/${PROJECT}/locations/${REGION}/${MODEL}"
TOKEN=$(gcloud auth print-access-token)

if [ "$ACTION" = "show" ]; then
  curl -s -H "Authorization: Bearer $TOKEN" "${BASE}:fetchPublisherModelConfig"; echo; exit 0
fi
if [ "$ACTION" = "on" ]; then ENABLED=true; else ENABLED=false; fi
# Full table reference: the dataset must exist and the table must not exist yet (Agent Platform creates it).
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "${BASE}:setPublisherModelConfig" \
  -d "{\"publisherModelConfig\": {\"loggingConfig\": {\"enabled\": ${ENABLED}, \"samplingRate\": 1,
       \"bigqueryDestination\": {\"outputUri\": \"bq://${PROJECT}.ai_logs.request_response_logging\"}}}}"
echo

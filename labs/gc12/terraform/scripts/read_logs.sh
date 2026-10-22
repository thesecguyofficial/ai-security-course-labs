#!/usr/bin/env bash
# Show the last sanitize log entries (they contain raw prompts: treat the output as sensitive).
#   scripts/read_logs.sh PROJECT_ID
set -euo pipefail
PROJECT=${1:?project id}
gcloud logging read \
  'jsonPayload.@type="type.googleapis.com/google.cloud.modelarmor.logging.v1.SanitizeOperationLogEntry"' \
  --project="$PROJECT" --limit=10 --freshness=1h --format=json

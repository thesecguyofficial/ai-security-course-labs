#!/usr/bin/env bash
# Import files from Cloud Storage into one corpus (RagFiles import). Returns a long-running operation.
#   scripts/import_files.sh REGION CORPUS_NAME gs://BUCKET/file1.txt [gs://BUCKET/file2.txt ...]
# CORPUS_NAME is the full name Terraform prints, e.g. projects/123/locations/europe-west4/ragCorpora/456.
# List a bucket's files with: gcloud storage ls gs://BUCKET
set -euo pipefail
REGION=${1:?region}; CORPUS=${2:?corpus name}; shift 2
[ $# -gt 0 ] || { echo "give at least one gs:// file" >&2; exit 2; }
URIS=$(python3 -c 'import json, sys; print(json.dumps(sys.argv[1:]))' "$@")
curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \
  "https://${REGION}-aiplatform.googleapis.com/v1/${CORPUS}/ragFiles:import" \
  -d "{\"importRagFilesConfig\": {\"gcsSource\": {\"uris\": ${URIS}}}}"
echo

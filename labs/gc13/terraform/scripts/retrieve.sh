#!/usr/bin/env bash
# Ask RAG Engine for passages from ONE corpus, as whoever is signed in to gcloud (you, or the agent's account via
# --impersonate-service-account). Prints the RetrieveContextsResponse JSON.
#   scripts/retrieve.sh PROJECT_ID REGION CORPUS_NAME "question" [metadata filter]
set -euo pipefail
PROJECT=${1:?project id}; REGION=${2:?region}; CORPUS=${3:?corpus name}; Q=${4:?question}; FILTER=${5:-}
BODY=$(python3 -c '
import json, sys
cfg = {"topK": 3}
if sys.argv[3]:
    cfg["filter"] = {"metadataFilter": sys.argv[3]}
print(json.dumps({"vertexRagStore": {"ragResources": [{"ragCorpus": sys.argv[1]}]},
                  "query": {"text": sys.argv[2], "ragRetrievalConfig": cfg}}))' "$CORPUS" "$Q" "$FILTER")
curl -s -X POST -H "Authorization: Bearer ${TSG_TOKEN:-$(gcloud auth print-access-token)}" -H "Content-Type: application/json" \
  "https://${REGION}-aiplatform.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}:retrieveContexts" -d "$BODY"
echo

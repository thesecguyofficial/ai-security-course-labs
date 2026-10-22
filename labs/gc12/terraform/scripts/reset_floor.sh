#!/usr/bin/env bash
# Teardown step 2 of 2 (after `terraform destroy`): switch the project floor setting off again.
# Terraform leaves the floor setting in place (deletion_policy ABANDON) because it is a per-project singleton.
#   scripts/reset_floor.sh PROJECT_ID
set -euo pipefail
PROJECT=${1:?project id}
# Floor settings live at locations/global: Google's floor settings page points gcloud at the global endpoint.
# Set it for this script only, whatever regional override your gcloud config has.
export CLOUDSDK_API_ENDPOINT_OVERRIDES_MODELARMOR="https://modelarmor.googleapis.com/"
gcloud model-armor floorsettings update \
  --full-uri="projects/${PROJECT}/locations/global/floorSetting" \
  --enable-floor-setting-enforcement=FALSE \
  --clear-integrated-services
gcloud model-armor floorsettings describe --full-uri="projects/${PROJECT}/locations/global/floorSetting"

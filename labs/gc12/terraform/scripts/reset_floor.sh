#!/usr/bin/env bash
# Teardown step 2 of 2 (after `terraform destroy`): switch the project floor setting off again.
# Terraform leaves the floor setting in place (deletion_policy ABANDON) because it is a per-project singleton.
#   scripts/reset_floor.sh PROJECT_ID
set -euo pipefail
PROJECT=${1:?project id}
gcloud model-armor floorsettings update \
  --full-uri="projects/${PROJECT}/locations/global/floorSetting" \
  --enable-floor-setting-enforcement=FALSE \
  --clear-integrated-services
gcloud model-armor floorsettings describe --full-uri="projects/${PROJECT}/locations/global/floorSetting"

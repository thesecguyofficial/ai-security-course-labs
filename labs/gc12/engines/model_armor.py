"""
OPTIONAL: the real Model Armor sanitize API (README Step 8). Costs nothing within the free monthly token allowance,
but it IS a call to Google Cloud in your own project. Not used by `make test`. Not run by the lab authors
(no cloud account in the build environment): treat it as a starting point and read the API reference.

    gcloud auth login && gcloud config set project YOUR_PROJECT
    python3 run_suite.py --engine model-armor \
        --template-name projects/YOUR_PROJECT/locations/europe-west4/templates/helpdesk-guard

Endpoint (regional): https://modelarmor.LOCATION.rep.googleapis.com/v1/{template}:sanitizeUserPrompt
Bodies: {"userPromptData": {"text": ...}} and {"modelResponseData": {"text": ...}, "userPrompt": ...}
Needs roles/modelarmor.user on the caller.
"""

import json
import os
import subprocess
import urllib.error
import urllib.request


class ModelArmorEngine:
    name = "Model Armor (real API)"

    def __init__(self, template_name: str = "", **_):
        if not template_name or "/locations/" not in template_name:
            raise SystemExit("--template-name projects/P/locations/L/templates/T is required for --engine model-armor")
        self.template_name = template_name
        self.location = template_name.split("/locations/")[1].split("/")[0]
        self.base = f"https://modelarmor.{self.location}.rep.googleapis.com/v1/{template_name}"
        self.token = os.environ.get("MODEL_ARMOR_TOKEN") or subprocess.run(
            ["gcloud", "auth", "print-access-token"], capture_output=True, text=True, check=True).stdout.strip()

    def _post(self, method: str, body: dict) -> dict:
        req = urllib.request.Request(f"{self.base}:{method}", data=json.dumps(body).encode(), method="POST",
                                     headers={"Authorization": f"Bearer {self.token}",
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise ConnectionError(f"Model Armor returned HTTP {e.code}: {e.read()[:300]!r}") from e
        except OSError as e:
            raise ConnectionError(f"Model Armor unreachable: {e}") from e

    def sanitize_user_prompt(self, text: str) -> dict:
        return self._post("sanitizeUserPrompt", {"userPromptData": {"text": text}})

    def sanitize_model_response(self, text: str, user_prompt: str = "") -> dict:
        body = {"modelResponseData": {"text": text}}
        if user_prompt:
            body["userPrompt"] = user_prompt
        return self._post("sanitizeModelResponse", body)

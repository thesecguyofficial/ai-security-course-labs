"""
armor_offline.py: a fake Model Armor client for TSG_MODE=offline, passed to ModelArmorPlugin(client=...).

ADK's plugin accepts "an optional pre-constructed async client (e.g. for testing)". This one answers with real
modelarmor_v1 result objects, decided by the lab's twin detector (../../gcp_twin.py), so the plugin's own decision
code runs unchanged. Set TSG_ARMOR_OUTAGE=1 to make every call fail.
"""

from __future__ import annotations

import os
import pathlib
import sys
from types import SimpleNamespace

from google.cloud import modelarmor_v1 as ma

sys.path.append(str(pathlib.Path(__file__).resolve().parents[2]))
from gcp_twin import ModelArmorTwin  # noqa: E402


class TwinModelArmorClient:
    def __init__(self):
        self.twin = ModelArmorTwin(available=os.environ.get("TSG_ARMOR_OUTAGE") != "1")
        self.transport = SimpleNamespace(close=self._close)

    async def _close(self):
        return None

    def _result(self, name: str, text: str):
        r = self.twin.sanitize(text, name)["sanitizationResult"]
        return SimpleNamespace(sanitization_result=ma.SanitizationResult(
            filter_match_state=ma.FilterMatchState[r["filterMatchState"]],
            invocation_result=ma.InvocationResult[r["invocationResult"]]))

    async def sanitize_user_prompt(self, request):
        return self._result(request.name, request.user_prompt_data.text)

    async def sanitize_model_response(self, request):
        return self._result(request.name, request.model_response_data.text)

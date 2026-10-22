"""
standin_llm.py: an ADK model class that is NOT AI, for running the real ADK runtime with no cloud account.

It wraps the lab's StandInModel (../../stand_in_model.py): picks tools, obeys [LAB-INJECTED-DIRECTIVE ...] text it
finds in tool results, and quotes what tools returned. Same decisions on every run.
"""

from __future__ import annotations

import pathlib
import sys
from typing import AsyncGenerator

from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types

sys.path.append(str(pathlib.Path(__file__).resolve().parents[2]))
from stand_in_model import StandInModel  # noqa: E402


class StandInLlm(BaseLlm):
    model: str = "stand-in-not-ai"

    async def generate_content_async(self, llm_request: LlmRequest, stream: bool = False
                                     ) -> AsyncGenerator[LlmResponse, None]:
        user_text, calls, results = "", {}, []
        for content in llm_request.contents:
            for part in content.parts or []:
                if content.role == "user" and part.text:
                    user_text, calls, results = part.text, {}, []         # a new question starts a new turn
                elif part.function_call:
                    calls[part.function_call.id] = (part.function_call.name, dict(part.function_call.args or {}))
                elif part.function_response:
                    name, args = calls.get(part.function_response.id, (part.function_response.name, {}))
                    results.append({"tool": name, "args": args, "result": dict(part.function_response.response or {})})
        step = StandInModel().next_step(user_text, _adapt(results))
        if "call" in step:
            name, args = step["call"]
            if name == "search_kb":
                args = {"query": args["query"]}     # the hardened tool has no "team" parameter to fill in
            part = types.Part(function_call=types.FunctionCall(name=name, args=args))
        else:
            part = types.Part(text=step["text"])
        yield LlmResponse(content=types.Content(role="model", parts=[part]))


def _adapt(results: list[dict]) -> list[dict]:
    """The ADK tools return {"passages": [...]}; show them to the stand-in in RAG Engine's response shape."""
    out = []
    for r in results:
        res = r["result"]
        if "passages" in res:
            res = {"contexts": {"contexts": [{"text": p["text"], "sourceUri": p["source_uri"]} for p in res["passages"]]}}
        out.append(dict(r, result=res))
    return out

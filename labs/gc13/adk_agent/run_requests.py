"""
run_requests.py: send the guided build's five requests to the ADK Helpdesk agent and print what happens.

    pip install -r requirements.txt                       # once (google-adk[gcp]==2.12.0)
    python3 run_requests.py                               # offline: stand-in model, twins, real ADK runtime
    TSG_MODEL_ARMOR_TEMPLATE=x python3 run_requests.py    # offline, with the Model Armor plugin (fake client)
    python3 run_requests.py --only G5                     # one request
    (cloud: GUIDED-BUILD.md Step 4 sets TSG_MODE=cloud and the real template and corpora)

Who is asking comes from a "verified ID token" (the lab's identity twin). In production your front end verifies
the token and YOUR server writes end_user and groups into session state; the client never sends them.
Confirmation requests are answered by a careful reviewer: approve closing T-2041, reject any email that isn't to
example.com or to the ticket's own customer. Use --ask to answer them yourself.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import pathlib
import sys
import warnings

sys.path.append(str(pathlib.Path(__file__).resolve().parent.parent))
from gcp_twin import IdentityTwin  # noqa: E402

REQUESTS = [
    ("G1", "tok-alice-0001", "How do I set up the VPN?"),
    ("G2", "tok-alice-0001", "What discount do hospital partners get in 2027?"),
    ("G3", "tok-alice-0001", "How do I get a refund for a customer?"),
    ("G4", "tok-bob-0002", "Please close ticket T-2041, the customer confirmed it is fixed."),
    ("G5", "tok-alice-0001", "Summarise ticket T-2042 for me."),
]


def careful_reviewer(call: dict) -> bool:
    from tsg_helpdesk import backends
    args = call.get("args", {})
    if call["name"] == "close_ticket":
        return args.get("ticket_id") == "T-2041"
    customer = backends.TICKETS.get(args.get("ticket_id", ""), {}).get("customer")
    return args.get("to", "").endswith("@example.com") or args.get("to") == customer


def _args(args) -> str:
    """Arguments as a person would review them: subject and body left out to keep lines short."""
    return json.dumps({k: v for k, v in dict(args or {}).items() if k not in ("subject", "body")})[:80]


def show(ev) -> list[str]:
    lines = []
    for p in (ev.content.parts if ev.content else []) or []:
        if p.function_call and p.function_call.name == "adk_request_confirmation":
            orig = p.function_call.args["originalFunctionCall"]
            lines.append(f"CONFIRMATION REQUESTED for {orig['name']}({_args(orig['args'])})")
        elif p.function_call:
            lines.append(f"model calls {p.function_call.name}({_args(p.function_call.args)})")
        elif p.function_response:
            lines.append(f"{p.function_response.name} returned {json.dumps(p.function_response.response)[:84]}")
        elif p.text:
            blocked = " [custom_metadata model_armor_blocked]" if (ev.custom_metadata or {}).get("model_armor_blocked") else ""
            lines.append(f"answer: {p.text[:100]}{blocked}")
    return lines


async def run(only: list[str] | None, ask: bool):
    from google.adk.runners import InMemoryRunner
    from google.genai import types
    from tsg_helpdesk import backends
    from tsg_helpdesk.agent import app

    runner = InMemoryRunner(app=app)
    for rid, token, text in REQUESTS:
        if only and rid not in only:
            continue
        user = IdentityTwin.verify(token)
        session = await runner.session_service.create_session(
            app_name=app.name, user_id=user, state={"end_user": user, "groups": IdentityTwin.groups(user)})
        print(f"\n{rid}  {user}: {text}")
        message = types.Content(role="user", parts=[types.Part(text=text)])
        while message is not None:
            pending = None
            async for ev in runner.run_async(user_id=user, session_id=session.id, new_message=message):
                for line in show(ev):
                    print(f"    {line}")
                for p in (ev.content.parts if ev.content else []) or []:
                    if p.function_call and p.function_call.name == "adk_request_confirmation":
                        pending = p.function_call
            message = None
            if pending:
                orig = pending.args["originalFunctionCall"]
                ok = (input("    approve? [y/N] ").strip().lower() == "y") if ask else careful_reviewer(orig)
                print(f"    reviewer: {'APPROVE' if ok else 'REJECT'}")
                message = types.Content(role="user", parts=[types.Part(function_response=types.FunctionResponse(
                    id=pending.id, name="adk_request_confirmation", response={"confirmed": ok}))])
    print(f"\noutbox: {[m['to'] for m in backends.OUTBOX]}   T-2041 status: {backends.STATE['tickets']['T-2041']['status']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--ask", action="store_true", help="answer confirmation requests yourself")
    ap.add_argument("--audit", action="store_true", help="also print the agent's tool-call log lines (tsg.audit)")
    a = ap.parse_args()
    if not os.environ.get("TSG_VERBOSE"):                 # keep ADK's experimental-feature notices out of the way
        warnings.filterwarnings("ignore")
        for name in ("", "google_adk", "google", "google_genai"):
            logging.getLogger(name).setLevel(logging.CRITICAL)   # incl. the plugin's "screening call failed" trace
    if a.audit:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("    audit: %(message)s"))
        audit = logging.getLogger("tsg.audit")
        audit.addHandler(handler)
        audit.setLevel(logging.INFO)
        audit.propagate = False
    print(f"mode: {os.environ.get('TSG_MODE', 'offline')}, Model Armor plugin: "
          f"{'on' if os.environ.get('TSG_MODEL_ARMOR_TEMPLATE') else 'off'}, tool output screened: "
          f"{'yes' if os.environ.get('TSG_MODEL_ARMOR_TEMPLATE') and os.environ.get('TSG_SCREEN_TOOL_OUTPUT', '1') == '1' else 'no'}")
    asyncio.run(run(a.only, a.ask))


if __name__ == "__main__":
    main()

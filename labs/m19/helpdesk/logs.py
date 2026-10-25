"""The app log: one JSON object per line. Core file: do not edit.

The capstone's attack log (detections/logs/) uses exactly the same fields, so a detection rule you write for the
attack log also runs on the log your own Helpdesk writes (state/app-log.jsonl).

Fields on every event: ts (UTC), event, request_id, session, user, user_role, user_tenant.
Events and their extra fields:
  request         chars, ip
  blocked         guard, reason
  retrieval       doc_id, doc_tenant, doc_audience, doc_source, doc_flags
  mcp_tools_list  server, tools_hash, tool_names
  tool_call       tool, server, decision, reason, untrusted_in_context, + recipient, recipient_domain,
                  recipient_is_requester, recipient_internal (send_email) | order, order_owner_is_user (lookup_order)
                  | target, target_is_user (crm_lookup)
  response        chars, contains (list of canary labels found in the reply, for the lab only)
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib
import threading

_LOCK = threading.Lock()


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class AppLog:
    def __init__(self, path: pathlib.Path | None):
        self.path = path
        self.events: list[dict] = []          # kept in memory too, for tests and evals

    def write(self, event: str, ctx_user: dict, request_id: str, session: str, **fields) -> dict:
        rec = {"ts": now_iso(), "event": event, "request_id": request_id, "session": session,
               "user": ctx_user.get("email", "?"), "user_role": ctx_user.get("role", "?"),
               "user_tenant": ctx_user.get("tenant", "?")}
        rec.update(fields)
        self.events.append(rec)
        if self.path is not None:
            with _LOCK:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, sort_keys=False) + "\n")
        return rec

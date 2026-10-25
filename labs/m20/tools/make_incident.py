"""Regenerate data/incident/api-audit.jsonl: a morning on the FIRST DRAFT, recorded by the two APIs.

    python3 tools/make_incident.py

Real lab runs, not hand-written rows: two normal requests, then an attacker who read the mail agent's debug log
replays the token at the tickets API and twice at the mail API. Timestamps are shifted to one fixed morning so the
file is the same on every laptop (jti values change on each run; the hunt doesn't care).
"""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import oauth  # noqa: E402
from services import Chain  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent.parent / "data" / "incident" / "api-audit.jsonl"
START = 1800000000  # 2027-01-15 08:00 UTC

with Chain("first-draft") as c:
    c.ask("bob", "Show me T-4712")
    c.ask("alice", "Summarise T-4713 and email me the summary")
    stolen = c.debug_log[-1]["authorization"][7:]
    oauth.call("GET", c.services["tickets-api"].url + "/tickets/T-4713", token=stolen)
    for subject in ("Your account is locked", "Final reminder"):
        oauth.call("POST", c.services["mail-api"].url + "/send", token=stolen,
                   body={"to": "alice@example.com", "subject": subject, "body": "click here"})
    rows = c.audit
base = rows[0]["ts"]
with OUT.open("w") as f:
    for i, row in enumerate(rows):
        row["ts"] = START + (row["ts"] - base) + i * 37
        f.write(json.dumps(row, sort_keys=True) + "\n")
print(f"wrote {len(rows)} rows to {OUT}")

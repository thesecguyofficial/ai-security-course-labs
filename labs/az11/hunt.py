"""
hunt.py: answer "who asked the model what?" from API Management AI gateway logs (lesson 11.4).

    python3 hunt.py

Contoso piloted the API Management AI gateway in front of its STAGING helpdesk deployment, with "Log LLM messages"
on (prompts and completions up to 32 KB per entry; bigger messages are split into 32-KB pieces with sequence numbers).
Its gateway was reachable from the internet. These are the (fake) logs for Monday 19 October 2026:

    logs/apim-gateway-log.json        ApiManagementGatewayLogs: who called (CallerIpAddress), CorrelationId, status
    logs/apim-llm-log.json            ApiManagementGatewayLlmLog: RequestMessages / ResponseMessages, tokens, SequenceNumber
    logs/foundry-requestresponse.json the Foundry resource's own RequestResponse rows for the same minutes

Rules: H01 calls from outside Contoso's networks; H02 instruction-override wording in a prompt; H03 a prompt big
enough to be split (bulk data pasted in). The challenge is in reconstruct() below.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from foundry_twin import load

CONTOSO_NETWORKS = [ipaddress.ip_network("10.20.0.0/16")]
OVERRIDE_WORDS = ("ignore your previous instructions", "ignore previous instructions", "system prompt")
CHUNK = 32 * 1024


@dataclass
class Exchange:
    correlation_id: str
    time: str
    caller: str
    prompt: str
    completion: str
    tokens: int
    pieces: int
    hits: list[str] = field(default_factory=list)


def reconstruct(rows: list[dict]) -> tuple[str, str]:
    """Join the log rows of ONE exchange (same CorrelationId) back into (prompt, completion).

    Requests and responses are separate entries. A message over 32 KB arrives as several entries, one per 32-KB
    piece, each with a SequenceNumber. CHALLENGE 3: this version joins the pieces in the order the rows came back
    from the query. Is that the order they were written in?
    """
    prompt = "".join(m["content"] for r in rows if r.get("RequestMessages") for m in r["RequestMessages"])
    completion = "".join(m["content"] for r in rows if r.get("ResponseMessages") for m in r["ResponseMessages"])
    return prompt, completion


def exchanges() -> list[Exchange]:
    gw = {r["CorrelationId"]: r for r in load("logs/apim-gateway-log.json")["rows"]}
    by_id: dict[str, list[dict]] = {}
    for r in load("logs/apim-llm-log.json")["rows"]:
        by_id.setdefault(r["CorrelationId"], []).append(r)
    out = []
    for cid, rows in by_id.items():
        prompt, completion = reconstruct(rows)
        g = gw.get(cid, {})
        req_rows = [r for r in rows if r.get("RequestMessages")]
        out.append(Exchange(cid, g.get("TimeGenerated", rows[0]["TimeGenerated"]), g.get("CallerIpAddress", "?"),
                            prompt, completion, rows[0].get("TotalTokens", 0), len(req_rows)))
    return sorted(out, key=lambda e: e.time)


def is_contoso(ip: str) -> bool:
    try:
        return any(ipaddress.ip_address(ip) in n for n in CONTOSO_NETWORKS)
    except ValueError:
        return False


def hunt() -> list[Exchange]:
    found = []
    for e in exchanges():
        if not is_contoso(e.caller):
            e.hits.append("H01 caller outside Contoso's networks")
        if any(w in e.prompt.lower() for w in OVERRIDE_WORDS):
            e.hits.append("H02 instruction-override wording")
        if e.pieces > 1 or len(e.prompt.encode()) > CHUNK:
            e.hits.append(f"H03 prompt split into {e.pieces} pieces ({len(e.prompt.encode()):,} bytes): bulk data pasted in")
        if e.hits:
            found.append(e)
    return found


def main() -> None:
    gw = load("logs/apim-gateway-log.json")["rows"]
    llm = load("logs/apim-llm-log.json")["rows"]
    diag = load("logs/foundry-requestresponse.json")["rows"]
    print(f"--- AZ11 hunt · AI gateway pilot, 19 Oct 2026 · {len(gw)} gateway requests, {len(llm)} LLM log rows ---\n")
    hits = hunt()
    for e in hits:
        print(f"  {e.time}  {e.correlation_id}  from {e.caller}  {e.tokens:,} tokens")
        for h in e.hits:
            print(f"      {h}")
        p = e.prompt.replace("\n", " ")
        print(f"      prompt:     {p[:110]}{'...' if len(p) > 110 else ''}")
        if e.pieces > 1:
            print(f"      prompt end: ...{p[-70:]}")
        print(f"      completion: {e.completion[:90]}")
    callers = sorted({r['CallerIPAddress'] for r in diag})
    print(f"\n{len(hits)} suspicious exchanges, all from {', '.join(sorted({e.caller for e in hits}))}.")
    print(f"The Foundry resource's own RequestResponse rows for the same minutes: {len(diag)} rows, caller(s) {', '.join(callers)}")
    print("= the gateway's own address in this sample. Behind a gateway the backend is called BY the gateway, so the person")
    print("  is in the gateway's logs: CallerIpAddress in ApiManagementGatewayLogs, joined to the LLM log on CorrelationId.")


if __name__ == "__main__":
    main()

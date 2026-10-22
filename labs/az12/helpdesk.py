"""
helpdesk.py: the TSG Helpdesk (FICTIONAL Contoso app from labs AZ10/AZ11), offline, with the Foundry guardrail twin.

    python3 helpdesk.py --config contoso "How do I reset my VPN password?"
    python3 helpdesk.py --config fixes --caller priya@contoso.com --ticket 4492 "Summarise ticket 4492"
    python3 helpdesk.py --config fixes --path agent --ticket 4495 --tool mcp:ticket-mailbox "Summarise ticket 4495"

Two paths, as in Foundry:
  model  helpdesk-web -> Chat Completions on deployment `helpdesk-chat` (the AZ11 deployment). The deployment's
         guardrail applies. The APP retrieves KB articles and tickets and decides whether to tag them as documents.
  agent  `helpdesk-agent` (prompt agent on the same deployment). Tickets arrive as TOOL RESPONSES. The AGENT's
         guardrail applies and fully overrides the deployment's.

App-side controls (deterministic, not classifiers), switched on in <config>/app.json:
  normalise_input        clean invisible characters before the guardrail (normalise.py, challenge 1)
  document_embedding     wrap retrieved content in the <documents> delimiter Microsoft documents for Prompt Shields
  retrieval_owner_check  only retrieve tickets the caller owns, and IT-only articles for IT staff (lesson M6)
  recipient_allowlist    send_email may only go to these domains (lesson M7)
"""

import argparse
import json
import os

import guardrail_twin as gt
import normalise as norm
import stand_in_model as model

HERE = os.path.dirname(os.path.abspath(__file__))


def _read(rel: str) -> str:
    with open(os.path.join(HERE, "data", rel), encoding="utf-8") as f:
        return f.read()


def ticket_doc(number: str, extra: dict | None = None) -> dict:
    t = (extra or {}).get(number) or json.load(open(os.path.join(HERE, "data", "tickets.json"), encoding="utf-8"))["tickets"][number]
    return {"id": f"ticket/{number}", "owner": t["owner"],
            "text": f"Ticket {number} | customer {t['customer']} | email {t['email']} phone {t['phone']} | owner {t['owner']}: {t['body']}"}


def kb_doc(name: str) -> dict:
    text = _read(f"kb/{name}")
    return {"id": f"kb/{name}", "it_only": "IT staff only" in text, "text": text}


def is_it_staff(caller: str) -> bool:
    return caller.startswith("it-") and caller.endswith("@contoso.com")


def ask(config: str, user: str, caller: str = "priya@contoso.com", kb: list[str] | None = None,
        tickets: list[str] | None = None, path: str = "model", tool: str = "azure_ai_search",
        tool_payload: dict | None = None, policy_override: str | None = None) -> dict:
    """One request end to end. Returns a record: what was blocked where, what the user saw, which tools ran."""
    app = gt.load(config, "app.json")
    rec = {"config": config, "path": path, "blocked": None, "shown": "", "tools_run": [], "notes": [], "annotations": {}}

    # ---- the app: what the guardrail will see
    text_for_guardrail = norm.normalise(user) if app.get("normalise_input") else user
    docs = [kb_doc(k) for k in (kb or [])] + [ticket_doc(t, tool_payload) for t in (tickets or [])]
    if app.get("retrieval_owner_check"):
        kept = [d for d in docs if (d.get("owner") in (None, caller) or is_it_staff(caller)) and (not d.get("it_only") or is_it_staff(caller))]
        if len(kept) < len(docs):
            rec["defused"] = "app: retrieval access filter (caller can't see " + ", ".join(d["id"] for d in docs if d not in kept) + ")"
        docs = kept

    if path == "model":
        dep = next(d for d in gt.load(config, "deployments.json")["deployments"] if d["name"] == "helpdesk-chat")
        policy_name = dep["properties"]["raiPolicyName"]
    else:
        agent = next(a for a in gt.load(config, "agents.json")["agents"] if a["name"] == "helpdesk-agent")
        policy_name = agent.get("raiPolicyName") or next(
            d for d in gt.load(config, "deployments.json")["deployments"] if d["name"] == agent["model_deployment"])["properties"]["raiPolicyName"]
    policy_name = policy_override or policy_name
    policy = gt.resolve_policy(config, policy_name)
    rec["guardrail"] = policy_name
    asynchronous = policy["properties"].get("mode") == "Asynchronous_filter"

    try:
        # ---- intervention point 1: user input
        prompt_results = {}
        fired = gt.check_text(policy, config, text_for_guardrail, "Prompt", prompt_results)
        tagged = path == "model" and app.get("document_embedding")
        if path == "model":
            fired += gt.check_documents(policy, docs if tagged else [], "Prompt", prompt_results)
            if docs and not tagged and gt._filters(policy, "Indirect Attack", "Prompt") and \
                    any(gt.detectors.document_attack(d["text"])["attackDetected"] for d in docs):
                rec["notes"].append("Indirect Attack is ON, but the app sent the documents untagged: Prompt Shields never saw them")
        rec["annotations"]["prompt"] = prompt_results
        if fired:
            raise gt.Blocked("input", fired[0], gt.input_error(prompt_results))

        # ---- agent: documents arrive as tool responses (intervention point 3)
        if path == "agent":
            tool_results = {}
            if tool in gt.MODERATED_TOOL_TYPES:
                fired = gt.check_documents(policy, docs, "PostToolCall", tool_results)
                if fired:
                    raise gt.Blocked("tool response", fired[0], {"status": 400, "body": {"error": {
                        "code": "content_filter", "type": "content_safety_error", "message": "(lab twin) blocked at tool response"}}})
            else:
                rec["notes"].append(f"tool type '{tool}' has no moderation support: no tool-response control can run on it")
            if tool in gt.MODERATED_TOOL_TYPES and not gt._filters(policy, "Indirect Attack", "PostToolCall") and \
                    any(gt.detectors.document_attack(d["text"])["attackDetected"] for d in docs):
                dep_policy = next(d for d in gt.load(config, "deployments.json")["deployments"]
                                  if d["name"] == agent["model_deployment"])["properties"]["raiPolicyName"]
                rec["notes"].append(f"agent guardrail '{policy_name}' has no Indirect Attack control at the tool response, "
                                    f"and it fully overrides the deployment's '{dep_policy}'")
            rec["annotations"]["tool_response"] = tool_results

        spot = spotlighting_used = path == "model" and tagged and gt.spotlighting_on(policy, app.get("api", "chat_completions"), False)
        model_docs = gt.spotlight(docs) if spot else docs
        if spotlighting_used and docs:
            before, after = sum(len(d["text"]) for d in docs), sum(len(d["text"]) for d in model_docs)
            rec["spotlighting_chars"] = (before, after)
            rec.setdefault("defused", "Spotlighting: the model read the documents as data, not instructions")
        out = model.generate(_read("system_prompt.txt"), user, model_docs, spotlighted=spot)

        # ---- intervention point 2: tool calls (agents; only moderated tools) + the app's own allow-list
        for call in out["tool_calls"]:
            to = call["args"].get("to", "")
            allow = app.get("recipient_allowlist")
            if allow is not None and allow and not any(to.endswith(d) for d in allow):
                rec["notes"].append(f"app: send_email to {to} refused by the recipient allow-list")
                raise gt.Blocked("app", "recipient allow-list (send_email)", {"status": 200, "body": {"tool_refused": to}})
            rec["tools_run"].append(call)

        # ---- intervention point 4: output
        out_results = {}
        fired = gt.check_output(policy, config, out["content"], out_results)
        rec["annotations"]["output"] = out_results
        if fired:
            if asynchronous:
                rec["shown"] = out["content"]
                rec["notes"].append("Asynchronous_filter: the text streamed to the user before the filter signal arrived")
            raise gt.Blocked("output", fired[0], gt.output_response(out["content"], out_results, True))
        rec["shown"] = out["content"]
        rec["response"] = gt.output_response(out["content"], out_results, False)
    except gt.Blocked as b:
        rec["blocked"] = {"stage": b.stage, "control": b.control}
        rec["response"] = b.response
    return rec


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("question")
    p.add_argument("--config", default="contoso", choices=["contoso", "fixes"])
    p.add_argument("--caller", default="priya@contoso.com")
    p.add_argument("--kb", action="append", default=[])
    p.add_argument("--ticket", action="append", default=[])
    p.add_argument("--path", default="model", choices=["model", "agent"])
    p.add_argument("--tool", default="azure_ai_search")
    a = p.parse_args()
    rec = ask(a.config, a.question, a.caller, a.kb, a.ticket, a.path, a.tool)
    print(json.dumps({k: v for k, v in rec.items() if k != "annotations"}, indent=2))


if __name__ == "__main__":
    main()

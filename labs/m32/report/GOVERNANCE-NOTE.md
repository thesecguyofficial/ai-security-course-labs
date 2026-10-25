# Governance and evidence note: TSG Ops Crew

> One page, for the person who has to sign off the Ops Crew going live. Replace every `<...>` and TODO.
> Lessons 18.1 to 18.3. The self-check (R4) looks for the five sections below and at least 8 rows of evidence.

## AI inventory entry

| Field | Value |
|---|---|
| System | TSG Ops Crew (capstone edition), three agents |
| Owner | <role, not a person's name> |
| Purpose | <...> |
| Users | <...> |
| Models | <stand-in locally; the models in your cloud stream> |
| Agents and tools | <triage: none; billing: issue_refund, send_email; analyst: run_query, crm_lookup, crm_list_customers> |
| Data it can read | <...> |
| Third-party components | <crm MCP server, ...> |

## Risk decisions

<Three to five decisions, one line each: the risk, what you decided (fix, reduce, accept, avoid), and who decides.>

## Evidence index

Every control you rely on, and the file, test, eval case or detection rule that proves it works.

| Control | Where it lives | Evidence | Framework reference |
|---|---|---|---|
| <per-agent tool allow-list> | <crew/guards.py authorize_tool_call> | <S03 to S05, inj-03 to inj-06, CI run> | <LLM03:2026; NIST AI RMF MANAGE> |
| TODO | at least 8 rows | | |

## Framework mapping

<Short paragraph or table: which of your controls and records support each NIST AI RMF function (GOVERN, MAP,
MEASURE, MANAGE), and which ISO/IEC 42001 management-system activities they give evidence for (for example risk
assessment, operational controls, monitoring). Map only what you actually did.>

## Residual risk

<What stays risky, who accepts it, and the date the risk is reviewed again.>

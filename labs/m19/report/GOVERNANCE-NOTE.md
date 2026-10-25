# Governance and evidence note: TSG Helpdesk

> One page, for the person who has to sign off the Helpdesk going live. Replace every `<...>` and TODO.
> Lessons 18.1 to 18.3. The self-check (R4) looks for the five sections below and at least 8 rows of evidence.

## AI inventory entry

| Field | Value |
|---|---|
| System | TSG Helpdesk (capstone edition) |
| Owner | <role, not a person's name> |
| Purpose | <...> |
| Users | <...> |
| Model | <stand-in locally; the model in your cloud stream> |
| Data it can read | <...> |
| Actions it can take | <...> |
| Third-party components | <crm MCP server, partner feed, ...> |

## Risk decisions

<Three to five decisions, one line each: the risk, what you decided (fix, reduce, accept, avoid), and who decides.>

## Evidence index

Every control you rely on, and the file, test, eval case or detection rule that proves it works.

| Control | Where it lives | Evidence | Framework reference |
|---|---|---|---|
| <recipient check on send_email> | <helpdesk/guards.py authorize_tool_call> | <S01, inj-01 to inj-06, CI run link> | <LLM01:2026; NIST AI RMF MANAGE> |
| TODO | at least 8 rows | | |

## Framework mapping

<Short paragraph or table: which of your controls and records support each NIST AI RMF function (GOVERN, MAP,
MEASURE, MANAGE), and which ISO/IEC 42001 management-system activities they give evidence for (for example risk
assessment, operational controls, monitoring). Map only what you actually did.>

## Residual risk and sign-off

<What stays risky, who accepts it, and the date the risk is reviewed again.>

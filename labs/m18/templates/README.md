# Governance templates (lesson 18.3)

Copy them, fill them, keep them next to the system they describe. They are deliberately short: a template nobody
finishes protects nobody.

| File | What it is for | Who fills it |
|---|---|---|
| `AI-POLICY.md` | One-page AI policy: what must be true before an AI system goes live, risk appetite, baseline controls, roles | Security with the business owner; approved by leadership |
| `AI-INVENTORY.csv` | One row per AI component (model, embedding model, MCP server, memory store), with owners and the EU AI Act result | Technical owner; `python3 govlab.py inventory` fills it from a system card |
| `MODEL-VENDOR-REVIEW.md` | Licence, data use, certification scope, supply chain, exit plan, decision | Security and procurement, per model, vendor or MCP server |
| `AI-INCIDENT-REPORT.md` | The Module 16 incident report plus AI system details, framework mapping and notification clocks | Security, with legal for section 6 |
| `ASSESSMENT.json`, `RISK-REGISTER.csv`, `EVIDENCE-INDEX.csv` | The risk assessment the lab checks and packs | You, in the lab (`make start` copies them) |

The 1-page **acceptable use policy** for staff (what may be pasted into which AI tool) is in lesson 4.5.

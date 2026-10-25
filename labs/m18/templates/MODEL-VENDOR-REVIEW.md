# Model and vendor review

Template from lesson 18.3. One review per model, AI vendor or MCP server, before onboarding and again on every major
version change. Answers come with evidence (a link, a document, a test result), not "yes".

**Item:** <model, service or MCP server, with exact version> · **Vendor:** <who> · **Reviewer:** <role> · **Date:** <date>

## 1. What and why
- Use case, and which AI system(s) in the inventory it belongs to:
- Data it will see (categories, personal data yes/no, customer data yes/no):
- What it can do (read only, write, send, spend, run code):

## 2. Licence and terms
- Licence or contract, read in full by <role>; is our use allowed?
- Does the vendor use our prompts, files or outputs to train or improve models? Where is that written?
- Retention: how long are prompts and outputs kept, and can we turn logging off or shorten it?
- Where is data processed and stored (regions)? Does that match our residency rules?

## 3. Assurance
- Certifications (for example ISO/IEC 42001, ISO/IEC 27001, SOC 2): **is this exact service in the scope of the
  certificate?** Attach the scope page.
- Model documentation: model card, known limits, evaluation results. For a general-purpose model offered in the EU,
  ask for the documentation its provider gives to downstream providers.
- Security contact and how fast the vendor tells us about incidents that affect us:

## 4. Our own checks
- Supply chain: pinned version and hash, code-free file format, scan result (lessons 9.2 and 9.3), or for an MCP
  server the reviewed tool descriptions and pin (lesson 8.5).
- Our tests: injection and misuse tests run against it (lesson 17.3), with results attached.
- Access: which identity it runs as, and what that identity may do (lesson 7.4).

## 5. Exit plan
How we switch it off or replace it within <days>, and what data we must get back or have deleted.

## 6. Decision
- [ ] Approved  [ ] Approved with conditions: <conditions, owner, due date>  [ ] Rejected
- Next review: <date or "on next major version">

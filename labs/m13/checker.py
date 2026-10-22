"""
checker.py: review a setup of the M13 port, the way you'd review the pull request. Offline, standard library only.

    python3 checker.py first-draft     # make check          (the port as first written)
    python3 checker.py ported          # make check-ported   (Bedrock Agents Classic, fixed)
    python3 checker.py harness         # make check-harness  (AgentCore harness)

19 rules, M13-01 to M13-19, each tagged with the lesson that explains it. M13-20 is yours to write (challenge 2).
Each rule reads only the JSON in setups/<name>/: request bodies, policies, and the app's notes on how it builds
requests. Exit code 1 if any HIGH finding (so it can fail a pipeline).
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass

import twin

RESTRICTED_PREFIXES = ("hr/", "it-admin/")


@dataclass
class Finding:
    rule: str
    severity: str
    lesson: str
    message: str

    def __str__(self):
        return f"[{self.severity:6}] {self.rule} ({self.lesson}) {self.message}"


def _statements(policy: dict) -> list[dict]:
    st = policy.get("Statement", [])
    return st if isinstance(st, list) else [st]


def _as_list(v) -> list:
    return v if isinstance(v, list) else [v]


def _cond_keys(st: dict) -> set[str]:
    return {k.lower() for conds in st.get("Condition", {}).values() for k in conds}


def _acl_sources(s: twin.Setup) -> list[dict]:
    return [twin._connector_params(ds) for ds in s.data_sources["dataSources"]]


# --------------------------------------------------------------------------------------------------------------------
# 13.1  Knowledge base
# --------------------------------------------------------------------------------------------------------------------
def rule_01(s):
    if s.app["identity"]["user_from"] != "session":
        return [Finding("M13-01", "HIGH", "13.1", f"the backend takes the user's identity from the {s.app['identity']['user_from'].replace('_', ' ')}, "
                        "not the signed-in session: anyone can claim to be anyone")]
    return []


def rule_02(s):
    f = s.app["retrieval"].get("filter", {})
    if "request" in f.get("department_from", ""):
        return [Finding("M13-02", "HIGH", "13.1", "per-user access is a metadata filter whose value the browser sends "
                        "(department): a filter is a relevance feature, and a client-supplied scope is a suggestion, not a control")]
    return []


def rule_03(s):
    r = s.app["retrieval"]
    if r.get("implicitFilterConfiguration"):
        return [Finding("M13-03", "HIGH", "13.1", "implicit metadata filtering is on: a model writes the filter from the user's words, "
                        "so the user chooses which department's documents come back")]
    return []


def rule_04(s):
    docs = [k for k in twin.all_docs() if k.startswith(RESTRICTED_PREFIXES)]
    if s.kb_type == "VECTOR":
        return [Finding("M13-04", "HIGH", "13.1", f"{len(docs)} restricted documents (hr/, it-admin/) sit in a customer-managed knowledge base with "
                        "no ACL awareness: any caller of Retrieve gets them unless every request carries the right filter")]
    idx = twin.ingest(s)
    open_restricted = [c.key for c in idx.chunks if c.key.startswith(RESTRICTED_PREFIXES) and c.acl is None]
    if open_restricted:
        return [Finding("M13-04", "HIGH", "13.1", f"restricted documents in a data source without ACL awareness (aclEnabled is not true): "
                        f"{', '.join(open_restricted)} go to everyone")]
    return []


def rule_05(s):
    if (s.kb_access or {}).get("kind") != "global-acl":
        return []
    unknown = sorted({e["Name"] for p in s.kb_access["globalAcl"] for e in p["aclEntries"]} - set(twin.COMPANY["directory"]))
    if unknown:
        return [Finding("M13-05", "LOW", "13.1", f"ACL names not in the identity provider: {', '.join(unknown)}. Emails must match exactly; "
                        "a mismatch fails silently (no results for that person)")]
    return []


def rule_06(s):
    out = []
    for st in _statements(s.kb_service_role["trust"]):
        keys = _cond_keys(st)
        if not {"aws:sourceaccount", "aws:sourcearn"} <= keys:
            out.append(Finding("M13-06", "MEDIUM", "13.1", "knowledge base service role trust policy has no aws:SourceAccount + AWS:SourceArn "
                               "conditions (AWS's documented confused-deputy guard)"))
    return out


def rule_07(s):
    bucket = f"arn:aws:s3:::{twin.BUCKET}"
    for st in _statements(s.kb_service_role["policy"]):
        if st["Effect"] != "Allow":
            continue
        res = _as_list(st.get("Resource", []))
        if any(r in ("*", "arn:aws:s3:::*") for r in res) or not all(r in (bucket, bucket + "/*") for r in res) \
                or "aws:resourceaccount" not in _cond_keys(st):
            return [Finding("M13-07", "MEDIUM", "13.1", "knowledge base service role can read S3 beyond the knowledge base bucket, or without "
                            "an aws:ResourceAccount condition: whoever can point a data source at a bucket can index it")]
    return []


def rule_08(s):
    for st in _statements(s.bucket_policy):
        if st["Effect"] == "Allow" and "s3:PutObject" in _as_list(st["Action"]) and \
                any(r.endswith(f"{twin.BUCKET}/*") for r in _as_list(st["Resource"])):
            who = st.get("Principal", {}).get("AWS", "?")
            return [Finding("M13-08", "MEDIUM", "13.1", f"{who.split(':')[-1]} can write anywhere in the knowledge base bucket: a staff upload "
                            "can land in public/ (poisoning everyone's answers) or in hr/ and inherit HR's ACL prefix")]
    return []


def rule_09(s):
    kb = s.knowledge_base["knowledgeBaseConfiguration"]
    if s.kb_type == "MANAGED":
        key = kb["managedKnowledgeBaseConfiguration"].get("serverSideEncryptionConfiguration", {}).get("kmsKeyArn")
    else:
        enc = s.knowledge_base.get("_vectorBucket", {}).get("encryptionConfiguration", {})
        key = enc.get("kmsKeyArn") if enc.get("sseType") == "aws:kms" else None
    if not key:
        return [Finding("M13-09", "MEDIUM", "13.1", "no customer managed KMS key on the knowledge base, but AnyCompany requires one for "
                        f"{', '.join(twin.COMPANY['cmk_required_for'])} (M11): you can't revoke or audit use of an AWS owned key")]
    return []


def _trail_types(s) -> set[str]:
    types = set()
    for sel in s.logging["cloudtrail"]["AdvancedEventSelectors"]:
        fs = {f["Field"]: f.get("Equals", []) for f in sel["FieldSelectors"]}
        if "Data" in fs.get("eventCategory", []):
            types |= set(fs.get("resources.type", []))
    return types


def rule_10(s):
    if "AWS::Bedrock::KnowledgeBase" not in _trail_types(s):
        return [Finding("M13-10", "MEDIUM", "13.1", "CloudTrail doesn't record Retrieve / RetrieveAndGenerate: they are data events on "
                        "AWS::Bedrock::KnowledgeBase, off by default")]
    return []


def rule_11(s):
    if not any(d["logType"] == "APPLICATION_LOGS" for d in s.logging.get("kbLogDeliveries", [])):
        return [Finding("M13-11", "LOW", "13.1", "no ingestion log delivery (APPLICATION_LOGS): you can't see which documents were "
                        "added, updated or failed in each sync")]
    return []


# --------------------------------------------------------------------------------------------------------------------
# 13.2  Agent
# --------------------------------------------------------------------------------------------------------------------
WRITE_TOOLS = ("reset_mfa",)


def rule_12(s):
    import helpdesk
    out = []
    for tool in WRITE_TOOLS:
        if not helpdesk.tool_available(s, tool):
            continue
        if s.platform == "agentcore-harness":
            t = next(t for t in s.agent["createHarness"]["tools"] if t["name"] == tool)
            if t["type"] != "inline_function":
                out.append(Finding("M13-12", "HIGH", "13.2", f"{tool} runs on the harness side ({t['type']}): the app never sees the call, "
                                   "so nobody confirms it"))
                continue
        if not helpdesk.needs_confirmation(s, tool):
            where = "requireConfirmation is not ENABLED" if s.platform == "bedrock-agents-classic" else "the app doesn't ask the user"
            out.append(Finding("M13-12", "HIGH", "13.2", f"write action {tool} runs without user confirmation ({where}): "
                               "a retrieved document can trigger it"))
        elif not s.app.get("confirmation", {}).get("show_arguments"):
            out.append(Finding("M13-12", "MEDIUM", "13.2", f"the confirmation for {tool} doesn't show the arguments: people approve "
                               "what they can't see"))
    return out


def rule_13(s):
    if s.platform != "bedrock-agents-classic" or not s.lambda_:
        return []
    src = s.lambda_.get("caller_identity_from", "none")
    if src == "none":
        return [Finding("M13-13", "HIGH", "13.2", "the action Lambda doesn't know who the end user is: it acts on whatever target the "
                        "model passes, with the agent's own permissions")]
    if s.app.get("session_attributes_from") != "session":
        return [Finding("M13-13", "HIGH", "13.2", f"the Lambda reads the caller from {src}, but the app copies sessionAttributes from the "
                        "browser's request: the caller is whoever the browser says")]
    return []


def rule_14(s):
    if s.platform != "bedrock-agents-classic" or not s.lambda_:
        return []
    for st in _statements(s.lambda_["resourcePolicy"]):
        if st["Effect"] == "Allow" and st.get("Principal", {}).get("Service") == "bedrock.amazonaws.com":
            keys = _cond_keys(st)
            if "aws:sourcearn" not in keys:
                return [Finding("M13-14", "HIGH", "13.2", "Lambda resource policy lets bedrock.amazonaws.com invoke the function without an "
                                "AWS:SourceArn condition: any agent (another team's, another account's) can call reset_mfa")]
    return []


def rule_15(s):
    if s.platform != "bedrock-agents-classic" or not s.lambda_:
        return []
    for st in _statements(s.lambda_["executionRolePolicy"]):
        acts, res = _as_list(st["Action"]), _as_list(st.get("Resource", []))
        if st["Effect"] == "Allow" and (any(a == "*" or a.endswith(":*") for a in acts) or "*" in res):
            return [Finding("M13-15", "HIGH", "13.2", f"Lambda execution role allows {', '.join(acts)} on {', '.join(res)}: one injected "
                            "call can do anything the identity service can")]
    return []


def rule_16(s):
    import helpdesk
    if helpdesk.code_tool_available(s):
        how = ("the AMAZON.CodeInterpreter action group is enabled" if s.platform == "bedrock-agents-classic"
               else "allowedTools is missing or allows built-ins, so the default shell and file_operations tools are on")
        return [Finding("M13-16", "HIGH", "13.2", f"the agent can run code it doesn't need: {how}")]
    return []


def rule_17(s):
    claim = set(s.app.get("guardrail", {}).get("assumed_to_cover", []))
    if claim & {"retrieved_chunks", "tool_results"} and not s.app.get("screen_retrieved_chunks"):
        return [Finding("M13-17", "MEDIUM", "13.2", "the app assumes the agent's guardrail checks retrieved chunks and tool results; AWS "
                        "documents it on prompts sent to the agent and responses returned (M12: tool results aren't evaluated)")]
    if not s.app.get("screen_retrieved_chunks"):
        return [Finding("M13-17", "LOW", "13.2", "retrieved chunks reach the model unscreened: hidden text in a document is read as "
                        "instructions (challenge 1)")]
    return []


def rule_18(s):
    if s.platform == "bedrock-agents-classic" and "AWS::Bedrock::AgentAlias" not in _trail_types(s):
        return [Finding("M13-18", "MEDIUM", "13.2", "CloudTrail doesn't record InvokeAgent: it is a data event on AWS::Bedrock::AgentAlias, "
                        "off by default")]
    return []


def rule_19(s):
    if s.platform == "bedrock-agents-classic" and not s.agent["createAgent"].get("guardrailConfiguration"):
        return [Finding("M13-19", "MEDIUM", "13.2", "no guardrail associated with the agent (M12 baseline)")]
    return []


# --------------------------------------------------------------------------------------------------------------------
# CHALLENGE 2 (13.2): write this rule
# --------------------------------------------------------------------------------------------------------------------
def rule_20(s):
    """M13-20, HIGH: a principal that end users control (setups/<name>/invokers.json, "end_user_reachable": true) is
    allowed bedrock-agentcore:InvokeHarness. InvokeHarness accepts tools, allowedTools and systemPrompt on every call,
    so that principal can give the agent new tools and new instructions. Name the principal in the message.
    Harness setups only; return [] for others. Today: nothing."""
    return []


RULES = [rule_01, rule_02, rule_03, rule_04, rule_05, rule_06, rule_07, rule_08, rule_09, rule_10, rule_11,
         rule_12, rule_13, rule_14, rule_15, rule_16, rule_17, rule_18, rule_19, rule_20]
ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def run(setup_name: str | twin.Setup) -> list[Finding]:
    s = setup_name if isinstance(setup_name, twin.Setup) else twin.Setup(setup_name)
    found = [f for r in RULES for f in r(s)]
    return sorted(found, key=lambda f: (ORDER[f.severity], f.rule))


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    name = argv[0] if argv else "first-draft"
    s = twin.Setup(name)
    found = run(s)
    for f in found:
        print(f)
    counts = {k: sum(f.severity == k for f in found) for k in ORDER}
    print(f"\n{counts['HIGH']} HIGH, {counts['MEDIUM']} MEDIUM, {counts['LOW']} LOW  ({len(found)} findings)")
    if s.platform == "bedrock-agents-classic":
        print("note: Bedrock Agents Classic is closed to new customers since 30 Jul 2026 (maintenance mode). Accounts with no "
              "Agents activity in the past 12 months can't call CreateAgent: see setups/harness for the AgentCore path.")
    sys.exit(1 if counts["HIGH"] else 0)


if __name__ == "__main__":
    main()

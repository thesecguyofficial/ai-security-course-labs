"""
twin.py: the OFFLINE stand-in for the AWS pieces of the M13 port. Standard-library Python, no AWS account.

It reads a setup folder (setups/<name>/: the request bodies, policies and app notes under review) and copies the
DOCUMENTED behaviour of each AWS feature the lab needs. Every rule below cites the page it comes from; the README's
"How faithful is the twin?" table lists them again.

  * Knowledge base ingestion and Retrieve, for both kinds of knowledge base:
      - customer-managed (type VECTOR): metadata filters (equals / in / orAll / andAll ...) and implicit filtering,
        where a MODEL writes the filter from the user's query (kb-test-config)
      - Bedrock Managed Knowledge Base (type MANAGED) with ACL awareness on an S3 data source: global ACL file,
        per-document .metadata.json overrides it, deny beats allow, documents with no ACL are not ingested, no
        userContext = zero results from ACL-enabled sources, non-ACL sources return to everyone, ACL changes only
        after a resync (kb-managed-acl, kb-managed-ds-s3-acl, kb-test-retrieve-acl)
  * A small evaluator for the Lambda resource-based policy that lets Amazon Bedrock invoke an action group
    (agents-permissions: Principal bedrock.amazonaws.com, AWS:SourceAccount, AWS:SourceArn)

What the twin does NOT do: real embeddings (scores are keyword overlap), real-time ACL verification (AWS doesn't
offer it for S3 sources anyway), group ACLs (AWS's S3 ACL file only takes Type USER), or anything a model does.

    python3 twin.py retrieve ported "salary bands 2027" --user bob@example.com
    python3 twin.py ingest ported
"""

from __future__ import annotations

import argparse
import copy
import fnmatch
import json
import pathlib
import re
import sys
from dataclasses import dataclass, field

HERE = pathlib.Path(__file__).resolve().parent
COMPANY = json.loads((HERE / "anycompany.json").read_text(encoding="utf-8"))
BUCKET = COMPANY["kb_bucket"]
DOCS_DIR = HERE / "data" / "docs"
SETUP_FILES = ("knowledge-base", "data-sources", "kb-access", "kb-service-role", "bucket-policy", "logging", "app",
               "agent", "lambda", "invokers")


# --------------------------------------------------------------------------------------------------------------------
# Loading a setup
# --------------------------------------------------------------------------------------------------------------------
class Setup:
    """One folder under setups/. Each JSON file becomes an attribute: setup.app, setup.agent, setup.kb_access ..."""

    def __init__(self, name: str):
        self.name = name
        folder = HERE / "setups" / name
        if not folder.is_dir():
            raise SystemExit(f"no such setup: {name} (choose from: {', '.join(sorted(p.name for p in (HERE / 'setups').iterdir()))})")
        for stem in SETUP_FILES:
            path = folder / f"{stem}.json"
            attr = stem.replace("-", "_") + ("_" if stem == "lambda" else "")   # setup.lambda_ (lambda is a keyword)
            setattr(self, attr, json.loads(path.read_text(encoding="utf-8")) if path.exists() else None)

    @property
    def kb_type(self) -> str:
        return self.knowledge_base["knowledgeBaseConfiguration"]["type"]

    @property
    def platform(self) -> str:
        return self.agent["platform"]

    def copy(self) -> "Setup":
        return copy.deepcopy(self)


def all_docs() -> dict[str, str]:
    """Every object in the knowledge base bucket: key -> text (the ACL file itself is not a document)."""
    return {p.relative_to(DOCS_DIR).as_posix(): p.read_text(encoding="utf-8") for p in sorted(DOCS_DIR.rglob("*.md"))}


# --------------------------------------------------------------------------------------------------------------------
# Ingestion
# --------------------------------------------------------------------------------------------------------------------
@dataclass
class Chunk:
    key: str
    text: str
    metadata: dict = field(default_factory=dict)
    acl: list | None = None          # None = this data source has no ACL awareness: returned to every caller
    data_source: str = ""

    def uri(self) -> str:
        return f"s3://{BUCKET}/{self.key}"


@dataclass
class Index:
    chunks: list[Chunk]
    skipped: list[tuple[str, str]]   # (key, why) for the ingestion log


def _connector_params(ds: dict) -> dict:
    cfg = ds["dataSourceConfiguration"]
    if cfg["type"] == "MANAGED_KNOWLEDGE_BASE_CONNECTOR":
        return cfg["managedKnowledgeBaseConnectorConfiguration"]["connectorParameters"]
    return {}


def ingest(setup: Setup, acl_override: list | None = None) -> Index:
    """Build the index the way a StartIngestionJob would. `acl_override` replaces the global ACL file's content."""
    docs = all_docs()
    access = setup.kb_access or {}
    chunks, skipped = [], []
    for ds in setup.data_sources["dataSources"]:
        params = _connector_params(ds)
        acl_enabled = bool(params.get("aclEnabled"))
        global_acl = acl_override if acl_override is not None else access.get("globalAcl", [])
        per_doc = access.get("perDocument", {})
        for key, text in docs.items():
            meta = {}
            if access.get("kind") == "metadata-files":
                meta = dict(access["files"].get(key, {}).get("metadataAttributes", {}))
            acl = None
            if acl_enabled:
                # kb-managed-ds-s3-acl: "Per-document metadata takes precedence over the global ACL file."
                if key in per_doc:
                    acl = per_doc[key].get("accessControlList", [])
                else:
                    uri = f"s3://{BUCKET}/{key}"
                    matches = [e for e in global_acl if uri.startswith(e["keyPrefix"])]
                    if matches:
                        best = max(matches, key=lambda e: len(e["keyPrefix"]))   # most specific prefix wins (twin choice)
                        acl = best["aclEntries"]
                if acl is None:
                    # "For ACL-enabled Amazon S3 data sources, documents without an associated ACL entry are not ingested."
                    skipped.append((key, "no ACL entry: not ingested"))
                    continue
            chunks.append(Chunk(key, text, meta, acl, ds["name"]))
    return Index(chunks, skipped)


# --------------------------------------------------------------------------------------------------------------------
# Retrieve
# --------------------------------------------------------------------------------------------------------------------
STOP = set("a an the and or of to for in on is are my me i how do what whats what's please can you your it this that "
           "with from all new".split())


def _words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", text.lower()) if w not in STOP and len(w) > 1}


def _score(query: str, chunk: Chunk) -> float:
    q, d = _words(query), _words(chunk.text + " " + chunk.key.replace("/", " ").replace("-", " "))
    return round(len(q & d) / max(len(q), 1), 3)


def _match(flt: dict, meta: dict) -> bool:
    """RetrievalFilter evaluation for the operators the lab uses (kb-test-config, 'Filtering operators')."""
    (op, arg), = flt.items()
    if op in ("andAll", "orAll"):
        results = [_match(f, meta) for f in arg]
        return all(results) if op == "andAll" else any(results)
    key, value = arg["key"], arg["value"]
    have = meta.get(key)
    if op == "equals":
        return have == value
    if op == "notEquals":
        return have != value
    if op == "in":
        return have in value
    if op == "notIn":
        return have not in value
    raise ValueError(f"operator not modelled in the twin: {op}")


def acl_allows(acl: list, user: str | None) -> bool:
    """kb-managed-acl: allowed if the user is on an allow list and not on a deny list. 'Deny always overrides allow.'"""
    if user is None:
        return False
    names = {(e["Name"], e["Access"]) for e in acl if e.get("Type") == "USER"}
    return (user, "ALLOW") in names and (user, "DENY") not in names


def implicit_filter(query: str, config: dict) -> dict | None:
    """Implicit metadata filtering: a MODEL reads the user's query and the attribute descriptions and writes the filter.
    The stand-in does what a helpful model would: if the query names a department value, it filters on it."""
    for attr in config["metadataAttributes"]:
        values = re.findall(r"\b(all|hr|it|sales)\b", attr.get("description", "").lower())
        for v in values:
            if re.search(rf"\b{v}\b", query.lower()):
                return {"equals": {"key": attr["key"], "value": v}}
    return None


def retrieve(setup: Setup, query: str, *, user_context: dict | None = None, retrieval_configuration: dict | None = None,
             index: Index | None = None, n: int = 3) -> dict:
    """Shape of a Retrieve response: {"retrievalResults": [{content, location, metadata, score}, ...]}."""
    index = index or ingest(setup)
    cfg = retrieval_configuration or {}
    vector = cfg.get("vectorSearchConfiguration", {})
    managed = cfg.get("managedSearchConfiguration", {})
    flt = vector.get("filter") or managed.get("filter")
    if flt is None and vector.get("implicitFilterConfiguration"):
        flt = implicit_filter(query, vector["implicitFilterConfiguration"])
    user = (user_context or {}).get("userId")
    results = []
    for c in index.chunks:
        if c.acl is not None and not acl_allows(c.acl, user):
            continue      # "If you do not provide userContext ... ACL-enabled data sources return zero results."
        if flt is not None and not _match(flt, c.metadata):
            continue
        s = _score(query, c)
        if s > 0:
            results.append((s, c))
    results.sort(key=lambda t: (-t[0], t[1].key))
    out = [{"content": {"text": c.text, "type": "TEXT"},
            "location": {"type": "S3", "s3Location": {"uri": c.uri()}},
            "metadata": dict(c.metadata, **{"x-amz-bedrock-kb-source-uri": c.uri()}) if setup.kb_type == "VECTOR"
                        else dict(c.metadata, _source_uri=c.uri()),
            "score": s} for s, c in results[: vector.get("numberOfResults", managed.get("numberOfResults", n))]]
    return {"retrievalResults": out, "_filter_applied": flt}


# --------------------------------------------------------------------------------------------------------------------
# Lambda resource-based policy (who may invoke the action group function)
# --------------------------------------------------------------------------------------------------------------------
def lambda_allows(resource_policy: dict, *, source_arn: str, source_account: str) -> bool:
    """Is Amazon Bedrock, acting for the agent `source_arn`, allowed to invoke the function? (agents-permissions)
    Teaching model of IAM: Allow statements for Principal Service bedrock.amazonaws.com; StringEquals and ArnLike
    conditions on AWS:SourceAccount / AWS:SourceArn (condition key names compared case-insensitively, as IAM does)."""
    for st in resource_policy["Statement"]:
        if st.get("Effect") != "Allow" or st.get("Principal", {}).get("Service") != "bedrock.amazonaws.com":
            continue
        ok = True
        for op, conds in st.get("Condition", {}).items():
            for k, v in conds.items():
                actual = {"aws:sourcearn": source_arn, "aws:sourceaccount": source_account}.get(k.lower())
                values = v if isinstance(v, list) else [v]
                if op == "StringEquals":
                    ok &= actual in values
                elif op == "ArnLike":
                    ok &= any(fnmatch.fnmatchcase(actual or "", pat) for pat in values)
                else:
                    ok = False
        if ok:
            return True
    return False


# --------------------------------------------------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("retrieve", help="one Retrieve call against a setup's knowledge base")
    a.add_argument("setup"); a.add_argument("query"); a.add_argument("--user", help="userContext.userId (managed KB)")
    a.add_argument("--department", help="metadata filter department (customer-managed KB)")
    b = sub.add_parser("ingest", help="what an ingestion job would index, and what it would skip")
    b.add_argument("setup")
    args = ap.parse_args(argv)
    s = Setup(args.setup)
    if args.cmd == "ingest":
        idx = ingest(s)
        for c in idx.chunks:
            who = "everyone (no ACL)" if c.acl is None else ", ".join(e["Name"] for e in c.acl if e["Access"] == "ALLOW")
            print(f"  indexed  {c.key:34} -> {who}")
        for key, why in idx.skipped:
            print(f"  SKIPPED  {key:34} ({why})")
        return
    cfg = None
    if args.department:
        cfg = {"vectorSearchConfiguration": {"filter": {"equals": {"key": "department", "value": args.department}}}}
    uc = {"userId": args.user} if args.user else None
    resp = retrieve(s, args.query, user_context=uc, retrieval_configuration=cfg)
    print(json.dumps({"retrievalResults": resp["retrievalResults"]}, indent=2))


if __name__ == "__main__":
    main(sys.argv[1:])

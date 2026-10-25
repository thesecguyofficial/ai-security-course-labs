#!/usr/bin/env python3
"""Capstone self-check: verifies the OBJECTIVE parts of your submission. Passing it is required for a Pass grade;
the grade itself comes from a person reading your work against RUBRIC.md.

    python3 selfcheck.py                     # make check: check this folder
    python3 selfcheck.py --repo ../my-capstone --json results/selfcheck.json
    python3 selfcheck.py --ci                # what the GitHub Actions workflow runs (no colours, JSON + JUnit)

What it checks (RUBRIC.md, "Automated checks"):
  H1 the core Helpdesk files and the checking tools are unchanged     H2 the app listens on 127.0.0.1 only
  H3 no real-looking secrets in the repo                              H4 a hardened CI workflow runs this self-check
  T1 functional tests pass (normal use still works)                   T2 security tests pass (S01 to S11)
  E1 the eval gate passes (core cases + yours)                        E2 the gate FAILS on each of 3 regressions
  D1 your rules catch all five incidents on 3 simulated days, max 2 false alerts a day
  C1 the cloud check for your stream has no HIGH findings
  R1 threat model  R2 findings  R3 incident report  R4 governance note  R5 portfolio README: complete, no placeholders
INFO lines (merit evidence, never required): your own eval cases, ATLAS IDs on rules, MEDIUM cloud findings.

Graders run the course's own copy against your repo (--repo), so the tests, cases and simulator it uses are
always the originals. Seeds can be changed (--seeds) to check rules on days you have never seen.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
LOCK = HERE / "selfcheck.lock.json"
LOCKED = ["helpdesk/__init__.py", "helpdesk/app.py", "helpdesk/common.py", "helpdesk/core.py", "helpdesk/logs.py",
          "helpdesk/mcp_client.py", "helpdesk/mcp_server.py", "helpdesk/model.py", "helpdesk/rag.py",
          "helpdesk/tools.py", "data/users.json", "data/customers.json", "data/orders.json",
          "tests/util.py", "tests/test_functional.py", "tests/test_security.py", "evals/cases.json",
          "evals/run_evals.py", "detections/attack_sim.py", "detections/detect.py", "detections/score.py",
          "cloud/cloud_check.py"]
SECRET_PATTERNS = {
    "AWS access key ID": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
    "private key": r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "GitHub token": r"\b(ghp|gho|ghs|ghu)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b",
    "Slack token": r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
    "OpenAI-style key": r"\bsk-(proj-)?[A-Za-z0-9_-]{32,}\b",
    "Google API key": r"\bAIza[0-9A-Za-z_-]{35}\b",
}
PLACEHOLDER = re.compile(r"<(?!https?://)[^<>\n]{3,}>|\bTODO\b")
OWASP_ID = re.compile(r"\b(LLM|ASI)\d{2}:20\d{2}\b")
ATLAS_ID = re.compile(r"\bAML\.T\d{4}(\.\d{3})?\b")
REPORTS = {
    "R1": ("report/THREAT-MODEL.md", ["## 1.", "## 2.", "## 3.", "## 4."]),
    "R2": ("report/FINDINGS.md", ["## Summary", "## Findings", "## Variants I tried", "## Cloud"]),
    "R3": ("report/INCIDENT-REPORT.md", ["## Summary", "## Timeline", "## Scope", "## Root cause", "## Containment",
                                         "## Evidence", "## Detection gaps", "## Lessons learned"]),
    "R4": ("report/GOVERNANCE-NOTE.md", ["## AI inventory entry", "## Risk decisions", "## Evidence index",
                                         "## Framework mapping", "## Residual risk"]),
    "R5": ("README.md", ["## What this is", "## Run it", "## What I found and fixed", "## Evidence",
                         "## How I built this", "## What I'd do next"]),
}


class Report:
    def __init__(self, plain: bool):
        self.rows: list[dict] = []
        self.plain = plain

    def add(self, cid: str, ok: bool | None, title: str, detail: str = "") -> None:
        """ok=True pass, False fail, None info (never required)."""
        self.rows.append({"id": cid, "status": "INFO" if ok is None else ("PASS" if ok else "FAIL"),
                          "title": title, "detail": detail})
        mark = "INFO" if ok is None else ("PASS" if ok else "FAIL")
        print(f"[{mark}] {cid:<3} {title}" + (f"\n         {detail}" if detail else ""), flush=True)

    @property
    def passed(self) -> bool:
        return all(r["status"] != "FAIL" for r in self.rows)


def sha(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def run(cmd: list[str], cwd: pathlib.Path, env_extra: dict | None = None, timeout: int = 600) -> tuple[int, str]:
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", **(env_extra or {}))
    p = subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr)


def tail(text: str, n: int = 6) -> str:
    lines = [ln for ln in text.strip().splitlines() if ln.strip()]
    return "\n         ".join(lines[-n:])


def strip_code(text: str) -> str:
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    text = re.sub(r"`[^`\n]*`", "", text)
    return re.sub(r"<!--.*?-->", "", text, flags=re.S)


# ---- H: hygiene ----------------------------------------------------------------------------------------------------
def check_hygiene(repo: pathlib.Path, rep: Report) -> None:
    lock = json.loads(LOCK.read_text())["files"]
    changed = [f for f in LOCKED if not (repo / f).exists() or sha(repo / f) != lock.get(f)]
    rep.add("H1", not changed, "core Helpdesk files and checking tools are the originals",
            ("changed or missing: " + ", ".join(changed) + " (put controls in helpdesk/guards.py or config.py)")
            if changed else "")

    host = ""
    try:
        cfg_text = (repo / "helpdesk/config.py").read_text()
    except OSError:
        cfg_text = ""          # missing/unreadable config.py: H1 already reports it; H2 just fails here
    m = re.search(r'^HOST\s*=\s*["\']([^"\']+)["\']', cfg_text, re.M)
    if m:
        host = m.group(1)
    rep.add("H2", host in ("127.0.0.1", "::1", "localhost"), "the app listens on 127.0.0.1 only", f"HOST = {host!r}")

    hits = []
    for p in repo.rglob("*"):
        if not p.is_file() or any(part in (".git", ".venv", "node_modules", "__pycache__") for part in p.parts):
            continue
        if p.stat().st_size > 2_000_000:
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for label, rx in SECRET_PATTERNS.items():
            if re.search(rx, text):
                hits.append(f"{p.relative_to(repo)} ({label})")
    rep.add("H3", not hits, "no real-looking secrets in the repo",
            ("rotate the key first, then remove it from git history: " + ", ".join(hits[:5])) if hits else "")

    wf_dir = repo / ".github" / "workflows"
    if not wf_dir.is_dir():
        wf_dir = repo / "template" / ".github" / "workflows"      # before `make export`
    problems, runs_check = [], False
    files = sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")) if wf_dir.is_dir() else []
    for wf in files:
        t = "\n".join(re.sub(r"(^|\s)#.*$", "", line) for line in wf.read_text(encoding="utf-8").splitlines())
        if "selfcheck.py" in t:
            runs_check = True
        if "pull_request_target" in t:
            problems.append(f"{wf.name}: pull_request_target")
        if not re.search(r"^permissions:\s*\n\s+contents:\s*read\s*$", t, re.M) and not re.search(
                r"^permissions:\s*(read-all|\{\s*contents:\s*read\s*\})", t, re.M):
            problems.append(f"{wf.name}: top-level permissions are not contents: read")
        for use in re.findall(r"uses:\s*([^\s#]+)", t):
            if not use.startswith("./") and not re.search(r"@[0-9a-f]{40}$", use):
                problems.append(f"{wf.name}: {use} is not pinned to a full commit SHA")
    if not files:
        problems.append("no workflow in .github/workflows")
    elif not runs_check:
        problems.append("no workflow runs selfcheck.py")
    rep.add("H4", not problems, "a hardened CI workflow runs the self-check", "; ".join(problems[:4]))


# ---- T, E: tests and evals -----------------------------------------------------------------------------------------
def check_tests(repo: pathlib.Path, rep: Report, tmp: pathlib.Path) -> None:
    shutil.copytree(HERE / "tests", tmp / "official" / "tests")
    env = {"PYTHONPATH": str(repo)}      # helpdesk from the repo under test, tests from the course's own copy
    for cid, name, title in (("T1", "test_functional", "functional tests pass (normal use still works)"),
                             ("T2", "test_security", "security tests pass (S01 to S11)")):
        code, out = run([sys.executable, "-m", "unittest", "-q", f"tests.{name}"], tmp / "official", env)
        fails = re.findall(r"^(?:FAIL|ERROR): (\S+)", out, re.M)
        rep.add(cid, code == 0, title, ("failing: " + ", ".join(fails)) if fails else ("" if code == 0 else tail(out)))


def check_evals(repo: pathlib.Path, rep: Report, results: pathlib.Path | None) -> None:
    runner = str(HERE / "evals" / "run_evals.py")
    args = [sys.executable, runner, "--repo", str(repo)]
    if results:
        args += ["--out", str(results / "evals.json"), "--junit", str(results / "evals.junit.xml")]
    code, out = run(args, repo)
    m = re.search(r"GATE (PASSED|FAILED): (\d+) of (\d+)", out)
    failing = re.findall(r"^\[FAIL\] (\S+)", out, re.M)
    rep.add("E1", code == 0, "the eval gate passes (core cases + yours)",
            (m.group(0) if m else tail(out)) + (f"; failing: {', '.join(failing)}" if failing else ""))
    missed = []
    for reg in ("injection", "retrieval", "output"):
        c2, o2 = run([sys.executable, runner, "--repo", str(repo), "--regression", reg, "--expect-fail",
                      "--core-only"], repo)
        if c2 != 0:
            missed.append(reg)
    rep.add("E2", code == 0 and not missed, "the gate fails on every regression (injection, retrieval, output)",
            ("fix E1 first" if code != 0 else ("not caught: " + ", ".join(missed) if missed else "3 of 3 caught")))
    mine_p = repo / "evals" / "my_cases.json"
    mine = json.loads(mine_p.read_text()).get("cases", []) if mine_p.exists() else []
    inj = sum(1 for c in mine if c.get("category") == "injection")
    normal = sum(1 for c in mine if c.get("category") == "normal")
    rep.add("E3", None, "your own eval cases (merit: 5+, with 2+ injection variants and 2+ normal cases)",
            f"{len(mine)} cases: {inj} injection, {normal} normal")


# ---- D: detections --------------------------------------------------------------------------------------------------
def check_detections(repo: pathlib.Path, rep: Report, seeds: list[int], results: pathlib.Path | None) -> None:
    rules_p = repo / "detections" / "rules.json"
    args = [sys.executable, str(HERE / "detections" / "score.py"), "--rules", str(rules_p), "--seeds",
            *map(str, seeds)]
    if results:
        args += ["--json", str(results / "detections.json")]
    code, out = run(args, repo)
    lines = [ln.strip() for ln in out.splitlines() if ln.startswith("[")]
    rep.add("D1", code == 0, f"rules catch S1 to S5 on seeds {', '.join(map(str, seeds))} with max 2 false alerts a day",
            "\n         ".join(lines) if lines else tail(out))
    try:
        rules = json.loads(rules_p.read_text())["rules"]
        with_atlas = sum(1 for r in rules if r.get("atlas"))
        rep.add("D2", None, "rules mapped to MITRE ATLAS (merit evidence)", f"{with_atlas} of {len(rules)} rules have ATLAS IDs")
    except (OSError, ValueError, KeyError):
        pass


# ---- C: cloud --------------------------------------------------------------------------------------------------------
def check_cloud(repo: pathlib.Path, rep: Report, results: pathlib.Path | None) -> None:
    args = [sys.executable, str(HERE / "cloud" / "cloud_check.py"), "--repo", str(repo)]
    if results:
        args += ["--json", str(results / "cloud.json")]
    code, out = run(args, repo)
    summary = next((ln for ln in out.splitlines() if " HIGH, " in ln), tail(out, 2))
    if code == 3:
        rep.add("C1", False, "cloud check for your stream", summary + " (set \"stream\": \"aws\" in capstone.json)")
        return
    rep.add("C1", code == 0, "the cloud check for your stream has no HIGH findings", summary)
    m = re.search(r"(\d+) MEDIUM", summary)
    if code == 0 and m:
        rep.add("C2", None, "MEDIUM cloud findings (merit: none)", f"{m.group(1)} MEDIUM")


# ---- R: reports ------------------------------------------------------------------------------------------------------
def check_reports(repo: pathlib.Path, rep: Report, seed1_ids: set[str]) -> None:
    exported = (repo / "CAPSTONE-GUIDE.md").exists()
    for cid, (rel, headings) in REPORTS.items():
        path = repo / rel
        if cid == "R5" and not exported:
            path = repo / "report" / "README-TEMPLATE.md"
        if not path.exists():
            rep.add(cid, False, f"{rel} is complete", "file missing")
            continue
        raw = path.read_text(encoding="utf-8")
        text = strip_code(raw)
        problems = [f"missing heading {h!r}" for h in headings if h not in raw]
        left = PLACEHOLDER.findall(text)
        if left:
            problems.append(f"{len(left)} placeholders or TODO left")
        words = len(re.findall(r"\w+", text))
        if cid == "R1":
            rows = re.findall(r"^\|\s*T\d{2}\s*\|.*$", raw, re.M)
            if len(rows) < 10:
                problems.append(f"{len(rows)} threats (want 10+)")
            if sum(1 for r in rows if OWASP_ID.search(r)) < 10:
                problems.append("every threat needs an OWASP ID with the year, e.g. LLM01:2026")
            if sum(1 for r in rows if ATLAS_ID.search(r)) < 5:
                problems.append("at least 5 threats need a MITRE ATLAS technique ID")
        if cid == "R2":
            for n in range(1, 7):
                if not re.search(rf"^###\s+F-{n}\b", raw, re.M):
                    problems.append(f"no section ### F-{n}")
            sections = re.split(r"^###\s+F-\d+", raw, flags=re.M)[1:]
            for i, s in enumerate(sections, 1):
                if not re.search(r"\b(S\d{2}|[a-z]{2,4}-\d{2})\b", s):
                    problems.append(f"finding {i} names no test or eval ID")
            if words < 600:
                problems.append(f"{words} words (want 600+)")
        if cid == "R3":
            timeline = re.findall(r"^\s*[-*]?\s*`?2027-01-20T\d{2}:\d{2}", raw, re.M)
            if len(timeline) < 5:
                problems.append(f"{len(timeline)} timeline lines (want 5+, starting 2027-01-20Thh:mm)")
            ids = set(re.findall(r"req-\d{5}-[0-9a-f]{6}", raw))
            real = ids & seed1_ids
            if len(real) < 3:
                problems.append(f"{len(real)} request IDs from the seed-1 attack log (want 3+)")
        if cid == "R4":
            rows = [r for r in re.findall(r"^\|.*\|\s*$", raw.split("## Evidence index", 1)[-1].split("## ", 1)[0], re.M)
                    if not re.match(r"^\|\s*(Control|-)", r)]
            if len(rows) < 8:
                problems.append(f"{len(rows)} evidence rows (want 8+)")
            for fn in ("GOVERN", "MAP", "MEASURE", "MANAGE"):
                if fn not in raw:
                    problems.append(f"framework mapping does not mention NIST AI RMF {fn}")
            if "42001" not in raw:
                problems.append("framework mapping does not mention ISO/IEC 42001")
        if cid == "R5" and words < 250:
            problems.append(f"{words} words (want 250+)")
        rep.add(cid, not problems, f"{path.relative_to(repo)} is complete", "; ".join(problems[:5]))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=str(HERE))
    ap.add_argument("--seeds", nargs="+", type=int, default=[1, 2, 3])
    ap.add_argument("--json", help="write every check as JSON")
    ap.add_argument("--ci", action="store_true", help="CI mode: also write results/ (JSON + JUnit)")
    ap.add_argument("--write-lock", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.write_lock:      # course maintainers only: record the original files
        LOCK.write_text(json.dumps({"files": {f: sha(HERE / f) for f in LOCKED}}, indent=1) + "\n")
        print(f"wrote {LOCK.name} ({len(LOCKED)} files)")
        return 0

    repo = pathlib.Path(a.repo).resolve()
    results = (repo / "results") if a.ci else None
    if results:
        results.mkdir(exist_ok=True)
    print(f"Capstone self-check: {repo}\n")
    rep = Report(plain=a.ci)
    sys.path.insert(0, str(HERE / "detections"))
    import attack_sim  # noqa: E402
    seed1_ids = {e["request_id"] for e in attack_sim.generate(1)[0]}
    with tempfile.TemporaryDirectory(prefix="tsg-selfcheck-") as tmp:
        check_hygiene(repo, rep)
        check_tests(repo, rep, pathlib.Path(tmp))
        check_evals(repo, rep, results)
        check_detections(repo, rep, a.seeds, results)
        check_cloud(repo, rep, results)
        check_reports(repo, rep, seed1_ids)
    required = [r for r in rep.rows if r["status"] != "INFO"]
    passed = sum(1 for r in required if r["status"] == "PASS")
    print(f"\nOBJECTIVE CHECKS {'PASSED' if rep.passed else 'NOT YET PASSED'}: {passed} of {len(required)}"
          + ("" if rep.passed else ". Fix the FAIL lines above, then run it again."))
    out = {"repo": str(repo), "passed": rep.passed, "seeds": a.seeds, "checks": rep.rows}
    for target in filter(None, [a.json, results and str(results / "selfcheck.json")]):
        pathlib.Path(target).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(target).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return 0 if rep.passed else 1


if __name__ == "__main__":
    sys.exit(main())

"""
scan.py: a configuration scanner for a self-hosted inference stack (lessons 26.0 to 26.3).

    python3 scan.py stacks/first-draft          # every finding, worst first
    python3 scan.py stacks/hardened             # what's left after hardening
    python3 scan.py stacks/first-draft --json   # the same as JSON (for CI)

It READS files only: docker-compose.yml, k8s/*.yaml, cluster.yaml (eksctl), gateway.json, nodes.json, models.json
and the model folders they name. It never starts a container, never imports model code and never opens a network
connection. Exit code 1 when anything critical or high is found, so it can gate a pipeline.
"""

import json
import pathlib
import re
import sys

import yaml

HERE = pathlib.Path(__file__).resolve().parent
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SHORT = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW "}

# id: (severity, lesson, title). Severity "advisory" = taken from the matching advisory.
RULES = {
    "AUTH-01": ("critical", "26.0", "the gateway accepts requests without a key"),
    "AUTH-02": ("high", "26.0", "the gateway's path allow-list lets management paths through"),
    "AUTH-03": ("low", "26.0", "vLLM runs without --api-key (a second lock behind the gateway)"),
    "EXP-01": ("high", "26.0", "an engine port is published on every host address"),
    "EXP-02": ("high", "26.0", "a model server is exposed by a LoadBalancer or NodePort Service"),
    "DEV-01": ("high", "26.0", "VLLM_SERVER_DEV_MODE=1 turns on development endpoints"),
    "RCE-01": ("high", "26.1", "--trust-remote-code lets the server run code that ships with a model"),
    "VER-00": ("medium", "26.1", "the image isn't pinned to a version"),
    "VER-01": ("advisory", "26.1", "the engine version is in an advisory's affected range"),
    "RAY-01": ("critical", "26.1", "the Ray dashboard and Jobs API are reachable without token auth"),
    "CACHE-01": ("high", "26.2", "the prefix cache is shared across tenants"),
    "CACHE-02": ("medium", "26.2", "the gateway hands tenants per-request timing"),
    "SEC-01": ("high", "26.3", "a secret is written into the file"),
    "K8S-01": ("high", "26.3", "a pod runs privileged or on the host network"),
    "K8S-02": ("medium", "26.3", "no default-deny NetworkPolicy for the namespace"),
    "NODE-01": ("medium", "26.3", "the GPU node group has no nvidia.com/gpu taint"),
    "NODE-02": ("high", "26.3", "pods can reach the node's IAM role through IMDS"),
    "NODE-03": ("advisory", "26.3", "the NVIDIA container toolkit is in an advisory's affected range"),
    "NODE-04": ("high", "26.3", "tenants time-share one GPU (no memory isolation)"),
    "MODEL-01": ("high", "26.1", "the model ships pickle-based weights"),
    "MODEL-02": ("high", "26.1", "the model points to custom code (auto_map or .py files)"),
}

# Image repository -> product name used in advisories.json
PRODUCTS = {
    "ollama/ollama": "ollama",
    "vllm/vllm-openai": "vllm",
    "nvcr.io/nvidia/tritonserver": "tritonserver",
    "rayproject/ray": "ray",
}
ENGINES = set(PRODUCTS.values())
MANAGEMENT_PATHS = ("/api/pull", "/api/push", "/api/delete", "/api/create", "/api/copy",
                    "/update_weights", "/pause", "/resume", "/collective_rpc", "/sleep", "/metrics", "/version")
SECRET_NAME = re.compile(r"(TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY)$", re.I)
PICKLE_SUFFIXES = (".bin", ".pt", ".pth", ".pkl", ".ckpt")


class Finding:
    def __init__(self, rule, where, detail, severity=None):
        sev, lesson, title = RULES[rule]
        self.rule, self.where, self.detail, self.lesson, self.title = rule, where, detail, lesson, title
        self.severity = severity if sev == "advisory" else sev

    def as_dict(self):
        return {"rule": self.rule, "severity": self.severity, "where": self.where, "title": self.title,
                "detail": self.detail, "lesson": self.lesson}


# ---------- helpers

def version_tuple(v):
    """'v0.10.2' -> (0, 10, 2); '25.03-py3' -> (25, 3). Non-numeric parts are ignored."""
    v = str(v).lstrip("v").split("-")[0]
    return tuple(int(x) for x in re.findall(r"\d+", v))


def in_range(version, introduced, fixed):
    v = version_tuple(version)
    if fixed is None:
        return False  # disputed / no fix: handled by its own rule, not by version
    return version_tuple(introduced) <= v < version_tuple(fixed)


def split_image(image):
    """'nvcr.io/nvidia/tritonserver:25.03-py3' -> ('nvcr.io/nvidia/tritonserver', '25.03-py3')."""
    name, _, tag = image.rpartition(":")
    if not name or "/" in tag:  # no tag at all (the colon belonged to a registry port)
        return image, ""
    return name, tag


def load_advisories():
    return json.loads((HERE / "advisories.json").read_text(encoding="utf-8"))["advisories"]


def load_stack(folder):
    folder = pathlib.Path(folder)
    stack = {"folder": folder, "compose": {}, "k8s": [], "cluster": {}, "gateway": {}, "nodes": [], "models": []}
    if (folder / "docker-compose.yml").exists():
        stack["compose"] = yaml.safe_load((folder / "docker-compose.yml").read_text(encoding="utf-8")) or {}
    for f in sorted((folder / "k8s").glob("*.yaml")) if (folder / "k8s").exists() else []:
        stack["k8s"] += [d for d in yaml.safe_load_all(f.read_text(encoding="utf-8")) if d]
    if (folder / "cluster.yaml").exists():
        stack["cluster"] = yaml.safe_load((folder / "cluster.yaml").read_text(encoding="utf-8")) or {}
    for name, key in (("gateway.json", "gateway"), ("nodes.json", "nodes"), ("models.json", "models")):
        if (folder / name).exists():
            data = json.loads((folder / name).read_text(encoding="utf-8"))
            stack[key] = data if key == "gateway" else data.get(key, [])
    return stack


def services(stack):
    return (stack["compose"].get("services") or {}).items()


def product_of(image):
    name, _ = split_image(image)
    return PRODUCTS.get(name)


def args_of(svc):
    cmd = svc.get("command") or []
    return cmd if isinstance(cmd, list) else str(cmd).split()


def env_of(svc):
    env = svc.get("environment") or {}
    if isinstance(env, list):
        env = dict(e.split("=", 1) if "=" in e else (e, "") for e in env)
    return {k: str(v) for k, v in env.items()}


def literal_secret(value):
    """A value that is written into the file, rather than a reference like ${VAR} or $(VAR)."""
    value = str(value).strip()
    return bool(value) and not value.startswith(("${", "$(")) and value.lower() not in ("true", "false")


# ---------- checks (each returns a list of Finding)

def check_compose(stack):
    out = []
    for name, svc in services(stack):
        product = product_of(svc.get("image", ""))
        for port in svc.get("ports") or []:
            if isinstance(port, dict):
                host_ip = port.get("host_ip", "")
                text = f"{port.get('published')}:{port.get('target')}"
            else:
                parts = str(port).split(":")
                host_ip = parts[0] if len(parts) == 3 else ""
                text = str(port)
            if name != "gateway" and host_ip not in ("127.0.0.1", "::1", "[::1]"):
                out.append(Finding("EXP-01", f"docker-compose.yml: {name}",
                                   f'ports "{text}" listens on 0.0.0.0 and [::] of the host'))
        args, env = args_of(svc), env_of(svc)
        if product == "vllm":
            if "--trust-remote-code" in args:
                out.append(Finding("RCE-01", f"docker-compose.yml: {name}", "command has --trust-remote-code"))
            if "--api-key" not in args:
                out.append(Finding("AUTH-03", f"docker-compose.yml: {name}", "no --api-key in the command"))
            if env.get("VLLM_SERVER_DEV_MODE") == "1":
                out.append(Finding("DEV-01", f"docker-compose.yml: {name}", "VLLM_SERVER_DEV_MODE=1"))
        for key, value in env.items():
            if SECRET_NAME.search(key) and literal_secret(value):
                out.append(Finding("SEC-01", f"docker-compose.yml: {name}", f"environment {key} holds a literal value"))
    return out


def images(stack):
    """Every (where, image) in the compose file and the Kubernetes manifests."""
    for name, svc in services(stack):
        if svc.get("image"):
            yield f"docker-compose.yml: {name}", svc["image"]
    for doc in stack["k8s"]:
        spec = ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}
        for c in spec.get("containers") or []:
            yield f"k8s: {doc['metadata']['name']}/{c['name']}", c.get("image", "")


def check_versions(stack, advisories):
    out = []
    for where, image in images(stack):
        product = product_of(image)
        if product not in ENGINES:
            continue
        _, tag = split_image(image)
        if tag in ("", "latest"):
            out.append(Finding("VER-00", where, f"{image}: pin a version you have checked against the advisories"))
            continue
        for adv in advisories:
            if adv["product"] == product and in_range(tag, adv["introduced"], adv["fixed"]):
                out.append(Finding("VER-01", where, f"{image}: {adv['id']} ({adv['part']}; fixed in {adv['fixed']}; "
                                   f"{adv['condition']})", severity=adv["severity"]))
    return out


def check_k8s(stack):
    out = []
    namespaces, deny_all = set(), set()
    for doc in stack["k8s"]:
        kind, meta = doc.get("kind"), doc.get("metadata") or {}
        ns = meta.get("namespace", meta.get("name") if kind == "Namespace" else "default")
        if kind == "Namespace":
            namespaces.add(meta["name"])
        if kind == "NetworkPolicy":
            spec = doc.get("spec") or {}
            if spec.get("podSelector") in ({}, None) and "Egress" in (spec.get("policyTypes") or []) \
                    and not spec.get("egress"):
                deny_all.add(ns)
        if kind == "Service" and (doc.get("spec") or {}).get("type") in ("LoadBalancer", "NodePort"):
            out.append(Finding("EXP-02", f"k8s: Service {meta['name']}", f"type {doc['spec']['type']}"))
        if kind in ("Deployment", "StatefulSet", "DaemonSet", "Pod"):
            pod = (doc.get("spec") or {}).get("template", {}).get("spec") if kind != "Pod" else doc.get("spec")
            pod = pod or {}
            if pod.get("hostNetwork"):
                out.append(Finding("K8S-01", f"k8s: {meta['name']}", "hostNetwork: true"))
            for c in pod.get("containers") or []:
                if (c.get("securityContext") or {}).get("privileged"):
                    out.append(Finding("K8S-01", f"k8s: {meta['name']}/{c['name']}", "privileged: true"))
                if "--trust-remote-code" in (c.get("args") or []):
                    out.append(Finding("RCE-01", f"k8s: {meta['name']}/{c['name']}", "args have --trust-remote-code"))
                for e in c.get("env") or []:
                    if SECRET_NAME.search(e.get("name", "")) and "value" in e and literal_secret(e["value"]):
                        out.append(Finding("SEC-01", f"k8s: {meta['name']}/{c['name']}",
                                           f"env {e['name']} holds a literal value (use a secretKeyRef or Pod Identity)"))
    for ns in sorted(namespaces - deny_all):
        out.append(Finding("K8S-02", f"k8s: namespace {ns}", "no NetworkPolicy that denies all egress by default"))
    return out


def check_cluster(stack):
    out = []
    for ng in (stack["cluster"].get("managedNodeGroups") or []) + (stack["cluster"].get("nodeGroups") or []):
        where = f"cluster.yaml: nodegroup {ng.get('name')}"
        gpu = str(ng.get("instanceType", "")).startswith(("g", "p"))
        if gpu and not any(t.get("key") == "nvidia.com/gpu" for t in ng.get("taints") or []):
            out.append(Finding("NODE-01", where, f"{ng.get('instanceType')} without the nvidia.com/gpu taint"))
        # eksctl defaults disableIMDSv1 to true, so only an explicit false is a finding; disablePodIMDS must be true
        missing = (["disableIMDSv1 is false"] if ng.get("disableIMDSv1") is False else []) + \
                  (["disablePodIMDS not set to true"] if ng.get("disablePodIMDS") is not True else [])
        if missing:
            out.append(Finding("NODE-02", where, ", ".join(missing)))
    return out


def check_nodes(stack, advisories):
    out = []
    for node in stack["nodes"]:
        where = f"nodes.json: {node['name']}"
        for adv in advisories:
            if adv["product"] == "nvidia-container-toolkit" and \
                    in_range(node.get("nvidia_container_toolkit", "0"), adv["introduced"], adv["fixed"]):
                out.append(Finding("NODE-03", where, f"toolkit {node['nvidia_container_toolkit']}: {adv['id']} "
                                   f"(fixed in {adv['fixed']}; {adv['condition']})", severity=adv["severity"]))
        if node.get("gpu_sharing") == "time-slicing" and len(node.get("tenants", [])) > 1:
            out.append(Finding("NODE-04", where, f"time-slicing shared by {', '.join(node['tenants'])}"))
        if node.get("imds_http_tokens") != "required" or node.get("imds_hop_limit", 2) > 1:
            out.append(Finding("NODE-02", where, f"IMDS tokens {node.get('imds_http_tokens')}, "
                                                 f"hop limit {node.get('imds_hop_limit')}"))
    return out


def check_gateway(stack):
    gw, out = stack["gateway"], []
    if not gw:
        return out
    if not gw.get("require_auth"):
        out.append(Finding("AUTH-01", "gateway.json", "require_auth is false"))
    allowed = gw.get("allow_paths") or []
    leaks = [p for p in allowed if p.endswith("*") or p in MANAGEMENT_PATHS]
    if leaks:
        out.append(Finding("AUTH-02", "gateway.json", f"allow_paths has {', '.join(leaks)}"))
    if gw.get("cache_scope") != "per_tenant":
        out.append(Finding("CACHE-01", "gateway.json", f"cache_scope is {gw.get('cache_scope')!r}"))
    if gw.get("expose_timing"):
        out.append(Finding("CACHE-02", "gateway.json", "expose_timing is true"))
    return out


def check_models(stack):
    out = []
    for rel in stack["models"]:
        folder = HERE / rel
        if not folder.is_dir():
            continue
        for f in sorted(folder.iterdir()):
            if f.suffix in PICKLE_SUFFIXES:
                out.append(Finding("MODEL-01", rel, f"{f.name}: prefer safetensors (Module 9)"))
            if f.suffix == ".py":
                out.append(Finding("MODEL-02", rel, f"{f.name} ships with the model (read as text only, never run)"))
        cfg = folder / "config.json"
        if cfg.exists() and "auto_map" in json.loads(cfg.read_text(encoding="utf-8")):
            out.append(Finding("MODEL-02", rel, "config.json has auto_map (CVE-2025-66448 loaded this even "
                                                "with trust_remote_code=False before vLLM 0.11.1)"))
    return out


def check_ray(stack):
    """CHALLENGE 1 (lesson 26.1): Ray's Jobs API runs code by design (CVE-2023-48022, disputed, no fix coming).

    Return a Finding("RAY-01", where, detail) for every Ray head in the compose file that is reachable without
    token authentication. Decide what "reachable" means from the lesson: think about the dashboard host flag,
    the published ports and the RAY_AUTH_MODE environment variable. The hardened stack must produce none.
    """
    return []


CHECKS = [check_compose, check_k8s, check_cluster, check_gateway, check_models, check_ray]


def scan(folder):
    stack, advisories = load_stack(folder), load_advisories()
    findings = [f for check in CHECKS for f in check(stack)]
    findings += check_versions(stack, advisories) + check_nodes(stack, advisories)
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule, f.where))


def summary(findings):
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITY_ORDER}
    return f"Findings: {len(findings)} (" + ", ".join(f"{s} {n}" for s, n in counts.items()) + ")"


def main(argv):
    if not argv or argv[0].startswith("-"):
        print(__doc__)
        return 2
    findings = scan(argv[0])
    if "--json" in argv:
        print(json.dumps([f.as_dict() for f in findings], indent=2))
    else:
        print(f"Scan of {argv[0]}  (files read: compose, k8s, cluster, gateway, nodes, models; nothing run)")
        for f in findings:
            print(f"  {SHORT[f.severity]}  {f.rule:<8}  {f.lesson}  {f.title}")
            print(f"                       {f.where}: {f.detail}")
        print(summary(findings))
    return 1 if any(f.severity in ("critical", "high") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

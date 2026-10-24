#!/usr/bin/env python3
"""Lab doctor: checks that this computer is ready for the AI Security Engineer labs.

Run it any time, on its own or at the end of setup:

    python3 tools/doctor.py          (Mac / Linux / WSL, or: make doctor)
    py tools\\doctor.py               (Windows)

It prints one line per check:  [ok] passed,  [!!] warning (labs still work),  [XX] failed.
Every warning and failure comes with the exact next step. Exit code: 0 when nothing failed, 1 otherwise.

It only reads things. It never installs, changes settings or sends data anywhere. The only network
calls are to Ollama on 127.0.0.1 and, for the Docker test, Docker pulling its tiny hello-world image.
Standard library only, and it runs on any Python 3.8 or newer so it can tell you when yours is too old.
"""
import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIN_PY = (3, 11)          # M5, M7 and M10 onwards use 3.11 features
TESTED_MAX_PY = (3, 13)   # M4 (Presidio, spaCy) and M9 pins are tested up to 3.13
M9_MIN_PY = (3, 12)       # M9 pins numpy 2.5.4, which requires Python 3.12+
OLLAMA_URL = "http://127.0.0.1:11434"
MODELS = ["gemma3:1b", "embeddinggemma"]
MIN_RAM_GB = 8
MIN_DISK_GB = 15
HARD_MIN_DISK_GB = 2

OK, WARN, FAIL, SKIP = "ok", "warn", "fail", "skip"


class Result:
    def __init__(self, name, status, detail="", advice=""):
        self.name, self.status, self.detail, self.advice = name, status, detail, advice

    def as_dict(self):
        return {"name": self.name, "status": self.status, "detail": self.detail, "advice": self.advice}


# ---------------------------------------------------------------- small helpers (tests replace these)

def run(cmd, timeout=30):
    """Run a command. Returns (exit_code, combined_output). 127 = not found, 124 = timed out."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, ""
    except OSError as e:
        return 126, str(e)


def http_get(url, timeout=3):
    """GET a URL. Returns (status_code, body_text) or (None, error_text)."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:  # connection refused, timeout, DNS
        return None, str(e)


def is_windows():
    return os.name == "nt"


def venv_python(root):
    if is_windows():
        return os.path.join(root, ".venv", "Scripts", "python.exe")
    return os.path.join(root, ".venv", "bin", "python")


def setup_cmd():
    if is_windows():
        return "powershell -ExecutionPolicy Bypass -File setup.ps1"
    return "./setup.sh"


# ---------------------------------------------------------------- checks

def check_venv(root, runner=run):
    py = venv_python(root)
    if not os.path.exists(py):
        return Result("Python 3.11+ in the shared .venv", FAIL, "no .venv at the repo root",
                      "Run %s (it creates .venv with the right Python)." % setup_cmd())
    code, out = runner([py, "-c", "import sys; print('%d.%d.%d' % sys.version_info[:3])"])
    if code != 0:
        return Result("Python 3.11+ in the shared .venv", FAIL, "the .venv is broken (%s)" % out.strip()[:120],
                      "Delete the .venv folder and run %s again." % setup_cmd())
    version = out.strip().splitlines()[-1]
    parts = tuple(int(x) for x in re.findall(r"\d+", version)[:2])
    if parts < MIN_PY:
        return Result("Python 3.11+ in the shared .venv", FAIL, "the .venv uses Python %s" % version,
                      "Delete the .venv folder and run %s again: it picks Python 3.11 or newer." % setup_cmd())
    if parts > TESTED_MAX_PY:
        return Result("Python 3.11+ in the shared .venv", WARN, "Python %s" % version,
                      "Fine for most labs. M4 and M9 pin packages tested up to Python 3.13; if their `make setup` "
                      "fails, install Python 3.13 and run %s again." % setup_cmd())
    code, _ = runner([py, "-m", "pip", "--version"])
    if code != 0:
        return Result("Python 3.11+ in the shared .venv", FAIL, "Python %s, but pip is missing" % version,
                      "Delete the .venv folder and run %s again." % setup_cmd())
    if parts < M9_MIN_PY:
        return Result("Python 3.11+ in the shared .venv", WARN, "Python %s" % version,
                      "Every lab works except M9, whose pinned numpy needs Python 3.12 or newer. Before M9, install "
                      "Python 3.12+ (Ubuntu 24.04 / Debian 13 have it), delete .venv and run %s again." % setup_cmd())
    return Result("Python 3.11+ in the shared .venv", OK, "Python %s" % version)


def check_tool(name, label, advice, missing_status=FAIL, which=shutil.which):
    path = which(name)
    if path:
        return Result(label, OK, path)
    return Result(label, missing_status, "not found on PATH", advice)


def check_docker(runner=run, which=shutil.which, hello=True):
    """Three results: CLI present, daemon reachable, a container runs."""
    label_cli, label_daemon, label_run = "Docker installed", "Docker engine running", "Docker can run a container"
    if not which("docker"):
        adv = "Run %s and answer y to Docker, or see docs/SETUP.md (Docker)." % setup_cmd()
        return [Result(label_cli, FAIL, "docker not found on PATH", adv),
                Result(label_daemon, SKIP), Result(label_run, SKIP)]
    out_res = [Result(label_cli, OK, which("docker"))]
    code, out = runner(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=30)
    if code != 0:
        if "permission denied" in out.lower():
            out_res.append(Result(label_daemon, WARN, "the engine runs, but your user may not use it",
                                  "Use `sudo docker ...`, or add yourself to the docker group (root-level access, "
                                  "see docs/SETUP.md): sudo usermod -aG docker $USER, then log out and back in."))
            out_res.append(Result(label_run, SKIP))
            return out_res
        if sys.platform == "darwin":
            adv = "Start Docker Desktop from Applications (or `colima start` if you use Colima), wait for it, run this again."
        elif is_windows():
            adv = "Start Docker Desktop from the Start menu, wait until it says Engine running, run this again."
        else:
            adv = "Start the engine: sudo systemctl start docker (WSL: start Docker Desktop on Windows)."
        detail = "timed out" if code == 124 else "the engine is not answering"
        if code == 127:
            detail = "docker command failed to start"
        out_res.append(Result(label_daemon, FAIL, detail, adv))
        out_res.append(Result(label_run, SKIP))
        return out_res
    out_res.append(Result(label_daemon, OK, "engine %s" % out.strip()))
    if not hello:
        out_res.append(Result(label_run, SKIP, "skipped (--no-hello)"))
        return out_res
    code, out = runner(["docker", "run", "--rm", "hello-world"], timeout=180)
    if code == 0 and "Hello from Docker" in out:
        out_res.append(Result(label_run, OK, "hello-world ran and was removed"))
    else:
        out_res.append(Result(label_run, FAIL, *docker_run_failure(code, out)))
    return out_res


def docker_run_failure(code, out):
    """(detail, advice) for a failed `docker run --rm hello-world`."""
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    err = next((l for l in lines if "error" in l.lower()), lines[-1] if lines else "no output")
    low = out.lower()
    if code == 124:
        return "timed out after 3 minutes", "A slow or blocked download. Try `docker run --rm hello-world` yourself."
    if "x509" in low or "certificate" in low:
        return ("TLS certificate error while downloading hello-world",
                "Your network inspects HTTPS (common on work networks). Docker needs your company's root "
                "certificate: docs/SETUP.md, 'Work laptops'.")
    if "forbidden" in low or "proxy" in low or "timeout" in low or "no such host" in low:
        return ("could not download the hello-world image from Docker Hub",
                "A proxy or firewall blocks Docker Hub. Set the proxy in Docker Desktop (Settings, Resources, "
                "Proxies) or ask IT to allow registry-1.docker.io: docs/SETUP.md, 'Work laptops'.")
    return (err[:110], "Try `docker run --rm hello-world` yourself and read the error. docs/SETUP.md lists the usual ones.")


def listening_addresses_linux(port, proc_root="/proc"):
    """Local addresses with a socket LISTENING on `port`, read from /proc/net/tcp and tcp6. None if unreadable."""
    found = []
    readable = False
    for fname, width in (("tcp", 8), ("tcp6", 32)):
        path = os.path.join(proc_root, "net", fname)
        try:
            with open(path) as f:
                lines = f.read().splitlines()[1:]
            readable = True
        except OSError:
            continue
        for line in lines:
            cols = line.split()
            if len(cols) < 4 or cols[3] != "0A":     # 0A = LISTEN
                continue
            addr_hex, port_hex = cols[1].split(":")
            if int(port_hex, 16) != port:
                continue
            found.append(_decode_proc_addr(addr_hex, width))
    return found if readable else None


def _decode_proc_addr(addr_hex, width):
    if width == 8:
        b = bytes.fromhex(addr_hex)[::-1]
        return socket.inet_ntop(socket.AF_INET, b)
    raw = bytes.fromhex(addr_hex)
    b = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    return socket.inet_ntop(socket.AF_INET6, b)


LOOPBACK = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}


def lan_address():
    """This computer's own address on its network (no packet is sent: UDP connect only picks a route)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))   # TEST-NET-1, documentation range: nothing is sent
        ip = s.getsockname()[0]
        s.close()
        return None if ip.startswith("127.") else ip
    except OSError:
        return None


def port_open(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_ollama_exposure(env=None, listen_reader=listening_addresses_linux, lan=lan_address, probe=port_open,
                          platform_name=None):
    env = os.environ if env is None else env
    platform_name = sys.platform if platform_name is None else platform_name
    label = "Ollama listens on 127.0.0.1 only"
    host = env.get("OLLAMA_HOST", "")
    fix = ("Remove the OLLAMA_HOST setting (lesson 0.6, Step 5) and restart Ollama. Ollama has no login: "
           "on 0.0.0.0 anyone on your Wi-Fi can use it.")
    if host and not re.match(r"^(https?://)?(127\.0\.0\.1|localhost|\[::1\])(:\d+)?/?$", host):
        return Result(label, FAIL, "OLLAMA_HOST=%s in this terminal" % host, fix)
    addrs = listen_reader(11434) if platform_name.startswith("linux") else None
    if addrs:
        exposed = [a for a in addrs if a not in LOOPBACK]
        if exposed:
            return Result(label, FAIL, "listening on %s" % ", ".join(sorted(set(exposed))), fix)
        return Result(label, OK, "listening on %s" % ", ".join(sorted(set(addrs))))
    ip = lan()
    if ip and probe(ip, 11434):
        return Result(label, FAIL, "port 11434 answers on %s (your network address)" % ip, fix)
    detail = "not reachable on %s" % ip if ip else "no network address to test from"
    return Result(label, OK, detail)


def check_ollama(get=http_get, env=None, exposure=check_ollama_exposure, models=True):
    label = "Ollama running (API on 127.0.0.1:11434)"
    code, body = get(OLLAMA_URL + "/api/version")
    if code != 200:
        if sys.platform == "darwin":
            adv = "Open Ollama from Applications (or run `ollama serve` in a new terminal), then run this again."
        elif is_windows():
            adv = "Start Ollama from the Start menu (or run `ollama serve` in a new window), then run this again."
        else:
            adv = "Start it: sudo systemctl start ollama (no systemd, e.g. WSL: run `ollama serve` in a new terminal)."
        if not shutil.which("ollama"):
            adv = "Ollama is not installed. Run %s and answer y to Ollama." % setup_cmd()
        return [Result(label, FAIL, "no answer from %s" % OLLAMA_URL, adv),
                Result("Ollama listens on 127.0.0.1 only", SKIP),
                Result("Lab models downloaded", SKIP)]
    try:
        version = json.loads(body).get("version", "?")
    except ValueError:
        version = "?"
    results = [Result(label, OK, "Ollama %s" % version), exposure(env=env)]
    if not models:
        return results + [Result("Lab models downloaded", SKIP, "skipped on request")]
    code, body = get(OLLAMA_URL + "/api/tags")
    have = set()
    if code == 200:
        try:
            for m in json.loads(body).get("models", []):
                name = m.get("name", "")
                have.add(name)
                if name.endswith(":latest"):
                    have.add(name[: -len(":latest")])
        except ValueError:
            pass
    missing = [m for m in MODELS if m not in have]
    if missing:
        results.append(Result("Lab models downloaded", FAIL, "missing: %s" % ", ".join(missing),
                              "Run: " + " && ".join("ollama pull %s" % m for m in missing)))
    else:
        results.append(Result("Lab models downloaded", OK, ", ".join(MODELS)))
    return results


def total_ram_gb(runner=run):
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        return int(line.split()[1]) / 1024 / 1024
        elif sys.platform == "darwin":
            code, out = runner(["sysctl", "-n", "hw.memsize"])
            if code == 0:
                return int(out.strip()) / 1024 ** 3
        elif is_windows():
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("sullAvailExtendedVirtual", ctypes.c_ulonglong)]
            m = MEMORYSTATUSEX()
            m.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
                return m.ullTotalPhys / 1024 ** 3
    except (OSError, ValueError, AttributeError):
        pass
    return None


def check_resources(root, ram_gb=None, free_gb=None):
    ram = total_ram_gb() if ram_gb is None else ram_gb
    if free_gb is None:
        free_gb = shutil.disk_usage(root).free / 1024 ** 3
    out = []
    if ram is None:
        out.append(Result("Memory (RAM)", WARN, "could not read", "8 GB or more is comfortable for the labs."))
    elif ram + 0.5 < MIN_RAM_GB:   # "8 GB" machines report a little less than 8
        out.append(Result("Memory (RAM)", WARN, "%.1f GB" % ram,
                          "Below 8 GB: close other apps while a model runs, and prefer the smaller model "
                          "qwen3:0.6b (lesson 0.6, Step 4). Most labs use a stand-in model and need very little."))
    else:
        out.append(Result("Memory (RAM)", OK, "%.1f GB" % ram))
    if free_gb < HARD_MIN_DISK_GB:
        out.append(Result("Free disk space", FAIL, "%.1f GB free" % free_gb,
                          "Free at least 5 GB: the two models alone need about 1.5 GB."))
    elif free_gb < MIN_DISK_GB:
        out.append(Result("Free disk space", WARN, "%.1f GB free" % free_gb,
                          "15 GB free is comfortable (models, Docker images, lab packages). "
                          "`docker system prune` and `ollama rm <model>` free space."))
    else:
        out.append(Result("Free disk space", OK, "%.1f GB free" % free_gb))
    return out


# ---------------------------------------------------------------- report

MARKS_UNICODE = {OK: "\u2713", WARN: "!", FAIL: "\u2717", SKIP: "-"}
MARKS_ASCII = {OK: "[ok]", WARN: "[!!]", FAIL: "[XX]", SKIP: "[--]"}


def marks_for(stream):
    enc = getattr(stream, "encoding", None) or "ascii"
    try:
        "\u2713\u2717".encode(enc)
        return MARKS_UNICODE
    except (UnicodeEncodeError, LookupError):
        return MARKS_ASCII


def collect(args):
    root = args.root
    results = []
    results.append(check_venv(root))
    results.append(check_tool("git", "git installed", "Run %s and answer y to git." % setup_cmd()))
    if not is_windows():
        results.append(check_tool("make", "make installed", "Most lab shortcuts use make. Run %s, or "
                                  "run the python commands shown in each lab README." % setup_cmd(), WARN))
    skip = set(args.skip)
    if "docker" in skip:
        results += [Result("Docker", SKIP, "skipped on request")]
    else:
        results += check_docker(hello=not args.no_hello)
    if "ollama" in skip:
        results += [Result("Ollama", SKIP, "skipped on request")]
    else:
        results += check_ollama(models="models" not in skip)
    results += check_resources(root)
    return results


def main(argv=None):
    p = argparse.ArgumentParser(description="Check this computer is ready for the AI Security Engineer labs.")
    p.add_argument("--root", default=ROOT, help="repo root (default: the folder above tools/)")
    p.add_argument("--skip", default="", help="comma list of checks to skip: docker, ollama, models")
    p.add_argument("--no-hello", action="store_true", help="do not run the hello-world container")
    p.add_argument("--json", action="store_true", help="print results as JSON")
    args = p.parse_args(argv)
    args.skip = [s.strip() for s in args.skip.split(",") if s.strip()]

    results = collect(args)
    failed = [r for r in results if r.status == FAIL]
    if args.json:
        print(json.dumps([r.as_dict() for r in results], indent=2))
        return 1 if failed else 0

    marks = marks_for(sys.stdout)
    print("Lab doctor: %s %s, Python %s running this check" % (
        platform.system() or sys.platform, platform.machine(), platform.python_version()))
    print()
    width = max(len(r.name) for r in results)
    for r in results:
        line = "  %s  %s  %s" % (marks[r.status].ljust(4 if marks is MARKS_ASCII else 1), r.name.ljust(width), r.detail)
        print(line.rstrip())
        if r.advice and r.status in (FAIL, WARN):
            print("        next step: %s" % r.advice)
    warned = [r for r in results if r.status == WARN]
    print()
    if failed:
        print("%d check(s) failed. Fix them from the top down (each fix often clears the ones below it), "
              "then run this again. Help: docs/SETUP.md" % len(failed))
        return 1
    if warned:
        print("Ready, with %d warning(s) above. You can start the labs." % len(warned))
    else:
        print("All good. You're ready for the labs: start with labs/m01.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

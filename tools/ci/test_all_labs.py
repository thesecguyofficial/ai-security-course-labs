"""Run every lab's own tests, the way a student would, on any OS (Mac, Linux, Windows).

Labs with packages get their own .venv inside the lab folder (like `make setup`); the rest use the
Python that runs this script. Prints one line per lab and a summary; exits 1 if any lab fails.

    python tools/ci/test_all_labs.py            # every lab
    python tools/ci/test_all_labs.py m05 az12   # some labs
"""
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LABS = ROOT / "labs"
WINDOWS = os.name == "nt"
# The capstones run their tests through unittest (see their Makefiles).
SPECIAL = {
    "m19": ["-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"],
    "m32": ["-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v", "-p", "test_functional.py"],
}


def lab_python(lab: Path) -> str:
    """The lab's own .venv when it has packages, else this Python."""
    if not (lab / "requirements.txt").exists():
        return sys.executable
    venv = lab / ".venv"
    py = venv / ("Scripts/python.exe" if WINDOWS else "bin/python")
    if not py.exists():
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
        subprocess.run([str(py), "-m", "pip", "install", "--quiet", "--upgrade", "pip"], check=True)
        subprocess.run([str(py), "-m", "pip", "install", "--quiet", "-r", "requirements.txt"], cwd=lab, check=True)
    return str(py)


def run(lab: Path):
    if lab.name in SPECIAL:
        args = SPECIAL[lab.name]
    elif (lab / "run_tests.py").exists():
        args = ["run_tests.py"]
    else:
        return "SKIP", "no tests in this lab", 0.0
    start = time.time()
    try:
        py = lab_python(lab)
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        p = subprocess.run([py, *args], cwd=lab, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1200, env=env)
    except subprocess.CalledProcessError as e:
        return "FAIL", f"setup failed: {e}", time.time() - start
    except subprocess.TimeoutExpired:
        return "FAIL", "timed out after 20 minutes", time.time() - start
    tail = (p.stdout + p.stderr).strip().splitlines()[-25:]
    return ("PASS" if p.returncode == 0 else "FAIL"), "\n".join(tail), time.time() - start


def main(names):
    labs = sorted(d for d in LABS.iterdir() if d.is_dir() and (not names or d.name in names))
    results = []
    for lab in labs:
        status, detail, secs = run(lab)
        results.append((lab.name, status, secs))
        print(f"{status:4}  {lab.name:5}  {secs:6.1f}s", flush=True)
        if status == "FAIL":
            print("      " + detail.replace("\n", "\n      "), flush=True)
    failed = [n for n, s, _ in results if s == "FAIL"]
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"### Lab tests on {sys.platform}, Python {sys.version.split()[0]}\n\n| Lab | Result | Seconds |\n|---|---|---|\n")
            for n, s, t in results:
                f.write(f"| {n} | {s} | {t:.0f} |\n")
    print(f"\n{sum(s == 'PASS' for _, s, _ in results)} passed, {len(failed)} failed, {sum(s == 'SKIP' for _, s, _ in results)} without tests")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

"""Static and smoke tests for setup.sh and setup.ps1. Standard library only; no installs, no network.

Run:  python3 -m unittest discover -s tools/tests -v     (or: make test-setup)
shellcheck runs when it is on PATH (pip install shellcheck-py); CI always installs it.
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "tools", "style"))
import style_check  # noqa: E402

SH = os.path.join(ROOT, "setup.sh")
PS1 = os.path.join(ROOT, "setup.ps1")
DOCTOR = os.path.join(ROOT, "tools", "doctor.py")
POSIX = os.name != "nt"


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class HouseVoice(unittest.TestCase):
    """style_check.py only reads text files, so the scripts' own messages are checked here."""

    def test_no_banned_words_or_em_dashes(self):
        for path in (SH, PS1, DOCTOR, os.path.join(ROOT, "tools", "check_python.py")):
            text = read(path)
            self.assertNotIn("\u2014", text, path)
            hits = [m.group(0) for m in style_check.BANNED_RE.finditer(text)]
            self.assertEqual(hits, [], path)


class Checksums(unittest.TestCase):
    def test_sha256sums_is_current(self):
        listed = {}
        for line in read(os.path.join(ROOT, "SHA256SUMS")).splitlines():
            digest, name = line.split(None, 1)
            listed[name.strip().lstrip("*")] = digest
        self.assertEqual(sorted(listed), sorted(["setup.sh", "setup.ps1", "tools/doctor.py"]))
        for name, digest in listed.items():
            with open(os.path.join(ROOT, name), "rb") as f:
                actual = hashlib.sha256(f.read()).hexdigest()
            self.assertEqual(actual, digest, "%s changed: run `make checksums` and commit SHA256SUMS" % name)

    def test_line_endings_are_pinned(self):
        attrs = read(os.path.join(ROOT, ".gitattributes"))
        for name in ("setup.sh", "setup.ps1", "tools/doctor.py", "SHA256SUMS"):
            self.assertRegex(attrs, r"(?m)^%s\s+-text" % re.escape(name))


class PowerShellScript(unittest.TestCase):
    def test_ascii_only(self):
        # Windows PowerShell 5.1 reads a script without a BOM as the local code page: keep it plain ASCII.
        with open(PS1, "rb") as f:
            data = f.read()
        self.assertTrue(all(b < 128 for b in data), "setup.ps1 must be ASCII-only")

    def test_no_pwsh7_only_syntax(self):
        text = read(PS1)
        for pattern in (r"\?\?", r"\?\.", r"\s\?\s[^:]+\s:\s", r"-Encoding\s+utf8NoBOM", r"&&", r"\|\|"):
            self.assertIsNone(re.search(pattern, text), "PowerShell 7-only syntax: %s" % pattern)

    def test_parameters_exist(self):
        text = read(PS1)
        for p in ("Yes", "Check", "Uninstall", "NoDocker", "NoOllama", "NoModels"):
            self.assertIn("[switch]$%s" % p, text)

    def test_never_pipes_downloads_into_a_shell(self):
        self.assertNotRegex(read(PS1), r"(?i)(irm|iwr|invoke-(restmethod|webrequest))[^\n|]*\|\s*iex")


class ShellScript(unittest.TestCase):
    def test_never_curl_pipe_sh(self):
        code = "\n".join(l for l in read(SH).splitlines() if not l.lstrip().startswith("#"))
        self.assertNotRegex(code, r"curl[^\n|]*\|\s*(sudo\s+)?(ba)?sh")

    def test_never_sets_ollama_host(self):
        for path in (SH, PS1):
            self.assertNotRegex(read(path), r"OLLAMA_HOST=0\.0\.0\.0|OLLAMA_HOST\s*=\s*['\"]0\.0\.0\.0")

    def test_sudo_only_through_run_sudo(self):
        bad = [l for l in read(SH).splitlines()
               if re.search(r"\bsudo\b", l) and not l.lstrip().startswith("#")
               and "run_sudo" not in l and 'SUDO="sudo"' not in l and "say " not in l and "warn " not in l
               and "printf" not in l and "$SUDO docker info" not in l]
        self.assertEqual(bad, [])

    @unittest.skipUnless(POSIX and shutil.which("bash"), "needs bash")
    def test_bash_syntax(self):
        subprocess.run(["bash", "-n", SH], check=True)

    @unittest.skipUnless(POSIX and shutil.which("shellcheck"), "shellcheck not installed (pip install shellcheck-py)")
    def test_shellcheck_clean(self):
        p = subprocess.run(["shellcheck", "-x", SH], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(p.returncode, 0, p.stdout.decode())

    @unittest.skipUnless(POSIX and shutil.which("bash"), "needs bash")
    def test_help_and_bad_option(self):
        p = subprocess.run(["bash", SH, "--help"], stdout=subprocess.PIPE)
        self.assertEqual(p.returncode, 0)
        self.assertIn(b"--check", p.stdout)
        p = subprocess.run(["bash", SH, "--no-such-option"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(p.returncode, 2)


if __name__ == "__main__":
    unittest.main()

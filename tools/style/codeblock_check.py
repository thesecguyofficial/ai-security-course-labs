#!/usr/bin/env python3
"""Copy-paste checker for shell code blocks in Markdown.

Why: the site has copy buttons, so every shell block must paste and run cleanly. Interactive zsh
(the macOS default) does NOT treat `#` as a comment unless `setopt interactivecomments` is on, so a
trailing `# comment` becomes arguments ("zsh: number expected", "command not found"). A `$ ` prompt
prefix breaks the paste too. This file is identical in the course-content and labs repos (keep them
in sync).

Checks shell-type fences: bash, sh, shell, zsh, console, powershell/pwsh, and unlabelled fences whose
first non-empty line looks like a shell command. Errors on:
  - a line starting with `#` (comment line). Allowed: `#!` on line 1 of a block when the 2 lines
    before the fence mention a file name (the block is that file's content, not terminal input).
  - a trailing ` #` comment outside quotes.
  - a line starting with `$ ` (prompt prefix). Show transcripts in a ```text block instead.
Heredoc bodies (`<<EOF` ... `EOF`) and text inside quotes are not checked.

Opt-out for a real exception: put `<!-- codeblock-ok -->` (optionally `<!-- codeblock-ok: reason -->`)
on the line right before the fence.

Usage: python3 tools/style/codeblock_check.py [paths...]   (files or folders; default: current folder)
       --exclude NAME   skip files with this exact name (repeatable; e.g. --exclude slides.md)
       --self-test      run the built-in test cases
Exit code 1 when any error is found.
"""
import pathlib
import re
import sys

SHELL_LANGS = {"bash", "sh", "shell", "zsh", "console", "powershell", "pwsh", "ps1", "ps"}
# First words that mark an unlabelled fence as shell input.
SHELL_WORDS = {
    "cd", "ls", "git", "python", "python3", "py", "pip", "pip3", "pipx", "npm", "npx", "node", "docker", "curl",
    "wget", "make", "brew", "apt", "apt-get", "sudo", "export", "echo", "cat", "ollama", "uv", "chmod", "mkdir",
    "rm", "cp", "mv", "shasum", "sha256sum", "grep", "source", "kubectl", "aws", "az", "gcloud", "terraform", "gh",
    "pytest", "set", "setx", "winget", "choco", "Get-FileHash", "Set-ExecutionPolicy", "unzip", "tar", "open",
    "code", "which", "where", "env", "touch", "head", "tail", "jq", "ssh", "scp", "kill", "ps", "dig", "nslookup",
    "openssl", "cosign", "syft", "grype", "trivy", "semgrep", "garak", "promptfoo", "pre-commit", "deactivate",
    "conda", "poetry", "systemctl", "launchctl", "xcode-select", "wsl", "powershell", "pwsh", "nc", "lsof",
}
FENCE_RE = re.compile(r"^(\s*)(`{3,}|~{3,})\s*([^\s`]*)")
HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
FILE_MENTION_RE = re.compile(r"[\w./-]+\.[A-Za-z0-9]{1,5}\b|\bfile\b", re.I)
OPT_OUT = "<!-- codeblock-ok"


def looks_like_shell(first: str) -> bool:
    s = first.strip()
    if s.startswith("$ ") or s.startswith("./") or s.startswith(".\\"):
        return True
    word = s.split()[0] if s.split() else ""
    return word in SHELL_WORDS


def trailing_comment(line: str, state: dict) -> bool:
    """True if `line` has a ` #` comment outside quotes. `state["q"]` carries an open quote across lines."""
    q = state.get("q")
    prev = " "
    i = 0
    while i < len(line):
        c = line[i]
        if q:
            if c == "\\" and q == '"':
                i += 2
                prev = "x"
                continue
            if c == q:
                q = None
        else:
            if c == "\\":
                i += 2
                prev = "x"
                continue
            if c in ("'", '"'):
                q = c
            elif c == "#" and prev in (" ", "\t") and i > 0:
                state["q"] = None
                return True
        prev = c
        i += 1
    state["q"] = q
    return False


def check_block(lines, start_no, before, lang):
    """lines = block body (fence indent removed). Returns [(line_no, message)]."""
    errs = []
    state = {"q": None}
    heredoc = None
    first_seen = False
    ps = lang in ("powershell", "pwsh", "ps1", "ps")
    for k, raw in enumerate(lines):
        no = start_no + k
        if heredoc:
            if raw.strip() == heredoc:
                heredoc = None
            continue
        s = raw.strip()
        if not s:
            continue
        is_first = not first_seen
        first_seen = True
        if state["q"] is None:
            if s.startswith("#!") and is_first and FILE_MENTION_RE.search(before):
                continue
            if s.startswith("#") or (ps and s.startswith("<#")):
                errs.append((no, "comment line in a shell block (zsh pastes it as a command): move it to the prose"))
                continue
            if raw.lstrip().startswith("$ ") or s == "$":
                errs.append((no, "`$ ` prompt prefix breaks paste: remove it, or make the block ```text"))
                continue
        if trailing_comment(raw, state):
            errs.append((no, "trailing ` #` comment (zsh treats it as arguments): move it to the prose"))
        m = HEREDOC_RE.search(raw)
        if m and state["q"] is None:
            heredoc = m.group(2)
    return errs


def check_text(text: str):
    """Returns [(line_no, message)] for one Markdown document."""
    lines = text.splitlines()
    errs = []
    i = 0
    while i < len(lines):
        m = FENCE_RE.match(lines[i])
        if not m:
            i += 1
            continue
        indent, fence, lang = m.group(1), m.group(2), m.group(3).lower()
        j = i + 1
        body = []
        close = re.compile(r"^\s*" + re.escape(fence[0]) + "{" + str(len(fence)) + r",}\s*$")
        while j < len(lines) and not close.match(lines[j]):
            ln = lines[j]
            body.append(ln[len(indent):] if ln.startswith(indent) else ln.lstrip())
            j += 1
        prev = lines[i - 1].strip() if i > 0 else ""
        before = "\n".join(lines[max(0, i - 2):i])
        first = next((b for b in body if b.strip()), "")
        shell = lang in SHELL_LANGS or (lang == "" and first and looks_like_shell(first))
        if shell and not prev.startswith(OPT_OUT):
            errs += check_block(body, i + 2, before, lang)
        i = j + 1
    return errs


def iter_files(paths, excludes):
    for p in paths:
        p = pathlib.Path(p)
        files = [p] if p.is_file() else sorted(p.rglob("*.md"))
        for f in files:
            parts = set(f.parts)
            if f.name in excludes or parts & {".venv", "node_modules", ".git", ".work"}:
                continue
            yield f


def self_test():
    cases = [
        ("```bash\nshasum -a 256 setup.sh            # Mac\n```\n", 1),
        ("```bash\n# Mac\nshasum -a 256 setup.sh\n```\n", 1),
        ("```bash\n$ ls\n```\n", 1),
        ("```bash\nshasum -a 256 setup.sh\n```\n", 0),
        ("```bash\necho 'a # b' \"c # d\"\ncurl https://x.com/#frag\n```\n", 0),
        ("```bash\necho $# ${#arr[@]}\n```\n", 0),
        ("```\nls -la   # list\n```\n", 1),                    # unlabelled shell fence
        ("```\n# Title\nplain text\n```\n", 0),                # unlabelled, not shell
        ("```python\n# fine\nx = 1  # fine\n```\n", 0),
        ("```text\n$ ls\n# output\n```\n", 0),
        ("Create a file `run.sh` with:\n\n```bash\n#!/usr/bin/env bash\nset -e\n```\n", 0),
        ("Run this:\n\n```bash\n#!/usr/bin/env bash\n```\n", 1),
        ("```bash\ncat > f.py <<'EOF'\n# python comment\nEOF\nls\n```\n", 0),
        ("<!-- codeblock-ok: transcript -->\n```bash\n$ ls\n```\n", 0),
        ("1. Run:\n\n   ```bash\n   ls # x\n   ```\n", 1),
        ("```powershell\nGet-FileHash setup.ps1 -Algorithm SHA256   # Windows\n```\n", 1),
        ("```bash\npython3 -c 'import x\n# inside quotes\nprint(1)'\n```\n", 0),
    ]
    bad = 0
    for text, want in cases:
        got = len(check_text(text))
        if got != want:
            bad += 1
            print(f"FAIL want {want} got {got}: {text!r}")
    print(f"[codeblock] self-test: {len(cases) - bad}/{len(cases)} passed")
    return 1 if bad else 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    excludes, paths, it = set(), [], iter(argv)
    for a in it:
        if a == "--exclude":
            excludes.add(next(it, ""))
        else:
            paths.append(a)
    total = nfiles = 0
    for f in iter_files(paths or ["."], excludes):
        nfiles += 1
        for no, msg in check_text(f.read_text(encoding="utf-8")):
            total += 1
            print(f"ERROR {f}:{no}: {msg}")
    print(f"[codeblock] {nfiles} files, {total} errors")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

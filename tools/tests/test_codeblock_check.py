"""Unit tests for tools/style/codeblock_check.py. Standard library only.

Run:  python3 -m unittest discover -s tools/tests -v     (or: make test-setup)
"""
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "tools", "style"))
import codeblock_check as cc  # noqa: E402


def errors(text):
    return [msg for _, msg in cc.check_text(text)]


class ShellBlockTests(unittest.TestCase):
    def test_trailing_comment_is_an_error(self):
        # The block the course owner pasted into zsh: "zsh: number expected".
        self.assertEqual(len(errors("```bash\nshasum -a 256 setup.sh   # Mac (Linux: sha256sum setup.sh)\n```\n")), 1)

    def test_comment_line_is_an_error(self):
        self.assertEqual(len(errors("```sh\n# Windows\nmake doctor\n```\n")), 1)

    def test_prompt_prefix_is_an_error(self):
        self.assertEqual(len(errors("```console\n$ make test\n```\n")), 1)

    def test_indented_block_in_a_list(self):
        self.assertEqual(len(errors("1. Run:\n\n   ```bash\n   make check   # 3 findings\n   ```\n")), 1)

    def test_powershell_comment(self):
        self.assertEqual(len(errors("```powershell\nGet-FileHash setup.ps1 -Algorithm SHA256   # Windows\n```\n")), 1)

    def test_unlabelled_shell_fence(self):
        self.assertEqual(len(errors("```\ncd labs/m01   # first\n```\n")), 1)

    def test_clean_blocks_pass(self):
        self.assertEqual(errors("```bash\nshasum -a 256 setup.sh\n```\n"), [])
        self.assertEqual(errors("```bash\necho 'a # b' \"c # d\" $# ${#x}\ncurl https://example.com/#top\n```\n"), [])

    def test_other_languages_and_output_are_skipped(self):
        self.assertEqual(errors("```python\n# a comment\nx = 1  # fine\n```\n"), [])
        self.assertEqual(errors("```text\n$ make test\nALL TESTS PASSED  # 3 run\n```\n"), [])
        self.assertEqual(errors("```\n# A heading in plain text\nnot a command\n```\n"), [])

    def test_heredoc_body_is_skipped(self):
        self.assertEqual(errors("```bash\ncat > f.py <<'EOF'\n# python comment\nEOF\n```\n"), [])

    def test_shebang_in_a_file_block(self):
        self.assertEqual(errors("Create `run.sh` with:\n\n```bash\n#!/usr/bin/env bash\nset -e\n```\n"), [])
        self.assertEqual(len(errors("Run:\n\n```bash\n#!/usr/bin/env bash\n```\n")), 1)

    def test_opt_out_marker(self):
        self.assertEqual(errors("<!-- codeblock-ok: transcript -->\n```bash\n$ ls\n```\n"), [])

    def test_built_in_self_test(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "style", "codeblock_check.py"), "--self-test"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_repo_is_clean(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "style", "codeblock_check.py"), ROOT],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout[-3000:])


if __name__ == "__main__":
    unittest.main()

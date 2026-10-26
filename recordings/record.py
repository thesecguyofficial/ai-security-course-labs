#!/usr/bin/env python3
"""Record a real terminal session for a lab video.

Runs a login shell as the real user `thesecguy` inside `asciinema rec`, types each command of a
scenario at human speed, answers the prompts the scenario lists, and waits for the real output.
Nothing is edited: the .cast file is exactly what the terminal printed. Outputs (in OUT_DIR):

  session.cast     asciinema v2 recording (every byte the terminal showed, with timing)
  steps.json       when each step started and ended, plus every key the driver sent
  transcript.txt   the same session as plain text, for the run log and for review

Usage: python3 recordings/record.py recordings/scenarios/<name>.json OUT_DIR
"""
import json
import os
import pathlib
import random
import re
import sys
import time

import pexpect

PROMPT = r"thesecguy@lab[^\r\n]*?\$ "
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\x1b[()][0-9A-B]|\r")


def main():
    sc = json.loads(pathlib.Path(sys.argv[1]).read_text())
    out = pathlib.Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    rows, cols = sc.get("rows", 26), sc.get("cols", 100)
    rnd = random.Random(sc.get("seed", 7))
    raw = open(out / "raw.log", "w", encoding="utf-8", errors="replace")
    t0 = time.monotonic()
    now = lambda: round(time.monotonic() - t0, 3)
    child = pexpect.spawn(
        "asciinema",
        ["rec", "-q", "--overwrite", "--cols", str(cols), "--rows", str(rows),
         "-c", "sudo -iu thesecguy env -i HOME=/home/thesecguy USER=thesecguy LOGNAME=thesecguy SHELL=/bin/bash LANG=C.UTF-8 TERM=xterm-256color PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin COLUMNS=%d LINES=%d bash -i" % (cols, rows),
         str(out / "session.cast")],
        dimensions=(rows, cols), encoding="utf-8", codec_errors="replace", timeout=None,
        # A clean environment: nothing from GitHub's own runner account (HOME, XDG_*, tool caches)
        # may leak into the student's session.
        env={"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/root"), "LANG": "C.UTF-8",
             "TERM": "xterm-256color"})
    child.logfile_read = raw
    child.expect(PROMPT, timeout=60)
    time.sleep(0.5)
    child.send("\x0c")                      # Ctrl-L: clear the screen, the prompt redraws (not a typed command)
    child.expect(PROMPT, timeout=10)
    time.sleep(1.0)
    log = {"scenario": sc["name"], "start": now(), "steps": [], "keys": []}

    def type_text(text):
        for ch in text:
            child.send(ch)
            time.sleep(rnd.uniform(0.035, 0.09) if ch != " " else rnd.uniform(0.06, 0.14))

    for st in sc["steps"]:
        rec = {"label": st.get("label", ""), "speed": st.get("speed", 1), "start": now()}
        time.sleep(st.get("pause_before", 0.6))
        log["keys"].append({"t": now(), "what": "type"})
        type_text(st["type"])
        time.sleep(0.35)
        child.send(st.get("enter", "\r"))
        until = st.get("until", PROMPT)
        answers = st.get("answers", [])
        pats = [until] + [a["re"] for a in answers]
        while True:
            i = child.expect(pats, timeout=st.get("timeout", 1800))
            if i == 0:
                break
            a = answers[i - 1]
            time.sleep(a.get("delay", 1.2))
            log["keys"].append({"t": now(), "what": a.get("note", a["re"])})
            if a.get("typed", True):
                type_text(a["send"].rstrip("\r"))
                if a["send"].endswith("\r"):
                    time.sleep(0.3); child.send("\r")
            else:
                child.send(a["send"])
            time.sleep(a.get("after", 0))
        rec["end"] = now()
        log["steps"].append(rec)
        time.sleep(st.get("pause_after", 1.8))
    log["end"] = now()
    child.send("exit\r")
    child.expect(pexpect.EOF, timeout=30)
    raw.close()
    (out / "steps.json").write_text(json.dumps(log, indent=2) + "\n")
    text = ANSI.sub("", (out / "raw.log").read_text(errors="replace"))
    (out / "transcript.txt").write_text(text)
    (out / "raw.log").unlink()
    print(f"recorded {len(log['steps'])} steps in {log['end']:.0f} s -> {out}")


if __name__ == "__main__":
    main()

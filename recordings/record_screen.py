#!/usr/bin/env python3
"""Record a REAL editor session for a course lab video (labs that are done in an editor, not a terminal).

VS Code (code-server) runs as the user thesecguy on this fresh machine. Playwright drives a real Chromium
window and records it as video while it types every change into the lab file, at a steady typing speed.
Nothing is pasted: each character goes through the keyboard into the editor. At the end the saved file
is compared with the expected result; any difference rejects the take.

    python3 record_screen.py recordings/scenarios/m02-2.5-editor.json out/m02-2.5-editor http://127.0.0.1:8080

Writes: screen.mp4 (the recording), marks.json (seconds into the video where each part starts and ends),
result.md (the saved file), steps.json (what was typed where), shots/ (one picture per part, for review).
"""
import json
import pathlib
import subprocess
import sys
import time

from playwright.sync_api import sync_playwright

W, H = 1600, 900
TYPE_DELAY = 14  # ms per character


def plan(template: str, sections: list) -> tuple[list[str], list[dict]]:
    """Apply the scenario's edits to the template text (off camera) and return the expected lines plus a
    list of concrete actions (line number + what to type). Fails before recording if an anchor is missing."""
    lines = template.split("\n")
    actions = []
    for sec in sections:
        for ed in sec["edits"]:
            anchor = ed.get("append") or ed.get("replace")
            idx = next((i for i, l in enumerate(lines) if l.rstrip() == anchor.rstrip()), None)
            if idx is None:
                raise SystemExit(f"anchor not found in template: {anchor!r}")
            if "append" in ed:
                lines[idx] = lines[idx].rstrip() + ed["text"]
                actions.append({"mark": sec["mark"], "line": idx + 1, "mode": "append", "text": ed["text"]})
            else:
                lines[idx] = ed["with"]
                actions.append({"mark": sec["mark"], "line": idx + 1, "mode": "replace", "text": ed["with"]})
            for j, extra in enumerate(ed.get("then", []), 1):
                lines.insert(idx + j, extra)
            if ed.get("then"):
                actions[-1]["then"] = ed["then"]
    return lines, actions


def main():
    scen = json.loads(pathlib.Path(sys.argv[1]).read_text())
    out = pathlib.Path(sys.argv[2])
    url = sys.argv[3]
    home = pathlib.Path("/home/thesecguy")
    folder = home / scen["folder"]
    template = (folder / scen["template"]).read_text()
    expected, actions = plan(template, scen["sections"])
    (out / "shots").mkdir(parents=True, exist_ok=True)
    vids = out / "video-raw"
    marks, t0 = [], None

    def now():
        return round(time.monotonic() - t0, 2)

    def mark(label, page):
        marks.append({"label": label, "t": now()})
        page.screenshot(path=str(out / "shots" / f"{len(marks):02d}-{label.replace(' ', '-').lower()}.png"))

    with sync_playwright() as p:
        b = p.chromium.launch(args=["--no-first-run", "--disable-infobars"])
        ctx = b.new_context(viewport={"width": W, "height": H}, record_video_dir=str(vids),
                            record_video_size={"width": W, "height": H}, color_scheme="dark")
        page = ctx.new_page()
        t0 = time.monotonic()
        page.goto(f"{url}/?folder={folder}")
        page.wait_for_selector(".monaco-workbench", timeout=120000)
        page.wait_for_selector(".explorer-folders-view .monaco-list-row", timeout=60000)
        page.wait_for_timeout(2500)
        page.keyboard.press("Escape")
        mark("Open the lab folder", page)

        # Open the blank template from the Explorer, so the student sees what they are copying.
        page.locator(".explorer-folders-view .monaco-list-row", has_text=scen["template"]).first.click()
        page.wait_for_timeout(3000)
        mark("The template", page)

        # Copy it in VS Code's own terminal, exactly as the guide says.
        page.keyboard.press("Control+`")
        page.wait_for_selector(".terminal-wrapper .xterm", timeout=60000)
        page.wait_for_timeout(2500)
        mark("Copy the template", page)
        for cmd in scen["terminal"]:
            page.keyboard.type(cmd, delay=45)
            page.wait_for_timeout(400)
            page.keyboard.press("Enter")
            page.wait_for_timeout(1500)
        page.wait_for_timeout(1500)
        if not (folder / scen["file"]).exists():
            raise SystemExit("the copy didn't happen: my-threat-model.md is missing")
        page.keyboard.press("Control+`")  # hide the terminal again

        # Open the copy, and its live preview beside it.
        page.keyboard.press("Control+p")
        page.wait_for_timeout(700)
        page.keyboard.type(scen["file"], delay=45)
        page.wait_for_timeout(700)
        page.keyboard.press("Enter")
        page.wait_for_timeout(1500)
        page.keyboard.press("Control+k")
        page.keyboard.press("v")
        page.wait_for_timeout(3000)
        # Focus back on the editor (left group) and hide the file list, so the text is bigger on screen.
        page.keyboard.press("Control+1")
        page.wait_for_timeout(500)
        page.keyboard.press("Control+b")
        page.wait_for_timeout(1200)

        current = None
        for act in actions:
            if act["mark"] != current:
                if current:
                    marks.append({"label": f"{current} done", "t": now()})
                current = act["mark"]
                mark(current, page)
            page.keyboard.press("Control+g")
            page.wait_for_timeout(350)
            page.keyboard.type(str(act["line"]), delay=40)
            page.keyboard.press("Enter")
            page.wait_for_timeout(350)
            # Select the whole logical line (Ctrl+L), then drop its line break from the selection: unlike
            # Shift+End, this also works when word wrap shows a long line on several rows.
            page.keyboard.press("Control+l")
            page.keyboard.press("Shift+ArrowLeft")
            if act["mode"] == "append":
                page.keyboard.press("ArrowRight")  # collapse to the end of the line
            page.wait_for_timeout(250)
            page.keyboard.type(act["text"], delay=TYPE_DELAY)
            for extra in act.get("then", []):
                page.keyboard.press("Enter")   # auto-indent is off in settings, so the new line starts empty
                page.keyboard.type(extra, delay=TYPE_DELAY)
            page.keyboard.press("Control+s")
            page.wait_for_timeout(600)
        marks.append({"label": f"{current} done", "t": now()})
        page.wait_for_timeout(2500)
        mark("Saved", page)
        page.wait_for_timeout(2000)
        marks.append({"label": "End", "t": now()})
        video_path = page.video.path()
        ctx.close()
        b.close()

    got = (folder / scen["file"]).read_text()
    (out / "result.md").write_text(got)
    want = "\n".join(expected)
    if got.rstrip("\n") != want.rstrip("\n"):
        import difflib
        diff = "\n".join(difflib.unified_diff(want.split("\n"), got.split("\n"), "expected", "saved", lineterm=""))
        (out / "diff.txt").write_text(diff)
        print(diff[:4000])
        raise SystemExit("take rejected: the saved file differs from what was typed")
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", video_path, "-c:v", "libx264", "-preset", "veryfast",
                    "-crf", "18", "-pix_fmt", "yuv420p", "-r", "30", str(out / "screen.mp4")], check=True)
    (out / "marks.json").write_text(json.dumps(marks, indent=2) + "\n")
    (out / "steps.json").write_text(json.dumps(actions, indent=2, ensure_ascii=False) + "\n")
    print("marks:")
    for m in marks:
        print(f"  {m['t']:7.2f}s  {m['label']}")
    print("take accepted: the saved file matches, character for character")


if __name__ == "__main__":
    main()

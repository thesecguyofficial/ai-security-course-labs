#!/usr/bin/env python3
"""Record a REAL OWASP Threat Dragon session for the M2 lab video, part 1 (lesson 2.5, "understand it").

Threat Dragon (OWASP, Apache-2.0) runs from its official container image on this fresh machine, in local mode
(no account, nothing leaves the machine). Playwright drives a real Chromium window and records it while it opens
the lab's starter model (labs/m02/tsg-helpdesk-starter.json from this checkout), opens its diagram, and selects
one element of each kind so the Properties panel shows what the file says about it: an external entity, a process,
the model, a data store, the untrusted flow into the model, and a trust boundary.

    python3 record_threatdragon_open.py out/m02-2.5-threatdragon-open http://127.0.0.1:3000 labs/m02/tsg-helpdesk-starter.json

Writes: screen.webm (untouched recording), marks.json, model.json (the model Threat Dragon saves back at the end),
shots/. Headless Chromium can't show the operating system's file dialog, so the page's file picker returns the
lab file itself (the same bytes as in the repository); everything after that is Threat Dragon's own code.
"""
import json
import pathlib
import shutil
import sys
import time

from playwright.sync_api import sync_playwright

W, H = 1600, 900
HOLD = 3500     # ms on each selected element, so the Properties panel can be read


def center(bb):
    return bb["x"] + bb["width"] / 2, bb["y"] + bb["height"] / 2


def main():
    out = pathlib.Path(sys.argv[1])
    url = sys.argv[2]
    lab_file = pathlib.Path(sys.argv[3])
    text = lab_file.read_text("utf-8")
    want = json.loads(text)
    (out / "shots").mkdir(parents=True, exist_ok=True)
    marks, t0 = [], None

    def now():
        return round(time.monotonic() - t0, 2)

    def mark(label, pg):
        marks.append({"label": label, "t": now()})
        pg.screenshot(path=str(out / "shots" / f"{len(marks):02d}-{label.replace(' ', '-').lower()}.png"))

    def deselect(pg):
        pg.mouse.click(1560, 640)
        pg.wait_for_timeout(400)

    def select_node(pg, name):
        deselect(pg)
        want_txt = name.replace(" ", "")
        for n in pg.locator("#graph-container .x6-node").all():
            if (n.get_attribute("data-shape") or "").startswith("trust-boundary"):
                continue
            if want_txt == (n.text_content() or "").replace("\xa0", "").replace(" ", ""):
                bb = n.bounding_box()
                pg.mouse.move(*center(bb), steps=15)
                pg.mouse.click(*center(bb))
                break
        else:
            raise SystemExit(f"element {name!r} not found on the diagram")
        pg.wait_for_timeout(HOLD)
        if pg.input_value("#name") != name:
            raise SystemExit(f"selected {pg.input_value('#name')!r}, wanted {name!r}")

    def select_edge(pg, name):
        """Click the flow's line between the model and the label, as record_threatdragon.py does. A click on a
        flow sometimes lands on Threat Dragon's bend-point tool instead of selecting it, so try a few points along
        the line (the line is straight, so a bend point added there is redundant and removed at once)."""
        for frac in (0.8, 0.75, 0.85, 0.7, 0.9, 0.78, 0.82, 0.72):
            deselect(pg)
            at = pg.evaluate("""([want, frac]) => {
                for (const e of document.querySelectorAll('#graph-container .x6-edge')) {
                    if ((e.textContent || '').replace(/\\s+/g, ' ').trim() !== want) continue;
                    const path = e.querySelector('path[stroke]:not([stroke="transparent"])');
                    const pt = path.getPointAtLength(path.getTotalLength() * frac), m = path.getScreenCTM();
                    return [pt.x * m.a + pt.y * m.c + m.e, pt.x * m.b + pt.y * m.d + m.f];
                }
                return null;
            }""", [name, frac])
            if not at:
                raise SystemExit(f"flow {name!r} not found on the diagram")
            pg.mouse.move(*at, steps=15)
            pg.mouse.click(*at)
            pg.wait_for_timeout(900)
            if pg.locator("#name").count() and pg.input_value("#name") == name:
                pg.wait_for_timeout(HOLD)
                return
        raise SystemExit(f"could not select the flow {name!r}")

    def select_boundary(pg, name):
        deselect(pg)
        bb = pg.evaluate("""(want) => {
            for (const n of document.querySelectorAll('#graph-container .x6-node[data-shape="trust-boundary-box"]')) {
                if ((n.textContent || '').replace(/\\s+/g, ' ').trim() !== want) continue;
                const r = n.getBoundingClientRect();
                return {x: r.x, y: r.y, width: r.width, height: r.height};
            }
            return null;
        }""", name)
        if not bb:
            raise SystemExit(f"boundary {name!r} not found on the diagram")
        at = (bb["x"] + bb["width"] * 0.35, bb["y"] + 18)   # its name label (the top-left corner holds the delete button)
        pg.mouse.move(*at, steps=15)
        pg.mouse.click(*at)
        pg.wait_for_timeout(HOLD)
        if pg.input_value("#name") != name:
            raise SystemExit(f"selected {pg.input_value('#name')!r}, wanted {name!r}")

    with sync_playwright() as p:
        b = p.chromium.launch()
        ctx = b.new_context(viewport={"width": W, "height": H}, accept_downloads=True,
                            record_video_dir=str(out / "video-raw"), record_video_size={"width": W, "height": H})
        ctx.add_init_script(
            "delete window.showSaveFilePicker;"
            f"const __labFile = {json.dumps(text)};"
            "window.showOpenFilePicker = async () => [{ getFile: async () =>"
            f" new File([__labFile], {json.dumps(lab_file.name)}, {{ type: 'application/json' }}) }}];")
        pg = ctx.new_page()
        t0 = time.monotonic()
        pg.goto(url)
        pg.wait_for_selector("#local-login-btn", timeout=60000)
        pg.wait_for_timeout(2500)
        mark("Open Threat Dragon", pg)
        pg.click("#local-login-btn")
        pg.wait_for_timeout(2500)

        mark("Open model", pg)
        pg.click('a[href="#/local/threatmodel/import"]')
        pg.wait_for_selector("#td-open-btn", timeout=10000)
        pg.wait_for_timeout(2000)
        pg.click("#td-open-btn")
        pg.wait_for_selector(f"text={want['summary']['title']}", timeout=10000)
        pg.wait_for_timeout(4000)

        mark("Diagram", pg)
        pg.click(f"text={want['detail']['diagrams'][0]['title']}")
        pg.wait_for_selector("#graph-container .x6-node", timeout=30000)
        pg.wait_for_timeout(5000)

        mark("External entity", pg)
        select_node(pg, "Customer")
        mark("Process", pg)
        select_node(pg, "Chat app")
        mark("Model", pg)
        select_node(pg, "Model")
        mark("Data store", pg)
        select_node(pg, "Knowledge base")
        mark("Untrusted flow", pg)
        select_edge(pg, "F4 UNTRUSTED: retrieved articles")
        mark("Boundary", pg)
        select_boundary(pg, "Model boundary")
        deselect(pg)
        pg.wait_for_timeout(1500)

        mark("Saved", pg)
        with pg.expect_download() as d:
            pg.locator("button:has-text('Save')").first.click()
        d.value.save_as(str(out / "model.json"))
        pg.wait_for_timeout(2000)
        marks.append({"label": "End", "t": now()})
        video = pg.video.path()
        ctx.close()
        b.close()

    saved = json.loads((out / "model.json").read_text())
    names = sorted(c.get("data", {}).get("name") for c in saved["detail"]["diagrams"][0]["cells"])
    expect = sorted(c["data"]["name"] for c in want["detail"]["diagrams"][0]["cells"])
    if names != expect:
        raise SystemExit(f"take rejected: Threat Dragon saved {names}, the lab file has {expect}")
    bent = [c["data"]["name"] for c in saved["detail"]["diagrams"][0]["cells"]
            if c["shape"] == "flow" and c["data"]["name"].startswith("F4") and c.get("vertices")]
    if bent:
        raise SystemExit(f"take rejected: selecting {bent} changed its line")
    shutil.copy(video, out / "screen.webm")
    (out / "marks.json").write_text(json.dumps(marks, indent=2) + "\n")
    print("marks:")
    for m in marks:
        print(f"  {m['t']:7.2f}s  {m['label']}")
    print(f"take accepted: opened {lab_file.name}, {len(expect)} cells, saved back unchanged in names")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Record a REAL OWASP Threat Dragon session for the M2 lab video (lesson 2.5).

Threat Dragon (OWASP, Apache-2.0) runs from its official container image on this fresh machine, in local mode
(no account, nothing leaves the machine). Playwright drives a real Chromium window and records it while it:
creates the TSG Helpdesk model, draws part of the data-flow diagram by drag and drop, names every element by
typing, puts a trust boundary around the model, asks Threat Dragon for its own threat suggestions on the
untrusted flow into the model, cycles through the STRIDE types it offers for a flow, adds one AI threat by hand
and saves the model.

    python3 record_threatdragon.py out/m02-2.5-threatdragon http://127.0.0.1:3000

Writes: screen.webm (untouched recording), marks.json, model.json (the model Threat Dragon saved), shots/.
The browser's save-file picker is removed before the page loads, so Threat Dragon uses its download path (the one
Firefox and Safari users get); the downloaded file is the real saved model.
"""
import json
import pathlib
import shutil
import sys
import time

from playwright.sync_api import sync_playwright

W, H = 1600, 900
SLOW = 45      # ms per character for names
FAST = 14      # ms per character for long text

THREAT = {
    "title": "Indirect prompt injection via imported tickets",
    "description": ("A customer files a ticket with hidden instructions. The nightly import turns it into a help "
                    "article. The model later retrieves it and follows it for other customers. "
                    "OWASP LLM01:2026, LLM05:2026, ASI06. ATLAS AML.T0070, AML.T0051.001."),
    "mitigation": ("Do not auto-import customer text: staff review and rewrite first. Record each article's source. "
                   "Log retrieved article IDs per answer."),
}


def center(bb):
    return bb["x"] + bb["width"] / 2, bb["y"] + bb["height"] / 2


def main():
    out = pathlib.Path(sys.argv[1])
    url = sys.argv[2]
    (out / "shots").mkdir(parents=True, exist_ok=True)
    marks, t0 = [], None

    def now():
        return round(time.monotonic() - t0, 2)

    def mark(label, pg):
        marks.append({"label": label, "t": now()})
        pg.screenshot(path=str(out / "shots" / f"{len(marks):02d}-{label.replace(' ', '-').lower()}.png"))

    def drag(pg, a, b, steps=30):
        pg.mouse.move(*a)
        pg.mouse.down()
        pg.mouse.move(a[0] + 5, a[1] + 5, steps=3)
        pg.mouse.move(*b, steps=steps)
        pg.wait_for_timeout(150)
        pg.mouse.up()
        pg.wait_for_timeout(500)

    def stencil(pg, shape):
        return center(pg.locator(f'.x6-widget-stencil .x6-cell[data-shape="{shape}"]').first.bounding_box())

    def type_name(pg, text):
        pg.fill("#name", "")
        pg.click("#name")
        pg.keyboard.type(text, delay=SLOW)
        pg.wait_for_timeout(300)

    def place(pg, shape, at, name):
        drag(pg, stencil(pg, shape), at)
        pg.mouse.click(*at)
        pg.wait_for_timeout(400)
        type_name(pg, name)

    def node(pg, name):
        want = name.replace(" ", "")
        for n in pg.locator("#graph-container .x6-node").all():
            if want in (n.text_content() or "").replace("\xa0", "").replace(" ", ""):
                return n.bounding_box()
        raise SystemExit(f"element {name!r} not found on the diagram")

    def port(bb, side):
        cx, cy = center(bb)
        return {"left": (bb["x"] + 2, cy), "right": (bb["x"] + bb["width"] - 2, cy),
                "top": (cx, bb["y"] + 2), "bottom": (cx, bb["y"] + bb["height"] - 2)}[side]

    def deselect(pg):
        pg.mouse.click(1500, 650)
        pg.wait_for_timeout(300)

    def connect(pg, a, aside, b, bside, name):
        deselect(pg)
        ab, bb = node(pg, a), node(pg, b)
        pg.mouse.move(*center(ab))
        pg.wait_for_timeout(300)
        pa, pb = port(ab, aside), port(bb, bside)
        drag(pg, pa, pb)
        pg.mouse.click((pa[0] + pb[0]) / 2, (pa[1] + pb[1]) / 2)
        pg.wait_for_timeout(400)
        type_name(pg, name)

    def grow_boundary(pg):
        """Drag the boundary's corner handles so it clearly encloses the model with room around it."""
        if not pg.locator(".x6-widget-transform-resize").count():   # still selected after the drop, usually
            bb = pg.locator('#graph-container .x6-node[data-shape="trust-boundary-box"]').first.bounding_box()
            pg.mouse.click(bb["x"] + 3, bb["y"] + 3)
            pg.wait_for_timeout(500)
        for pos, dx, dy in (("top-left", -90, -70), ("bottom-right", 90, 70)):
            h = pg.locator(f'.x6-widget-transform-resize[data-position="{pos}"]').first
            a = center(h.bounding_box())
            drag(pg, a, (a[0] + dx, a[1] + dy), steps=20)
        pg.wait_for_timeout(600)

    with sync_playwright() as p:
        b = p.chromium.launch()
        ctx = b.new_context(viewport={"width": W, "height": H}, accept_downloads=True,
                            record_video_dir=str(out / "video-raw"), record_video_size={"width": W, "height": H})
        ctx.add_init_script("delete window.showSaveFilePicker;")
        pg = ctx.new_page()
        t0 = time.monotonic()
        pg.goto(url)
        pg.wait_for_selector("#local-login-btn", timeout=60000)
        pg.wait_for_timeout(2500)
        mark("Open Threat Dragon", pg)
        pg.click("#local-login-btn")
        pg.wait_for_timeout(2000)

        mark("New model", pg)
        pg.click('a[href="#/local/threatmodel/new"]')
        pg.wait_for_timeout(1500)
        pg.fill("#title", "")
        pg.click("#title")
        pg.keyboard.type("TSG Helpdesk", delay=SLOW)
        pg.click(".add-diagram-link")
        pg.wait_for_timeout(700)
        pg.fill(".td-diagram", "")
        pg.click(".td-diagram")
        pg.keyboard.type("Chat and knowledge base", delay=SLOW)
        pg.wait_for_timeout(600)
        with pg.expect_download():
            pg.click("#td-save-btn")
        pg.wait_for_timeout(1500)
        pg.click("#td-close-btn")
        pg.wait_for_timeout(1500)
        pg.click("text=Chat and knowledge base")
        pg.wait_for_selector(".x6-widget-stencil .x6-cell", timeout=30000)
        pg.wait_for_timeout(2000)

        mark("Draw elements", pg)
        place(pg, "actor", (420, 260), "Customer")
        place(pg, "process", (760, 260), "Chat app")
        place(pg, "process", (1180, 260), "Model")
        place(pg, "store", (1180, 560), "Knowledge base")
        mark("Draw flows", pg)
        connect(pg, "Customer", "right", "Chat app", "left", "F1 chat message")
        connect(pg, "Chat app", "right", "Model", "left", "F2 prompt + context")
        connect(pg, "Knowledge base", "top", "Model", "bottom", "F4 UNTRUSTED: retrieved articles")

        mark("Boundary", pg)
        deselect(pg)
        drag(pg, stencil(pg, "trust-boundary-box"), (1180, 262))
        type_name(pg, "Model boundary")
        grow_boundary(pg)
        deselect(pg)
        pg.wait_for_timeout(1500)

        mark("Suggestions", pg)
        for y in (470, 455, 485, 440):          # the F4 flow, below its label
            pg.mouse.click(1180, y)
            pg.wait_for_timeout(800)
            if pg.locator("#name").count():
                break
        if not pg.locator("#name").count() or "F4" not in pg.input_value("#name"):
            raise SystemExit("could not select the F4 flow")
        pg.click("text=New Threat by Context")
        pg.wait_for_selector("#threat-edit", timeout=10000)
        pg.wait_for_timeout(4000)              # hold on "No suggestions available"
        pg.click("text=Cancel")
        pg.wait_for_timeout(1000)
        mark("Types", pg)
        pg.click("text=New Threat by Type")
        pg.wait_for_selector("#threat-edit", timeout=10000)
        pg.wait_for_timeout(2500)
        for _ in range(2):
            pg.click("#threat-edit >> text=Next")
            pg.wait_for_timeout(2500)
        pg.click("text=Cancel")
        pg.wait_for_timeout(1000)

        mark("AI threat", pg)
        pg.get_by_text("New Threat", exact=True).first.click()
        pg.wait_for_selector("#threat-edit #title", timeout=10000)
        pg.wait_for_timeout(800)
        pg.fill("#threat-edit #title", "")
        pg.click("#threat-edit #title")
        pg.keyboard.type(THREAT["title"], delay=SLOW // 2)
        pg.select_option("#threat-edit #threat-type", label="Tampering")
        pg.click("#threat-edit #severity >> text=High")
        for field in ("description", "mitigation"):   # Threat Dragon pre-fills these with a hint as real text
            pg.click(f"#threat-edit #{field}")
            pg.keyboard.press("Control+A")
            pg.keyboard.press("Delete")
            pg.keyboard.type(THREAT[field], delay=FAST)
        pg.wait_for_timeout(1500)
        pg.click("#threat-edit >> text=Apply")
        pg.wait_for_timeout(2500)

        mark("Saved", pg)
        with pg.expect_download() as d:
            pg.locator("button:has-text('Save')").first.click()
        d.value.save_as(str(out / "model.json"))
        pg.wait_for_timeout(3000)
        marks.append({"label": "End", "t": now()})
        video = pg.video.path()
        ctx.close()
        b.close()

    model = json.loads((out / "model.json").read_text())
    cells = model["detail"]["diagrams"][0]["cells"]
    names = [c.get("data", {}).get("name") for c in cells]
    threats = [t for c in cells for t in (c.get("data", {}).get("threats") or [])]
    for want in ("Customer", "Chat app", "Model", "Knowledge base", "F4 UNTRUSTED: retrieved articles", "Model boundary"):
        if want not in names:
            raise SystemExit(f"take rejected: {want!r} is not in the saved model ({names})")
    mine = [t for t in threats if t.get("title") == THREAT["title"]]
    if not mine:
        raise SystemExit("take rejected: the AI threat is not in the saved model")
    for field in ("description", "mitigation"):
        if mine[0].get(field) != THREAT[field]:
            raise SystemExit(f"take rejected: saved {field} is {mine[0].get(field)!r}")
    bnd = [c for c in cells if c.get("shape") == "trust-boundary-box"]
    if not bnd or bnd[0]["size"]["width"] < 250 or bnd[0]["size"]["height"] < 160:
        raise SystemExit(f"take rejected: the boundary is too small to read ({bnd and bnd[0].get('size')})")
    shutil.copy(video, out / "screen.webm")
    (out / "marks.json").write_text(json.dumps(marks, indent=2) + "\n")
    print("marks:")
    for m in marks:
        print(f"  {m['t']:7.2f}s  {m['label']}")
    print(f"take accepted: saved model has {len(cells)} cells and {len(threats)} threat(s)")


if __name__ == "__main__":
    main()

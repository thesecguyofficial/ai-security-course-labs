"""
explore.py: read a Threat Dragon model one step at a time, before you threat-model it (M2 lab, part 1).

Nothing here changes the file. Each command shows one idea of a threat model:

    python3 explore.py elements     # 1. the parts of the system, by data-flow-diagram type
    python3 explore.py flows        # 2. every arrow: what moves from where to where
    python3 explore.py boundaries   # 3. each trust boundary: what's inside, which arrows cross it
    python3 explore.py stride       # 4. the STRIDE questions to ask each part
    python3 explore.py model        # 5. every arrow into the AI model, trusted or untrusted

It reads tsg-helpdesk-starter.json by default. Add --file my-model.json to read a model you saved yourself
from OWASP Threat Dragon. Plain Python: no packages, no network.
"""

import argparse
import json
import pathlib
import textwrap

KINDS = {  # Threat Dragon shape -> data-flow-diagram element
    "actor": ("external entity", "a person or system outside your control"),
    "process": ("process", "code that runs and changes data"),
    "store": ("data store", "where data rests"),
}
# STRIDE per element: the same table Threat Dragon uses (td.vue/src/service/threats/models/stride.js)
STRIDE = {
    "actor": "SR",
    "process": "STRIDE",
    "store": "TRID",
    "flow": "TID",
}
LETTER = {
    "S": "Spoofing: pretending to be someone or something else",
    "T": "Tampering: changing data or code",
    "R": "Repudiation: denying an action, because nothing proves it",
    "I": "Information disclosure: data reaching someone who shouldn't see it",
    "D": "Denial of service: making it slow or unavailable",
    "E": "Elevation of privilege: doing more than you're allowed to",
}


def load(path):
    model = json.loads(pathlib.Path(path).read_text("utf-8"))
    cells = [c for d in model["detail"]["diagrams"] for c in d["cells"]]
    return model, cells


def name(c):
    return c.get("data", {}).get("name") or "(no name)"


def nodes(cells):
    return [c for c in cells if c["shape"] in KINDS]


def flows(cells):
    return [c for c in cells if c["shape"] == "flow"]


def boxes(cells):
    return [c for c in cells if c["shape"] == "trust-boundary-box"]


def inside(node, box):
    """True if the centre of an element lies inside a trust boundary box."""
    x = node["position"]["x"] + node["size"]["width"] / 2
    y = node["position"]["y"] + node["size"]["height"] / 2
    bx, by = box["position"]["x"], box["position"]["y"]
    return bx <= x <= bx + box["size"]["width"] and by <= y <= by + box["size"]["height"]


def ends(f, by_id):
    return by_id.get(f["source"].get("cell")), by_id.get(f["target"].get("cell"))


def crosses(f, box, by_id):
    """A flow crosses a boundary when exactly one of its two ends is inside it."""
    a, b = ends(f, by_id)
    return bool(a and b) and inside(a, box) != inside(b, box)


def cmd_elements(model, cells, by_id):
    ns = nodes(cells)
    print(f'model: "{model["summary"]["title"]}"  ->  {len(ns)} elements\n')
    for shape, (kind, meaning) in KINDS.items():
        group = [c for c in ns if c["shape"] == shape]
        print(f"{kind} ({meaning}): {len(group)}")
        for c in group:
            text = textwrap.wrap(c["data"].get("description", ""), 100) or [""]
            print(f"   {name(c):<18} {text[0]}")
            for line in text[1:]:
                print(f"   {'':<18} {line}")
        print()


def cmd_flows(model, cells, by_id):
    fs = flows(cells)
    print(f"{len(fs)} data flows (arrows). Each one carries data from one element to another.\n")
    for f in fs:
        a, b = ends(f, by_id)
        print(f"   {name(f):<36} {name(a):>16} -> {name(b)}")


def cmd_boundaries(model, cells, by_id):
    for box in boxes(cells):
        inner = [name(c) for c in nodes(cells) if inside(c, box)]
        crossing = [name(f) for f in flows(cells) if crosses(f, box, by_id)]
        print(f"trust boundary: {name(box)}")
        print(f"   inside:   {', '.join(inner) or '(nothing)'}")
        print(f"   crossing: {len(crossing)} flows")
        for n in crossing:
            print(f"      {n}")
        print()


def cmd_stride(model, cells, by_id):
    print("STRIDE per element: which of the six questions to ask each part (Threat Dragon's table)\n")
    for k, v in LETTER.items():
        print(f"   {k}  {v}")
    print(f"\n   {'element':<36} {'type':<16} S T R I D E")
    for c in nodes(cells) + flows(cells):
        kind = KINDS.get(c["shape"], ("data flow",))[0]
        marks = " ".join(k if k in STRIDE[c["shape"]] else "." for k in "STRIDE")
        print(f"   {name(c):<36} {kind:<16} {marks}")


def cmd_model(model, cells, by_id):
    target = next((c for c in nodes(cells) if name(c).lower() == "model"), None)
    if not target:
        raise SystemExit('no element called "Model" in this file')
    print("everything that reaches the model becomes part of one stream of text (lesson 2.1)\n")
    for f in flows(cells):
        a, b = ends(f, by_id)
        if b is target:
            n = name(f)
            label = "UNTRUSTED" if "UNTRUSTED" in n.upper() else "TRUSTED" if "TRUSTED" in n.upper() else "not labelled yet"
            print(f"   {label:<17} {n}  (from {name(a)})")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("step", choices=["elements", "flows", "boundaries", "stride", "model"])
    p.add_argument("--file", default=str(pathlib.Path(__file__).with_name("tsg-helpdesk-starter.json")))
    a = p.parse_args()
    model, cells = load(a.file)
    by_id = {c["id"]: c for c in cells}
    globals()[f"cmd_{a.step}"](model, cells, by_id)


if __name__ == "__main__":
    main()

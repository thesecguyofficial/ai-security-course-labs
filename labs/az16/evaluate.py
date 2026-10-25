"""
evaluate.py: score a rule pack against the five incidents the simulator planted, using the answer key.

    python3 evaluate.py hardened                    # the az16 pack on the hardened telemetry
    python3 evaluate.py first-draft --pack soc-v1   # the old SOC rules on the old telemetry

For each scenario:
    CAUGHT           an alert touches the incident AND names the entity a responder acts on
                     (the leaked service principal, the end user, the conversation, the uploading account)
    SEEN, NOT NAMED  an alert touches the incident but names something else (the Foundry resource, the APIM subscription, a domain, the deploy pipeline):
                     useful, but you can't contain it from that alert alone
    MISSED           no alert touches it
A false alarm is an alert that touches none of the five incidents.
"""

from __future__ import annotations

import json
import sys

import detect
import simulate


def score(alerts: list[dict], truth: dict) -> dict:
    ids = {s: set(v) for s, v in truth.items()}
    res = {}
    for s, meta in simulate.SCENARIOS.items():
        touching = [a for a in alerts if ids[s] & set(a["evidence"])]
        named = [a for a in touching if a["entity"] == meta["entity"]]
        res[s] = {"status": "CAUGHT" if named else ("SEEN, NOT NAMED" if touching else "MISSED"),
                  "rules": sorted({a["rule"] for a in (named or touching)}),
                  "named": sorted({a["entity"] for a in touching})}
    all_ids = set().union(*ids.values())
    res["false_alarms"] = [a for a in alerts if not all_ids & set(a["evidence"])]
    return res


def evaluate(setup: str, pack: str = "az16", challenge: bool = True, built: dict | None = None) -> dict:
    """built = simulate.build(setup) to work in memory (the tests); otherwise read out/<setup>/."""
    if built is None:
        tel = detect.Telemetry(setup)
        truth = json.loads((detect.HERE / "out" / setup / "truth.json").read_text())
    else:
        tel, truth = detect.Telemetry.from_build(built), built["truth"]
    alerts = detect.run(tel, pack, challenge)
    return {"alerts": alerts, **score(alerts, truth)}


def summary(res: dict) -> str:
    st = [res[s]["status"] for s in simulate.SCENARIOS]
    return (f"Caught {st.count('CAUGHT')} of 5 | seen but not named {st.count('SEEN, NOT NAMED')} | "
            f"missed {st.count('MISSED')} | false alarms {len(res['false_alarms'])}")


def main(argv: list[str]):
    args = [a for a in argv if not a.startswith("--")]
    pack = argv[argv.index("--pack") + 1] if "--pack" in argv else "az16"
    if pack in args:
        args.remove(pack)
    setup = args[0] if args else "hardened"
    res = evaluate(setup, pack)
    print(f"Pack {pack} on {setup} telemetry: {len(res['alerts'])} alerts\n")
    for s, meta in simulate.SCENARIOS.items():
        r = res[s]
        who = f"named {', '.join(r['named'])}" if r["named"] else ""
        print(f"  {s}  {r['status']:16} {meta["title"]:34} {' '.join(r['rules']):24} {who}")
    for a in res["false_alarms"]:
        print(f"  false alarm: {a['rule']} {a['title']} ({a['entity']}: {a['detail']})")
    print("\n" + summary(res))


if __name__ == "__main__":
    main(sys.argv[1:])

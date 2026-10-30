"""
respond.py: the automated responder, and a replay of the attacker's 30 minutes against it.

    python3 respond.py first-draft     # a 15-minute clean-up job that deactivates the key
    python3 respond.py hardened        # event-driven: deactivate the key AND deny the user's sessions

The mock IAM below follows two documented AWS behaviours: a deactivated access key "can no longer be used by API
calls", and temporary credentials "are valid until they expire" unless you change the permissions behind them
(a deny on the user's aws:userId also covers sessions from GetSessionToken). Timings come from data/org.json
"assumptions": lab numbers, not AWS figures.
"""

from __future__ import annotations

import datetime as dt
import sys

import scenarios
from lab import ASSUMPTIONS, ORG, iso, load_setup, mmss, ts


def new_iam() -> dict:
    """A tiny IAM: users, their key status, and attached deny policies. Fake, local, in memory."""
    iam = {"users": {}}
    for d in ORG["decoys"]:
        iam["users"][d["user"]] = {"keys": {d.get("access_key_id", "decoy"): "Active"}, "deny_all": False}
    for p in ORG["app_principals"]:
        iam["users"][p["user"]] = {"keys": {p["access_key_id"]: "Active"}, "deny_all": False}
    iam["users"]["svc-other-team"] = {"keys": {"TSGLABOTHERKEY000004": "Active"}, "deny_all": False}
    return iam


def plan(setup: dict, first_call: dt.datetime) -> dict:
    """When does the responder act on an alert about a call made at first_call?"""
    a, r = ASSUMPTIONS, setup["responder"]
    arrival = first_call + dt.timedelta(seconds=a["s3_delivery_s"] if r["reads"] == "s3" else a["eventbridge_delivery_s"])
    if r["mode"] == "batch":
        midnight = arrival.replace(hour=0, minute=0, second=0)
        n = int((arrival - midnight).total_seconds() // r["interval_s"]) + 1
        run = midnight + dt.timedelta(seconds=n * r["interval_s"])
    else:
        run = arrival
    acted = run + dt.timedelta(seconds=a["responder_action_s"])
    effective = acted + dt.timedelta(seconds=a["iam_propagation_s"])
    return {"arrival": arrival, "run": run, "acted": acted, "effective": effective, "actions": list(r["actions"])}


def act(setup: dict, iam: dict, user: str, arn: str) -> list[str]:
    """Carry out the setup's actions on ONE principal: the one named in the alert's userIdentity."""
    done = []
    if arn in setup["responder"].get("never_touch", []):
        return ["refused: principal is on the never-touch list"]
    u = iam["users"].get(user)
    if u is None:
        return [f"refused: {user} is not a user in this org"]
    for action in setup["responder"]["actions"]:
        if action == "deactivate_key":
            for k in u["keys"]:
                u["keys"][k] = "Inactive"
            done.append(f"UpdateAccessKey {user} -> Inactive")
        elif action == "deny_user_sessions":
            u["deny_all"] = True
            done.append(f"PutUserPolicy {user} deny-all on aws:userId (covers GetSessionToken sessions)")
        elif action == "snapshot_evidence":
            done.append("evidence: CloudTrail records of the last hour copied to the incident folder")
        elif action == "open_incident":
            done.append("incident opened (lab ticket)")
    return done


def replay(setup: dict) -> dict:
    timeline = scenarios.attack_timeline()
    t0 = ts(timeline[0]["time"])
    p = plan(setup, t0)
    iam = new_iam()
    user = scenarios.APP["user"]
    arn = f"arn:aws:iam::{scenarios.APP['account']}:user/{user}"
    done = act(setup, iam, user, arn)
    results = []
    for c in timeline:
        t = ts(c["time"])
        denied = False
        if t >= p["effective"]:
            u = iam["users"][user]
            if c["kind"] == "long-term" and u["keys"].get(c["key"]) == "Inactive":
                denied = True
            if u["deny_all"]:
                denied = True
        results.append(dict(c, outcome="AccessDenied" if denied else "allowed"))
    ok = [r for r in results if r["outcome"] == "allowed"]
    after = [r for r in ok if ts(r["time"]) >= p["effective"]]
    return {"setup": setup["name"], "t0": t0, "plan": p, "done": done, "results": results, "succeeded": len(ok),
            "succeeded_after_action": len(after), "time_to_act_s": (p["effective"] - t0).total_seconds(),
            "lab_cost_usd": round(len(ok) * ASSUMPTIONS["lab_price_per_call_usd"], 2), "iam": iam}


def report(r: dict) -> None:
    p, slo = r["plan"], ASSUMPTIONS["containment_slo_s"]
    print(f"setup {r['setup']} | responder: {r['plan']['actions']}")
    print(f"  {iso(r['t0'])}  first call with the leaked key, from {scenarios.ATTACKER_IP}")
    print(f"  {iso(p['arrival'])}  alert reaches the responder")
    print(f"  {iso(p['run'])}  responder runs")
    for d in r["done"]:
        print(f"                        {d}")
    print(f"  {iso(p['effective'])}  changes in effect (lab assumption: {ASSUMPTIONS['iam_propagation_s']} s)")
    verdict = "within" if r["time_to_act_s"] <= slo else "OVER"
    print(f"time to act: {mmss(r['time_to_act_s'])} ({verdict} the {mmss(slo)} target)")
    print(f"attacker calls that worked: {r['succeeded']} of {len(r['results'])}, {r['succeeded_after_action']} of them "
          f"AFTER the responder acted | lab cost {r['lab_cost_usd']:.2f} USD")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    report(replay(load_setup(sys.argv[1])))

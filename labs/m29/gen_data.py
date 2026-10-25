"""
gen_data.py: (re)writes the org's day of logs in data/org-day/ from scenarios.py, so the files you read and the
cases the tests run are the same. You don't need to run it: the files are already in the folder.

    python3 gen_data.py
"""

from lab import DATA, write_jsonl
import scenarios

if __name__ == "__main__":
    write_jsonl(DATA / "org-day" / "cloudtrail.jsonl", scenarios.org_day())
    write_jsonl(DATA / "org-day" / "resolver-query-logs.jsonl", scenarios.org_day_dns())
    print("wrote data/org-day/cloudtrail.jsonl and data/org-day/resolver-query-logs.jsonl")

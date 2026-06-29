#!/usr/bin/env python3
import json
import glob
from collections import defaultdict

def main():
    sink_details = defaultdict(lambda: defaultdict(list))

    for f in glob.glob("realvuln_results_all/*.json"):
        repo = f.replace("realvuln_results_all/", "").replace(".json", "")
        try:
            with open(f) as fp:
                data = json.load(fp)
        except Exception:
            continue
        for s in data.get("findings", []):
            if s["status"] == "unknown":
                sink_details[s["sink"]][repo].append(s["line"])

    for sink, repos in sorted(sink_details.items()):
        print(f"\n🔹 {sink}:")
        for repo, lines in repos.items():
            print(f"  {repo}: {lines[:5]}... (всего {len(lines)})")

if __name__ == "__main__":
    main()
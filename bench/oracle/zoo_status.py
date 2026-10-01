#!/usr/bin/env python3
"""Per-function differential status for one repo/level, as JSON.

Used by the syntax-zoo test to report which construct is open instead of an
aggregate diff count. Output: [[function_short_name, oracle_nodes, status], ...]
where status is "OK" or "<n> diff".
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import diff as differ  # noqa: E402


def main():
    repo, level, fixtures, rust = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    pa = os.path.join(fixtures, repo, level)
    pb = os.path.join(rust, repo, level)
    if not (os.path.exists(pa) and os.path.exists(pb)):
        print(json.dumps([["<missing>", 0, "MISSING"]]))
        return
    a = json.load(open(pa))
    b = json.load(open(pb))
    amap = {f["function"]: f for f in a.get("functions", [])}
    bmap = {f["function"]: f for f in b.get("functions", [])}
    rows = []
    for fn, of in sorted(amap.items()):
        rf = bmap.get(fn)
        short = fn.split("::")[-1]
        if rf is None:
            rows.append([short, len(of.get("nodes", [])), "MISSING"])
            continue
        out = []
        differ.diff(of, rf, "", out)
        rows.append([short, len(of.get("nodes", [])), "OK" if not out else f"{len(out)} diff"])
    for fn in sorted(set(bmap) - set(amap)):
        rows.append([fn.split("::")[-1] + " [extra]", None, "EXTRA"])
    print(json.dumps(rows))


if __name__ == "__main__":
    main()
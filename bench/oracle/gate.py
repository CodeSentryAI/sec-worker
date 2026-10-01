#!/usr/bin/env python3
"""R4.1 differential gate runner.

Manifest-driven: the gate universe comes from fixture-manifest.json, never from
"whatever directories happen to exist". Every expected-success repo must
produce a non-empty output for every level, otherwise the gate FAILs instead of
silently skipping. This is the exact failure class that produced a run of fake
IDENTICAL results earlier.

Usage:
  python gate.py --emit                     # run the Rust emitter, then diff
  python gate.py --diff-only --out DIR      # just diff existing DIR
"""
import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import diff as differ

HERE = os.path.dirname(os.path.abspath(__file__))
SEC_WORKER = os.path.abspath(os.path.join(HERE, "..", ".."))
SLITHER_RS = os.environ.get("SLITHER_RS", os.path.abspath(os.path.join(SEC_WORKER, "..", "slither-rs")))
FIXTURES = os.path.join(HERE, "fixtures")
MANIFEST = os.path.join(HERE, "fixture-manifest.json")
LEVELS = ["model.json", "cfg.json", "analysis.json"]
PROFILE = int(os.environ.get("RUST_PROFILE", "0"))  # 0 = debug


def expected_success():
    m = json.load(open(MANIFEST))
    return sorted(k for k, v in m["repos"].items() if v == "success")


def expected_failure():
    m = json.load(open(MANIFEST))
    return sorted(k for k, v in m["repos"].items() if v != "success")


def solc_version(repo):
    p = json.load(open(os.path.join(FIXTURES, repo, "provenance.json")))
    return p["solc_version"]


def emit(out_dir):
    profile = "release" if PROFILE else "debug"
    binary = os.path.join(SLITHER_RS, "target", profile, "slither-oracle-compat")
    if not os.path.exists(binary):
        print(f"FATAL: emitter binary missing: {binary}\n  run: cargo build{' --release' if PROFILE else ''}")
        sys.exit(2)
    failures = []
    for repo in expected_success():
        os.makedirs(os.path.join(out_dir, repo), exist_ok=True)
        cmd = [
            binary,
            "--repo", repo,
            "--solc", solc_version(repo),
            "--fixtures", FIXTURES,
            "--out", out_dir,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"EMIT-FAIL {repo}: exit {r.returncode}")
            print("  " + (r.stderr.strip().splitlines() or ["<no stderr>"])[-1][:200])
            failures.append(repo)
        else:
            tail = [l for l in r.stdout.splitlines() if l.strip()]
            if tail:
                print("  " + tail[-1][:160])
    if failures:
        print(f"\nEMIT FAILED for: {', '.join(failures)}")
    return failures


def diff_level(repo, level, out_dir):
    """Returns (status, [lines]). status in OK | DIFF | MISSING_RUST | MISSING_ORACLE."""
    pa = os.path.join(FIXTURES, repo, level)
    pb = os.path.join(out_dir, repo, level)
    if not os.path.exists(pa):
        return "MISSING_ORACLE", [f"oracle fixture absent: {pa}"]
    if not os.path.exists(pb):
        return "MISSING_RUST", [f"rust emitter produced no {level}"]
    if os.path.getsize(pa) == 0 or os.path.getsize(pb) == 0:
        side = "oracle" if os.path.getsize(pa) == 0 else "rust"
        return "MISSING_RUST", [f"{side} {level} is empty"]
    r = subprocess.run(
        [sys.executable, os.path.join(HERE, "diff_one.py"), pa, pb],
        capture_output=True, text=True,
    )
    out = [l for l in r.stdout.splitlines() if l.strip()]
    return ("OK", []) if r.returncode == 0 and not out else ("DIFF", out)


def syntax_zoo_coverage(fixtures, rust):
    """G6: every construct the syntax-zoo defines must match the oracle exactly.

    Compared per function with the same structural comparator the rest of the
    gate uses, so a missing lowering names its own construct instead of hiding
    inside an aggregate diff count.
    """
    zf = os.path.join(fixtures, "syntax-zoo", "cfg.json")
    zr = os.path.join(rust, "syntax-zoo", "cfg.json")
    if not (os.path.exists(zf) and os.path.exists(zr)):
        return None
    a = json.load(open(zf))
    b = json.load(open(zr))
    amap = {f["function"]: f for f in a.get("functions", [])}
    bmap = {f["function"]: f for f in b.get("functions", [])}
    rows = []
    for fn, of in sorted(amap.items()):
        rf = bmap.get(fn)
        if rf is None:
            rows.append((fn.split("::")[-1], len(of.get("nodes", [])), None, "MISSING"))
            continue
        out = []
        differ.diff(of, rf, "", out)
        rows.append((fn.split("::")[-1], len(of.get("nodes", [])), len(rf.get("nodes", [])), "OK" if not out else f"{len(out)} diff"))
    # functions the rust side invented that the oracle does not have
    for fn in sorted(set(bmap) - set(amap)):
        rows.append((fn.split("::")[-1] + " [extra]", None, len(bmap[fn].get("nodes", [])), "EXTRA"))
    return rows


def mkdtempSync_det():
    """Re-emit with the rust binary into a scratch dir for the determinism check."""
    import tempfile
    d = tempfile.mkdtemp(prefix="r41-det-")
    profile = "release" if PROFILE else "debug"
    binary = os.path.join(SLITHER_RS, "target", profile, "slither-oracle-compat")
    if not os.path.exists(binary):
        return d
    for repo in expected_success():
        os.makedirs(os.path.join(d, repo), exist_ok=True)
        subprocess.run(
            [binary, "--repo", repo, "--solc", solc_version(repo), "--fixtures", FIXTURES, "--out", d],
            capture_output=True,
            text=True,
            env={**os.environ, "ALLOW_PARTIAL_LOWERING": "1"},
        )
    return d


def stable_id_problems(repo, rust):
    """Stable ids must be unique where the oracle makes them unique.

    The invariant is *scoped*, not global: contract/function ids are unique
    within model.json, and node/variable ids are unique within a function. A
    state variable legitimately appears in many functions, so a global check
    would report false positives.
    """
    problems = []
    m = os.path.join(rust, repo, "model.json")
    if not os.path.exists(m):
        return [f"{repo}: no model.json emitted (stable-id check skipped, not passed)"]
    data = json.load(open(m))

    def dupe(ids):
        seen, d = set(), []
        for i in ids:
            if i in seen:
                d.append(i)
            seen.add(i)
        return d

    for c in data.get("contracts", []):
        fids = [f["id"] for f in c.get("functions", [])]
        for x in dupe(fids):
            problems.append(f"{repo}: duplicate function id {x}")
        for f in c.get("functions", []):
            pass
    cfg = os.path.join(rust, repo, "cfg.json")
    if os.path.exists(cfg):
        for f in json.load(open(cfg)).get("functions", []):
            nids = [n["id"] for n in f.get("nodes", [])]
            for x in dupe(nids):
                problems.append(f"{repo}: duplicate node id {x} in {f['function']}")
            vids = [v["id"] for v in f.get("variables", [])]
            for x in dupe(vids):
                problems.append(f"{repo}: duplicate variable id {x} in {f['function']}")
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/tmp/rs-gate")
    ap.add_argument("--emit", action="store_true")
    ap.add_argument("--diff-only", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--only", default=None)
    ap.add_argument("--level", default=None)
    args = ap.parse_args()

    out_dir = os.path.abspath(args.out)
    if args.emit and not args.diff_only:
        emit(out_dir)

    repos = expected_success()
    if args.only:
        repos = [args.only]
    levels = [args.level] if args.level else LEVELS

    # ---- G0: the gate universe is the manifest, and every expected file exists
    g0_problems = []
    for repo in expected_success():
        for level in LEVELS:
            if not os.path.exists(os.path.join(FIXTURES, repo, level)):
                g0_problems.append(f"oracle fixture missing: {repo}/{level}")
        for extra in ("solc-input.json", "solc-output.json", "provenance.json"):
            if not os.path.exists(os.path.join(FIXTURES, repo, extra)):
                g0_problems.append(f"oracle fixture missing: {repo}/{extra}")
    for repo in expected_failure():
        if os.path.exists(os.path.join(FIXTURES, repo, "cfg.json")):
            g0_problems.append(f"manifest says compile_failure but fixtures exist: {repo}")

    # ---- per-level tallies
    tallies = {}
    for level in levels:
        total = 0
        bad = []
        for repo in repos:
            status, lines = diff_level(repo, level, out_dir)
            n = len(lines)
            if status != "OK":
                total += max(n, 1)
                bad.append(repo)
                print(f"  {repo:<16}{level:<16}{status:<18}{n if n else '-'}")
                for l in lines[: 8 if not args.verbose else len(lines)]:
                    print(f"      {l[:190]}")
                if n > 8 and not args.verbose:
                    print(f"      ... and {n - 8} more")
        tallies[level] = (total, bad)

    # ---- G5: rust determinism + scoped stable-id uniqueness
    g5_problems = []
    det = mkdtempSync_det()
    try:
        for repo in repos:
            for level in LEVELS:
                p1 = os.path.join(out_dir, repo, level)
                p2 = os.path.join(det, repo, level)
                if not (os.path.exists(p1) and os.path.exists(p2)):
                    continue
                if open(p1).read() != open(p2).read():
                    g5_problems.append(f"non-deterministic: {repo}/{level}")
            idp = stable_id_problems(repo, out_dir)
            g5_problems.extend(idp)
    finally:
        import shutil
        shutil.rmtree(det, ignore_errors=True)

    zoo = syntax_zoo_coverage(FIXTURES, out_dir)

    # ---- gate ladder. A gate is only REACHED when every earlier gate passed;
    # a downstream green must never mask an upstream red.
    print()
    print("=" * 74)
    print("R4.1 GATE LADDER  (G0 -> G6; a gate is REACHED only if all prior gates pass)")
    print("=" * 74)
    gates = []
    gates.append(("G0 fixture manifest complete", not g0_problems,
                  "manifest complete" if not g0_problems else f"{len(g0_problems)} problem(s)"))
    m_total, m_bad = tallies.get("model.json", (0, []))
    gates.append(("G1 model.json == oracle", m_total == 0,
                  "all expected-success IDENTICAL" if m_total == 0 else f"{m_total} diff(s) in {len(m_bad)} repo(s)"))
    c_total, c_bad = tallies.get("cfg.json", (0, []))
    gates.append(("G2 cfg.json == oracle", c_total == 0,
                  "all expected-success IDENTICAL" if c_total == 0 else f"{c_total} diff(s) in {len(c_bad)} repo(s)"))
    a_total, a_bad = tallies.get("analysis.json", (0, []))
    gates.append(("G3/G4 direct effects + call facts", a_total == 0,
                  "all expected-success IDENTICAL" if a_total == 0 else f"{a_total} diff(s) in {len(a_bad)} repo(s)"))
    gates.append(("G5 determinism + stable-id uniqueness", not g5_problems,
                  "deterministic, ids unique" if not g5_problems else f"{len(g5_problems)} problem(s)"))
    if zoo is None:
        g6_ok, g6_msg = False, "syntax-zoo fixture absent"
    else:
        open_rows = [r for r in zoo if r[3] != "OK"]
        g6_ok = not open_rows
        g6_msg = "all constructs IDENTICAL" if not open_rows else f"{len(open_rows)}/{len(zoo)} construct(s) open"
    gates.append(("G6 syntax-zoo constructs covered", g6_ok, g6_msg))

    blocked = False
    for name, ok, msg in gates:
        if blocked and not ok:
            state = "BLOCKED"
        elif ok:
            state = "PASS"
        else:
            state = "OPEN"
            blocked = True
        print(f"  {name:<42}{state:<10}{msg}")

    if g0_problems:
        print("\n  G0 problems:")
        for p in g0_problems[:10]:
            print(f"    - {p}")
    if g5_problems:
        print("\n  G5 problems:")
        for p in g5_problems[:10]:
            print(f"    - {p}")
    if zoo:
        print("\n  G6 syntax-zoo per-construct status:")
        for name, o, r, st in zoo:
            print(f"    {name:<32}oracle={o:<4}rust={str(r):<5}{st}")

    print("=" * 74)
    print("R4.1 is COMPLETE only when every gate above reads PASS.")
    sys.exit(0 if all(ok for _, ok, _ in gates) else 1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Root-cause clustering for R4.1 differential diffs.

A raw diff count is close to useless for prioritisation: one ordinal-mapping
bug inflates node ids, which then breaks successors, callsites, expression
attachments and analysis facts, so a single root cause can surface as tens of
thousands of "differences".

This tool groups every difference into a *category* (which field diverged) and
then attributes each diverging function to the *AST syntax kinds* its source
range actually contains. That distinguishes "while/try lowering is missing"
from "node ids are misassigned", which a flat count cannot.

Usage:
  python cluster.py --fixtures DIR --rust DIR [--repo gas-toy] [--level cfg.json]
"""
import argparse
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import diff as differ  # noqa: E402

# Ordered most-specific first; the first matching rule wins.
CATEGORIES = [
    ("missing function", lambda p, k: "missing" in k and ".functions[" in p and ".nodes[" not in p and ".variables[" not in p),
    ("missing node", lambda p, k: "missing" in k and ".nodes[" in p),
    ("extra node", lambda p, k: "missing" in k and ".nodes[" in p),
    ("missing variable", lambda p, k: "missing" in k and ".variables[" in p),
    ("missing contract", lambda p, k: "missing" in k and ".contracts[" in p),
    ("node kind mismatch", lambda p, k: p.endswith(".kind")),
    ("span mismatch", lambda p, k: ".source." in p),
    ("entry mismatch", lambda p, k: p.endswith(".entry")),
    ("successor mismatch", lambda p, k: ".successors" in p),
    ("expression mismatch", lambda p, k: ".expression" in p),
    ("read mismatch", lambda p, k: ".reads" in p or p.endswith(".reads")),
    ("write mismatch", lambda p, k: ".writes" in p or p.endswith(".writes")),
    ("state read/write", lambda p, k: ".state_reads" in p or ".state_writes" in p),
    ("call classification", lambda p, k: any(c in p for c in ("internal_calls", "high_level_calls", "low_level_calls", "library_calls", "solidity_calls"))),
    ("mutability mismatch", lambda p, k: p.endswith(".mutability")),
    ("modifiers mismatch", lambda p, k: p.endswith(".modifiers")),
    ("missing field", lambda p, k: "missing" in k),
    ("type mismatch", lambda p, k: k.startswith("type ")),
    ("value mismatch", lambda p, k: "!=" in k),
    ("other", lambda p, k: True),
]


def categorize(path: str, kind: str):
    for name, test in CATEGORIES:
        if test(path, kind):
            return name
    return "other"


def span_index(solc_output_path):
    """(start, end, nodeType) for every AST node, for containment queries."""
    if not os.path.exists(solc_output_path):
        return []
    out = []
    data = json.load(open(solc_output_path))

    def walk(n):
        if isinstance(n, dict):
            src = n.get("src")
            nt = n.get("nodeType")
            if isinstance(src, str) and nt:
                head = src.split(":")[0]
                if "-" in head:
                    a, b = head.split("-")
                    out.append((int(a), int(b), nt))
                else:
                    s, ln = head.split(":")[0], head.split(":")[1] if len(head.split(":")) > 1 else "0"
                    out.append((int(s), int(s) + int(ln), nt))
            for v in n.values():
                walk(v)
        elif isinstance(n, list):
            for v in n:
                walk(v)

    for src in data.get("sources", {}).values():
        if isinstance(src, dict) and "ast" in src:
            walk(src["ast"])
    return out


def function_span(fn_obj):
    """Union range of a function's CFG nodes, from cfg.json."""
    nodes = fn_obj.get("nodes") or []
    if not nodes:
        return None
    lo = min(n["source"]["start"] for n in nodes)
    hi = max(n["source"]["start"] + n["source"]["length"] for n in nodes)
    return lo, hi


def syntax_kinds(span, index):
    if not span or not index:
        return set()
    lo, hi = span
    # statement/expression kinds actually inside this function's source range
    interesting = {
        "WhileStatement", "DoWhileStatement", "ForStatement", "IfStatement",
        "TryStatement", "UncheckedBlock", "Break", "Continue", "Return",
        "EmitStatement", "RevertStatement", "InlineAssembly",
        "ModifierInvocation", "ModifierDefinition", "Assembly",
        "VariableDeclarationStatement", "ExpressionStatement",
    }
    return {nt for (s, e, nt) in index if s >= lo and e <= hi and nt in interesting}


def collect(repo, level, fixtures, rust):
    pa = os.path.join(fixtures, repo, level)
    pb = os.path.join(rust, repo, level)
    if not os.path.exists(pa) or not os.path.exists(pb):
        return None
    out = []
    differ.diff(json.load(open(pa)), json.load(open(pb)), "", out)
    parsed = []
    for line in out:
        # "<path>: <rest>"  where rest is "missing in A/B", "type X != Y", "'a' != 'b'"
        if ": " in line:
            path, rest = line.rsplit(": ", 1)
        else:
            path, rest = line, ""
        parsed.append((path, rest))
    return parsed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", required=True)
    ap.add_argument("--rust", required=True)
    ap.add_argument("--repo", action="append", default=None)
    ap.add_argument("--level", action="append", default=None)
    ap.add_argument("--top", type=int, default=12)
    args = ap.parse_args()

    manifest = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixture-manifest.json")))
    repos = args.repo or sorted(k for k, v in manifest["repos"].items() if v == "success")
    levels = args.level or ["model.json", "cfg.json", "analysis.json"]

    for repo in repos:
        index = span_index(os.path.join(args.fixtures, repo, "solc-output.json"))
        cfg = {}
        cfg_path = os.path.join(args.fixtures, repo, "cfg.json")
        if os.path.exists(cfg_path):
            for f in json.load(open(cfg_path)).get("functions", []):
                cfg[f["function"]] = syntax_kinds(function_span(f), index)
        analysis_fns = {}
        an_path = os.path.join(args.fixtures, repo, "analysis.json")
        if os.path.exists(an_path):
            for f in json.load(open(an_path)).get("functions", []):
                analysis_fns[f["function"]] = cfg.get(f["function"], set())

        print(f"\n{'=' * 74}\n{repo}\n{'=' * 74}")
        for level in levels:
            diffs = collect(repo, level, args.fixtures, args.rust)
            if diffs is None:
                print(f"  {level:<16} MISSING (compare skipped)")
                continue
            cats = Counter()
            per_fn = Counter()
            kind_counter = Counter()
            table = cfg if level == "cfg.json" else (analysis_fns if level == "analysis.json" else {})
            for path, rest in diffs:
                cats[categorize(path, rest)] += 1
                # attribute to the innermost enclosing function id in the path
                fn = None
                marker = ".functions["
                idx = path.rfind(marker)
                if idx >= 0:
                    start = idx + len(marker)
                    depth = 1
                    i = start
                    while i < len(path) and depth:
                        if path[i] == "[":
                            depth += 1
                        elif path[i] == "]":
                            depth -= 1
                            if depth == 0:
                                break
                        i += 1
                    fn = path[start:i]
                if fn:
                    per_fn[fn] += 1
                    for k in table.get(fn, ()):  # syntax kinds in that function
                        kind_counter[k] += 1
            total = len(diffs)
            print(f"\n  {level}  —  {total} difference(s)")
            if not total:
                continue
            print(f"    {'category':<24}{'count':>7}{'share':>9}")
            for name, n in cats.most_common():
                print(f"    {name:<24}{n:>7}{100.0 * n / total:>8.1f}%")
            if per_fn:
                print(f"\n    top {args.top} functions by divergence:")
                for fn, n in per_fn.most_common(args.top):
                    kinds = ",".join(sorted(table.get(fn, ()))) or "-"
                    short = fn.split("::")[-1]
                    print(f"      {n:>6}  {short[:52]:<52} [{kinds[:70]}]")
            if kind_counter:
                total_kind = sum(kind_counter.values()) or 1
                print(f"\n    divergence weight by AST syntax kind present in the function:")
                for name, n in kind_counter.most_common():
                    print(f"      {name:<28}{n:>7}{100.0 * n / total_kind:>8.1f}%")


if __name__ == "__main__":
    main()
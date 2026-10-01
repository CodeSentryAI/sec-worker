#!/usr/bin/env python3
"""Structural diff for slither-oracle snapshot directories.

Order-insensitive: collections keyed by their stable id ("id", "function",
"node", "name", "repo") are compared as maps; everything else compares
recursively. Exit 0 = snapshots semantically identical.

Usage: python diff.py <dirA> <dirB> [--file model.json,cfg.json,...]
"""
import json
import os
import sys

KEY_FIELDS = {"id", "function", "node", "name", "repo"}
LEVELS = ["model.json", "cfg.json", "ir.json", "analysis.json"]  # frozen contract; ssa.json is non-frozen


def diff(a, b, path, out):
    if type(a) is not type(b):
        out.append(f"{path}: type {type(a).__name__} != {type(b).__name__} ({a!r} vs {b!r})")
        return
    if isinstance(a, dict):
        keys = sorted(set(a) | set(b))
        for k in keys:
            if k not in a:
                out.append(f"{path}.{k}: missing in A")
            elif k not in b:
                out.append(f"{path}.{k}: missing in B")
            else:
                diff(a[k], b[k], f"{path}.{k}", out)
    elif isinstance(a, list):
        ka = _keyed_map(a)
        kb = _keyed_map(b)
        if ka is not None and kb is not None:
            for k in sorted(set(ka) | set(kb)):
                if k not in ka:
                    out.append(f"{path}[{k}]: missing in A")
                elif k not in kb:
                    out.append(f"{path}[{k}]: missing in B")
                else:
                    diff(ka[k], kb[k], f"{path}[{k}]", out)
        else:
            if len(a) != len(b):
                out.append(f"{path}: length {len(a)} != {len(b)}")
            for i, (x, y) in enumerate(zip(a, b)):
                diff(x, y, f"{path}[{i}]", out)
    elif a != b:
        out.append(f"{path}: {a!r} != {b!r}")


def _keyed_map(lst):
    """If every element is a dict with the same key field, return key->elem."""
    if not lst or not all(isinstance(x, dict) for x in lst):
        return None
    key = next((k for k in ("id", "function", "node") if all(k in x for x in lst)), None)
    if key is None:
        return None
    m = {}
    for x in lst:
        k = x[key]
        if k in m:
            return None  # duplicate keys: fall back to ordered compare
        m[k] = x
    return m


def main():
    dir_a, dir_b = sys.argv[1], sys.argv[2]
    levels = LEVELS
    if len(sys.argv) > 4 and sys.argv[3] == "--file":
        levels = sys.argv[4].split(",")

    # Gate universe comes from the manifest, not from "whatever dirs exist".
    # A directory-intersection universe silently drops a repo that failed to
    # generate on one side, which is how a whole corpus once reported a false
    # IDENTICAL.
    manifest_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixture-manifest.json")
    if os.path.exists(manifest_path):
        manifest = json.load(open(manifest_path))["repos"]
        repos = sorted(k for k, v in manifest.items() if v == "success")
    else:
        repos = sorted((set(os.listdir(dir_a)) & set(os.listdir(dir_b))) - {"bundles"})

    total = 0
    problems = []
    for repo in repos:
        for level in levels:
            pa = os.path.join(dir_a, repo, level)
            pb = os.path.join(dir_b, repo, level)
            a_ok, b_ok = os.path.exists(pa), os.path.exists(pb)
            if not a_ok and not b_ok:
                print(f"MISSING {repo}/{level} on BOTH sides (check invocation: dir args must be fixture ROOTS)")
                problems.append(f"{repo}/{level}")
                total += 1
                continue
            if not a_ok or not b_ok:
                print(f"MISSING {repo}/{level} in {'A' if not a_ok else 'B'}")
                problems.append(f"{repo}/{level}")
                total += 1
                continue
            a = json.load(open(pa))
            b = json.load(open(pb))
            out = []
            diff(a, b, f"{repo}/{level}", out)
            if out:
                total += len(out)
                problems.append(f"{repo}/{level}")
                for line in out[:20]:
                    print(line)
                if len(out) > 20:
                    print(f"  ... and {len(out) - 20} more")
            else:
                print(f"OK  {repo}/{level}")
    print(f"\n{'IDENTICAL' if total == 0 else f'{total} difference(s)'}")
    sys.exit(0 if total == 0 else 1)


if __name__ == "__main__":
    main()

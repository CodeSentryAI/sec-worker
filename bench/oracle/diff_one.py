#!/usr/bin/env python3
"""Structural diff for a single pair of oracle snapshots.

Shared comparator with diff.py (which diffs whole directory trees). Order-
insensitive: collections of records carrying a stable key field ("id",
"function", "node") are compared as maps rather than sequences, so cosmetic
ordering never registers as a semantic difference.

Usage: python diff_one.py <fileA> <fileB>
Exit 0 = structurally identical.
"""
import json
import sys

import diff

# Fields that identify a record inside a keyed collection.
KEYS = ("id", "function", "node")


def main():
    a = json.load(open(sys.argv[1]))
    b = json.load(open(sys.argv[2]))
    out = []
    diff.diff(a, b, "", out)
    if out:
        for line in out:
            print(line)
        print(f"{len(out)} difference(s)")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
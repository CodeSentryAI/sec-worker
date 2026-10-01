#!/usr/bin/env python3
"""Detector-dependency mining: which slither semantic facts does each detector
consume? Statically scans the installed detector sources (version-pinned).

Output: detector -> set of API/fact buckets, inverted coverage counts, written
as JSON + printed as a markdown table. This gives an objective ordering for
slither-core-rs: implement the fact that unlocks the most detectors first.
"""
import json
import os
import re
import sys

# API bucket -> regex over detector source text
API_PATTERNS = {
    "node.irs (non-SSA IR)": r"\.irs\b",
    "node.irs_ssa (SSA IR)": r"\.irs_ssa\b",
    "function.nodes (CFG iteration)": r"\.nodes\b",
    "node.sons/fathers (CFG edges)": r"\.(sons|fathers)\b",
    "node.expression": r"\.expression\b",
    "function.entry_point": r"entry_point",
    "state_variables_written": r"state_variables_written",
    "state_variables_read": r"state_variables_read",
    "variables_written": r"variables_written",
    "variables_read": r"variables_read",
    "internal_calls": r"internal_calls",
    "solidity_calls": r"solidity_calls",
    "high_level_calls": r"high_level_calls",
    "library_calls": r"library_calls",
    "low_level_calls": r"low_level_calls",
    "external_calls_as_expressions": r"external_calls_as_expressions",
    "data_dependency": r"data_depencenc|data_dependency|DATA_DEPENDENCY",
    "dominators/postdominators": r"dominator",
    "slithir ops isinstance": r"isinstance\([^)]*,\s*(?:slither\.slithir|Slice|Assignment|Binary|Unary|SolidityCall|HighLevelCall|LowLevelCall|InternalCall|LibraryCall|Return|Condition|TypeConversion|Index|Length|Member|Unpack|InitArray|NewArray|NewStructure|Delete|EventCall|Transfer|Send|Phi)",
    "IR lvalue": r"\.lvalue\b",
    "IR read set": r"\.read\b|\.reads\b",
    "modifiers": r"\.modifiers\b",
    "is_protected (auth check)": r"is_protected",
    "contract inheritance": r"\.inheritance\b|is_inherited",
    "SourceMapping/spans": r"source_mapping",
    "taint": r"taint",
}


def find_detector_files(slither_pkg):
    det_dir = os.path.join(slither_pkg, "detectors")
    files = []
    for root, _, names in os.walk(det_dir):
        for n in names:
            if n.endswith(".py") and n != "__init__.py":
                p = os.path.join(root, n)
                try:
                    with open(p, encoding="utf-8") as fh:
                        src = fh.read()
                except OSError:
                    continue
                if "AbstractDetector" in src or "AbstractDetection" in src:
                    files.append((p, src))
    return sorted(files)


def main():
    import importlib.util
    from importlib.metadata import version as pkg_version

    v = pkg_version("slither-analyzer")
    if not v.startswith("0.11.6"):
        raise SystemExit(f"pinned to 0.11.6, found {v}")
    spec = importlib.util.find_spec("slither")
    slither_pkg = os.path.dirname(spec.origin)
    files = find_detector_files(slither_pkg)

    per_detector = {}
    for path, src in files:
        name = os.path.splitext(os.path.basename(path))[0]
        used = {api for api, pat in API_PATTERNS.items() if re.search(pat, src)}
        per_detector[f"{name}"] = sorted(used)

    coverage = {api: [] for api in API_PATTERNS}
    for det, used in per_detector.items():
        for api in used:
            coverage[api].append(det)

    out_path = sys.argv[1] if len(sys.argv) > 1 else "detector_apis.json"
    result = {
        "slither_version": "0.11.6",
        "detectors_scanned": len(per_detector),
        "per_detector": {k: per_detector[k] for k in sorted(per_detector)},
        "coverage": {k: sorted(v) for k, v in sorted(coverage.items(), key=lambda kv: -len(kv[1]))},
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1)

    print(f"detectors scanned: {len(per_detector)}\n")
    print("| API / fact | # detectors | share |")
    print("|---|---|---|")
    total = len(per_detector)
    for api, dets in sorted(coverage.items(), key=lambda kv: -len(kv[1])):
        if dets:
            print(f"| {api} | {len(dets)} | {100 * len(dets) / total:.0f}% |")
    print(f"\nwritten: {out_path}")


if __name__ == "__main__":
    main()

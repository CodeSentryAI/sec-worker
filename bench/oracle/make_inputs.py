#!/usr/bin/env python3
"""Generate deterministic Rust inputs + provenance per fixture repo.

Writes into bench/oracle/fixtures/<repo>/:
  solc-input.json   standard-json input (repo-relative source keys)
  solc-output.json  raw solc --standard-json output
  provenance.json   solc version, settings hash, sources hash, output hash,
                    oracle (slither) version, export schema version

Usage: python make_inputs.py <corpus.json> <fixtures-dir> [--repos a,b]
"""
import glob
import hashlib
import json
import os
import re
import subprocess
import sys

SCHEMA_VERSION = 2
ORACLE_SLITHER = "0.11.6"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main():
    corpus = json.load(open(sys.argv[1]))
    fixtures = sys.argv[2]
    repos = None
    if len(sys.argv) > 4 and sys.argv[3] == "--repos":
        repos = set(sys.argv[4].split(","))

    for name, entry in corpus.items():
        if repos and name not in repos:
            continue
        root = os.path.abspath(entry["path"])
        source_dir = os.path.join(root, entry.get("sourceDir", "."))

        # solc version: explicit or highest installed satisfying all pragmas
        # (mirrors the oracle exporter's resolution)
        version = entry.get("solc")
        artifacts = os.path.expanduser("~/.solc-select/artifacts")
        installed = sorted(
            (m.group(1) for m in (re.match(r"^solc-(\d+\.\d+\.\d+)$", e) for e in os.listdir(artifacts)) if m),
            key=lambda v: tuple(int(x) for x in v.split(".")),
        )
        if not version or version == "auto":
            sol_files_all = sorted(glob.glob(os.path.join(source_dir, "**", "*.sol"), recursive=True))
            text = "\n".join(open(f, errors="ignore").read() for f in sol_files_all)
            constraints = [m.strip() for m in re.findall(r"pragma\s+solidity\s+([^;]+);", text)]
            version = installed[-1]
            for v in reversed(installed):
                vt = tuple(int(x) for x in v.split("."))
                ok = True
                for c in constraints:
                    for tok in c.split():
                        if not tok_ok(vt, tok):
                            ok = False
                            break
                    if not ok:
                        break
                if ok:
                    version = v
                    break

        out_dir = os.path.join(fixtures, name)
        if not os.path.isdir(out_dir):
            print(f"[{name}] no oracle fixture dir; skipping")
            continue
        sol_files = sorted(glob.glob(os.path.join(source_dir, "**", "*.sol"), recursive=True))
        if not sol_files:
            print(f"[{name}] no .sol sources; skipping")
            continue
        sources = {os.path.relpath(f, root).replace(os.sep, "/"): {"content": open(f, errors="ignore").read()} for f in sol_files}
        inp = {
            "language": "Solidity",
            "sources": sources,
            "settings": {"outputSelection": {"*": {"": ["ast"], "*": ["abi"]}}, "optimizer": {"enabled": False}},
        }
        inp_bytes = json.dumps(inp, sort_keys=True).encode()
        solc = os.path.join(artifacts, f"solc-{version}", f"solc-{version}")
        if not os.path.exists(solc):
            print(f"[{name}] SKIP: solc {version} missing")
            continue
        r = subprocess.run([solc, "--standard-json"], input=inp_bytes, capture_output=True, cwd=root)
        out_bytes = r.stdout
        try:
            parsed = json.loads(out_bytes)
            errors = [e for e in parsed.get("errors", []) if e.get("severity") == "error"]
        except json.JSONDecodeError:
            print(f"[{name}] SKIP: solc output unparsable")
            continue
        if errors:
            print(f"[{name}] SKIP: {len(errors)} compile errors")
            continue

        json.dump(inp, open(os.path.join(out_dir, "solc-input.json"), "w"), indent=1, sort_keys=True)
        json.dump(parsed, open(os.path.join(out_dir, "solc-output.json"), "w"))

        source_paths = sorted(sources.keys())
        provenance = {
            "schema_version": SCHEMA_VERSION,
            "oracle_slither_version": ORACLE_SLITHER,
            "solc_version": version,
            "settings_sha256": sha256(json.dumps(inp["settings"], sort_keys=True).encode()),
            "source_paths": source_paths,
            "sources_sha256": sha256(json.dumps(source_paths).encode()) + "/" + sha256(
                b"".join(sorted(sources[p]["content"].encode() for p in source_paths))
            )[:32],
            "solc_output_sha256": sha256(out_bytes),
            "input_sha256": sha256(inp_bytes),
        }
        json.dump(provenance, open(os.path.join(out_dir, "provenance.json"), "w"), indent=1, sort_keys=True)
        print(f"[{name}] inputs + provenance written (solc {version}, {len(sources)} sources)")


def tok_ok(vt, tok):
    import re

    m = re.match(r"^\^(\d+)\.(\d+)\.(\d+)$", tok)
    if m:
        b = tuple(int(x) for x in m.groups())
        return vt[0] == b[0] and vt >= b
    m = re.match(r"^(>=|<=|>|<|==|=)?\s*(\d+)\.(\d+)\.(\d+)$", tok)
    if m:
        op, b = m.group(1) or "=", tuple(int(x) for x in m.groups()[1:])
        c = (vt > b) - (vt < b)
        return {">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0}.get(op, c == 0)
    return False


if __name__ == "__main__":
    main()

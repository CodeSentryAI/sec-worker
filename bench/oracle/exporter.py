#!/usr/bin/env python3
"""slither-oracle exporter — version-pinned to Slither 0.11.6.

Given the benchmark corpus, export deterministic canonical JSON snapshots of
detector-observable semantics at four levels:

  model.json     identity layer: contracts, functions, variables (declarations)
  cfg.json       CFG/expression graph per function (nodes, kinds, spans,
                 canonical expressions, reads/writes, successors)
  ir.json        SlithIR and SSA as separate arrays, per function/node
  analysis.json  derived facts detectors consume: state R/W, call
                 classification, data dependencies

Stable-ID rules (never Python object ids / memory addresses / iteration order):
  contract  <relpath>::<Name>
  function  <contract-id>::<full_name>
  variable  <scope-id>::<name>@<span-start>
  node      <function-id>#n<ordinal>   (ordinal by sort on span/kind/expr-str)
  ir        <node-id>.i<ordinal>

Every collection is emitted sorted by its stable id, so the same slither
version + bundle always yields byte-identical output (see diff.py).

Usage: python exporter.py <corpus.json> <out-dir> [--repos a,b]
"""
import glob
import json
import os
import pickle
import re
import sys
import time

# Slither's SSA phi construction and data-dependency fixpoint iterate Python
# sets of strings/objects, whose order is randomized per process. Snapshots are
# only reproducible with a pinned hash seed — re-exec ourselves under seed 0.
if os.environ.get("PYTHONHASHSEED") != "0":
    env = dict(os.environ, PYTHONHASHSEED="0")
    os.execve(sys.executable, [sys.executable, *sys.argv], env)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # bench/
from slither_driver import compile_bundle  # noqa: E402

SLITHER_PIN = "0.11.6"


def log(*args):
    print(*args, file=sys.stderr, flush=True)


def check_version():
    from importlib.metadata import version as pkg_version

    v = pkg_version("slither-analyzer")
    if not v.startswith(SLITHER_PIN):
        raise SystemExit(f"slither-oracle is pinned to slither {SLITHER_PIN}, found {v}")


# ---------------------------------------------------------------- spans & ids

def _canon_file(sm, repo_root):
    """Best canonical source file from a source mapping, relative to repo root."""
    fn_obj = getattr(sm, "filename", None) if sm is not None else None
    candidates = []
    if fn_obj is not None:
        candidates = [getattr(fn_obj, "absolute", None), getattr(fn_obj, "relative", None), getattr(fn_obj, "used", None)]
    else:
        candidates = [
            getattr(sm, "filename_absolute", None),
            getattr(sm, "filename_relative", None),
            getattr(sm, "filename_used", None),
        ]
    for f in candidates:
        if not f:
            continue
        if os.path.isabs(f):
            try:
                return os.path.relpath(f, repo_root).replace(os.sep, "/")
            except ValueError:
                return f
        cand = os.path.join(repo_root, f)
        if os.path.exists(cand):
            return os.path.relpath(cand, repo_root).replace(os.sep, "/")
        return f.replace(os.sep, "/")
    return "unknown"


def rel_span(source_mapping, repo_root):
    """Canonical source span relative to the repo root."""
    if source_mapping is None:
        return None
    return {
        "file": _canon_file(source_mapping, repo_root),
        "start": source_mapping.start,
        "length": source_mapping.length,
        "lines": sorted({source_mapping.lines[0], source_mapping.lines[-1]}) if getattr(source_mapping, "lines", None) else [],
    }


def contract_id(contract, repo_root):
    file_part = _canon_file(getattr(contract, "source_mapping", None), repo_root)
    return f"{file_part}::{contract.name}"


def function_id(fn, cid):
    return f"{cid}::{fn.full_name}"


def var_id(v, scope_id, ordinal_fallback):
    name = getattr(v, "name", None) or f"<anon-{ordinal_fallback}>"
    sm = getattr(v, "source_mapping", None)
    start = sm.start if sm is not None and sm.start is not None else ordinal_fallback
    return f"{scope_id}::{name}@{start}"


def node_id(fid, ordinal):
    return f"{fid}#n{ordinal}"


def ir_id(nid, ordinal):
    return f"{nid}.i{ordinal}"


# ---------------------------------------------------------------- expressions

def expr_json(e, var_lookup):
    """Canonical expression tree. Duck-typed fields + canonical str fallback."""
    if e is None:
        return None
    kind = type(e).__name__
    node = {"kind": kind, "str": str(e)}

    def first_attr(*names):
        for n in names:
            v = getattr(e, n, None)
            if v is not None:
                return v
        return None

    try:
        if kind == "Identifier":
            ref = var_lookup.get(id(e.value))
            if ref:
                node["ref"] = ref
        elif kind == "Literal":
            node["value"] = str(e.value)
            node["type"] = str(e.type)
        elif kind == "MemberAccess":
            node["member"] = e.member_name
            node["obj"] = expr_json(getattr(e, "expression", None), var_lookup)
        elif kind == "BinaryOperation":
            node["op"] = str(e.type)
            node["lhs"] = expr_json(first_attr("expression_left", "left"), var_lookup)
            node["rhs"] = expr_json(first_attr("expression_right", "right"), var_lookup)
        elif kind == "UnaryOperation":
            node["op"] = str(e.type)
            node["operand"] = expr_json(getattr(e, "expression", None), var_lookup)
        elif kind == "AssignmentOperation":
            node["op"] = str(e.type)
            node["lhs"] = expr_json(first_attr("expression_left", "lvalue"), var_lookup)
            node["rhs"] = expr_json(first_attr("expression_right", "rvalue"), var_lookup)
        elif kind == "CallExpression":
            node["called"] = expr_json(getattr(e, "called", None), var_lookup)
            node["args"] = [expr_json(a, var_lookup) for a in (getattr(e, "arguments", None) or [])]
        elif kind == "IndexAccess":
            node["base"] = expr_json(first_attr("expression_left", "left"), var_lookup)
            node["index"] = expr_json(first_attr("expression_right", "right"), var_lookup)
        elif kind == "TupleExpression":
            node["items"] = [expr_json(x, var_lookup) for x in (e.expressions or [])]
        elif kind == "TypeConversion":
            node["type"] = str(e.type)
            node["operand"] = expr_json(getattr(e, "expression", None), var_lookup)
        elif kind == "ConditionalExpression":
            node["cond"] = expr_json(first_attr("result", "cond"), var_lookup)
            node["then"] = expr_json(first_attr("if_true", "then"), var_lookup)
            node["else"] = expr_json(first_attr("if_false", "else"), var_lookup)
    except Exception as err:  # keep exporting; flag imperfect subtrees
        node["export_err"] = str(err)[:80]
    return node


def canon_ir_str(op_name, s):
    """Canonicalize IR strings whose operand order is semantically irrelevant.
    Phi operands form a set; slither emits them in set-iteration order."""
    if op_name != "Phi":
        return s
    m = re.match(r"^(.*ϕ\(\[)(.*)(\]\).*)$", s)
    if not m:
        return s
    operands = sorted(x.strip() for x in m.group(2).split(",") if x.strip())
    return f"{m.group(1)}{', '.join(operands)}{m.group(3)}"


# ------------------------------------------------------------------- exporter

def var_kind(v, fn, contract):
    if v in (contract.state_variables_ordered or []):
        return "state"
    if fn is not None:
        if v in (fn.parameters or []):
            return "param"
        if v in (fn.returns or []):
            return "return"
    return "local"


def canon_type(t):
    """Canonical type string; tuple-typed variables hold a list of type objects."""
    if isinstance(t, (list, tuple)):
        return "/".join(sorted(str(x) for x in t))
    return str(t)


def export_repo(task, out_dir):
    name = task["name"]
    repo_root = task["repoRoot"]

    bundle_path = task.get("bundlePath")
    if not bundle_path or not os.path.exists(bundle_path):
        # compile on demand (same path as the bench harness)
        bundle_path = os.path.join(out_dir, "..", "bundles", f"{name}.pkl")
        os.makedirs(os.path.dirname(bundle_path), exist_ok=True)
        task = {**task, "bundlePath": bundle_path}
        compile_bundle(task, {"phases": {}, "metrics": {}, "errors": []})

    from slither import Slither

    with open(bundle_path, "rb") as f:
        cc = pickle.load(f)
    sl = Slither(cc)

    contracts_out = []
    cfg_functions = []
    ir_functions = []
    ssa_functions = []
    analysis_functions = []

    contracts = sorted(sl.contracts, key=lambda c: contract_id(c, repo_root))
    for contract in contracts:
        cid = contract_id(contract, repo_root)
        inherits = sorted(f.name for f in (contract.inheritance or []) if f.name != contract.name)
        state_vars = {}

        model_functions = []
        for fn in sorted(contract.functions_declared, key=lambda f: function_id(f, cid)):
            fid = function_id(fn, cid)
            params = [getattr(p, "type", None) and str(p.type) or "?" for p in (fn.parameters or [])]
            returns = [getattr(r, "type", None) and str(r.type) or "?" for r in (fn.returns or [])]
            # slither sets BOTH _pure and _view for stateMutability=="pure"
            # (slither/solc_parsing/declarations/function.py), so `pure` must be
            # tested first or every pure function is misreported as view.
            mutability = (
                "payable" if getattr(fn, "payable", False)
                else "pure" if getattr(fn, "pure", False)
                else "view" if getattr(fn, "view", False)
                else "nonpayable"
            )
            model_functions.append({
                "id": fid,
                "name": fn.name,
                "visibility": fn.visibility,
                "mutability": mutability,
                "modifiers": sorted(str(m) for m in (fn.modifiers or [])),
                "parameters": params,
                "returns": returns,
            })

            # ---- variable registry for this function (stable ids) ----
            vars_registry = {}      # id(var) -> stable id
            vars_by_id = {}         # stable id -> var object
            counter = 0
            scope_members = (
                list(fn.parameters or [])
                + list(fn.returns or [])
                + list(fn.variables_written or [])
                + list(fn.variables_read or [])
            )
            seen = set()
            for v in scope_members:
                if v is None or id(v) in seen:
                    continue
                seen.add(id(v))
                counter += 1
                vid = var_id(v, fid, counter)
                vars_registry[id(v)] = vid
                vars_by_id[vid] = v
            for sv in (contract.state_variables_ordered or []):
                vid = var_id(sv, cid, 0)
                vars_registry[id(sv)] = vid
                vars_by_id[vid] = sv

            def var_ref(v):
                if v is None:
                    return None
                vid = vars_registry.get(id(v))
                if vid:
                    return vid
                # on-demand stable id for temporaries/references (TMP_1, REF_0...):
                # names are assigned deterministically by the pinned slither version
                vname = getattr(v, "name", None)
                if vname:
                    vid = f"{fid}::{vname}"
                    vars_registry[id(v)] = vid
                    vars_by_id.setdefault(vid, v)
                    return vid
                return f"<unresolved:{type(v).__name__}>"

            # ---- model.json: function variables ----
            model_vars = []
            for vid in sorted(vars_by_id):
                v = vars_by_id[vid]
                model_vars.append({
                    "id": vid,
                    "name": getattr(v, "name", None),
                    "kind": var_kind(v, fn, contract),
                    "type": canon_type(getattr(v, "type", "?")),
                })

            # ---- cfg.json ----
            nodes = list(fn.nodes or [])
            def node_sort_key(n):
                sm = n.source_mapping
                return (
                    (getattr(sm, "filename_absolute", "") or "") if sm else "",
                    sm.start if sm else 0,
                    sm.length if sm else 0,
                    str(n.type),
                    str(n.expression),
                )
            nodes_sorted = sorted(nodes, key=node_sort_key)
            nid_map = {id(n): node_id(fid, i) for i, n in enumerate(nodes_sorted)}

            cfg_nodes = []
            for n in nodes_sorted:
                nid = nid_map[id(n)]
                reads = sorted({var_ref(v) for v in (n.variables_read or []) if var_ref(v)})
                writes = sorted({var_ref(v) for v in (n.variables_written or []) if var_ref(v)})
                cfg_nodes.append({
                    "id": nid,
                    "kind": str(n.type),
                    "source": rel_span(n.source_mapping, repo_root),
                    "expression": expr_json(n.expression, vars_registry) if n.expression else None,
                    "reads": [r for r in reads if r],
                    "writes": [w for w in writes if w],
                    "successors": sorted(nid_map[id(s)] for s in (n.sons or []) if id(s) in nid_map),
                })
            entry = nid_map.get(id(fn.entry_point)) if fn.entry_point else None
            cfg_functions.append({
                "function": fid,
                "contract": cid,
                "entry": entry,
                "nodes": sorted(cfg_nodes, key=lambda x: x["id"]),
                "variables": sorted(model_vars, key=lambda x: x["id"]),
            })

            # ---- ir.json (frozen contract: non-SSA IR only) ----
            # SSA is emitted to ssa.json as a NON-frozen reference: slither's SSA
            # version numbering and phi membership are process-nondeterministic
            # (object-id-hash iteration during renaming), so they cannot be part
            # of a byte-stable compatibility contract.
            ir_nodes = []
            ssa_nodes = []
            for n in nodes_sorted:
                nid = nid_map[id(n)]
                irs = [{"id": ir_id(nid, i), "op": type(o).__name__, "str": canon_ir_str(type(o).__name__, str(o))} for i, o in enumerate(n.irs or [])]
                ssa = [{"id": ir_id(nid, i), "op": type(o).__name__, "str": canon_ir_str(type(o).__name__, str(o))} for i, o in enumerate(n.irs_ssa or [])]
                if irs:
                    ir_nodes.append({"node": nid, "ir": irs})
                if ssa:
                    ssa_nodes.append({"node": nid, "ssa": ssa})
            ir_functions.append({
                "function": fid,
                "nodes": sorted(ir_nodes, key=lambda x: x["node"]),
            })
            ssa_functions.append({
                "function": fid,
                "nodes": sorted(ssa_nodes, key=lambda x: x["node"]),
            })

            # ---- analysis.json (fact schema v2: direct, intraprocedural,
            # non-propagated facts; call records carry callsite node stable id
            # + callee semantic id when resolvable, "unresolved" otherwise.
            # Per-expression call identity arrives with R4.2 IR op ids.) ----
            def resolve_called_fid(op, default_cid):
                target = getattr(op, "function", None)
                if target is None or not hasattr(target, "full_name"):
                    return None
                declarer = getattr(target, "contract_declarer", None)
                cid2 = contract_id(declarer, repo_root) if declarer is not None else default_cid
                return function_id(target, cid2)

            def node_ref(n):
                return nid_map.get(id(n), f"<unresolved-node:{n}>")

            def call_record(op, classify):
                node_str = node_ref(getattr(op, "node", None))
                return {"callsite": node_str, **classify}

            internal = []
            high = []
            low = []
            lib = []
            solid = []
            seen_calls = set()
            for n in nodes_sorted:
                for op in (n.irs or []):
                    op_kind = type(op).__name__
                    rec = None
                    if op_kind == "InternalCall":
                        callee = resolve_called_fid(op, cid)
                        rec = ("internal_calls", {"callsite": node_ref(n), "callee": callee or "unresolved"})
                    elif op_kind == "HighLevelCall":
                        dest = getattr(op, "destination", None)
                        tgt = getattr(op, "function", None)
                        member = getattr(op, "member_name", None) or getattr(tgt, "name", None) or "?"
                        # callee is the semantic id only when the destination is
                        # a directly-typed base (not an IR temp); otherwise the
                        # record is explicit "unresolved" (R4.2 resolves these).
                        dest_kind = type(dest).__name__ if dest is not None else "?"
                        if tgt is not None and dest_kind not in ("TemporaryVariable", "ReferenceVariable", "SolidityVariableComposed"):
                            declarer = getattr(tgt, "contract_declarer", None)
                            cid2 = contract_id(declarer, repo_root) if declarer is not None else cid
                            callee = function_id(tgt, cid2)
                        else:
                            callee = "unresolved"
                        rec = ("high_level_calls", {"callsite": node_ref(n), "member": member, "callee": callee})
                    elif op_kind == "LibraryCall":
                        tgt = getattr(op, "function", None)
                        lib_obj = getattr(tgt, "contract_declarer", None) if tgt else None
                        callee = f"{getattr(lib_obj, 'name', '?')}.{getattr(tgt, 'full_name', '?')}" if tgt else "unresolved"
                        rec = ("library_calls", {"callsite": node_ref(n), "callee": callee})
                    elif op_kind == "LowLevelCall":
                        opstr = str(op)
                        kind = "delegatecall" if "delegatecall" in opstr else "staticcall" if "staticcall" in opstr else "call"
                        rec = ("low_level_calls", {"callsite": node_ref(n), "kind": kind, "callee": "unresolved"})
                    elif op_kind == "Transfer":
                        rec = ("low_level_calls", {"callsite": node_ref(n), "kind": "transfer", "callee": "unresolved"})
                    elif op_kind == "Send":
                        rec = ("low_level_calls", {"callsite": node_ref(n), "kind": "send", "callee": "unresolved"})
                    elif op_kind == "SolidityCall":
                        sf = getattr(op, "function", None)
                        rec = ("solidity_calls", {"callsite": node_ref(n), "callee": getattr(sf, "full_name", "unresolved")})
                    if rec:
                        key = (rec[0], json.dumps(rec[1], sort_keys=True))
                        if key not in seen_calls:
                            seen_calls.add(key)
                            getattr({"internal_calls": internal, "high_level_calls": high, "low_level_calls": low,
                                     "library_calls": lib, "solidity_calls": solid}[rec[0]], "append")(rec[1])

            analysis_functions.append({
                "function": fid,
                "reads": sorted({var_ref(v) for v in (fn.variables_read or []) if var_ref(v)}),
                "writes": sorted({var_ref(v) for v in (fn.variables_written or []) if var_ref(v)}),
                "state_reads": sorted({var_ref(v) for v in (fn.state_variables_read or []) if var_ref(v)}),
                "state_writes": sorted({var_ref(v) for v in (fn.state_variables_written or []) if var_ref(v)}),
                "internal_calls": sorted(internal, key=lambda x: (x["callsite"], x.get("callee") or "")),
                "high_level_calls": sorted(high, key=lambda x: (x["callsite"], x.get("callee") or "")),
                "low_level_calls": sorted(low, key=lambda x: (x["callsite"], x.get("kind") or "")),
                "library_calls": sorted(lib, key=lambda x: (x["callsite"], x.get("callee") or "")),
                "solidity_calls": sorted(solid, key=lambda x: (x["callsite"], x.get("callee") or "")),
            })

        model_functions.sort(key=lambda x: x["id"])
        for sv in (contract.state_variables_ordered or []):
            state_vars[var_id(sv, cid, 0)] = {
                "name": sv.name,
                "type": canon_type(sv.type),
                "visibility": getattr(sv, "visibility", "?"),
                "constant": bool(getattr(sv, "is_constant", False)),
                "immutable": bool(getattr(sv, "is_immutable", False)),
            }
        contracts_out.append({
            "id": cid,
            "name": contract.name,
            "kind": getattr(contract, "contract_kind", None) and str(contract.contract_kind) or "?",
            "is_library": bool(getattr(contract, "is_library", False)),
            "is_interface": bool(getattr(contract, "is_interface", False)),
            "inherits": inherits,
            "state_variables": {k: state_vars[k] for k in sorted(state_vars)},
            "functions": model_functions,
        })

    meta = {
        "repo": name,
        "slither_version": SLITHER_PIN,
        "solc": task.get("solcVersion"),
        "exported_at": "deterministic",
    }

    write_json(os.path.join(out_dir, name, "model.json"), {"meta": meta, "contracts": sorted(contracts_out, key=lambda c: c["id"])})
    write_json(os.path.join(out_dir, name, "cfg.json"), {"meta": meta, "functions": sorted(cfg_functions, key=lambda x: x["function"])})
    write_json(os.path.join(out_dir, name, "ir.json"), {"meta": meta, "functions": sorted(ir_functions, key=lambda x: x["function"])})
    write_json(os.path.join(out_dir, name, "analysis.json"), {"meta": meta, "functions": sorted(analysis_functions, key=lambda x: x["function"])})
    # NON-FROZEN reference: SSA + data dependencies are process-nondeterministic
    # in Python slither (see README); useful for debugging, not for diffing.
    write_json(os.path.join(out_dir, name, "ssa.json"), {"meta": meta, "functions": sorted(ssa_functions, key=lambda x: x["function"])})
    log(f"[{name}] exported model/cfg/ir/analysis (+ssa reference)")


def write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
        fh.write("\n")


def main():
    check_version()
    corpus_path = sys.argv[1]
    out_dir = sys.argv[2]
    repos_filter = None
    if len(sys.argv) > 4 and sys.argv[3] == "--repos":
        repos_filter = set(sys.argv[4].split(","))

    corpus = json.load(open(corpus_path))
    for name, entry in corpus.items():
        if repos_filter and name not in repos_filter:
            continue
        t0 = time.time()
        repo_root = os.path.abspath(entry["path"])
        source_dir = os.path.join(repo_root, entry.get("sourceDir", "."))
        sol_files = sorted(glob.glob(os.path.join(source_dir, "**", "*.sol"), recursive=True))
        if not sol_files:
            log(f"[{name}] no .sol files, skipping")
            continue
        # resolve solc: highest installed solc-select version satisfying all pragmas
        import re

        from pathlib import Path

        artifacts_dir = os.path.expanduser("~/.solc-select/artifacts")
        installed = sorted(
            (m.group(1) for m in (re.match(r"^solc-(\d+\.\d+\.\d+)$", e) for e in os.listdir(artifacts_dir)) if m),
            key=lambda v: tuple(int(x) for x in v.split(".")),
        )
        if not installed:
            raise SystemExit("no solc versions installed under ~/.solc-select/artifacts")

        text = "\n".join(Path(f).read_text(errors="ignore") for f in sol_files)
        constraints = [m.strip() for m in re.findall(r"pragma\s+solidity\s+([^;]+);", text)]

        def tok_ok(vt, tok):
            m = re.match(r"^\^(\d+)\.(\d+)\.(\d+)$", tok)
            if m:
                b = tuple(int(x) for x in m.groups())
                return vt[0] == b[0] and vt >= b and vt[1] >= b[1] or (vt[0] == b[0] and vt[1] > b[1])
            m = re.match(r"^(>=|<=|>|<|==|=)?\s*(\d+)\.(\d+)\.(\d+)$", tok)
            if m:
                op, b = m.group(1) or "=", tuple(int(x) for x in m.groups()[1:])
                c = (vt > b) - (vt < b)
                return {">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0}.get(op, c == 0)
            return False

        def satisfies(vt, cons):
            return all(all(tok_ok(vt, t) for t in c.split()) for c in cons)

        version = entry.get("solc")
        if not version or version == "auto":
            version = next(
                (v for v in reversed(installed) if satisfies(tuple(int(x) for x in v.split(".")), constraints or [])),
                installed[-1],
            )
        solc_path = os.path.join(artifacts_dir, f"solc-{version}", f"solc-{version}")
        if not os.path.exists(solc_path):
            raise SystemExit(f"solc binary missing: {solc_path}")
        log(f"[{name}] solc {version} ({len(constraints)} pragmas)")

        bundle_path = os.path.join(out_dir, "bundles", f"{name}.pkl")
        if not os.path.exists(bundle_path):
            os.makedirs(os.path.dirname(bundle_path), exist_ok=True)
            task = {
                "name": name,
                "targetDir": source_dir,
                "repoRoot": repo_root,
                "solc": solc_path,
                "bundlePath": bundle_path,
                "solcVersion": version,
                "timeoutCompile": 600,
                "timeoutAnalyze": 900,
            }
            try:
                compile_bundle(task, {"phases": {}, "metrics": {}, "errors": []})
            except Exception as e:  # noqa: BLE001 - one broken repo must not kill the sweep
                log(f"[{name}] SKIP (compile failed): {str(e)[:160]}")
                continue
        try:
            export_task = {
                "name": name,
                "repoRoot": repo_root,
                "solc": solc_path,
                "solcVersion": version,
                "bundlePath": bundle_path,
            }
            export_repo(export_task, out_dir)
        except Exception as e:  # noqa: BLE001
            log(f"[{name}] SKIP (export failed): {str(e)[:160]}")
            continue
        log(f"[{name}] done in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()

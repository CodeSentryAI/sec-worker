# sec-worker

Sandboxed security-scan worker: bubblewrap-isolated detector execution producing
normalized findings. This is the LAN-side analysis half of the Chain Fox scan
pipeline — the VPS control plane (`chain-fox-frontend-dao/server`) never runs
untrusted code; this worker does, inside a no-network namespace jail.

## Architecture

```text
task input dir ──► prepare (trusted, host)  ──► bwrap sandbox ──► normalized Finding[]
                  lockbud: lockfile +         RO input, RW output,
                  staged CARGO_HOME           no network, rlimits,
                  pecatch: solc resolution    in-ns pids limit, wall clock
```

- **Sandbox backend**: bubblewrap (no Docker). All namespaces unshared
  (`--unshare-all`), filesystem reduced to `/usr` (+ classic `/bin`, `/lib*`
  aliases), explicit toolchain binds, `/work/input` read-only, `/work/output`
  read-write, cleared environment, `/tmp`+`/run` tmpfs.
- **Resource limits**: `prlimit` sets RLIMIT_AS / RLIMIT_CPU / RLIMIT_FSIZE
  (per-process); the pids limit is applied *inside* the user namespace via
  `ulimit -u` so it uses the namespace's fresh counter instead of the host
  user's task count (which breaks `unshare(CLONE_NEWUSER)` with EAGAIN on busy
  hosts). Wall-clock kill switch: SIGKILL to the process group from the runner.
- **Detectors** are pluggable in `src/detectors/registry.ts`; each one does
  trusted host-side preparation, builds a sandbox request, and normalizes its
  raw report into the shared finding format (`src/types.ts`).

## Detectors

| id | ecosystem | engine | raw output |
|---|---|---|---|
| `lockbud-stable` | rust | local fork `~/Projects/lockbud-stable`, pinned `nightly-2026-02-07`, driven as `RUSTC=<bin> cargo check --offline --locked` | `LOCKBUD_RESOURCE_REPORT` JSON (`findings[]` with lint/severity/confidence/primary_location/evidence) |
| `pecatch` | solidity | slither 0.9.1 + peCatch gas checkers (`and-in-if`, `unchecked`, `redundant-sload`, `alloc-in-loop`, …) | slither `--json` report |

Toolchain paths are configured in `src/config.ts` (overridable via `SEC_*`
env vars). Toolchains are bind-mounted at their **host-identical absolute
paths** so venv shebangs and baked rpaths resolve unchanged.

## Usage

```bash
# one-off containment check after any environment change
npm run selftest

# run a detector
npm run detect -- --detector lockbud-stable --input <dir> --output <dir>
npm run detect -- --detector pecatch       --input <dir> --output <dir> [--checkers a,b,c]

# full suite (sandbox probes + detector e2e on fixtures)
npm test
```

Exit codes mirror lockbud's `detect.sh`: `0` clean, `1` findings, `2` error.
Each run writes `findings.json` (normalized) and `run.json` (metadata) into the
output dir; raw detector reports are kept alongside as evidence.

## Findings schema (v1)

```jsonc
{
  "rule_id": "lockbud-stable.double-lock" | "pecatch.and-in-if",
  "ecosystem": "rust" | "solidity",
  "detector": "lockbud-stable 0.1.0 (nightly-2026-02-07…)",
  "severity": "critical|high|medium|low|informational",
  "confidence": "high|medium|low",
  "evidence_level": "static-evidence",
  "location": { "file": "src/main.rs", "line": 6, "column": 18 },
  "message": "…",
  "raw": { /* original detector item, preserved for evidence */ }
}
```

The detector's evidence grade is authoritative; a later LLM review stage may
explain or downgrade findings but must not upgrade them.

## Benchmark harness (A/B/C costs)

`npm run bench` measures where the money actually goes, per repo and run mode:

```text
[A] acquisition   repo copy (clone proxy)
[B] compilation   solc --standard-json over all sources -> pickled CompilationBundle
[C] analysis      slither 0.11.6 model build (CFG/SlithIR) + all detectors
```

Modes: `cold` (first submission: copy+compile+analyze), `repo` (resubmission:
no copy, fresh compile), `bundle` (compilation cached: load bundle + analyze
only). Every run also records `detectors_repeat_s` — the detector-only cost of
a warm model — and peak RSS. Phase timings come from a python driver
(`bench/slither_driver.py`) that drives crytic-compile/slither 0.11.6 as a
library (bench venv, separate from the peCatch venv).

```bash
npm run bench -- --corpus bench/corpus.json --out bench/results \
    [--repos v2-core,openzeppelin] [--modes cold,repo,bundle]
```

Corpus: the 9 repos shipped in the peCatch artifact (Uniswap v2/v3,
OpenZeppelin, Seaport, Seadrop, solmate, …) plus the local fixture. Results
land in `bench/results/summary.md`.

### Measured baseline (2026-10-01, WSL 6C/9G, slither 0.11.6, all ~75 detectors)

| repo | loc | contracts | compile_s | model_s | det_s | det_only_s | rss_mb |
|---|---|---|---|---|---|---|---|
| gas-toy | 22 | 1 | 0.02 | 0.01 | 0.01 | 0.00 | 41 |
| v2-core (0.5.16) | 539 | 12 | 0.16 | 0.24 | 0.08 | 0.05 | 61 |
| solidity-lib (0.6.12) | 906 | 23 | 0.22 | 0.24 | 0.10 | 0.06 | 60 |
| v3-core (0.7.6) | 5,056 | 62 | 0.80 | 1.60 | 0.65 | 0.31 | 176 |
| solmate (0.8.15) | 9,916 | 73 | 3.50 | 8.20 | 5.20 | 2.90 | 616 |
| openzeppelin (0.8.28) | 23,691 | 313 | 6.50 | 13.40 | 5.90 | 5.30 | 728 |
| seadrop / seaport | — | — | — | — | — | — | — |

Takeaways:
1. Even cold, **analysis (model+detectors) dominates direct-solc compilation 2–4×**
   on everything that compiles standalone.
2. With a cached bundle, the marginal cost of a duplicate submission is
   **100% analysis** (cache load is 0.1–0.3s); model construction alone is the
   biggest warm component (~13s on OpenZeppelin) — bigger than all detectors
   combined.
3. **Memory is the concurrency ceiling**: ~730MB peak at 313 contracts means
   roughly 8–12 concurrent slither analyses per 16GB machine.
4. Seadrop/Seaport fail without `node_modules` (ERC721A, @rari-capital/solmate) —
   the framework/dependency-setup path (A+B for real projects) is the biggest
   unbuilt cost, far exceeding anything a language rewrite would save.

### Model-build dissection (bundle-cached, slither 0.11.6 PhaseTimer, 2026-10-01)

| stage (s) | v2-core (12c) | v3-core (62c) | solmate (73c) | openzeppelin (313c) |
|---|---|---|---|---|
| parse_contracts | 0.08 | 0.48 | 3.04 | 5.68 |
| — cfg_analyze_third_part (function bodies → expression/CFG objects) | 0.08 | 0.44 | 2.95 | 5.48 |
| analyze_contracts | 0.17 | 1.10 | 4.57 | 7.36 |
| — convert_to_slithir (IR + SSA + propagation) | 0.09 | 0.59 | 2.99 | 4.93 |
| — compute_dependency (taint/read-write) | 0.07 | 0.50 | 1.57 | 2.38 |
| inheritance/using-for/storage layout | <0.05 | <0.1 | <0.2 | <0.2 |
| **model total** | **0.26** | **1.69** | **6.24** | **13.5** |
| detectors (all) | 0.10 | 0.66 | 8.48 | 7.21 |
| peak RSS (MB) | 61 | 175 | 614 | 729 |
| analyses/s/GB (peak-RSS efficiency) | 47.9 | 2.50 | 0.113 | 0.068 |

Dissection findings:
1. **Function-body → expression/CFG object construction is the single largest
   model stage** (`cfg_analyze_third_part`: 5.5s of 13.5s on OZ, ~96% of
   parse_contracts). This is the "AST Python object explosion" — every
   expression becomes a Python object.
2. **SlithIR + SSA conversion is second** (4.9s), dependency/taint third (2.4s).
   Declarations/inheritance are negligible (<5%).
3. So a Rust semantic engine should be built in this order: **(1) compact
   arena-backed expression/CFG representation, (2) SlithIR/SSA conversion,
   (3) dependency graphs** — porting detectors last.
4. Detector-level: `return-bomb` alone costs ~2.5s/run on OZ (a quarter of all
   detector time); the `reentrancy-*` family dominates on function-heavy repos
   (solmate). Useful for production detector-set tuning.
5. Throughput efficiency (`a/s/GB`) spans **3 orders of magnitude** across the
   corpus (48 for tiny repos vs 0.068 for OZ) — the single best cost model for
   hosting; a Rust target of ~150MB/4s would land ~1.7 a/s/GB, a ~25× gain at
   OZ scale.

Note: slither 0.9.1/0.11.6 cannot reload its own exported artifacts (dir/.json/
.zip targets all silently analyze 0 contracts or route to the solc platform) —
the harness therefore uses a pickled `CryticCompile` as the compilation cache,
which is exactly the deserialization cost a Rust `CompilationBundle` loader
would pay. `compile_force_framework="Solc-json"` + `solc_args="--allow-paths
<root>"` + `solc_working_dir=<root>` is the working incantation for standard-json
compilation via the library API.

## slither-rs — R4.1 status (2026-10-01)

Rust workspace at `~/Projects/BW2/slither-rs` (`cargo build`; three crates:
`solc-model` AST ingestion, `slither-core` arena/program/CFG,
`slither-oracle-compat` canonical emitter). Input: per-repo `solc-output.json`
(regenerated solc standard-json ASTs, repo-relative source keys) + provenance
per fixture.

### The false-positive incident, and what now prevents a repeat

An earlier version of this file claimed "R4.1a–d green / all-6-IDENTICAL". That
was a **false positive caused by the measurement pipeline**: `diff.py` was
being handed a per-repo directory instead of a fixture root, and it *silently
continued* whenever a file was missing on both sides — so the comparison never
ran and the summary printed IDENTICAL. A whole per-repo "green" row was
vacuous.

Three fail-closed rules now make that class of bug impossible:

| rule | enforcement |
|---|---|
| missing ≠ pass | `diff.py` reports `MISSING … (check invocation)`; `gate.py` reports `MISSING_RUST` / `MISSING_ORACLE` and fails |
| uncompared ≠ identical | a level that cannot be compared is a gate failure, never a skipped line |
| partial universe ≠ green | the gate universe comes from `fixture-manifest.json`, never from "whatever directories exist" |
| downstream green cannot mask upstream red | `gate.py` prints a G0→G6 ladder where a gate is only REACHED if every earlier gate passed; failures cascade as `BLOCKED` |
| an unlowered statement is not a clean diff | the emitter refuses to be trusted: it prints `INCOMPLETE-LOWERING` with the offending kinds and exits non-zero unless `ALLOW_PARTIAL_LOWERING=1` |

### Gate ladder (`python bench/oracle/gate.py --emit --out /tmp/rs-gate`)

```
G0 fixture manifest complete              PASS      manifest complete
G1 model.json == oracle                   OPEN      diffs remain on 5 repos
G2 cfg.json == oracle                     BLOCKED   …
G3/G4 direct effects + call facts         BLOCKED   …
G5 determinism + stable-id uniqueness     BLOCKED   …
G6 syntax-zoo constructs covered          BLOCKED   13/14 construct(s) open
```

**G0 and G1 are green.** `model.json` is byte-identical to the frozen oracle on
all seven expected-success fixtures — gas-toy, v2-core (0.5.16), solidity-lib,
v3-core (0.7.6), solmate, OpenZeppelin (313 contracts / 1872 functions) and
syntax-zoo. G2 (CFG) is still open and everything below it is therefore
`BLOCKED` by construction, not green.

### Per-repo differential state

| repo | model.json | cfg.json | analysis.json |
|---|---|---|---|
| gas-toy | **IDENTICAL** | **IDENTICAL** | **IDENTICAL** |
| v2-core | **IDENTICAL** | open | open |
| solidity-lib | **IDENTICAL** | open | open |
| v3-core | **IDENTICAL** | open | open |
| solmate | **IDENTICAL** | open | open |
| openzeppelin | **IDENTICAL** | open | open |
| syntax-zoo | **IDENTICAL** | 13 constructs open | open |

Run `python bench/oracle/cluster.py --fixtures bench/oracle/fixtures --rust
<dir> --level cfg.json` for root-cause clustering (which field diverged, and
which AST syntax kinds the diverging functions contain) — a flat diff count is
close to useless for prioritisation, because one ordinal-mapping bug inflates
node ids which then break successors, callsites and analysis facts.

### gas-toy is the permanent smoke gate

`npm test` runs `tests/r41-gas-toy.test.ts`, which requires gas-toy to be
**0 / 0 / 0** on model/cfg/analysis against the frozen oracle, byte-identical
across two runs, and refuses to pass if the emitter reported any unlowered
statement. It is cheap enough to run on every change, so a regression is caught
long before the full corpus is consulted.

### syntax-zoo isolates each construct

`tests/fixtures/solidity-syntax-zoo/SyntaxZoo.sol` holds one minimal function
per construct (while / do-while / break / continue / unchecked / try-catch /
modifier / tuple decl / named return / compound assign), frozen as a 7th
fixture. Large repos hide which lowering rule is missing; here each red function
names its own construct. `npm test` also runs `tests/r41-syntax-zoo.test.ts`,
which asserts the identity layer is green and that the recorded list of
*open* constructs (`EXPECTED_OPEN`, each with its reason) exactly matches
reality — so the list cannot silently go stale, and it fails when a construct
is fixed until the entry is removed. Shrinking that list is the progress metric.

Constructs already closed this way: `modifierCase`, and node-count parity for
`forCase` / `whileCase` / `breakCase` / `continueCase` / `compoundAssignCase` /
`namedReturnCase` / `ifCase`.

### Slither semantics recovered by differential discovery

Each of these was found by diffing, then confirmed against slither 0.11.6
source before being implemented:

- **`pure` must be tested before `view`** — slither sets *both* `_pure` and
  `_view` for `stateMutability: "pure"`
  (`solc_parsing/declarations/function.py`). The oracle was misreporting every
  pure function as `view`; that was an **oracle bug**, fixed in the exporter
  and all fixtures re-frozen.
- **slither synthesizes no empty `constructor()`** — every `constructor` in the
  oracle maps to a real `kind: "constructor"` FunctionDefinition, including the
  empty-parameter ones. The previously implemented "synthetic constructor for
  contracts with bases" rule was a mis-discovery and inflated OpenZeppelin by
  253 bogus entries.
- **elementary type aliases** — `uint`→`uint256`, `int`→`int256`, `byte`→`bytes1`
  (`core/solidity_types/elementary_type.py`); pre-0.6 ASTs spell the short form.
- **user-defined types are qualified at each use site** (`struct
  UniswapV3PoolDeployer.Parameters`), which a global name→owner map cannot
  disambiguate when two contracts declare the same struct.
- **`slitherConstructorConstantVariables()` / `slitherConstructorVariables()`** —
  created iff an *accessible* state variable has an initializer, constant
  resp. non-constant. "Accessible" excludes **private inherited** variables
  (`Contract.state_variables` vs `state_variables_ordered`), which is why a
  child of a contract with a private initialized variable does *not* get one.
- **modifiers are not inlined** — an invocation becomes one `EXPRESSION` node
  whose callee is `{"kind":"Identifier","str":name}` with no `ref`. Modifier
  bodies are separate analysis units. Kept as a compat-level node so source
  mapping, callgraph and summaries are not polluted.
- **implicit RETURN for named returns** — a function relying on named return
  parameters and able to fall off the end gets a RETURN node spanning the first
  return parameter, with a tuple of the return variables.
- **`_remove_alone_endif`** — an ENDIF with no fathers is dropped, iterated to a
  fix point; and `IF → ENDIF` is linked **only when there is no else branch**.
- **solc AST dialects** — `Return`/`Break`/`Continue` (not `…Statement`);
  initializer spelled `value` before 0.6 and `initialValue` after; `constant`
  on the declaration in 0.5.x vs the inner `VariableDeclaration` from 0.6;
  immutability spelled `mutability: "immutable"` in the 0.7 legacy AST;
  `modifierName` as a nested node pre-0.8; `baseConstructorSpecifier` entries
  are base-constructor calls, not modifiers.
- **expression/RW rules** — `++`/`--` read *and* write their operand; a
  compound assignment (`+=`) reads its target as well as writing it; a
  terminator (return/break/continue) does not fall through, so ENDIF must not
  acquire a spurious son.
- **reads/writes are `sorted(set(...))` of stable ids** — both the dedup and
  the lexicographic order are part of the contract.
- **two-pass variable registry** — params/returns/R-W get a function-scoped id
  (anonymous members named `<anon-N>`, N = 1-based position in that sequence),
  then state variables are re-registered contract-scoped; the first-pass id
  survives in the variables list, so a touched state variable legitimately
  appears twice under both scopes.

**Performance baseline (debug build, full AST→model→CFG→emit) unchanged:**
v2-core 77ms / 14MB, v3-core 499ms / 66MB, solmate 1.1s / 163MB, openzeppelin
2.2s / 198MB (vs Python 0.24s/61MB → 13.5s/729MB). The two sides' phase
boundaries are not yet symmetric, so no speedup claim is made — that waits for
the symmetric benchmark after R4.1 closes.

### Next, in dependency order

1. G2 cfg, driven by the syntax-zoo list: `doWhileCase`, `tryCase`,
   `tupleDeclCase`, `uncheckedCase` are the structural gaps; the rest are
   expression-detail gaps.
2. A CFG for synthetic functions (`slitherConstructorVariables()`), which has
   no AST definition.
3. Only then G3/G4 (direct effects + call facts), with `CallTarget` resolution
   (`Resolved`/`Builtin`/`Dynamic`/`Unresolved`) kept on a separate axis from
   `CallKind`, resolving through solc `referencedDeclaration`/type information
   rather than `name + argc`.

## slither-oracle — semantic compatibility fixtures

`npm run oracle` is the pre-Rust deliverable: a version-pinned (slither 0.11.6)
exporter that freezes **detector-observable semantics** of the benchmark corpus
into canonical JSON at four levels, one directory per repo under
`bench/oracle/fixtures/`:

| file | level | contents |
|---|---|---|
| `model.json` | identity | contracts (`<relpath>::<Name>`), functions (`<contract>::<signature>`), variables (`<scope>::<name>@<span>`), visibility/mutability/inheritance |
| `cfg.json` | CFG/expression | per function: nodes (`<fn>#n<ordinal>`, ordered by span/kind/expr — never by allocation), kinds, spans, structural expression trees, reads/writes, successors, entry |
| `ir.json` | SlithIR (non-SSA) | per node: op class + canonical string, node-stable ir ids |
| `analysis.json` | derived facts | state R/W, variables R/W, internal/high/low/library/solidity calls |

**FROZEN = model/cfg/ir/analysis.** `ssa.json` is additionally emitted as a
NON-frozen debugging reference (SSA + data dependencies). Two reproducibility
findings forced this split — both genuine slither properties, worth knowing
before building slither-core-rs:

1. **SSA version numbering is process-nondeterministic** (`amount0_1` vs
   `amount0_2` across runs): phi insertion and renaming iterate sets of
   objects keyed by id()-hash, which PYTHONHASHSEED cannot pin. The phi
   operand *set* is also emitted in varying order (canonicalized to sorted in
   our strings, but membership indices remain unstable).
2. **Data-dependency edges are not reproducible at all**: the fixpoint's
   output *content* (not just order) varies run-to-run — dependency sets of
   the same variable differed in size across two exports of the identical
   bundle. 12 detectors consume data_dependency; their differential gates will
   need semantic canonicalization (relabeling/closure) rather than raw dumps.

With those excluded, exporting the whole corpus twice yields **IDENTICAL**
snapshots (verified): `npm run oracle -- diff bench/oracle/fixtures /tmp/oracle-check`.

`diff.py` is the structural comparator the future Rust differential tests will
use (order-insensitive, key-field aware). Fixture JSONs are frozen artifacts;
the `bundles/` pickle caches that seed them are regenerable and git-ignored.

## Detector dependency mining

`npm run oracle -- mining bench/oracle/detector_apis.json` statically scans the
pinned slither's detector sources (98 files) and reports which semantic facts
each detector consumes. Coverage (share of detectors using each fact):

| fact | share |
|---|---|
| slithir ops (isinstance dispatch) | 39% |
| node.irs (non-SSA IR) | 38% |
| function.nodes (CFG iteration) | 35% |
| entry_point | 23% |
| sons/fathers (CFG edges) | 17% |
| variables_written / read | 15% / 13% |
| internal_calls | 14% |
| data_dependency | 12% |
| node.irs_ssa (SSA) | **3%** |

Objective build order for slither-core-rs confirmed: **CFG + non-SSA IR + call
classification + R/W sets** cover the overwhelming majority of detectors;
SSA is a niche requirement (3 detectors) and can trail.

## Environment bootstrap

```bash
sudo ./bootstrap/bootstrap.sh            # apt packages (bubblewrap, python3-venv, …)
./bootstrap/install-toolchains.sh        # rust pin + lockbud build + peCatch venv (no sudo)
```

py3.12 notes baked into the install script: slither 0.9.1 needs
`setuptools<81` (`pkg_resources`), the abandoned `pysha3` dep is satisfied by
`safe-pysha3` (cp312 wheel) plus a metadata-only `pysha3` stub, and peCatch
installs editable because `pecatch_plugin/detectors/` lacks `__init__.py`.

## Known limitations / next steps

- **No seccomp filter yet** (namespaces + rlimits only). nsjail is the planned
  second backend (`SandboxRunner` interface stays stable).
- **No cgroup memory/pids aggregate**: RLIMIT_AS/FS are per-process. A systemd
  transient scope (`MemoryMax`, `TasksMax`) is the next hardening step.
- **Rust deps must be offline-analyzable**: `cargo fetch` runs in the trusted
  prepare phase; git deps are not supported in the restricted-network
  environment (crates.io works). Vendored deps always work.
- **Solidity**: only solc-compilable inputs (no foundry/hardhat dependency
  resolution yet); solc versions come from the `solc-select` cache — install
  missing versions host-side (`solc-select install <ver>`).
- peCatch checkers run on slither 0.9.1; upgrading slither needs a peCatch
  compatibility check (API of `AbstractDetector` moves between versions).
- Input dir is read-only by design (evidence tamper-proofing): tools that must
  write into the source tree will fail loudly rather than silently.

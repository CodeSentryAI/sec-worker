# Open decision requests

Questions that need a human decision, with the evidence gathered so far. Each
one blocks work that should not proceed on an assumption.

---

## D1 — Which `fixture-manifest.json` is authoritative, and what does `success` mean?

**Status:** open. Raised 2026-10-03 from slither-rs `13ceb9e`.

### The contradiction

Two manifests describe the same oracle corpus and disagree:

| repo | `success` | others |
| --- | --- | --- |
| `sec-worker/bench/oracle/fixture-manifest.json` | gas-toy, openzeppelin, solidity-lib, solmate, syntax-zoo, **v2-core, v3-core** (7) | seadrop / seaport `compile_failure` |
| `slither-rs/fixtures/fixture-manifest.json` | gas-toy, identity-zoo, syntax-zoo (3) | call-zoo / openzeppelin / solidity-lib / solmate / **v2-core / v3-core** = `planned` |

`identity-zoo` and `call-zoo` are absent from sec-worker's manifest entirely.

### What is actually measured today

slither-rs `13ceb9e`, root-level `scripts/diff_oracle.py`, per-layer:

- `gas-toy`, `identity-zoo`, `syntax-zoo` — **byte-identical on all three layers**.
- `v2-core` — `declaration_gaps=0`, still **fail-closed** on 2 `InlineAssembly`
  statements; cfg identical for 63/96 functions. Not a pass.
- `call-zoo` — `model.json` identical, `cfg.json` 36 diffs, `analysis.json` 6;
  all five call buckets match the frozen Slither 0.11.6 oracle entry for entry.

So slither-rs's manifest matches measurement. sec-worker's does not — at least
for v2-core.

### The part that makes this a real decision, not a typo

`success` is defined in slither-rs's own manifest as:

> fully vendored under fixtures/oracle (solc-input/output + model/cfg/analysis
> snapshots) AND gated by scripts/diff_oracle.py

Under that definition **4 of sec-worker's 7 `success` labels are false**. What is
tracked in git, in *both* repos:

| repos | tracked files |
| --- | --- |
| gas-toy, identity-zoo, syntax-zoo, call-zoo | full snapshot (solc-input, solc-output, model, cfg, analysis, ir, ssa) |
| openzeppelin, solidity-lib, solmate, v2-core, v3-core | **`provenance.json` only** |

The large real-world corpora are not committed (not by any `.gitignore` rule —
simply never added). Their `provenance.json` does pin everything needed to
rebuild them deterministically: `solc_version`, `source_paths`,
`input_sha256`, `solc_output_sha256`, `sources_sha256`. v2-core's, for example,
pins solc 0.5.16 and 12 UniswapV2Core paths by hash.

So a fresh clone cannot verify those five from git alone; it must re-fetch the
upstream sources and confirm the hashes.

### Why it matters

1. slither-rs's gate iterates the `success` set. If the four unvendored repos are
   really "success", they are **not** being diffed, so regressions in them are
   invisible. That is the exact failure mode the differential harness exists to
   prevent.
2. The two repos' reported numbers cannot be reconciled while they disagree, so
   HANDOFF/bench figures drift (this already happened twice).
3. "Regenerable from a hash-pinned provenance" is a legitimate and much cheaper
   alternative to vendoring — but it is a *different* guarantee, and only one of
   the two should be claimed.

### Questions

1. Which manifest is authoritative — sec-worker's or slither-rs's?
2. Is `success` defined as "snapshot vendored + gated" (slither-rs's current
   wording), or as "regenerates byte-identically from pinned provenance"?
3. Should openzeppelin / solidity-lib / solmate / v2-core / v3-core be
   `planned` until they are vendored **or** proven to regenerate to the pinned
   hashes?
4. Should one manifest be generated from the other, or from a single shared
   source of truth, so they cannot drift again?
5. Should the large corpora be gitignored explicitly (with a comment), so their
   absence is intentional and documented rather than looking like an oversight?

### Recommendation (not a decision)

Adopt slither-rs's manifest as authoritative and demote the four unvendored
repos to `planned` now; then promote each one as it is either vendored *or*
verified to regenerate to its pinned `solc_output_sha256`. Whichever definition
of `success` is chosen, encode it in one generator so the two files cannot
disagree.

### Reproducing the evidence

```bash
cd slither-rs
bash scripts/check_syntax_zoo.sh /tmp/zoo          # 3 repos, 3 layers, IDENTICAL
# v2-core needs its corpus rebuilt first (provenance.json pins the hashes);
# without it the driver exits fail-closed on 2 InlineAssembly.
git ls-files fixtures/oracle | sed 's#fixtures/oracle/##' | awk -F/ '{print $1}' | sort -u
```
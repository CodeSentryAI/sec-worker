import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * syntax-zoo gate: one minimal function per Solidity construct, so a missing
 * CFG lowering names its own construct instead of surfacing as thousands of
 * diffs buried in a large repo.
 *
 * This test is a *status report*, not a pass/fail gate on the whole file: R4.1
 * is still open, and the value here is that the list below is regenerated on
 * every run and cannot silently drift. `EXPECTED_OPEN` is the honest record of
 * which constructs are not yet lowered; shrinking it is the progress metric.
 * When a construct is fixed, this test fails until the entry is removed.
 */
const HERE = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(HERE, "..");
const SLITHER_RS = process.env.SLITHER_RS ?? path.resolve(PROJECT_ROOT, "..", "slither-rs");
const FIXTURES = path.join(PROJECT_ROOT, "bench", "oracle", "fixtures");
const REPO = "syntax-zoo";
const LEVELS = ["model.json", "cfg.json", "analysis.json"] as const;

/**
 * Constructs with known, still-open lowering gaps, with the reason. Remove an
 * entry once its function is IDENTICAL on all levels.
 */
const EXPECTED_OPEN: Record<string, string> = {
  "slitherConstructorVariables()": "synthetic function has no AST definition, so no CFG is built",
  "doWhileCase(uint256)": "DoWhileStatement not lowered (STARTLOOP->body->post->IFLOOP skeleton)",
  "tryCase(address,bytes)": "TryStatement/TryCatchClause not lowered",
  "tupleDeclCase()": "tuple variable declaration not expanded into per-component VARIABLE nodes + tuple assignment",
  "breakCase(uint256)": "break back-edge target/ordering differs",
  "continueCase(uint256)": "continue back-edge target/ordering differs",
  "ifCase(bool,bool)": "else-branch son ordering differs",
  "namedReturnCase(uint256)": "implicit-return tuple expression details differ",
  "whileCase(uint256)": "while back-edge/ordering details differ",
};

function buildRust(): boolean {
  const r = spawnSync(process.env.CARGO ?? "cargo", ["build"], { cwd: SLITHER_RS, encoding: "utf8" });
  if (r.error || r.status !== 0) {
    process.stderr.write(`cargo build failed: ${r.error?.message ?? `exit ${r.status}`}\n${r.stderr ?? ""}`);
    return false;
  }
  return true;
}

function emit(outDir: string) {
  const binary = path.join(SLITHER_RS, "target", "debug", "slither-oracle-compat");
  const provenance = JSON.parse(readFileSync(path.join(FIXTURES, REPO, "provenance.json"), "utf8"));
  const r = spawnSync(
    binary,
    ["--repo", REPO, "--solc", provenance.solc_version, "--fixtures", FIXTURES, "--out", outDir],
    { encoding: "utf8" },
  );
  return { ok: r.status === 0, stderr: r.stderr ?? "" };
}

function perFunctionDiff(repo: string, level: string, rustDir: string): Map<string, string[]> {
  const script = path.join(PROJECT_ROOT, "bench", "oracle", "zoo_status.py");
  const r = spawnSync("python3", [script, REPO, level, FIXTURES, rustDir], {
    encoding: "utf8",
    cwd: PROJECT_ROOT,
  });
  if (r.status !== 0) {
    throw new Error(`zoo_status.py failed: ${r.stderr}`);
  }
  return new Map(
    JSON.parse(r.stdout).map((row: [string, number, string]) => [row[0], [row[2]]]),
  );
}

test("syntax-zoo: model.json is IDENTICAL (identity layer is fully lowered)", () => {
  assert.ok(buildRust(), "cargo build failed");
  const outDir = mkdtempSync(path.join(tmpdir(), "zoo-"));
  try {
    const r = emit(outDir);
    assert.ok(r.ok, `emitter failed:\n${r.stderr}`);
    const status = perFunctionDiff(REPO, "model.json", outDir);
    const failing = [...status.entries()].filter(([, v]) => v[0] !== "OK");
    assert.deepEqual(
      failing.map(([k]) => k),
      [],
      `model.json regressions: ${JSON.stringify(failing)}`,
    );
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
});

test("syntax-zoo: open-construct list is accurate and did not grow", () => {
  assert.ok(buildRust(), "cargo build failed");
  const outDir = mkdtempSync(path.join(tmpdir(), "zoo-"));
  try {
    const r = emit(outDir);
    assert.ok(r.ok, `emitter failed:\n${r.stderr}`);
    const status = perFunctionDiff(REPO, "cfg.json", outDir);
    const actuallyOpen = [...status.entries()]
      .filter(([, v]) => v[0] !== "OK")
      .map(([k]) => k)
      .sort();
    const declared = Object.keys(EXPECTED_OPEN).sort();

    const undeclared = actuallyOpen.filter((k) => !declared.includes(k));
    assert.deepEqual(
      undeclared,
      [],
      `newly open constructs not recorded in EXPECTED_OPEN: ${undeclared.join(", ")}`,
    );
    // Fixed constructs must be removed from EXPECTED_OPEN so the list stays a
    // truthful progress record rather than a stale allowlist.
    const stale = declared.filter((k) => !actuallyOpen.includes(k));
    assert.deepEqual(
      stale,
      [],
      `these constructs are now IDENTICAL — remove them from EXPECTED_OPEN: ${stale.join(", ")}`,
    );
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
});
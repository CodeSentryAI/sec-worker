import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * gas-toy is the R4.1 smoke gate: the smallest end-to-end fixture, and the
 * only one required to be byte-identical to the frozen slither-oracle at every
 * stage. It is cheap enough to run on every change, so a regression here is
 * caught long before the full corpus is consulted.
 *
 * Fail-closed rules encoded below (each of these previously produced a false
 * green):
 *   - the emitter must exit 0 and report no unlowered statements
 *   - every level must actually exist on BOTH sides (missing != pass)
 *   - the emitter must be a clean, current build
 */
const HERE = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(HERE, "..");
const SLITHER_RS = process.env.SLITHER_RS ?? path.resolve(PROJECT_ROOT, "..", "slither-rs");
const FIXTURES = path.join(PROJECT_ROOT, "bench", "oracle", "fixtures");
const REPO = "gas-toy";
const LEVELS = ["model.json", "cfg.json", "analysis.json"] as const;

function buildRust(): boolean {
  const r = spawnSync(process.env.CARGO ?? "cargo", ["build"], { cwd: SLITHER_RS, encoding: "utf8" });
  if (r.error || r.status !== 0) {
    process.stderr.write(`cargo build in ${SLITHER_RS} failed: ${r.error?.message ?? `exit ${r.status}`}\n`);
    process.stderr.write(r.stderr ?? "");
    return false;
  }
  return true;
}

function emitRust(outDir: string): { ok: boolean; stderr: string; stdout: string } {
  const binary = path.join(SLITHER_RS, "target", "debug", "slither-oracle-compat");
  const provenance = JSON.parse(readFileSync(path.join(FIXTURES, REPO, "provenance.json"), "utf8"));
  // deliberately NOT setting ALLOW_PARTIAL_LOWERING: an unlowered statement
  // must fail this gate rather than produce a quietly-wrong snapshot.
  const r = spawnSync(
    binary,
    ["--repo", REPO, "--solc", provenance.solc_version, "--fixtures", FIXTURES, "--out", outDir],
    { encoding: "utf8" },
  );
  return { ok: r.status === 0, stderr: r.stderr ?? "", stdout: r.stdout ?? "" };
}

function diffOne(a: string, b: string): { ok: boolean; out: string } {
  const r = spawnSync("python3", [path.join(PROJECT_ROOT, "bench", "oracle", "diff_one.py"), a, b], {
    encoding: "utf8",
    cwd: path.join(PROJECT_ROOT, "bench", "oracle"),
  });
  return { ok: r.status === 0, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

test("R4.1 smoke gate: gas-toy is 0/0/0 against the frozen oracle", () => {
  assert.ok(buildRust(), "cargo build failed");

  const outDir = mkdtempSync(path.join(tmpdir(), "r41-smoke-"));
  try {
    const emit = emitRust(outDir);
    assert.ok(
      emit.ok,
      `emitter failed; unlowered statements are a hard failure:\n${emit.stderr}`,
    );
    assert.ok(
      !/INCOMPLETE-LOWERING/.test(emit.stderr),
      `emitter reported unlowered statements:\n${emit.stderr}`,
    );

    const failures: string[] = [];
    for (const level of LEVELS) {
      const oracleFile = path.join(FIXTURES, REPO, level);
      const rustFile = path.join(outDir, REPO, level);
      if (!existsSync(oracleFile)) {
        failures.push(`${level}: oracle fixture missing`);
        continue;
      }
      if (!existsSync(rustFile)) {
        failures.push(`${level}: rust emitter produced no output (missing != pass)`);
        continue;
      }
      const d = diffOne(oracleFile, rustFile);
      if (!d.ok) failures.push(`${level}:\n${d.out.trim()}`);
    }
    assert.equal(failures.length, 0, `differential gate failed:\n${failures.join("\n")}`);
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
});

test("R4.1 smoke gate: rust emission is deterministic across runs", () => {
  assert.ok(buildRust(), "cargo build failed");

  const a = mkdtempSync(path.join(tmpdir(), "r41-det-a-"));
  const b = mkdtempSync(path.join(tmpdir(), "r41-det-b-"));
  try {
    assert.ok(emitRust(a).ok, "first run failed");
    assert.ok(emitRust(b).ok, "second run failed");
    for (const level of LEVELS) {
      const fa = path.join(a, REPO, level);
      const fb = path.join(b, REPO, level);
      assert.ok(existsSync(fa) && existsSync(fb), `${level} missing from one run`);
      assert.equal(readFileSync(fa, "utf8"), readFileSync(fb, "utf8"), `${level} differs between runs`);
    }
  } finally {
    rmSync(a, { recursive: true, force: true });
    rmSync(b, { recursive: true, force: true });
  }
});
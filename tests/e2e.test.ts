import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { runSandboxed } from "../src/sandbox/bwrap.ts";
import { runDetector } from "../src/detectors/registry.ts";
import { toolchains } from "../src/config.ts";
import { isExecutable } from "../src/util.ts";

const PROJECT_ROOT = path.resolve(new URL(import.meta.url).pathname, "..", "..");

async function withOutput<T>(fn: (out: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(path.join(tmpdir(), "sec-e2e-"));
  const out = path.join(dir, "out");
  await mkdir(out, { recursive: true });
  try {
    return await fn(out);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("sandbox: exec + filesystem containment", async () => {
  const input = path.join(PROJECT_ROOT, "tests", "fixtures", "rust-doublelock");
  const r = await runSandboxed({
    argv: ["/bin/bash", "-c", "echo ok && test ! -e /home/chain-fox && test ! -e /mnt/c && touch /work/input/nope 2>/dev/null && exit 42 || exit 0"],
    mounts: [{ host: input, sandbox: "/work/input" }],
    env: {},
    network: "none",
    limits: { memoryMb: 512, cpuSeconds: 30, pids: 64, maxFileSizeMb: 16, wallSeconds: 20 },
  });
  assert.equal(r.exitCode, 0, `stderr: ${r.stderr}`);
  assert.match(r.stdout, /ok/);
});

test("sandbox: wall-clock timeout kills the tree", async () => {
  const r = await runSandboxed({
    argv: ["/bin/bash", "-c", "sleep 30"],
    mounts: [],
    env: {},
    network: "none",
    limits: { memoryMb: 512, cpuSeconds: 60, pids: 64, maxFileSizeMb: 16, wallSeconds: 3 },
  });
  assert.equal(r.timedOut, true);
});

test("lockbud-stable finds the fixture double-lock", { skip: !(await isExecutable(toolchains.lockbudBin)) }, async () => {
  const input = path.join(PROJECT_ROOT, "tests", "fixtures", "rust-doublelock");
  await withOutput(async (out) => {
    const res = await runDetector({ detectorId: "lockbud-stable", inputDir: input, outputDir: out });
    assert.equal(res.ok, true, `stderr: ${res.stderrExcerpt}`);
    assert.equal(res.timedOut, false);
    assert.ok(res.findings.length >= 1, "expected at least one finding");
    assert.equal(res.findings[0]!.rule_id, "lockbud-stable.double-lock");
    assert.equal(res.findings[0]!.ecosystem, "rust");
    assert.equal(res.findings[0]!.location.file, "src/main.rs");
  });
});

test("pecatch finds the fixture gas issues", { skip: !(await isExecutable(path.join(toolchains.pecatchVenv, "bin", "slither"))) }, async () => {
  const input = path.join(PROJECT_ROOT, "tests", "fixtures", "solidity-gas");
  await withOutput(async (out) => {
    const res = await runDetector({ detectorId: "pecatch", inputDir: input, outputDir: out });
    assert.equal(res.ok, true, `stderr: ${res.stderrExcerpt}`);
    const checks = res.findings.map((f) => f.rule_id);
    assert.ok(checks.includes("pecatch.and-in-if"), `checks: ${checks.join(",")}`);
    assert.ok(res.findings.every((f) => f.location.file === "GasIssues.sol"), `files: ${res.findings.map((f) => f.location.file).join(",")}`);
  });
});

test("solc resolution picks the highest satisfying installed version", async () => {
  const { satisfiesPragmas, installedSolcVersions } = await import("../src/detectors/pecatch.ts");
  assert.equal(satisfiesPragmas([0, 8, 28], ["^0.8.19"]), true);
  assert.equal(satisfiesPragmas([0, 8, 4], ["^0.8.19"]), false);
  assert.equal(satisfiesPragmas([0, 8, 20], [">=0.6.0 <0.9.0"]), true);
  const installed = await installedSolcVersions();
  assert.ok(installed.length > 0, "expected cached solc versions");
});

test("fixtures directory is intact", async () => {
  await writeFile("/dev/null", ""); // sanity: fs access works
  const lock = await stat(path.join(PROJECT_ROOT, "tests", "fixtures", "rust-doublelock", "Cargo.lock"));
  assert.ok(lock.isFile());
});

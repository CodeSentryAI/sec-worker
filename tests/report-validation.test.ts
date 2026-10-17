import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { collectResults as collectLockbud } from "../src/detectors/lockbud.ts";
import { collectResults as collectPecatch } from "../src/detectors/pecatch.ts";
import { assessDetectorExecution, getDetector } from "../src/detectors/registry.ts";
import { runMultiDetectorScan, type MultiDetectorRunner } from "../src/multi_run.ts";
import type { SandboxResult } from "../src/types.ts";

const sandboxResult: SandboxResult = {
  exitCode: 0,
  signal: null,
  timedOut: false,
  stdout: "",
  stderr: "raw sandbox stderr excerpt",
  durationMs: 9,
  truncated: false,
};

async function fixture<T>(fn: (root: string, input: string, output: string) => Promise<T>): Promise<T> {
  const root = await mkdtemp(path.join(tmpdir(), "sec-report-validation-"));
  const input = path.join(root, "input");
  const output = path.join(root, "direct-output");
  await Promise.all([mkdir(input), mkdir(output)]);
  try { return await fn(root, input, output); }
  finally { await rm(root, { recursive: true, force: true }); }
}

test("both detector collectors report malformed JSON and invalid root shapes", async () => {
  await fixture(async (_root, input, output) => {
    for (const invalidJson of ["{", "{}"] as const) {
      await writeFile(path.join(output, "lockbud-report.json"), invalidJson);
      const rust = await collectLockbud(output, sandboxResult, "lockbud test");
      assert.equal(rust.findings.length, 0);
      assert.equal(rust.reportPath, path.join(output, "lockbud-report.json"));
      assert.match(rust.reportError ?? "", invalidJson === "{" ? /invalid Lockbud report/ : /findings must be an array/);

      await writeFile(path.join(output, "slither-report.json"), invalidJson);
      const solidity = await collectPecatch(output, input, sandboxResult, "pecatch test");
      assert.equal(solidity.findings.length, 0);
      assert.equal(solidity.reportPath, path.join(output, "slither-report.json"));
      assert.match(solidity.reportError ?? "", invalidJson === "{" ? /invalid Slither report/ : /detectors array/);
    }
  });
});

test("empty valid Lockbud and Slither report shapes remain parseable", async () => {
  await fixture(async (_root, input, output) => {
    await writeFile(path.join(output, "lockbud-report.json"), JSON.stringify({ findings: [] }));
    const rust = await collectLockbud(output, sandboxResult, "lockbud test");
    assert.equal(rust.reportError, undefined);

    await writeFile(path.join(output, "slither-report.json"), JSON.stringify({
      success: true, error: null, results: { detectors: [] },
    }));
    const solidity = await collectPecatch(output, input, sandboxResult, "pecatch test");
    assert.equal(solidity.reportError, undefined);

    // Slither 0.9.1 omits `results.detectors` entirely when there are no findings.
    await writeFile(path.join(output, "slither-report.json"), JSON.stringify({
      success: true, error: null, results: {},
    }));
    const clean = await collectPecatch(output, input, sandboxResult, "pecatch test");
    assert.equal(clean.reportError, undefined);
    assert.equal(clean.findings.length, 0);
  });
});

test("malformed report outcomes become ERROR/FAILED in multi-run while retaining path and reason", async () => {
  await fixture(async (root, input) => {
    for (const detectorId of ["lockbud-stable", "pecatch"] as const) {
      const runner: MultiDetectorRunner = async ({ inputDir, outputDir }) => {
        const isLockbud = detectorId === "lockbud-stable";
        const reportPath = path.join(outputDir, isLockbud ? "lockbud-report.json" : "slither-report.json");
        await writeFile(reportPath, "{}");
        const collected = isLockbud
          ? await collectLockbud(outputDir, sandboxResult, "test version")
          : await collectPecatch(outputDir, inputDir, sandboxResult, "test version");
        return {
          version: "test version",
          ok: collected.reportError === undefined,
          timedOut: false,
          exitCode: sandboxResult.exitCode,
          findings: collected.findings,
          reportPath: collected.reportPath,
          stderrExcerpt: sandboxResult.stderr,
          durationMs: sandboxResult.durationMs,
          error: collected.reportError,
        };
      };
      const result = await runMultiDetectorScan({
        inputDir: input,
        outputDir: path.join(root, `multi-${detectorId}`),
        detectorIds: [detectorId],
        runner,
      });
      assert.equal(result.aggregateStatus, "FAILED", detectorId);
      assert.equal(result.detectors[0]!.status, "ERROR", detectorId);
      assert.equal(result.detectors[0]!.rawReportPath, `detectors/${detectorId}/${detectorId === "pecatch" ? "slither-report.json" : "lockbud-report.json"}`);
      assert.match(result.detectors[0]!.error ?? "", /invalid (Lockbud|Slither) report/);
      assert.equal(result.detectors[0]!.stderrExcerpt, "raw sandbox stderr excerpt");
      assert.equal(result.findings.length, 0);
    }
  });
});

test("configured exit semantics allow Slither fail-pedantic findings but reject crashes", () => {
  for (const id of ["lockbud-stable", "pecatch"] as const) {
    const detector = getDetector(id);
    assert.equal(detector.isSuccessExitCode(0, 0), true);
    assert.equal(detector.isSuccessExitCode(1, 1), false);
    assert.equal(detector.isSuccessExitCode(null, 1), false);
    assert.equal(assessDetectorExecution(detector, { exitCode: 0, timedOut: false }, true, undefined, 1).ok, true);
    const crashedAfterWritingReport = assessDetectorExecution(detector, { exitCode: 1, timedOut: false }, true, undefined, 1);
    assert.equal(crashedAfterWritingReport.ok, false);
    assert.match(crashedAfterWritingReport.error ?? "", /exited with code 1/);
  }
  const pecatch = getDetector("pecatch");
  assert.equal(pecatch.isSuccessExitCode(255, 0), false);
  assert.equal(pecatch.isSuccessExitCode(255, 2), true);
  assert.equal(assessDetectorExecution(pecatch, { exitCode: 255, timedOut: false }, true, undefined, 2).ok, true);
  assert.equal(assessDetectorExecution(pecatch, { exitCode: 255, timedOut: false }, true, "invalid report", 2).ok, false);
});

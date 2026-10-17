import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Finding } from "../src/types.ts";
import { multiRunExitCode, runMultiDetectorScan, type MultiDetectorRunner } from "../src/multi_run.ts";
import { getDetector } from "../src/detectors/registry.ts";

async function fixture<T>(fn: (root: string, input: string) => Promise<T>): Promise<T> {
  const root = await mkdtemp(path.join(tmpdir(), "sec-multi-test-"));
  const input = path.join(root, "input");
  await mkdir(input);
  await writeFile(path.join(input, "source.sol"), "// fixture\n");
  try { return await fn(root, input); }
  finally { await rm(root, { recursive: true, force: true }); }
}

function finding(tier: "signal" | "verified", id: string): Finding {
  const base = {
    rule_id: id,
    ecosystem: "solidity" as const,
    detector: "pecatch test",
    severity: "low" as const,
    confidence: "high" as const,
    evidence_level: "static-evidence" as const,
    location: { file: "source.sol", line: 1 },
    message: id,
    raw: { id },
  };
  return tier === "signal" ? { ...base, trust_tier: "signal" } : {
    ...base,
    trust_tier: "verified",
    verification: { verifier_id: "test", verifier_version: "1", evidence: ["artifact"] },
  };
}

function outcome(findings: Finding[] = [], overrides: Partial<{
  version: string; ok: boolean; timedOut: boolean; exitCode: number | null;
  reportPath: string; stderrExcerpt: string; durationMs: number;
}> = {}) {
  return {
    version: "test-detector 1.2",
    ok: true,
    timedOut: false,
    exitCode: 0,
    findings,
    reportPath: "/raw/report.json",
    stderrExcerpt: "",
    durationMs: 12,
    ...overrides,
  };
}

test("mixed detector outcomes keep successful findings and preserve per-detector evidence", async () => {
  await fixture(async (root, input) => {
    const output = path.join(root, "out");
    const runner: MultiDetectorRunner = async ({ detectorId, outputDir }) => {
      if (detectorId === "lockbud-stable") throw new Error("prepare failed");
      await writeFile(path.join(outputDir, "raw.json"), "{}\n");
      return outcome([finding("verified", "verified-rule"), finding("signal", "signal-rule")], {
        reportPath: path.join(outputDir, "raw.json"), durationMs: 43,
      });
    };
    const result = await runMultiDetectorScan({
      inputDir: input, outputDir: output, detectorIds: ["lockbud-stable", "pecatch"], runner,
    });
    assert.equal(result.aggregateStatus, "PARTIAL");
    assert.equal(result.exitCode, 2);
    assert.deepEqual(result.findings.map((item) => item.rule_id), ["verified-rule", "signal-rule"]);
    assert.deepEqual(result.trustTierCounts, { total: 2, verified: 1, signal: 1 });
    assert.deepEqual(result.detectors.map((d) => d.status), ["ERROR", "SUCCESS"]);
    assert.equal(result.detectors[0]!.error, "prepare failed");
    assert.equal(result.detectors[1]!.version, "test-detector 1.2");
    assert.equal(result.detectors[1]!.durationMs, 43);
    assert.equal(result.detectors[1]!.rawReportPath, "detectors/pecatch/raw.json");
    assert.equal(result.detectors[1]!.reportedFindingsCount, 2);
    assert.equal(result.detectors[1]!.acceptedFindingsCount, 2);
    assert.equal(result.detectors[0]!.reportedFindingsCount, 0);
    assert.equal(result.detectors[0]!.acceptedFindingsCount, 0);
    const published = JSON.parse(await readFile(path.join(output, "report.json"), "utf8"));
    assert.equal(published.aggregateStatus, "PARTIAL");
    assert.equal(published.findings.length, 2);
    assert.equal(JSON.parse(await readFile(path.join(output, "findings.json"), "utf8")).length, 2);
  });
});

test("COMPLETE clean and findings scans retain conventional exit semantics", async () => {
  await fixture(async (root, input) => {
    const clean = await runMultiDetectorScan({
      inputDir: input, outputDir: path.join(root, "clean"), detectorIds: ["pecatch"],
      runner: async ({ outputDir }) => {
        const reportPath = path.join(outputDir, "raw.json");
        await writeFile(reportPath, "{}\n");
        return outcome([], { reportPath });
      },
    });
    const findings = await runMultiDetectorScan({
      inputDir: input, outputDir: path.join(root, "findings"), detectorIds: ["pecatch"],
      runner: async ({ outputDir }) => {
        const reportPath = path.join(outputDir, "raw.json");
        await writeFile(reportPath, "{}\n");
        return outcome([finding("signal", "one")], { reportPath });
      },
    });
    assert.equal(clean.aggregateStatus, "COMPLETE");
    assert.equal(clean.exitCode, 0);
    assert.equal(findings.aggregateStatus, "COMPLETE");
    assert.equal(findings.exitCode, 1);
    assert.equal(multiRunExitCode("FAILED", 0), 2);
    assert.equal(multiRunExitCode("PARTIAL", 5), 2);
  });
});

test("external, missing, and symlink raw reports are rejected and their findings are discarded", async () => {
  await fixture(async (root, input) => {
    const external = path.join(root, "external.json");
    await writeFile(external, "{}\n");
    for (const kind of ["external", "missing", "symlink"] as const) {
      const runner: MultiDetectorRunner = async ({ outputDir }) => {
        const realReport = path.join(outputDir, "raw.json");
        if (kind === "symlink") {
          await writeFile(realReport, "{}\n");
          await symlink(realReport, path.join(outputDir, "link.json"));
        }
        const reportPath = kind === "external" ? external
          : kind === "missing" ? realReport : path.join(outputDir, "link.json");
        return outcome([finding("signal", `reported-${kind}`)], { reportPath });
      };
      const result = await runMultiDetectorScan({
        inputDir: input, outputDir: path.join(root, `out-${kind}`), detectorIds: ["pecatch"], runner,
      });
      assert.equal(result.aggregateStatus, "FAILED", kind);
      assert.equal(result.detectors[0]!.status, "ERROR", kind);
      assert.equal(result.detectors[0]!.rawReportPath, null, kind);
      assert.match(result.detectors[0]!.error ?? "", /existing regular non-symlink file/);
      assert.equal(result.detectors[0]!.reportedFindingsCount, 1, kind);
      assert.equal(result.detectors[0]!.acceptedFindingsCount, 0, kind);
      assert.equal(result.findings.length, 0, kind);
    }
  });
});

test("detector execution is sequential, timeout is retained, and all-failed is FAILED", async () => {
  await fixture(async (root, input) => {
    let active = 0;
    let maxActive = 0;
    const result = await runMultiDetectorScan({
      inputDir: input, outputDir: path.join(root, "out"), detectorIds: ["pecatch", "lockbud-stable"],
      runner: async ({ detectorId, outputDir }) => {
        active++;
        maxActive = Math.max(active, maxActive);
        await new Promise((resolve) => setTimeout(resolve, 2));
        active--;
        const reportPath = path.join(outputDir, "raw.json");
        await writeFile(reportPath, "{}\n");
        if (detectorId === "pecatch") return outcome([finding("signal", "timed-out")], { reportPath, ok: false, timedOut: true, exitCode: null });
        return outcome([finding("signal", "failed")], { reportPath, ok: false, exitCode: 7 });
      },
    });
    assert.equal(maxActive, 1);
    assert.equal(result.aggregateStatus, "FAILED");
    assert.deepEqual(result.detectors.map((d) => d.status), ["TIMEOUT", "ERROR"]);
    assert.deepEqual(result.detectors.map((d) => d.reportedFindingsCount), [1, 1]);
    assert.deepEqual(result.detectors.map((d) => d.acceptedFindingsCount), [0, 0]);
    assert.equal(result.findings.length, 0);
  });
});

test("registry lookup rejects inherited object keys", () => {
  assert.throws(() => getDetector("toString"), /unknown detector/);
  assert.throws(() => getDetector("__proto__"), /unknown detector/);
  assert.equal(getDetector("pecatch").id, "pecatch");
});

test("per-detector output directory creation failure preserves earlier findings", async () => {
  await fixture(async (root, input) => {
    const result = await runMultiDetectorScan({
      inputDir: input,
      outputDir: path.join(root, "out"),
      detectorIds: ["pecatch", "lockbud-stable"],
      runner: async ({ outputDir }) => {
        const reportPath = path.join(outputDir, "raw.json");
        await writeFile(reportPath, "{}\n");
        await writeFile(path.join(path.dirname(outputDir), "lockbud-stable"), "block directory creation");
        return outcome([finding("signal", "first-success")], { reportPath });
      },
    });
    assert.equal(result.aggregateStatus, "PARTIAL");
    assert.deepEqual(result.findings.map((item) => item.rule_id), ["first-success"]);
    assert.deepEqual(result.detectors.map((record) => record.status), ["SUCCESS", "ERROR"]);
    assert.match(result.detectors[1]!.error ?? "", /EEXIST|not a directory/i);
  });
});

test("invalid IDs, duplicates, existing output, and overlapping output fail closed", async () => {
  await fixture(async (root, input) => {
    const runner: MultiDetectorRunner = async () => outcome();
    const duplicateOutput = path.join(root, "duplicate");
    await assert.rejects(runMultiDetectorScan({ inputDir: input, outputDir: duplicateOutput,
      detectorIds: ["pecatch", "pecatch"], runner }), /duplicate/);
    assert.deepEqual(await readdir(root), ["input"]);
    await assert.rejects(runMultiDetectorScan({ inputDir: input, outputDir: path.join(root, "unknown"),
      detectorIds: ["missing"], runner }), /unknown detector/);
    await assert.rejects(runMultiDetectorScan({ inputDir: input, outputDir: input,
      detectorIds: ["pecatch"], runner }), /must not already exist/);
    await assert.rejects(runMultiDetectorScan({ inputDir: input, outputDir: path.join(input, "nested"),
      detectorIds: ["pecatch"], runner }), /must not overlap/);
    await assert.rejects(runMultiDetectorScan({ inputDir: input, outputDir: root,
      detectorIds: ["pecatch"], runner }), /must not already exist/);
  });
});

test("report publication failure rejects and removes canonical partial report files", async () => {
  await fixture(async (root, input) => {
    const output = path.join(root, "out");
    let writes = 0;
    await assert.rejects(runMultiDetectorScan({
      inputDir: input, outputDir: output, detectorIds: ["pecatch"], runner: async () => outcome(),
      writeReport: async (filePath, value) => {
        writes++;
        if (writes === 2) throw new Error("disk full");
        await writeFile(filePath, JSON.stringify(value));
      },
    }), /failed to publish.*disk full/);
    assert.equal(await readdir(output).then((names) => names.some((n) => ["findings.json", "run.json", "report.json"].includes(n))), false);
  });
});

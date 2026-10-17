import { lstat, mkdir, realpath, rename, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { runDetector, getDetector, type RunDetectorOutcome } from "./detectors/registry.ts";
import type { Finding } from "./types.ts";

export type MultiDetectorStatus = "SUCCESS" | "ERROR" | "TIMEOUT";
export type MultiAggregateStatus = "COMPLETE" | "PARTIAL" | "FAILED";

export type MultiDetectorRunner = (opts: {
  detectorId: string;
  inputDir: string;
  outputDir: string;
}) => Promise<RunDetectorOutcome>;

export interface MultiRunOptions {
  inputDir: string;
  outputDir: string;
  detectorIds: string[];
  runner?: MultiDetectorRunner;
  writeReport?: (filePath: string, value: unknown) => Promise<void>;
}

interface DetectorRecord {
  detectorId: string;
  status: MultiDetectorStatus;
  version: string | null;
  ok: boolean;
  runnerOk: boolean | null;
  timedOut: boolean;
  exitCode: number | null;
  durationMs: number;
  rawReportPath: string | null;
  stderrExcerpt: string;
  error?: string;
  reportedFindingsCount: number;
  acceptedFindingsCount: number;
  verifiedCount: number;
  signalCount: number;
}

function isWithin(parent: string, child: string): boolean {
  const rel = path.relative(parent, child);
  return rel === "" || (!rel.startsWith(`..${path.sep}`) && rel !== ".." && !path.isAbsolute(rel));
}

async function validatedReportPath(outputRoot: string, detectorOutput: string, reportPath: string): Promise<string | null> {
  try {
    const reportAbsolute = path.resolve(reportPath);
    const rootStat = await lstat(detectorOutput);
    const reportStat = await lstat(reportAbsolute);
    if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || !reportStat.isFile() || reportStat.isSymbolicLink()) return null;
    const [canonicalOutput, canonicalDetector, canonicalReport] = await Promise.all([
      realpath(outputRoot), realpath(detectorOutput), realpath(reportAbsolute),
    ]);
    const detectorRelative = path.relative(canonicalDetector, canonicalReport);
    if (detectorRelative === "" || detectorRelative === ".." || detectorRelative.startsWith(`..${path.sep}`)
      || path.isAbsolute(detectorRelative)) return null;
    const outputRelative = path.relative(canonicalOutput, canonicalReport);
    if (outputRelative === "" || outputRelative === ".." || outputRelative.startsWith(`..${path.sep}`)
      || path.isAbsolute(outputRelative)) return null;
    return outputRelative.split(path.sep).join("/");
  } catch {
    return null;
  }
}

/** Resolve a not-yet-created path through its nearest existing ancestor. */
async function canonicalProspectivePath(target: string): Promise<string> {
  const absolute = path.resolve(target);
  const missing: string[] = [];
  let cursor = absolute;
  while (true) {
    try {
      await lstat(cursor);
      const base = await realpath(cursor);
      return path.join(base, ...missing.reverse());
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      const parent = path.dirname(cursor);
      if (parent === cursor) throw new Error(`cannot resolve output path: ${target}`);
      missing.push(path.basename(cursor));
      cursor = parent;
    }
  }
}

async function writeJsonAtomic(filePath: string, value: unknown): Promise<void> {
  const tempPath = `${filePath}.tmp-${process.pid}-${Math.random().toString(16).slice(2)}`;
  try {
    await writeFile(tempPath, `${JSON.stringify(value, null, 2)}\n`, { flag: "wx" });
    await rename(tempPath, filePath);
  } catch (error) {
    await rm(tempPath, { force: true }).catch(() => undefined);
    throw error;
  }
}

export function multiRunExitCode(status: MultiAggregateStatus, findingsCount: number): number {
  if (status !== "COMPLETE") return 2;
  return findingsCount > 0 ? 1 : 0;
}

/** Run requested detectors sequentially in isolated, fresh child output directories. */
export async function runMultiDetectorScan(options: MultiRunOptions) {
  const ids = options.detectorIds;
  if (!Array.isArray(ids) || ids.length === 0 || ids.some((id) => typeof id !== "string" || !id.trim())) {
    throw new Error("at least one non-empty detector ID is required");
  }
  if (new Set(ids).size !== ids.length) throw new Error("duplicate detector IDs are not allowed");
  // Validate all IDs before creating output or launching any detector.
  for (const id of ids) getDetector(id);

  const inputStat = await stat(options.inputDir).catch(() => null);
  if (!inputStat?.isDirectory()) throw new Error(`input is not a directory: ${options.inputDir}`);
  const inputCanonical = await realpath(options.inputDir);
  const outputAbsolute = path.resolve(options.outputDir);
  if (await lstat(outputAbsolute).then(() => true).catch(() => false)) {
    throw new Error(`output directory must not already exist: ${options.outputDir}`);
  }
  const outputCanonical = await canonicalProspectivePath(outputAbsolute);
  if (isWithin(inputCanonical, outputCanonical) || isWithin(outputCanonical, inputCanonical)) {
    throw new Error("input and output directories must not overlap");
  }

  await mkdir(outputAbsolute, { recursive: false });
  const runner = options.runner ?? runDetector;
  const records: DetectorRecord[] = [];
  const allFindings: Finding[] = [];
  const startedAt = new Date().toISOString();

  for (const detectorId of ids) {
    const detectorOutput = path.join(outputAbsolute, "detectors", detectorId);
    const started = Date.now();
    try {
      await mkdir(detectorOutput, { recursive: true });
      const outcome = await runner({ detectorId, inputDir: inputCanonical, outputDir: detectorOutput });
      const rawReportPath = await validatedReportPath(outputAbsolute, detectorOutput, outcome.reportPath);
      const status: MultiDetectorStatus = !rawReportPath
        ? "ERROR"
        : outcome.timedOut ? "TIMEOUT" : outcome.ok ? "SUCCESS" : "ERROR";
      const acceptedFindings = status === "SUCCESS" ? outcome.findings : [];
      allFindings.push(...acceptedFindings);
      records.push({
        detectorId,
        status,
        version: outcome.version,
        ok: status === "SUCCESS",
        runnerOk: outcome.ok,
        timedOut: outcome.timedOut,
        exitCode: outcome.exitCode,
        durationMs: outcome.durationMs,
        rawReportPath,
        stderrExcerpt: outcome.stderrExcerpt,
        ...(outcome.error ? { error: outcome.error } : !rawReportPath
          ? { error: "detector report must be an existing regular non-symlink file beneath its own output directory" }
          : status === "ERROR" ? { error: "detector runner reported failure" } : {}),
        reportedFindingsCount: outcome.findings.length,
        acceptedFindingsCount: acceptedFindings.length,
        verifiedCount: acceptedFindings.filter((finding) => finding.trust_tier === "verified").length,
        signalCount: acceptedFindings.filter((finding) => finding.trust_tier === "signal").length,
      });
    } catch (error) {
      records.push({
        detectorId,
        status: "ERROR",
        version: null,
        ok: false,
        runnerOk: null,
        timedOut: false,
        exitCode: null,
        durationMs: Date.now() - started,
        rawReportPath: null,
        stderrExcerpt: "",
        error: error instanceof Error ? error.message : String(error),
        reportedFindingsCount: 0,
        acceptedFindingsCount: 0,
        verifiedCount: 0,
        signalCount: 0,
      });
    }
  }

  const successes = records.filter((record) => record.status === "SUCCESS").length;
  const aggregateStatus: MultiAggregateStatus = successes === records.length
    ? "COMPLETE"
    : successes > 0 ? "PARTIAL" : "FAILED";
  const trustTierCounts = {
    total: allFindings.length,
    verified: allFindings.filter((finding) => finding.trust_tier === "verified").length,
    signal: allFindings.filter((finding) => finding.trust_tier === "signal").length,
  };
  const finishedAt = new Date().toISOString();
  const run = {
    schemaVersion: 1,
    inputDir: inputCanonical,
    outputDir: outputAbsolute,
    detectorIds: ids,
    aggregateStatus,
    exitCode: multiRunExitCode(aggregateStatus, allFindings.length),
    detectorCount: records.length,
    succeededCount: successes,
    failedCount: records.length - successes,
    trustTierCounts,
    startedAt,
    finishedAt,
    durationMs: records.reduce((total, record) => total + record.durationMs, 0),
    detectors: records,
  };

  // Publish metadata last. If any report write fails, remove all canonical report
  // files so callers cannot mistake a partially published scan for a complete one.
  const reportFiles = ["findings.json", "run.json", "report.json"].map((name) => path.join(outputAbsolute, name));
  const publish = options.writeReport ?? writeJsonAtomic;
  try {
    await publish(reportFiles[0]!, allFindings);
    await publish(reportFiles[1]!, run);
    await publish(reportFiles[2]!, { ...run, findings: allFindings });
  } catch (error) {
    await Promise.all(reportFiles.map((file) => rm(file, { force: true }).catch(() => undefined)));
    throw new Error(`failed to publish multi-detector reports: ${error instanceof Error ? error.message : String(error)}`);
  }
  return { ...run, findings: allFindings };
}

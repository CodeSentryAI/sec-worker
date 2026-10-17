/**
 * Internal repo URL scan implementation.
 *
 * Flow: canonicalize the URL → clone shallow into a private scratch dir → hand
 * the working tree to the existing sandboxed detector pipeline → write
 * artifacts to the caller's output dir → delete the scratch tree.
 *
 * The scratch tree is removed on every path (success, detector failure, clone
 * failure), because it is attacker-controlled source. Output artifacts live
 * outside the scratch tree and are never touched by cleanup.
 */
import { mkdir, mkdtemp, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { parseRepoUrl, type RepoRef } from "../repo_url.ts";
import { CloneError, type CloneRunner } from "../clone.ts";
import { runDetector } from "../detectors/registry.ts";
import { aggregateRunStatus } from "../run_status.ts";

/** Internal dependency-injection seam; not part of the production API. */
export interface InternalScanRepoOptions {
  /** The user-supplied repository URL. */
  repoUrl: string;
  /** Where run.json / findings.json / raw detector reports are written. */
  outputDir: string;
  /** Detector id passed through to the existing pipeline. */
  detectorId: string;
  checkers?: string[];
  /** Root for the private scratch dir; defaults to the OS temp dir. */
  scratchRoot?: string;
  /** Internal test seam only; never accepted by the public production API. */
  cloneRunner?: CloneRunner;
  /** Internal test seam: stands in for the sandboxed detector pipeline. */
  runPipeline?: typeof runDetector;
  /** Internal test seam: lets cleanup failure behavior be checked. */
  removeScratch?: (dir: string) => Promise<void>;
}

export interface ScanRepoResult {
  repo: RepoRef;
  commit: string;
  /** Absolute path of the output dir (outside the scratch tree). */
  outputDir: string;
  findingsPath: string;
  runPath: string;
  ok: boolean;
  exitCode: number;
  findingsCount: number;
  verifiedCount: number;
  signalCount: number;
  /** True only after the scratch tree has been successfully deleted. */
  sourceRemoved: boolean;
}

export class OutputOverlapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OutputOverlapError";
  }
}

export class StaleOutputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StaleOutputError";
  }
}

/**
 * Refuse an output dir that overlaps the scratch tree in either direction.
 *
 * Both directions are unsafe: writing results into the scratch tree would have
 * them deleted with the source, and a scratch tree inside the output dir would
 * leave untrusted source sitting in the artifact directory after cleanup fails.
 */
export function assertNoOutputOverlap(outputDir: string, scratchDir: string): void {
  const out = path.resolve(outputDir);
  const scratch = path.resolve(scratchDir);
  const containedIn = (parent: string, child: string): boolean => {
    const rel = path.relative(parent, child);
    return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
  };
  if (containedIn(scratch, out)) {
    throw new OutputOverlapError(`output dir is inside the temporary source tree: ${out}`);
  }
  if (containedIn(out, scratch)) {
    throw new OutputOverlapError(`output dir contains the temporary source tree: ${out}`);
  }
}

/** Refuse old artifacts so a run can never silently mix with a prior scan. */
export async function assertFreshOutputDir(outputDir: string): Promise<void> {
  const entries = await readdir(outputDir);
  if (entries.length > 0) {
    throw new StaleOutputError(`output directory is not empty; choose a fresh directory: ${outputDir}`);
  }
}

/**
 * Run the repo-url flow. Returns normally for anything the pipeline reported
 * (including detector failures, which come back as ok:false); throws only for
 * rejected input, unsafe output placement, and clone failures.
 */
export async function scanRepoUrlCore(opts: InternalScanRepoOptions): Promise<ScanRepoResult> {
  const repo = parseRepoUrl(opts.repoUrl);
  const clone = opts.cloneRunner;
  const pipeline = opts.runPipeline ?? runDetector;
  const removeScratch = opts.removeScratch ?? ((dir) => rm(dir, { recursive: true, force: true }));

  const outputAbs = path.resolve(opts.outputDir);
  const scratchRoot = path.resolve(opts.scratchRoot ?? tmpdir());

  // Reserve the scratch path before cloning so overlap can be judged against
  // the real directory, not a guess.
  await mkdir(scratchRoot, { recursive: true });
  const scratch = await mkdtemp(path.join(scratchRoot, "sec-repo-"));
  let failed = false;
  let failure: unknown;
  let failureStage: "acquisition" | "analysis" = "acquisition";
  let preflightSucceeded = false;
  let clonedCommit: string | null = null;
  let result: ScanRepoResult | undefined;
  let runRecord: Record<string, unknown> | undefined;
  let runPath: string | undefined;
  try {
    // This check belongs inside the cleanup scope because the temporary path
    // already exists and must be removed even when placement is rejected.
    assertNoOutputOverlap(outputAbs, scratch);
    await mkdir(outputAbs, { recursive: true });
    // Resolve symlinked ancestors after the output exists; lexical path checks
    // alone can miss an output alias into the private scratch tree.
    assertNoOutputOverlap(await realpath(outputAbs), await realpath(scratch));
    await assertFreshOutputDir(outputAbs);
    preflightSucceeded = true;

    const checkout = path.join(scratch, "src");
    const findingsPath = path.join(outputAbs, "findings.json");
    runPath = path.join(outputAbs, "run.json");
    if (!clone) {
      throw new CloneError(
        "quota-enforcing acquisition provider is not configured",
        "no explicit clone runner was supplied",
        { reason: "QUOTA_UNAVAILABLE" },
      );
    }
    const cloned = await clone(repo, checkout);
    clonedCommit = cloned.commit;
    failureStage = "analysis";
    const outcome = await pipeline({
      detectorId: opts.detectorId,
      inputDir: checkout,
      outputDir: outputAbs,
      ...(opts.checkers ? { checkers: opts.checkers } : {}),
    });

    const status = aggregateRunStatus(
      { ok: outcome.ok, timedOut: outcome.timedOut, exitCode: outcome.exitCode, durationMs: outcome.durationMs },
      undefined,
      outcome.findings.length,
    );

    await writeFile(findingsPath, JSON.stringify(outcome.findings, null, 2));
    runRecord = {
      source: {
        kind: "github-repo",
        url: repo.canonicalUrl,
        host: repo.host,
        owner: repo.owner,
        repo: repo.repo,
        commit: cloned.commit,
        depth: 1,
        submodules: false,
      },
      detector: opts.detectorId,
      detectorVersion: outcome.version,
      ...status,
      findingsCount: outcome.findings.length,
      verifiedCount: outcome.findings.filter((f) => f.trust_tier === "verified").length,
      signalCount: outcome.findings.filter((f) => f.trust_tier === "signal").length,
      reportPath: outcome.reportPath,
      finishedAt: new Date().toISOString(),
    };

    result = {
      repo,
      commit: cloned.commit,
      outputDir: outputAbs,
      findingsPath,
      runPath,
      ok: status.ok,
      exitCode: status.exitCode,
      findingsCount: outcome.findings.length,
      verifiedCount: outcome.findings.filter((f) => f.trust_tier === "verified").length,
      signalCount: outcome.findings.filter((f) => f.trust_tier === "signal").length,
      // Flip only after successful removal below.
      sourceRemoved: false,
    };
  } catch (e) {
    failed = true;
    failure = e;
  }

  let cleanupFailed = false;
  let cleanupFailure: unknown;
  try {
    await removeScratch(scratch);
  } catch (e) {
    cleanupFailed = true;
    cleanupFailure = e;
    console.error(`warning: could not remove temporary source ${scratch}: ${e instanceof Error ? e.message : e}`);
  }

  if (failed) {
    if (preflightSucceeded && runPath) {
      const errorSummary = summarizeError(failure);
      const cloneError = failure instanceof CloneError ? failure : undefined;
      const resourceLimit = cloneError?.reason === "RESOURCE_LIMIT"
        && cloneError.resource !== undefined
        && cloneError.limit !== undefined
        && cloneError.observed !== undefined
        ? { resource: cloneError.resource, limit: cloneError.limit, observed: cloneError.observed }
        : undefined;
      // Acquisition failures never have detector findings. Always emit the
      // empty canonical artifact so consumers cannot mistake a partial clone
      // for a successful scan with missing output.
      try {
        await writeFile(path.join(outputAbs, "findings.json"), "[]\n");
      } catch (writeFailure) {
        throw new AggregateError(
          [failure, ...(cleanupFailed ? [cleanupFailure] : []), writeFailure],
          "repo acquisition/analysis failed and empty findings metadata could not be written",
        );
      }
      const record = {
        status: failureStage === "acquisition" ? "ACQUISITION_FAILED" : "ANALYSIS_FAILED",
        source: {
          kind: "github-repo",
          url: repo.canonicalUrl,
          host: repo.host,
          owner: repo.owner,
          repo: repo.repo,
          commit: clonedCommit,
          depth: clonedCommit ? 1 : null,
          submodules: clonedCommit ? false : null,
          sourceRetained: cleanupFailed ? null : false,
          sourceRemoved: !cleanupFailed,
        },
        sourceCleanup: cleanupFailed
          ? { status: "failed", error: summarizeError(cleanupFailure) }
          : { status: "removed" },
        detector: opts.detectorId,
        ok: false,
        exitCode: 2,
        ...(failureStage === "acquisition" ? { reason: cloneError?.reason ?? "CLONE_FAILED" } : {}),
        ...(resourceLimit ? { resourceLimit } : {}),
        errorSummary,
        finishedAt: new Date().toISOString(),
      };
      try {
        await writeFile(runPath, JSON.stringify(record, null, 2));
      } catch (writeFailure) {
        throw new AggregateError(
          [failure, ...(cleanupFailed ? [cleanupFailure] : []), writeFailure],
          `repo ${record.status.toLowerCase()} and failure metadata could not be written`,
        );
      }
    }
    if (cleanupFailed) {
      throw new AggregateError(
        [failure, cleanupFailure],
        `repo scan failed (${failure instanceof Error ? failure.message : String(failure)}) and temporary source cleanup failed`,
      );
    }
    throw failure;
  }
  if (!result || !runRecord || !runPath) throw new Error("repo scan did not produce a result");

  if (cleanupFailed) {
    const cleanupMessage = cleanupFailure instanceof Error ? cleanupFailure.message : String(cleanupFailure);
    const source = runRecord.source as Record<string, unknown>;
    source.sourceRetained = null;
    source.sourceRemoved = false;
    runRecord.sourceCleanup = { status: "failed", error: cleanupMessage };
    runRecord.status = "CLEANUP_FAILED";
    runRecord.errorSummary = `temporary source cleanup failed: ${cleanupMessage}`.slice(0, 2000);
    runRecord.ok = false;
    runRecord.exitCode = 2;
    try {
      await writeFile(runPath, JSON.stringify(runRecord, null, 2));
    } catch (writeFailure) {
      throw new AggregateError(
        [cleanupFailure, writeFailure],
        `temporary source cleanup failed (${cleanupMessage}) and failure metadata could not be written`,
      );
    }
    throw new Error(`scan completed but temporary source cleanup failed; sourceRemoved=false: ${cleanupFailure instanceof Error ? cleanupFailure.message : cleanupFailure}`, { cause: cleanupFailure });
  }

  const source = runRecord.source as Record<string, unknown>;
  source.sourceRetained = false;
  source.sourceRemoved = true;
  runRecord.sourceCleanup = { status: "removed" };
  await writeFile(runPath, JSON.stringify(runRecord, null, 2));
  result.sourceRemoved = true;
  return result;
}

function summarizeError(error: unknown): string {
  const summary = error instanceof Error ? error.message : String(error);
  return summary.replace(/[\r\n\t]+/g, " ").slice(0, 2000);
}

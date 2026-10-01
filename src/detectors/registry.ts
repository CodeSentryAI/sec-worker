import { DEFAULT_LIMITS } from "../config.ts";
import type { SandboxRequest, SandboxResult } from "../types.ts";
import { runSandboxed } from "../sandbox/bwrap.ts";
import * as lockbud from "./lockbud.ts";
import * as pecatch from "./pecatch.ts";
import path from "node:path";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";

export interface Detector {
  id: "lockbud-stable" | "pecatch";
  ecosystem: "rust" | "solidity";
  version(): Promise<string>;
  /** Trusted host-side preparation (solc resolution, cargo lock/cache staging). */
  prepare?(inputDir: string, stagingDir: string): Promise<unknown>;
  buildSandboxRequest(inputDir: string, outputDir: string, stagingDir: string, prep: unknown, checkers?: string[]): SandboxRequest;
  collectResults(outputDir: string, inputDir: string, result: SandboxResult, version: string): Promise<{ findings: import("../types.ts").Finding[]; reportPath: string }>;
}

const lockbudDetector: Detector = {
  id: "lockbud-stable",
  ecosystem: "rust",
  version: lockbud.detectorVersion,
  prepare: (input, staging) => lockbud.prepare(input, staging),
  buildSandboxRequest: (input, output, staging, prep) => lockbud.buildSandboxRequest(input, output, staging, prep as lockbud.LockbudPrepare),
  collectResults: async (output, _input, result, version) => {
    const out = await lockbud.collectResults(output, result, version);
    return { findings: out.findings, reportPath: out.reportPath };
  },
};

const pecatchDetector: Detector = {
  id: "pecatch",
  ecosystem: "solidity",
  version: pecatch.detectorVersion,
  prepare: (input, _staging) => pecatch.prepare(input),
  buildSandboxRequest: (input, output, _staging, prep, checkers) =>
    pecatch.buildSandboxRequest(input, output, prep as pecatch.PecatchPrepare, checkers ?? [...DEFAULT_PECATCH_CHECKERS]),
  collectResults: async (output, input, result, version) => {
    const out = await pecatch.collectResults(output, input, result, version);
    return { findings: out.findings, reportPath: out.reportPath };
  },
};

const DEFAULT_PECATCH_CHECKERS = ["and-in-if", "implicit-return", "redundant-sload", "bool", "unchecked", "mem-call", "alloc-in-loop", "loop-invariant"];

export const DETECTORS: Record<string, Detector> = {
  "lockbud-stable": lockbudDetector,
  pecatch: pecatchDetector,
};

export function getDetector(id: string): Detector {
  const d = DETECTORS[id];
  if (!d) throw new Error(`unknown detector '${id}'; available: ${Object.keys(DETECTORS).join(", ")}`);
  return d;
}

export interface RunDetectorOptions {
  detectorId: string;
  inputDir: string;
  outputDir: string;
  checkers?: string[];
  keepStaging?: boolean;
}

export interface RunDetectorOutcome {
  version: string;
  ok: boolean;
  timedOut: boolean;
  exitCode: number | null;
  findings: import("../types.ts").Finding[];
  reportPath: string;
  stderrExcerpt: string;
  durationMs: number;
  stagingDir?: string;
}

/** Full pipeline for one detector run: prepare (trusted) -> sandbox run -> normalize. */
export async function runDetector(opts: RunDetectorOptions): Promise<RunDetectorOutcome> {
  const detector = getDetector(opts.detectorId);

  const stagingDir = await mkdtemp(path.join(tmpdir(), "sec-task-"));
  const version = await detector.version();

  try {
    const prep = (await detector.prepare?.(opts.inputDir, stagingDir)) ?? null;
    const req = detector.buildSandboxRequest(opts.inputDir, opts.outputDir, stagingDir, prep, opts.checkers);
    const result = await runSandboxed(req);
    const { findings, reportPath } = await detector.collectResults(opts.outputDir, opts.inputDir, result, version);

    const reportExists = await stat(reportPath).then(() => true).catch(() => false);
    const ok = !result.timedOut && reportExists;
    return {
      version,
      ok,
      timedOut: result.timedOut,
      exitCode: result.exitCode,
      findings,
      reportPath,
      stderrExcerpt: result.stderr.slice(-4000),
      durationMs: result.durationMs,
      stagingDir: opts.keepStaging ? stagingDir : undefined,
    };
  } finally {
    if (!opts.keepStaging) await rm(stagingDir, { recursive: true, force: true });
  }
}

export { DEFAULT_LIMITS };

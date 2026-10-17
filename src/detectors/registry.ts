import { DEFAULT_LIMITS } from "../config.ts";
import type { SandboxRequest, SandboxResult } from "../types.ts";
import { runSandboxed } from "../sandbox/bwrap.ts";
import * as lockbud from "./lockbud.ts";
import * as pecatch from "./pecatch.ts";
import path from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";

export interface Detector {
  id: "lockbud-stable" | "pecatch";
  ecosystem: "rust" | "solidity";
  version(): Promise<string>;
  /** Trusted host-side preparation (solc resolution, cargo lock/cache staging). */
  prepare?(inputDir: string, stagingDir: string): Promise<unknown>;
  buildSandboxRequest(inputDir: string, outputDir: string, stagingDir: string, prep: unknown, checkers?: string[]): SandboxRequest;
  /** Success exit codes for this exact adapter command. Findings themselves do not imply failure. */
  isSuccessExitCode(exitCode: number | null, findingCount: number): boolean;
  collectResults(outputDir: string, inputDir: string, result: SandboxResult, version: string): Promise<{
    findings: import("../types.ts").Finding[];
    reportPath: string;
    reportError?: string;
  }>;
}

const lockbudDetector: Detector = {
  id: "lockbud-stable",
  ecosystem: "rust",
  // The adapter runs `cargo check` without `--allow-failure`; reported lints are
  // warnings in the report, while a nonzero status means cargo/analyzer failed.
  isSuccessExitCode: (code) => code === 0,
  version: lockbud.detectorVersion,
  prepare: (input, staging) => lockbud.prepare(input, staging),
  buildSandboxRequest: (input, output, staging, prep) => lockbud.buildSandboxRequest(input, output, staging, prep as lockbud.LockbudPrepare),
  collectResults: async (output, _input, result, version) => {
    const out = await lockbud.collectResults(output, result, version);
    return { findings: out.findings, reportPath: out.reportPath, reportError: out.reportError };
  },
};

const pecatchDetector: Detector = {
  id: "pecatch",
  ecosystem: "solidity",
  // Slither 0.9.1 defaults fail_pedantic=true. Its main_impl exits -1 (255)
  // when findings exist; accept that code only alongside a validated nonempty
  // report. Other nonzero codes indicate output or execution failure.
  isSuccessExitCode: (code, findingCount) => code === 0 || (code === 255 && findingCount > 0),
  version: pecatch.detectorVersion,
  prepare: (input, _staging) => pecatch.prepare(input),
  buildSandboxRequest: (input, output, _staging, prep, checkers) =>
    pecatch.buildSandboxRequest(input, output, prep as pecatch.PecatchPrepare, checkers ?? [...DEFAULT_PECATCH_CHECKERS]),
  collectResults: async (output, input, result, version) => {
    const out = await pecatch.collectResults(output, input, result, version);
    return { findings: out.findings, reportPath: out.reportPath, reportError: out.reportError };
  },
};

const DEFAULT_PECATCH_CHECKERS = ["and-in-if", "implicit-return", "redundant-sload", "bool", "unchecked", "mem-call", "alloc-in-loop", "loop-invariant"];

export const DETECTORS: Record<string, Detector> = {
  "lockbud-stable": lockbudDetector,
  pecatch: pecatchDetector,
};

export function getDetector(id: string): Detector {
  if (!Object.hasOwn(DETECTORS, id)) {
    throw new Error(`unknown detector '${id}'; available: ${Object.keys(DETECTORS).join(", ")}`);
  }
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
  error?: string;
  durationMs: number;
  stagingDir?: string;
}

export function assessDetectorExecution(
  detector: Pick<Detector, "isSuccessExitCode">,
  result: Pick<SandboxResult, "exitCode" | "timedOut">,
  reportExists: boolean,
  reportError?: string,
  findingCount = 0,
): { ok: boolean; error?: string } {
  const exitCodeOk = detector.isSuccessExitCode(result.exitCode, findingCount);
  const errors = [
    ...(reportError ? [reportError] : []),
    ...(!reportExists ? ["detector report is missing"] : []),
    ...(!exitCodeOk ? [`detector process exited with code ${String(result.exitCode)}`] : []),
  ];
  return {
    ok: !result.timedOut && reportExists && !reportError && exitCodeOk,
    ...(errors.length > 0 ? { error: errors.join("; ") } : {}),
  };
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
    const { findings, reportPath, reportError } = await detector.collectResults(opts.outputDir, opts.inputDir, result, version);

    // Collectors only leave reportError unset after the secure no-follow open,
    // parse, and schema validation succeeds. Do not stat the pathname here:
    // stat follows symlinks and could inspect an attacker-selected host target.
    const reportValidated = reportError === undefined;
    const status = assessDetectorExecution(detector, result, reportValidated, reportError, findings.length);
    return {
      version,
      ok: status.ok,
      timedOut: result.timedOut,
      exitCode: result.exitCode,
      findings,
      reportPath,
      stderrExcerpt: result.stderr.slice(-4000),
      ...(status.error ? { error: status.error } : {}),
      durationMs: result.durationMs,
      stagingDir: opts.keepStaging ? stagingDir : undefined,
    };
  } finally {
    if (!opts.keepStaging) await rm(stagingDir, { recursive: true, force: true });
  }
}

export { DEFAULT_LIMITS };

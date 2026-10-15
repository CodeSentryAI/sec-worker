import type { Erc20CompileMetadata } from "./verified/erc20_compile.ts";

export interface DetectorRunStatus {
  ok: boolean;
  timedOut: boolean;
  exitCode: number;
  durationMs: number;
}

/** Combine detector and optional verifier outcomes without hiding either stage. */
export function aggregateRunStatus(
  detector: DetectorRunStatus,
  erc20Abi: Pick<Erc20CompileMetadata, "status" | "timed_out" | "duration_ms"> | undefined,
  findingsCount: number,
) {
  const ok = detector.ok && (!erc20Abi || erc20Abi.status === "complete");
  return {
    ok,
    detectorOk: detector.ok,
    detectorExitCode: detector.exitCode,
    timedOut: detector.timedOut || (erc20Abi?.timed_out ?? false),
    detectorTimedOut: detector.timedOut,
    detectorDurationMs: detector.durationMs,
    erc20AbiDurationMs: erc20Abi?.duration_ms,
    durationMs: detector.durationMs + (erc20Abi?.duration_ms ?? 0),
    exitCode: !ok ? 2 : findingsCount > 0 ? 1 : 0,
  };
}

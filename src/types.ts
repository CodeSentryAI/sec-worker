export interface SandboxLimits {
  /** RLIMIT_AS in megabytes (virtual address space). */
  memoryMb: number;
  /** RLIMIT_CPU: cumulative CPU seconds across the process tree. */
  cpuSeconds: number;
  /** RLIMIT_NPROC: max processes for the sandbox user. */
  pids: number;
  /** RLIMIT_FSIZE: max size of any single written file, in megabytes. */
  maxFileSizeMb: number;
  /** Wall-clock kill switch enforced by the runner (SIGKILL to the process group). */
  wallSeconds: number;
  /** Cap on captured stdout/stderr, in bytes. */
  outputCapBytes?: number;
}

export type SandboxNetwork = "none" | "host";

export interface SandboxMount {
  host: string;
  sandbox: string;
  rw?: boolean;
  /** Use --*-bind-try (tolerate missing host path) instead of failing. */
  optional?: boolean;
}

export interface SandboxRequest {
  /** Command to execute inside the sandbox (already absolute where possible). */
  argv: string[];
  mounts: SandboxMount[];
  env: Record<string, string>;
  cwd?: string;
  network?: SandboxNetwork;
  limits: SandboxLimits;
}

export interface SandboxResult {
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
  stdout: string;
  stderr: string;
  durationMs: number;
  /** True when stdout or stderr was truncated by the capture cap. */
  truncated: boolean;
}

export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type Confidence = "high" | "medium" | "low";

export interface FindingLocation {
  file: string;
  line?: number;
  column?: number;
}

/**
 * The single normalized finding format every detector must emit.
 * The LLM later consumes these as evidence, never as "verified bug".
 */
export interface Finding {
  rule_id: string;
  ecosystem: "rust" | "solidity";
  detector: string;
  severity: Severity;
  confidence: Confidence;
  evidence_level: "static-evidence";
  location: FindingLocation;
  message: string;
  raw: unknown;
}

export interface DetectorRunResult {
  detector: string;
  detectorVersion: string;
  /** The detector process ran and produced parseable output. */
  ok: boolean;
  findings: Finding[];
  exitCode: number | null;
  timedOut: boolean;
  stderrExcerpt?: string;
  durationMs: number;
  /** Paths (inside the task output dir) of raw artifacts kept for evidence. */
  rawPaths: string[];
}

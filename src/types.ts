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
export type TrustTier = "verified" | "signal";

export interface FindingLocation {
  file: string;
  line?: number;
  column?: number;
}

/** Stable SARIF rule namespace. Optional to keep existing detector output compatible. */
export interface FindingRuleComponent {
  kind: "driver" | "extension";
  name: string;
  guid?: string;
  /** Tool extension index, used to disambiguate equal names when GUIDs are absent. */
  component_index?: number;
  /** Descriptor index within the component, distinguishing duplicate rule IDs. */
  descriptor_index?: number;
  descriptor_guid?: string;
}

/** Common report data shared by verified results and unverified signals. */
interface FindingBase {
  rule_id: string;
  /** Present for imported SARIF so equal rule IDs from different components stay distinct. */
  rule_component?: FindingRuleComponent;
  ecosystem: "rust" | "solidity";
  detector: string;
  severity: Severity;
  confidence: Confidence;
  /** Evidence produced by the source detector; this alone does not mean verified. */
  evidence_level: "static-evidence";
  location: FindingLocation;
  message: string;
  raw: unknown;
}

/** A broad candidate from a detector that has not passed a product verifier. */
export interface SecuritySignal extends FindingBase {
  trust_tier: "signal";
  verification?: never;
}

/** A result promoted by a named validator with retained, inspectable evidence. */
export interface VerifiedFinding extends FindingBase {
  trust_tier: "verified";
  verification: {
    verifier_id: string;
    verifier_version: string;
    evidence: [string, ...string[]];
  };
}

/** The discriminant prevents a verified result from omitting its validation record. */
export type Finding = SecuritySignal | VerifiedFinding;

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

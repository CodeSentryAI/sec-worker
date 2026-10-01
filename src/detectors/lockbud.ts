import { spawn } from "node:child_process";
import { mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import { toolchains, DEFAULT_LIMITS } from "../config.ts";
import type { SandboxMount, SandboxRequest, SandboxResult, Finding, Severity, Confidence } from "../types.ts";
import { isExecutable, readJson } from "../util.ts";

export interface LockbudReportFinding {
  lint?: string;
  severity?: string;
  confidence?: string;
  title?: string;
  explanation?: string;
  primary_location?: { label?: string; file?: string; line?: number; column?: number };
  functions?: string[];
  [k: string]: unknown;
}

interface LockbudReport {
  findings?: LockbudReportFinding[];
  pending_candidates?: unknown[];
  load_errors?: unknown[];
  truncation?: unknown[];
}

function runHost(cmd: string, args: string[], cwd: string, env: Record<string, string>): Promise<number> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd, env: { ...process.env, ...env }, stdio: "ignore" });
    child.on("exit", (code) => resolve(code ?? 1));
    child.on("error", () => resolve(1));
  });
}

/** Extract package + bin target names from a Cargo.toml (no full TOML parse needed). */
export async function cargoTargetCrates(manifest: string): Promise<string> {
  const text = await readFile(manifest, "utf8");
  const names = new Set<string>();
  let section = "";
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    const sectionMatch = line.match(/^\[(?:package|bin)\]\s*$/);
    if (sectionMatch) { section = sectionMatch[0]; continue; }
    if (/^\[/.test(line)) { section = ""; continue; }
    if (section === "[package]" || section === "[bin]") {
      const m = line.match(/^name\s*=\s*"([^"]+)"/);
      if (m) names.add(m[1]!.replace(/-/g, "_"));
    }
  }
  return [...names].join(",");
}

export async function detectorVersion(): Promise<string> {
  const channel = path.basename(toolchains.rust);
  let ver = "0.1.0";
  try {
    const toml = await readFile(path.join(path.dirname(toolchains.lockbudBin), "../../Cargo.toml"), "utf8");
    const m = toml.match(/^version\s*=\s*"([^"]+)"/m);
    if (m) ver = m[1]!;
  } catch { /* keep default */ }
  return `lockbud-stable ${ver} (${channel})`;
}

export interface LockbudPrepare {
  targetCrates: string;
}

/**
 * Trusted (host-side) prepare: ensure a Cargo.lock exists and stage a private
 * CARGO_HOME so the sandboxed analysis phase can run fully offline. The staging
 * cargo home never contains the user's real credentials.
 */
export async function prepare(inputDir: string, stagingDir: string): Promise<LockbudPrepare> {
  const manifest = path.join(inputDir, "Cargo.toml");
  const targetCrates = await cargoTargetCrates(manifest);
  if (!targetCrates) throw new Error(`no [package] name found in ${manifest}`);

  const cargoHome = path.join(stagingDir, "cargo-home");
  await mkdir(cargoHome, { recursive: true });
  const cargo = path.join(toolchains.rust, "bin", "cargo");
  const lockPath = path.join(inputDir, "Cargo.lock");

  try {
    if (!(await isExecutable(cargo))) throw new Error(`cargo not found at ${cargo}`);
    if (!lockPath || !(await readFile(lockPath, "utf8").then(() => true).catch(() => false))) {
      await runHost(cargo, ["generate-lockfile", "--offline", "--manifest-path", manifest], inputDir, {
        CARGO_HOME: cargoHome,
      });
    }
    // Download crates.io deps into the staged cache so the sandbox needs no network.
    await runHost(cargo, ["fetch", "--manifest-path", manifest], inputDir, { CARGO_HOME: cargoHome });
  } catch (e) {
    // Tolerate fetch failure: vendored setups or no-dep projects still analyze offline.
    console.error(`[lockbud] prepare fetch warning: ${e instanceof Error ? e.message : e}`);
  }
  return { targetCrates };
}

export function buildSandboxRequest(inputDir: string, outputDir: string, stagingDir: string, prep: LockbudPrepare): SandboxRequest {
  const script = [
    "set -eu",
    "export CARGO_TARGET_DIR=/tmp/target",
    "export CARGO_HOME=/cargo-home",
    "export LOCKBUD_ANALYSIS_SCOPE=local-only",
    `export LOCKBUD_TARGET_CRATE=${JSON.stringify(prep.targetCrates)}`,
    "export LOCKBUD_RESOURCE_PIPELINE=direct",
    "export LOCKBUD_RESOURCE_REPORT=/work/output/lockbud-report.json",
    "export LOCKBUD_BODY_CACHE=32",
    "export LOCKBUD_DEMAND=1",
    `RUSTC=${JSON.stringify(toolchains.lockbudBin)} cargo check --offline --locked --manifest-path /work/input/Cargo.toml`,
  ].join("\n");

  const mounts: SandboxMount[] = [
    { host: toolchains.rust, sandbox: toolchains.rust },
    { host: path.dirname(toolchains.lockbudBin), sandbox: path.dirname(toolchains.lockbudBin) },
    { host: path.join(stagingDir, "cargo-home"), sandbox: "/cargo-home" },
    { host: inputDir, sandbox: "/work/input" },
    { host: outputDir, sandbox: "/work/output", rw: true },
  ];

  return {
    argv: ["/bin/sh", "-c", script],
    mounts,
    env: {
      PATH: `${toolchains.rust}/bin:/usr/bin:/bin`,
      LD_LIBRARY_PATH: `${toolchains.rust}/lib`,
      RUSTUP_TOOLCHAIN: path.basename(toolchains.rust),
    },
    cwd: "/work",
    network: "none",
    limits: { ...DEFAULT_LIMITS.rust },
  };
}

function normSeverity(v: unknown): Severity {
  const s = String(v ?? "").toLowerCase();
  if (s === "critical" || s === "high" || s === "medium" || s === "low" || s === "informational") return s;
  return "medium";
}

function normConfidence(v: unknown): Confidence {
  const s = String(v ?? "").toLowerCase();
  if (s === "high" || s === "medium" || s === "low") return s;
  return "low";
}

/** Parse "src/main.rs:77:16" or "src/main.rs:77:16: 77:32 (#0)" style labels. */
export function parseSpanLabel(label: string): { file: string; line?: number; column?: number } {
  const m = label.match(/^(.*?):(\d+):(\d+)/);
  if (!m) return { file: label };
  return { file: m[1]!, line: Number(m[2]), column: Number(m[3]) };
}

export function normalizeReport(report: LockbudReport, detectorVersion: string): Finding[] {
  const findings: Finding[] = [];
  for (const f of report.findings ?? []) {
    const loc = f.primary_location ?? {};
    const parsed = loc.label ? parseSpanLabel(loc.label) : { file: loc.file ?? "<unknown>" };
    findings.push({
      rule_id: `lockbud-stable.${f.lint ?? "unknown"}`,
      ecosystem: "rust",
      detector: detectorVersion,
      severity: normSeverity(f.severity),
      confidence: normConfidence(f.confidence),
      evidence_level: "static-evidence",
      location: { file: parsed.file, line: loc.line ?? parsed.line, column: loc.column ?? parsed.column },
      message: f.title ?? f.explanation ?? "lockbud-stable concurrency finding",
      raw: f,
    });
  }
  return findings;
}

export interface LockbudRunOutput {
  result: SandboxResult;
  findings: Finding[];
  reportPath: string;
}

export async function collectResults(outputDir: string, result: SandboxResult, version: string): Promise<LockbudRunOutput> {
  const reportPath = path.join(outputDir, "lockbud-report.json");
  let findings: Finding[] = [];
  try {
    const report = await readJson<LockbudReport>(reportPath);
    findings = normalizeReport(report, version);
  } catch { /* report missing or unparseable: surfaced via ok=false */ }
  return { result, findings, reportPath };
}

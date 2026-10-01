import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { toolchains, PECATCH_CHECKERS, DEFAULT_LIMITS } from "../config.ts";
import type { SandboxMount, SandboxRequest, SandboxResult, Finding, Severity, Confidence } from "../types.ts";
import { isExecutable, listFilesRecursive, readJson } from "../util.ts";

export interface SlitherDetectorResult {
  check?: string;
  impact?: string;
  confidence?: string;
  description?: string;
  elements?: Array<{
    name?: string;
    type?: string;
    source_mapping?: {
      filename_absolute?: string;
      filename_relative?: string;
      lines?: number[];
    };
  }>;
}

export interface SlitherReport {
  results?: { detectors?: SlitherDetectorResult[] };
  detectors?: SlitherDetectorResult[];
  error?: unknown;
}

export interface PecatchPrepare {
  solcPath: string;
  solcVersion: string;
}

type Version = [number, number, number];

function parseVersion(v: string): Version | null {
  const m = v.trim().match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function cmp(a: Version, b: Version): number {
  for (let i = 0; i < 3; i++) {
    if (a[i]! !== b[i]!) return a[i]! - b[i]!;
  }
  return 0;
}

/** Minimal Solidity-pragma satisfaction for the constraint forms that matter. */
export function satisfiesPragmas(version: Version, constraints: string[]): boolean {
  return constraints.every((c) => satisfiesOne(version, c.trim()));
}

function satisfiesOne(version: Version, constraint: string): boolean {
  const tokens = constraint.split(/\s+/).filter(Boolean);
  return tokens.every((t) => satisfiesToken(version, t));
}

function satisfiesToken([v0, v1, v2]: Version, token: string): boolean {
  let m = token.match(/^\^(\d+)\.(\d+)\.(\d+)$/);
  if (m) {
    const base: Version = [Number(m[1]), Number(m[2]), Number(m[3])];
    if (v0 !== base[0]) return false;
    return cmp([v0, v1, v2], base) >= 0 && (v1 > base[1] || (v1 === base[1]));
  }
  m = token.match(/^(>=|<=|>|<|==|=)?\s*(\d+)\.(\d+)\.(\d+)$/);
  if (m) {
    const op = m[1] ?? "=";
    const rhs: Version = [Number(m[2]), Number(m[3]), Number(m[4])];
    const c = cmp([v0, v1, v2], rhs);
    switch (op) {
      case ">=": return c >= 0;
      case "<=": return c <= 0;
      case ">": return c > 0;
      case "<": return c < 0;
      default: return c === 0;
    }
  }
  return false; // unsupported token (e.g. pre-release): do not pretend it matches
}

export async function installedSolcVersions(): Promise<string[]> {
  const artifacts = path.join(toolchains.solcSelectDir, "artifacts");
  let entries: string[];
  try {
    entries = await readdir(artifacts);
  } catch { return []; }
  const versions = entries
    .map((e) => e.match(/^solc-v?(\d+\.\d+\.\d+)$/)?.[1])
    .filter((v): v is string => !!v);
  return versions.sort((a, b) => {
    const av = parseVersion(a), bv = parseVersion(b);
    if (!av || !bv) return 0;
    return cmp(av, bv);
  });
}

async function resolveSolcBinary(version: string): Promise<string | null> {
  const dir = path.join(toolchains.solcSelectDir, "artifacts", `solc-${version}`);
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch { return null; }
  for (const name of [dir, ...entries].map((n) => path.join(dir, path.basename(n)))) {
    if (await isExecutable(name)) return name;
  }
  return null;
}

/** Trusted (host-side) prepare: pick an installed solc satisfying every pragma. */
export async function prepare(inputDir: string): Promise<PecatchPrepare> {
  const solFiles = (await listFilesRecursive(inputDir)).filter((f) => f.endsWith(".sol"));
  if (solFiles.length === 0) throw new Error(`no .sol files under ${inputDir}`);

  const constraints: string[] = [];
  for (const f of solFiles) {
    const text = await readFile(f, "utf8");
    for (const m of text.matchAll(/pragma\s+solidity\s+([^;]+);/g)) {
      constraints.push(m[1]!.trim());
    }
  }

  const installed = await installedSolcVersions();
  if (installed.length === 0) {
    throw new Error("no solc versions installed (run: solc-select install <version>)");
  }

  let chosen: string | null = null;
  if (constraints.length === 0) {
    chosen = installed[installed.length - 1]!;
  } else {
    for (const v of [...installed].reverse()) {
      const parsed = parseVersion(v);
      if (parsed && satisfiesPragmas(parsed, constraints)) { chosen = v; break; }
    }
  }
  if (!chosen) {
    throw new Error(
      `no installed solc satisfies pragmas [${constraints.join("; ")}]; installed: ${installed.join(", ")}. `
      + "Install the needed version with: solc-select install <version>",
    );
  }

  const solcPath = await resolveSolcBinary(chosen);
  if (!solcPath) throw new Error(`solc artifact missing or not executable for ${chosen}`);
  return { solcPath, solcVersion: chosen };
}

export async function detectorVersion(): Promise<string> {
  let slitherVer = "unknown";
  try {
    const meta = await readFile(path.join(toolchains.pecatchVenv, "lib", "python3.12", "site-packages", "slither_analyzer-0.9.1.dist-info", "METADATA"), "utf8");
    slitherVer = meta.match(/^Version:\s*(.+)$/m)?.[1]?.trim() ?? slitherVer;
  } catch { /* tolerate */ }
  return `pecatch (slither ${slitherVer}) + checkers: ${PECATCH_CHECKERS.join(",")}`;
}

export function buildSandboxRequest(inputDir: string, outputDir: string, prep: PecatchPrepare, checkers: string[]): SandboxRequest {
  const mounts: SandboxMount[] = [
    { host: toolchains.pecatchVenv, sandbox: toolchains.pecatchVenv },
    // peCatch is installed editable (its detectors/ subpackage lacks __init__.py,
    // so a regular install drops it); the plugin source must therefore be visible
    // at its real path. Read-only: it is trusted tooling, not user input.
    { host: toolchains.pecatchSource, sandbox: toolchains.pecatchSource },
    { host: toolchains.solcSelectDir, sandbox: toolchains.solcSelectDir },
    { host: inputDir, sandbox: "/work/input" },
    { host: outputDir, sandbox: "/work/output", rw: true },
  ];

  return {
    argv: [
      path.join(toolchains.pecatchVenv, "bin", "slither"),
      "/work/input",
      "--detect", checkers.join(","),
      "--json", "/work/output/slither-report.json",
      "--solc", prep.solcPath,
    ],
    mounts,
    env: {
      PATH: `${toolchains.pecatchVenv}/bin:/usr/bin:/bin`,
      PYTHONDONTWRITEBYTECODE: "1",
      PYTHONUNBUFFERED: "1",
    },
    cwd: "/work",
    network: "none",
    limits: { ...DEFAULT_LIMITS.solidity },
  };
}

function normSeverity(impact: unknown): Severity {
  const s = String(impact ?? "").toLowerCase();
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "informational"; // includes Optimization
}

function normConfidence(confidence: unknown): Confidence {
  const s = String(confidence ?? "").toLowerCase();
  if (s === "high" || s === "medium" || s === "low") return s;
  return "low";
}

/**
 * peCatch's custom detectors emit empty `elements[]` and encode locations in
 * the description text, e.g.:
 *   "andInIf() @ input/GasIssues.sol#8-13\n[BUG:] 0: input/GasIssues.sol#9"
 * Prefer the precise [BUG:] span; fall back to standard slither elements.
 */
function locationFromElement(d: SlitherDetectorResult, inputPrefix: string): { file: string; line?: number } {
  const description = d.description ?? "";
  const bug = description.match(/\[BUG\]:\s*\d+:\s*([^\s#]+)#(\d+)/);
  const generic = description.match(/@\s*([^\s#]+)#(\d+)/);
  const m = bug ?? generic;
  if (m) {
    let file = m[1]!;
    file = file.replace(/^input\//, "").replace(/^\/work\/input\//, "");
    return { file, line: Number(m[2]) };
  }
  const el = d.elements?.[0];
  const sm = el?.source_mapping ?? {};
  let file = sm.filename_relative ?? "";
  if (!file || path.isAbsolute(file)) {
    const abs = sm.filename_absolute ?? file;
    file = abs.startsWith(inputPrefix) ? path.relative(inputPrefix, abs) : abs;
  }
  return { file: file || "<unknown>", line: sm.lines?.[0] };
}

export function normalizeReport(report: SlitherReport, inputPrefix: string, version: string): Finding[] {
  const findings: Finding[] = [];
  // slither >=0.9 nests detector results under `results.detectors`.
  const items = report.results?.detectors ?? report.detectors ?? [];
  for (const d of items) {
    const check = d.check ?? "unknown";
    const el = d.elements?.[0];
    const { file, line } = locationFromElement(d, inputPrefix);
    const descFirstLine = (d.description ?? "").split("\n").map((s) => s.trim()).filter(Boolean)[0] ?? "slither finding";
    const elementName = el?.name ? ` (${el.name})` : "";
    findings.push({
      rule_id: (PECATCH_CHECKERS as readonly string[]).includes(check) ? `pecatch.${check}` : `slither.${check}`,
      ecosystem: "solidity",
      detector: version,
      severity: normSeverity(d.impact),
      confidence: normConfidence(d.confidence),
      evidence_level: "static-evidence",
      location: { file, line },
      message: `${descFirstLine}${elementName}`,
      raw: d,
    });
  }
  return findings;
}

export interface PecatchRunOutput {
  result: SandboxResult;
  findings: Finding[];
  reportPath: string;
}

export async function collectResults(outputDir: string, inputDir: string, result: SandboxResult, version: string): Promise<PecatchRunOutput> {
  const reportPath = path.join(outputDir, "slither-report.json");
  let findings: Finding[] = [];
  try {
    const report = await readJson<SlitherReport>(reportPath);
    findings = normalizeReport(report, inputDir, version);
  } catch { /* report missing or unparseable: surfaced via ok=false */ }
  return { result, findings, reportPath };
}

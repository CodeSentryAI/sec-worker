import { createHash, randomUUID } from "node:crypto";
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { DEFAULT_LIMITS, toolchains } from "../config.ts";
import type { Finding, VerifiedFinding } from "../types.ts";
import { runSandboxed } from "../sandbox/bwrap.ts";
import { prepare } from "../detectors/pecatch.ts";
import { checkErc20Abi, type Erc20AbiTarget } from "./erc20_abi.ts";

type JsonObject = Record<string, unknown>;

export interface Erc20CompileMetadata {
  status: "complete" | "not-applicable" | "indeterminate";
  reason?: string;
  run_id: string;
  compiler_selected_version?: string;
  compiler_reported_version?: string;
  compiler_binary_sha256?: string;
  input_sha256?: string;
  output_sha256?: string;
  input_artifact?: string;
  output_artifact?: string;
  version_artifact?: string;
  source_count: number;
  exit_code: number | null;
  signal: string | null;
  timed_out: boolean;
  truncated: boolean;
  duration_ms: number;
  stdout_excerpt?: string;
  stderr_excerpt?: string;
}

export interface Erc20CompileOutcome {
  findings: Finding[];
  metadata: Erc20CompileMetadata;
}

function sha256(value: Buffer | string): string {
  return createHash("sha256").update(value).digest("hex");
}

function jsonObject(value: unknown): JsonObject | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as JsonObject
    : undefined;
}

async function sourceFiles(root: string, current = root, depth = 0): Promise<string[]> {
  if (depth > 6) throw new Error("source tree exceeds maximum traversal depth (6)");
  const entries = await readdir(current, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
    const absolute = path.join(current, entry.name);
    if (entry.isDirectory()) files.push(...await sourceFiles(root, absolute, depth + 1));
    else if (entry.isFile() && entry.name.endsWith(".sol")) files.push(absolute);
  }
  return files;
}

export async function buildStandardJsonInput(sourceRoot: string): Promise<{ inputText: string; sourceCount: number }> {
  const files = await sourceFiles(sourceRoot);
  if (files.length === 0) throw new Error(`no .sol files under ${sourceRoot}`);
  const sources: Record<string, { content: string }> = {};
  for (const file of files) {
    const key = path.relative(sourceRoot, file).split(path.sep).join("/");
    if (!key || key.startsWith("../") || path.posix.isAbsolute(key) || sources[key]) {
      throw new Error(`invalid or duplicate Solidity source key: ${key}`);
    }
    sources[key] = { content: await readFile(file, "utf8") };
  }
  const input = {
    language: "Solidity",
    sources,
    settings: {
      outputSelection: {
        "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"], "": ["ast"] },
      },
    },
  };
  return { inputText: `${JSON.stringify(input, null, 2)}\n`, sourceCount: files.length };
}

function selectedFindingToVerified(finding: Finding, metadata: Erc20CompileMetadata): Finding {
  if (finding.trust_tier !== "signal" || finding.rule_id !== "erc20-abi.function-not-listed") return finding;
  if (!metadata.input_artifact || !metadata.output_artifact
    || !metadata.input_sha256 || !metadata.output_sha256 || !metadata.compiler_binary_sha256) return finding;
  const raw = jsonObject(finding.raw) ?? {};
  const sourcePointer = typeof raw.source_content_pointer === "string" ? raw.source_content_pointer : "";
  const abiPointer = typeof raw.compiler_abi_pointer === "string" ? raw.compiler_abi_pointer : "";
  if (!sourcePointer.startsWith("solc-input.json#/sources/")
    || !abiPointer.startsWith("solc-output.json#/contracts/")) return finding;
  const sourceEvidence = `${metadata.input_artifact}${sourcePointer.slice("solc-input.json".length)}`;
  const abiEvidence = `${metadata.output_artifact}${abiPointer.slice("solc-output.json".length)}`;
  const evidence: [string, ...string[]] = [
    `${metadata.input_artifact} sha256:${metadata.input_sha256}`,
    `${metadata.output_artifact} sha256:${metadata.output_sha256}`,
    `solc sha256:${metadata.compiler_binary_sha256}`,
    sourceEvidence,
    abiEvidence,
  ];
  const verified: VerifiedFinding = {
    ...finding,
    trust_tier: "verified",
    verification: {
      verifier_id: "erc20-abi-v1",
      verifier_version: "1.0.0",
      evidence,
    },
    raw: {
      ...raw,
      source_content_pointer: sourceEvidence,
      compiler_abi_pointer: abiEvidence,
      compiler_provenance: metadata,
    },
  };
  return verified;
}

/** Apply the trust upgrade only after the complete compiler evidence contract passes. */
function promoteErc20AbiFindings(findings: Finding[], metadata: Erc20CompileMetadata): Finding[] {
  if (metadata.status !== "complete") return findings;
  return findings.map((finding) => selectedFindingToVerified(finding, metadata));
}

/**
 * Build and run one bounded Standard JSON compilation from inline source
 * contents, preserving every input/output byte used by the ABI verifier.
 * Only missing required function ABI entries can be promoted to Verified.
 */
export async function runErc20AbiCompile(
  sourceRoot: string,
  target: Erc20AbiTarget,
  outputDir: string,
): Promise<Erc20CompileOutcome> {
  const runId = randomUUID();
  const inputArtifact = `erc20-${runId}-solc-input.json`;
  const outputArtifact = `erc20-${runId}-solc-output.json`;
  const versionArtifact = `erc20-${runId}-solc-version.txt`;
  let sourceCount = 0;
  let exitCode: number | null = null;
  let timedOut = false;
  let truncated = false;
  let durationMs = 0;
  const metadata: Erc20CompileMetadata = {
    status: "indeterminate",
    reason: "compiler did not produce complete evidence",
    run_id: runId,
    input_artifact: inputArtifact,
    output_artifact: outputArtifact,
    version_artifact: versionArtifact,
    source_count: 0,
    exit_code: null,
    signal: null,
    timed_out: false,
    truncated: false,
    duration_ms: 0,
  };
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), `erc20-${runId}-`));
  const inputDir = path.join(tempRoot, "input");
  const toolDir = path.join(tempRoot, "tool");
  const outputStaging = path.join(tempRoot, "output");
  try {
    await Promise.all([mkdir(inputDir), mkdir(toolDir), mkdir(outputStaging), mkdir(outputDir, { recursive: true })]);
    const built = await buildStandardJsonInput(sourceRoot);
    sourceCount = built.sourceCount;
    metadata.source_count = sourceCount;
    const inputPath = path.join(inputDir, "solc-input.json");
    await writeFile(inputPath, built.inputText, { flag: "wx" });
    metadata.input_sha256 = sha256(built.inputText);

    // Select solc against the exact source snapshot represented in Standard JSON.
    const snapshotDir = path.join(tempRoot, "snapshot");
    await mkdir(snapshotDir);
    const inputObj = JSON.parse(built.inputText) as { sources: Record<string, { content: string }> };
    for (const [key, value] of Object.entries(inputObj.sources)) {
      const destination = path.join(snapshotDir, ...key.split("/"));
      await mkdir(path.dirname(destination), { recursive: true });
      await writeFile(destination, value.content, { flag: "wx" });
    }
    const compiler = await prepare(snapshotDir);
    metadata.compiler_selected_version = compiler.solcVersion;
    const copiedSolc = path.join(toolDir, "solc");
    await copyFile(compiler.solcPath, copiedSolc);
    await chmod(copiedSolc, 0o555);
    metadata.compiler_binary_sha256 = sha256(await readFile(copiedSolc));

    const sandboxResult = await runSandboxed({
      argv: ["/bin/sh", "-c", "set -eu; /work/tool/solc --version > /work/output/solc-version.txt; /work/tool/solc --standard-json < /work/input/solc-input.json > /work/output/solc-output.json"],
      mounts: [
        { host: toolDir, sandbox: "/work/tool" },
        { host: inputDir, sandbox: "/work/input" },
        { host: outputStaging, sandbox: "/work/output", rw: true },
      ],
      env: {},
      cwd: "/work",
      network: "none",
      limits: { ...DEFAULT_LIMITS.solidity },
    });
    exitCode = sandboxResult.exitCode;
    metadata.signal = sandboxResult.signal;
    timedOut = sandboxResult.timedOut;
    truncated = sandboxResult.truncated;
    durationMs = sandboxResult.durationMs;
    metadata.stdout_excerpt = sandboxResult.stdout.slice(-4000);
    metadata.stderr_excerpt = sandboxResult.stderr.slice(-4000);
    metadata.exit_code = exitCode;
    metadata.timed_out = timedOut;
    metadata.truncated = truncated;
    metadata.duration_ms = durationMs;

    const stagedInput = await readFile(inputPath);
    const stagedOutputPath = path.join(outputStaging, "solc-output.json");
    const stagedVersionPath = path.join(outputStaging, "solc-version.txt");
    const outputBytes = await readFile(stagedOutputPath).catch(() => null);
    const versionText = await readFile(stagedVersionPath, "utf8").catch(() => "");
    await writeFile(path.join(outputDir, inputArtifact), stagedInput, { flag: "wx" });
    if (outputBytes) {
      await writeFile(path.join(outputDir, outputArtifact), outputBytes, { flag: "wx" });
      metadata.output_sha256 = sha256(outputBytes);
    }
    if (versionText) await writeFile(path.join(outputDir, versionArtifact), versionText, { flag: "wx" });
    metadata.compiler_reported_version = versionText.trim();

    const reported = versionText.match(/Version:\s*(\d+\.\d+\.\d+)/)?.[1];
    if (timedOut) metadata.reason = "solc compilation timed out";
    else if (truncated) metadata.reason = "sandbox compiler output was truncated";
    else if (exitCode !== 0) {
      const detail = metadata.stderr_excerpt?.trim();
      metadata.reason = `solc sandbox exited with status ${String(exitCode)}${detail ? `: ${detail}` : ""}`;
    }
    else if (!reported) metadata.reason = "solc --version output is missing or malformed";
    else if (reported !== compiler.solcVersion) metadata.reason = "selected solc path reported a different version";
    else if (!outputBytes || !metadata.output_sha256) metadata.reason = "solc output artifact is missing";
    else {
      let output: unknown;
      try { output = JSON.parse(outputBytes.toString("utf8")); }
      catch { metadata.reason = "solc output is not valid Standard JSON"; }
      if (output !== undefined) {
        const checked = checkErc20Abi(inputObj, output, target, reported);
        if (checked.status === "complete") {
          metadata.status = "complete";
          delete metadata.reason;
          return {
            findings: promoteErc20AbiFindings(checked.findings, metadata),
            metadata,
          };
        }
        if (checked.status === "not-applicable") {
          metadata.status = "not-applicable";
          metadata.reason = checked.reason;
          return { findings: [], metadata };
        }
        metadata.reason = checked.reason;
        return { findings: [], metadata };
      }
    }
    return { findings: [], metadata };
  } catch (error) {
    metadata.reason = error instanceof Error ? error.message : String(error);
    return { findings: [], metadata };
  } finally {
    // Persist metadata even on failure; raw compiler bytes remain under outputDir.
    metadata.source_count = sourceCount;
    metadata.exit_code = exitCode;
    metadata.timed_out = timedOut;
    metadata.truncated = truncated;
    metadata.duration_ms = durationMs;
    await writeFile(path.join(outputDir, `erc20-${runId}-provenance.json`), JSON.stringify(metadata, null, 2)).catch(() => {});
    await rm(tempRoot, { recursive: true, force: true }).catch(() => {});
  }
}

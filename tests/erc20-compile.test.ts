import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_LIMITS } from "../src/config.ts";
import { prepare } from "../src/detectors/pecatch.ts";
import { buildBwrapArgv } from "../src/sandbox/bwrap.ts";
import * as erc20Compile from "../src/verified/erc20_compile.ts";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixtureRoot = path.join(repoRoot, "tests/fixtures/erc20-inherited");
const fixtureSource = path.join(fixtureRoot, "Token.sol");
const bwrapBinary = process.env.SEC_BWRAP ?? "/usr/bin/bwrap";
const bwrapProbe = spawnSync(bwrapBinary, buildBwrapArgv({
  argv: ["/bin/true"], mounts: [], env: {}, cwd: "/", network: "none", limits: DEFAULT_LIMITS.solidity,
}), { encoding: "utf8" });
const bwrapError = bwrapProbe.stderr.trim() || bwrapProbe.error?.message || `exit ${bwrapProbe.status}`;
const bwrapNamespaceUnavailable = bwrapProbe.status !== 0
  && /no permissions to create new namespace|user namespaces?.*(disabled|not permitted)|operation not permitted.*namespace/i.test(bwrapError);
if (bwrapProbe.status !== 0 && !bwrapNamespaceUnavailable) {
  throw new Error(`bubblewrap capability probe failed for a reason other than unavailable namespaces: ${bwrapError}`);
}
const bwrapSkip = bwrapNamespaceUnavailable ? `real bubblewrap namespaces unavailable: ${bwrapError}` : false;

function sha256(value: Buffer | string): string {
  return createHash("sha256").update(value).digest("hex");
}

async function copyFixture(destination: string): Promise<void> {
  await mkdir(destination, { recursive: true });
  for (const name of ["Base.sol", "Token.sol"]) {
    await copyFile(path.join(fixtureRoot, name), path.join(destination, name));
  }
}

async function runInChild(sourceRoot: string, outputDir: string, solcSelectDir: string, maxWallSeconds = 5, fixedRunId?: string) {
  // The module is imported only after the child has received SEC_SOLC_SELECT_DIR.
  const modulePath = path.join(repoRoot, "src/verified/erc20_compile.ts");
  const script = `
    if (process.env.TEST_FIXED_RUN_ID) {
      const crypto = await import("node:crypto");
      const { syncBuiltinESMExports } = await import("node:module");
      crypto.default.randomUUID = () => process.env.TEST_FIXED_RUN_ID;
      syncBuiltinESMExports();
    }
    process.env.SEC_SOLC_SELECT_DIR = process.env.TEST_SOLC_SELECT_DIR;
    const { runErc20AbiCompile } = await import(${JSON.stringify(modulePath)});
    const result = await runErc20AbiCompile(
      process.env.TEST_SOURCE_ROOT,
      { source_path: process.env.TEST_TARGET_SOURCE, contract_name: process.env.TEST_TARGET_CONTRACT },
      process.env.TEST_OUTPUT_DIR,
      { maxWallSeconds: Number(process.env.TEST_WALL_SECONDS) },
    );
    process.stdout.write(JSON.stringify(result) + "\\n");
  `;
  const child = spawn(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", script], {
    env: {
      ...process.env,
      TEST_SOLC_SELECT_DIR: solcSelectDir,
      TEST_SOURCE_ROOT: sourceRoot,
      TEST_TARGET_SOURCE: "Token.sol",
      TEST_TARGET_CONTRACT: "Token",
      TEST_OUTPUT_DIR: outputDir,
      TEST_WALL_SECONDS: String(maxWallSeconds),
      ...(fixedRunId ? { TEST_FIXED_RUN_ID: fixedRunId } : {}),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  const exit = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => resolve(code));
  });
  const out = Buffer.concat(stdout).toString("utf8");
  assert.equal(exit, 0, `child failed (${exit}): ${Buffer.concat(stderr).toString("utf8")}\n${out}`);
  return JSON.parse(out.trim().split("\n").at(-1)!) as {
    findings: Array<Record<string, any>>;
    metadata: Record<string, any>;
  };
}

async function makeFakeSolc(root: string, mode: "success" | "malformed" | "malformed-entry" | "invalid-json" | "compile-error" | "nonzero" | "timeout"): Promise<string> {
  const solcRoot = path.join(root, "solc-select");
  const artifactDir = path.join(solcRoot, "artifacts", "solc-0.8.28");
  await mkdir(artifactDir, { recursive: true });
  const compiler = path.join(artifactDir, "solc");
  const output = fakeOutput(mode);
  const encoded = Buffer.from(mode === "invalid-json" ? "{not-json" : JSON.stringify(output)).toString("base64");
  const body = mode === "timeout"
    ? "sleep 20; exit 0"
    : `cat >/dev/null\nprintf '%s' '${encoded}' | base64 -d\n${mode === "nonzero" ? "exit 17" : "exit 0"}`;
  await writeFile(compiler, `#!/bin/sh\nif [ "$1" = "--version" ]; then\n  printf '%s\\n' 'solc, the solidity compiler commandline interface' 'Version: 0.8.28+commit.7893614a.Linux.g++'\n  exit 0\nfi\n${body}\n`);
  await chmod(compiler, 0o755);
  return solcRoot;
}

function fakeOutput(mode: string): unknown {
  const source = "// SPDX-License-Identifier: MIT\npragma solidity 0.8.28;\ncontract Token {}\n";
  const abi = [
    { type: "function", name: "totalSupply", inputs: [], outputs: [{ type: "uint256" }] },
    { type: "function", name: "balanceOf", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
    { type: "function", name: "transfer", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [{ type: "bool" }] },
    { type: "function", name: "transferFrom", inputs: [{ type: "address" }, { type: "address" }, { type: "uint256" }], outputs: [{ type: "bool" }] },
    { type: "function", name: "allowance", inputs: [{ type: "address" }, { type: "address" }], outputs: [{ type: "uint256" }] },
    { type: "event", name: "Transfer", anonymous: false, inputs: [{ type: "address", indexed: true }, { type: "address", indexed: true }, { type: "uint256", indexed: false }] },
    { type: "event", name: "Approval", anonymous: false, inputs: [{ type: "address", indexed: true }, { type: "address", indexed: true }, { type: "uint256", indexed: false }] },
  ];
  const output = {
    sources: { "Token.sol": { id: 0, ast: { nodeType: "SourceUnit", nodes: [{
      id: 1, nodeType: "ContractDefinition", name: "Token", contractKind: "contract", abstract: false,
      fullyImplemented: true, linearizedBaseContracts: [1], nodes: [], src: `0:${Buffer.byteLength(source)}:0`,
    }] } } },
    contracts: { "Token.sol": { Token: { abi, evm: { bytecode: { object: "60006000" }, deployedBytecode: { object: "6000" } } } } },
  };
  if (mode === "malformed") return { ...output, errors: { severity: "error", message: "bad shape" } };
  if (mode === "malformed-entry") return { ...output, errors: [{ severity: "error" }, "bad diagnostic"] };
  if (mode === "compile-error") return { ...output, errors: [{ severity: "error", component: "general", message: "synthetic compiler error", formattedMessage: "Error: synthetic compiler error" }] };
  return output;
}

function resolveJsonPointer(root: unknown, pointer: string): unknown {
  const hash = pointer.indexOf("#");
  assert.notEqual(hash, -1, `not an artifact JSON pointer: ${pointer}`);
  const fragment = decodeURIComponent(pointer.slice(hash + 1));
  let current: any = root;
  for (const part of fragment.split("/").slice(1)) {
    const decoded = part.replaceAll("~1", "/").replaceAll("~0", "~");
    current = current?.[decoded];
  }
  return current;
}

test("Standard JSON input captures stable relative source keys and requests ABI, AST, creation and runtime bytecode", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "erc20-input-test-"));
  try {
    await mkdir(path.join(root, "contracts", "lib"), { recursive: true });
    await writeFile(path.join(root, "contracts", "Token.sol"), "contract Token {}\n");
    await writeFile(path.join(root, "contracts", "lib", "Base.sol"), "contract Base {}\n");
    const result = await erc20Compile.buildStandardJsonInput(root);
    const parsed = JSON.parse(result.inputText);
    assert.equal(result.sourceCount, 2);
    assert.deepEqual(Object.keys(parsed.sources), ["contracts/Token.sol", "contracts/lib/Base.sol"]);
    assert.deepEqual(parsed.settings.outputSelection, {
      "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"], "": ["ast"] },
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("arbitrary callers cannot promote forged compiler metadata to Verified", () => {
  assert.equal("promoteErc20AbiFindings" in erc20Compile, false);
});

test("real solc 0.8.28 compiles imported inherited ERC-20; evidence pointers resolve to retained bytes", { skip: bwrapSkip }, async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), "erc20-real-"));
  const sourceRoot = path.join(temp, "src");
  const outputDir = path.join(temp, "out");
  try {
    await copyFixture(sourceRoot);
    const result = await erc20Compile.runErc20AbiCompile(sourceRoot, { source_path: "Token.sol", contract_name: "Token" }, outputDir, { maxWallSeconds: 30 });
    assert.equal(result.metadata.status, "complete", result.metadata.reason);
    assert.equal(result.metadata.compiler_selected_version, "0.8.28");
    assert.equal(result.metadata.compiler_reported_version?.match(/Version:\s*(\d+\.\d+\.\d+)/)?.[1], "0.8.28");
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0]?.rule_id, "erc20-abi.function-not-listed");
    assert.equal(result.findings[0]?.trust_tier, "verified");

    const metadata = result.metadata;
    const inputBytes = await readFile(path.join(outputDir, metadata.input_artifact!));
    const outputBytes = await readFile(path.join(outputDir, metadata.output_artifact!));
    const versionBytes = await readFile(path.join(outputDir, metadata.version_artifact!));
    const provenanceBytes = await readFile(path.join(outputDir, metadata.provenance_artifact!));
    const input = JSON.parse(inputBytes.toString("utf8"));
    const output = JSON.parse(outputBytes.toString("utf8"));
    const provenance = JSON.parse(provenanceBytes.toString("utf8"));
    assert.equal(sha256(inputBytes), metadata.input_sha256);
    assert.equal(sha256(outputBytes), metadata.output_sha256);
    const selectedCompiler = await prepare(sourceRoot);
    assert.equal(selectedCompiler.solcVersion, metadata.compiler_selected_version);
    assert.equal(sha256(await readFile(selectedCompiler.solcPath)), metadata.compiler_binary_sha256);
    assert.match(versionBytes.toString("utf8"), /Version:\s*0\.8\.28/);
    assert.equal(provenance.status, "complete");
    assert.equal(provenance.input_sha256, sha256(inputBytes));
    assert.equal(provenance.output_sha256, sha256(outputBytes));
    assert.deepEqual(input.sources["Base.sol"].content, await readFile(path.join(sourceRoot, "Base.sol"), "utf8"));
    assert.deepEqual(input.sources["Token.sol"].content, await readFile(fixtureSource, "utf8"));
    assert.ok(input.sources["Token.sol"].content.includes('import "./Base.sol"'));

    const finding = result.findings[0]!;
    const raw = finding.raw as Record<string, unknown>;
    const sourcePointer = String(raw.source_content_pointer);
    const abiPointer = String(raw.compiler_abi_pointer);
    assert.equal(sourcePointer.split("#", 1)[0], metadata.input_artifact);
    assert.equal(abiPointer.split("#", 1)[0], metadata.output_artifact);
    assert.equal(resolveJsonPointer(input, sourcePointer), input.sources["Token.sol"].content);
    const observedAbi = resolveJsonPointer(output, abiPointer);
    assert.deepEqual(observedAbi, output.contracts["Token.sol"].Token.abi);
    assert.equal(observedAbi.some((entry: any) => entry.type === "function" && entry.name === "approve"), false);
    assert.equal((finding.raw as any).missing_item.name, "approve");
    const tokenAst = output.sources["Token.sol"].ast.nodes.find((node: any) => node.nodeType === "ContractDefinition" && node.name === "Token");
    assert.ok(tokenAst, "solc AST must contain the imported Token contract");
    assert.ok(tokenAst.linearizedBaseContracts.length > 1, "Token ABI must include inherited Base declarations");
    assert.ok(finding.verification.evidence.some((entry: string) => entry.includes(`sha256:${metadata.input_sha256}`)));
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("fresh run in reused output directory cannot reuse stale compiler output", { skip: bwrapSkip }, async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), "erc20-reuse-"));
  const sourceRoot = path.join(temp, "src");
  const outputDir = path.join(temp, "out");
  try {
    await copyFixture(sourceRoot);
    const first = await erc20Compile.runErc20AbiCompile(sourceRoot, { source_path: "Token.sol", contract_name: "Token" }, outputDir, { maxWallSeconds: 30 });
    assert.equal(first.metadata.status, "complete", first.metadata.reason);
    assert.equal(first.findings.length, 1);
    await writeFile(path.join(sourceRoot, "Token.sol"), "pragma solidity 0.8.28; contract Token is {\n");
    const second = await erc20Compile.runErc20AbiCompile(sourceRoot, { source_path: "Token.sol", contract_name: "Token" }, outputDir, { maxWallSeconds: 30 });
    assert.notEqual(second.metadata.run_id, first.metadata.run_id);
    assert.equal(second.metadata.status, "indeterminate");
    assert.deepEqual(second.findings, []);
    assert.notEqual(second.metadata.input_artifact, first.metadata.input_artifact);
    assert.notEqual(second.metadata.output_artifact, first.metadata.output_artifact);
    const secondInput = JSON.parse(await readFile(path.join(outputDir, second.metadata.input_artifact!), "utf8"));
    assert.equal(secondInput.sources["Token.sol"].content, "pragma solidity 0.8.28; contract Token is {\n");
    const files = await readdir(outputDir);
    assert.ok(files.includes(second.metadata.provenance_artifact!));
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

for (const mode of ["success", "malformed", "malformed-entry", "invalid-json", "compile-error", "nonzero", "timeout"] as const) {
  test(`fake compiler ${mode} path remains inside bubblewrap`, { skip: bwrapSkip }, async () => {
    const temp = await mkdtemp(path.join(os.tmpdir(), `erc20-fake-${mode}-`));
    const sourceRoot = path.join(temp, "src");
    const outputDir = path.join(temp, "out");
    try {
      await mkdir(sourceRoot, { recursive: true });
      await writeFile(path.join(sourceRoot, "Token.sol"), "// SPDX-License-Identifier: MIT\npragma solidity 0.8.28;\ncontract Token {}\n");
      const solcSelectDir = await makeFakeSolc(temp, mode);
      const result = await runInChild(sourceRoot, outputDir, solcSelectDir, mode === "timeout" ? 1 : 5);
      if (mode === "success") {
        assert.equal(result.metadata.status, "complete", result.metadata.reason);
        assert.equal(result.findings.length, 1);
      } else {
        assert.equal(result.metadata.status, "indeterminate");
        assert.deepEqual(result.findings, []);
        if (mode === "malformed" || mode === "malformed-entry") assert.match(String(result.metadata.reason), /malformed/);
        if (mode === "invalid-json") assert.match(String(result.metadata.reason), /not valid Standard JSON/);
        if (mode === "compile-error") assert.match(String(result.metadata.reason), /compilation errors/);
        if (mode === "nonzero") assert.match(String(result.metadata.reason), /status 17/);
        if (mode === "timeout") assert.equal(result.metadata.timed_out, true);
      }
      assert.ok(result.metadata.provenance_artifact);
    } finally {
      await rm(temp, { recursive: true, force: true });
    }
  });
}

test("provenance persistence collision fails closed and clears otherwise Verified findings", { skip: bwrapSkip }, async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), "erc20-provenance-collision-"));
  const sourceRoot = path.join(temp, "src");
  const outputDir = path.join(temp, "out");
  const fixedRunId = "provenance-collision-test";
  try {
    await mkdir(sourceRoot, { recursive: true });
    await mkdir(outputDir, { recursive: true });
    await writeFile(path.join(sourceRoot, "Token.sol"), "// SPDX-License-Identifier: MIT\npragma solidity 0.8.28;\ncontract Token {}\n");
    await writeFile(path.join(outputDir, `erc20-${fixedRunId}-provenance.json`), "preserve-existing-artifact\n");
    const solcSelectDir = await makeFakeSolc(temp, "success");
    const result = await runInChild(sourceRoot, outputDir, solcSelectDir, 5, fixedRunId);
    assert.equal(result.metadata.status, "indeterminate");
    assert.match(String(result.metadata.reason), /failed to persist compiler provenance/);
    assert.deepEqual(result.findings, []);
    assert.equal(await readFile(path.join(outputDir, result.metadata.provenance_artifact!), "utf8"), "preserve-existing-artifact\n");
    assert.ok(result.metadata.input_sha256, "raw input evidence remains available when provenance persistence fails");
    assert.ok(result.metadata.output_sha256, "raw compiler output remains available when provenance persistence fails");
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("missing requested contract returns indeterminate without findings", { skip: bwrapSkip }, async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), "erc20-missing-target-"));
  const sourceRoot = path.join(temp, "src");
  try {
    await mkdir(sourceRoot, { recursive: true });
    await writeFile(path.join(sourceRoot, "Token.sol"), "// SPDX-License-Identifier: MIT\npragma solidity 0.8.28;\ncontract Token {}\n");
    const solcSelectDir = await makeFakeSolc(temp, "success");
    const childModulePath = path.join(repoRoot, "src/verified/erc20_compile.ts");
    const script = `process.env.SEC_SOLC_SELECT_DIR=process.env.TEST_SOLC_SELECT_DIR; const {runErc20AbiCompile}=await import(${JSON.stringify(childModulePath)}); const r=await runErc20AbiCompile(process.env.TEST_SOURCE_ROOT,{source_path:"Token.sol",contract_name:"Missing"},process.env.TEST_OUTPUT_DIR,{maxWallSeconds:5}); console.log(JSON.stringify(r));`;
    const child = spawnSync(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", script], {
      encoding: "utf8",
      env: { ...process.env, TEST_SOLC_SELECT_DIR: solcSelectDir, TEST_SOURCE_ROOT: sourceRoot, TEST_OUTPUT_DIR: path.join(temp, "out") },
    });
    assert.equal(child.status, 0, child.stderr);
    const result = JSON.parse(child.stdout.trim());
    assert.equal(result.metadata.status, "indeterminate");
    assert.match(result.metadata.reason, /contract AST not found/);
    assert.deepEqual(result.findings, []);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { Finding } from "../src/types.ts";
import {
  buildStandardJsonInput,
  promoteErc20AbiFindings,
  type Erc20CompileMetadata,
} from "../src/verified/erc20_compile.ts";

test("Standard JSON input captures stable relative source keys and asks for ABI plus AST", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "erc20-input-test-"));
  try {
    await mkdir(path.join(root, "contracts", "lib"), { recursive: true });
    await writeFile(path.join(root, "contracts", "Token.sol"), "contract Token {}\n");
    await writeFile(path.join(root, "contracts", "lib", "Base.sol"), "contract Base {}\n");
    const result = await buildStandardJsonInput(root);
    const parsed = JSON.parse(result.inputText);
    assert.equal(result.sourceCount, 2);
    assert.deepEqual(Object.keys(parsed.sources), ["contracts/Token.sol", "contracts/lib/Base.sol"]);
    assert.deepEqual(parsed.settings.outputSelection, {
      "*": { "*": ["abi"], "": ["ast"] },
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("only function ABI findings upgrade with complete compiler artifact evidence", () => {
  const findings: Finding[] = [
    {
      rule_id: "erc20-abi.function-not-listed",
      ecosystem: "solidity",
      detector: "chainfox-erc20-abi 0.8.28",
      severity: "medium",
      confidence: "high",
      trust_tier: "signal",
      evidence_level: "static-evidence",
      location: { file: "Token.sol", line: 4 },
      message: "missing mandatory function",
      raw: {
        source_content_pointer: "solc-input.json#/sources/Token.sol/content",
        compiler_abi_pointer: "solc-output.json#/contracts/Token.sol/Token/abi",
      },
    },
    {
      rule_id: "erc20-abi.event-declaration-not-listed",
      ecosystem: "solidity",
      detector: "chainfox-erc20-abi 0.8.28",
      severity: "informational",
      confidence: "low",
      trust_tier: "signal",
      evidence_level: "static-evidence",
      location: { file: "Token.sol", line: 4 },
      message: "event declaration absent",
      raw: {},
    },
  ];
  const metadata: Erc20CompileMetadata = {
    status: "complete",
    run_id: "run-1",
    compiler_selected_version: "0.8.28",
    compiler_reported_version: "Version: 0.8.28+commit.example",
    compiler_binary_sha256: "compiler-hash",
    input_sha256: "input-hash",
    output_sha256: "output-hash",
    input_artifact: "input.json",
    output_artifact: "output.json",
    version_artifact: "version.txt",
    source_count: 1,
    exit_code: 0,
    signal: null,
    timed_out: false,
    truncated: false,
    duration_ms: 1,
  };
  const result = promoteErc20AbiFindings(findings, metadata);
  assert.equal(result[0]?.trust_tier, "verified");
  if (result[0]?.trust_tier === "verified") {
    assert.equal(result[0].verification.verifier_id, "erc20-abi-v1");
    assert.equal(result[0].verification.evidence.length, 5);
    assert.equal(result[0].verification.evidence[3], "input.json#/sources/Token.sol/content");
    assert.equal(result[0].verification.evidence[4], "output.json#/contracts/Token.sol/Token/abi");
    assert.deepEqual(result[0].raw, {
      source_content_pointer: "input.json#/sources/Token.sol/content",
      compiler_abi_pointer: "output.json#/contracts/Token.sol/Token/abi",
      compiler_provenance: metadata,
    });
  }
  assert.equal(result[1]?.trust_tier, "signal");

  const incomplete = { ...metadata, status: "indeterminate" as const };
  assert.equal(promoteErc20AbiFindings(findings, incomplete)[0]?.trust_tier, "signal");
  const missingDigest = { ...metadata, compiler_binary_sha256: undefined };
  assert.equal(promoteErc20AbiFindings(findings, missingDigest)[0]?.trust_tier, "signal");
});

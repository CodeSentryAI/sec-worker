import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import * as erc20Compile from "../src/verified/erc20_compile.ts";

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

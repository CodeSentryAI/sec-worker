import { test } from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { checkErc20Abi } from "../src/verified/erc20_abi.ts";

const TARGET = { source_path: "src/Token.sol", contract_name: "Token" };
const source = "// 🦊 token\ncontract Token {}";
const functionAbi = (name: string, inputs: string[], output: string) => ({
  type: "function",
  name,
  inputs: inputs.map((type) => ({ type })),
  outputs: [{ type: output }],
});
const eventAbi = (name: string) => ({
  type: "event",
  name,
  inputs: [
    { type: "address", indexed: true },
    { type: "address", indexed: true },
    { type: "uint256", indexed: false },
  ],
});
const completeAbi = [
  { type: "constructor", inputs: [], stateMutability: "nonpayable" },
  functionAbi("totalSupply", [], "uint256"),
  functionAbi("balanceOf", ["address"], "uint256"),
  functionAbi("transfer", ["address", "uint256"], "bool"),
  functionAbi("transferFrom", ["address", "address", "uint256"], "bool"),
  functionAbi("approve", ["address", "uint256"], "bool"),
  functionAbi("allowance", ["address", "address"], "uint256"),
  eventAbi("Transfer"),
  eventAbi("Approval"),
];

function compilation(abi: unknown[], astMembers: unknown[] = []) {
  const declarationStart = Buffer.byteLength(source.slice(0, source.indexOf("contract")), "utf8");
  return {
    input: { sources: { [TARGET.source_path]: { content: source } } },
    output: {
      errors: [],
      contracts: { [TARGET.source_path]: { [TARGET.contract_name]: { abi } } },
      sources: {
        [TARGET.source_path]: {
          id: 0,
          ast: {
            nodeType: "SourceUnit",
            nodes: [{
              id: 1,
              nodeType: "ContractDefinition",
              id: 1,
              name: TARGET.contract_name,
              abstract: false,
              fullyImplemented: true,
              linearizedBaseContracts: [1],
              src: `${declarationStart}:16:0`,
              nodes: astMembers,
            }],
          },
        },
      },
    },
  };
}

test("ERC-20 required ABI surface passes with constructors and source locations", () => {
  const { input, output } = compilation(completeAbi);
  const result = checkErc20Abi(input, output, TARGET, "0.8.28");
  assert.equal(result.status, "complete");
  assert.equal(result.findings.length, 0);
});

test("missing ABI methods and omitted event declarations remain Signals before compiler integration", () => {
  const abi = completeAbi.filter((item) => {
    const entry = item as { name?: string };
    return entry.name !== "approve" && entry.name !== "Transfer";
  });
  const { input, output } = compilation(abi);
  const result = checkErc20Abi(input, output, TARGET, "0.8.28");
  assert.equal(result.status, "complete");
  assert.equal(result.findings.length, 2);
  assert.deepEqual(result.findings.map((finding) => finding.message).sort(), [
    "Compiler ABI for the selected contract does not list the mandatory ERC-20 item function approve(address,uint256); compiler-run provenance is not yet wired into the worker",
    "event Transfer(address,address,uint256) is absent from the compiler ABI; this alone does not show that the contract fails to emit the required event",
  ]);
  const method = result.findings.find((finding) => finding.rule_id === "erc20-abi.function-not-listed");
  const event = result.findings.find((finding) => finding.rule_id === "erc20-abi.event-declaration-not-listed");
  assert.ok(method);
  assert.equal(method.trust_tier, "signal");
  assert.equal("verification" in method, false);
  assert.equal(method.raw && (method.raw as { compiler_abi_pointer?: string }).compiler_abi_pointer?.includes("/contracts/"), true);
  assert.equal(method.location.file, TARGET.source_path);
  assert.equal(method.location.line, 2, "source offset is a UTF-8 byte offset");
  assert.ok(event);
  assert.equal(event.confidence, "low");
  assert.equal("verification" in event, false);
  assert.equal(event.location.line, 2);
});

test("fallback presence makes absent ABI entries indeterminate", () => {
  const { input, output } = compilation([], [{ nodeType: "FunctionDefinition", kind: "fallback" }]);
  const result = checkErc20Abi(input, output, TARGET, "0.8.28");
  assert.equal(result.status, "indeterminate");
  assert.equal(result.findings.length, 0);
  if (result.status === "indeterminate") assert.match(result.reason, /fallback/);
});

test("constructor assembly prevents Verified claims about ABI omissions", () => {
  const { input, output } = compilation([], [{
    nodeType: "FunctionDefinition",
    kind: "constructor",
    body: { nodeType: "Block", statements: [{ nodeType: "InlineAssembly" }] },
  }]);
  const result = checkErc20Abi(input, output, TARGET, "0.8.28");
  assert.equal(result.status, "indeterminate");
  assert.equal(result.findings.length, 0);
  if (result.status === "indeterminate") assert.match(result.reason, /constructor assembly/);
});

test("abstract contracts and compilation failures are not scored as ABI violations", () => {
  const abstract = compilation([]);
  abstract.output.sources[TARGET.source_path]!.ast.nodes[0]!.abstract = true;
  assert.equal(checkErc20Abi(abstract.input, abstract.output, TARGET, "0.8.28").status, "not-applicable");

  const failed = compilation([]);
  failed.output.errors = [{ severity: "error", message: "compile failed" }];
  const result = checkErc20Abi(failed.input, failed.output, TARGET, "0.8.28");
  assert.equal(result.status, "indeterminate");
  assert.equal(result.findings.length, 0);
});

test("source-key mismatches are indeterminate instead of producing Verified results", () => {
  const { input, output } = compilation([]);
  input.sources["extra.sol"] = { content: "contract Extra {}" };
  const result = checkErc20Abi(input, output, TARGET, "0.8.28");
  assert.equal(result.status, "indeterminate");
  assert.equal(result.findings.length, 0);
});

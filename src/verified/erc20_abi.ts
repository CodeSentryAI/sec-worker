import { Buffer } from "node:buffer";
import type { Finding } from "../types.ts";

type JsonObject = Record<string, unknown>;

export interface Erc20AbiTarget {
  source_path: string;
  contract_name: string;
}

export type Erc20AbiCheck =
  | { status: "complete"; findings: Finding[] }
  | { status: "indeterminate" | "not-applicable"; findings: []; reason: string };

interface AbiParameter {
  type?: string;
  indexed?: boolean;
}

interface AbiEntry {
  type?: string;
  name?: string;
  inputs?: AbiParameter[];
  outputs?: AbiParameter[];
}

interface Requirement {
  type: "function" | "event";
  name: string;
  inputs: Array<{ type: string; indexed?: boolean }>;
  outputs?: string[];
}

const REQUIRED: Requirement[] = [
  { type: "function", name: "totalSupply", inputs: [], outputs: ["uint256"] },
  { type: "function", name: "balanceOf", inputs: [{ type: "address" }], outputs: ["uint256"] },
  { type: "function", name: "transfer", inputs: [{ type: "address" }, { type: "uint256" }], outputs: ["bool"] },
  { type: "function", name: "transferFrom", inputs: [{ type: "address" }, { type: "address" }, { type: "uint256" }], outputs: ["bool"] },
  { type: "function", name: "approve", inputs: [{ type: "address" }, { type: "uint256" }], outputs: ["bool"] },
  { type: "function", name: "allowance", inputs: [{ type: "address" }, { type: "address" }], outputs: ["uint256"] },
  { type: "event", name: "Transfer", inputs: [{ type: "address", indexed: true }, { type: "address", indexed: true }, { type: "uint256", indexed: false }] },
  { type: "event", name: "Approval", inputs: [{ type: "address", indexed: true }, { type: "address", indexed: true }, { type: "uint256", indexed: false }] },
];

function object(value: unknown): JsonObject | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as JsonObject
    : undefined;
}

function sortedKeys(value: unknown): string[] | undefined {
  const record = object(value);
  return record ? Object.keys(record).sort() : undefined;
}

function sourceOffset(src: unknown): { start: number; length: number } | undefined {
  if (typeof src !== "string") return undefined;
  const [start, length] = src.split(":", 3).map(Number);
  return Number.isSafeInteger(start) && start >= 0 && Number.isSafeInteger(length) && length >= 0
    ? { start, length }
    : undefined;
}

function lineAt(source: string, byteOffset: number): number {
  return Buffer.from(source, "utf8").subarray(0, byteOffset).toString("utf8").split("\n").length;
}

function jsonPointerPart(value: string): string {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

function containsInlineAssembly(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsInlineAssembly);
  const node = object(value);
  if (!node) return false;
  if (node.nodeType === "InlineAssembly") return true;
  return Object.values(node).some(containsInlineAssembly);
}

function matches(entry: AbiEntry, requirement: Requirement): boolean {
  if (entry.type !== requirement.type || entry.name !== requirement.name) return false;
  const actualInputs = entry.inputs ?? [];
  if (actualInputs.length !== requirement.inputs.length) return false;
  if (!actualInputs.every((item, index) => {
    const expected = requirement.inputs[index]!;
    return item.type === expected.type
      && (expected.indexed === undefined || item.indexed === expected.indexed);
  })) return false;
  if (requirement.outputs) {
    const actualOutputs = entry.outputs ?? [];
    return actualOutputs.length === requirement.outputs.length
      && actualOutputs.every((item, index) => item.type === requirement.outputs![index]);
  }
  return true;
}

function isAbiEntry(value: unknown): value is AbiEntry {
  const entry = object(value);
  if (!entry || !["function", "event", "error", "constructor", "fallback", "receive"].includes(String(entry.type))) return false;
  if (["function", "event", "error"].includes(String(entry.type)) && typeof entry.name !== "string") return false;
  for (const key of ["inputs", "outputs"] as const) {
    const params = entry[key];
    const required = key === "inputs"
      ? ["function", "event", "error", "constructor"].includes(String(entry.type))
      : entry.type === "function";
    if (params === undefined && !required) continue;
    if (!Array.isArray(params) || !params.every((param) => {
      const item = object(param);
      return typeof item?.type === "string"
        && (item.indexed === undefined || typeof item.indexed === "boolean");
    })) return false;
  }
  return true;
}

/**
 * Verify only the mandatory ERC-20 ABI surface for one explicitly selected
 * concrete contract. This does not claim behavioral ERC-20 compliance.
 *
 * The check is indeterminate when a fallback can dispatch undeclared selectors,
 * since the ABI alone cannot establish which behavior it implements.
 */
export function checkErc20Abi(
  input: unknown,
  output: unknown,
  target: Erc20AbiTarget,
  compilerVersion: string,
): Erc20AbiCheck {
  const inObj = object(input);
  const outObj = object(output);
  if (!compilerVersion.trim()) {
    return { status: "indeterminate", findings: [], reason: "compiler version provenance is missing" };
  }
  const inputSources = object(inObj?.sources);
  const outputSources = object(outObj?.sources);
  const inputKeys = sortedKeys(inputSources);
  const outputKeys = sortedKeys(outputSources);
  if (!inputKeys || !outputKeys) {
    return { status: "indeterminate", findings: [], reason: "Standard JSON input/output must contain sources objects" };
  }
  if (inputKeys.length !== outputKeys.length || inputKeys.some((key, i) => key !== outputKeys[i])) {
    return { status: "indeterminate", findings: [], reason: "input/output source paths differ" };
  }

  const errors = Array.isArray(outObj?.errors) ? outObj.errors : [];
  if (errors.some((item) => object(item)?.severity === "error")) {
    return { status: "indeterminate", findings: [], reason: "solc output contains compilation errors" };
  }

  const inputSource = object(inputSources[target.source_path]);
  const sourceText = inputSource?.content;
  if (typeof sourceText !== "string") {
    return { status: "indeterminate", findings: [], reason: `no inline source content for ${target.source_path}` };
  }
  const outputSource = object(outputSources[target.source_path]);
  const ast = object(outputSource?.ast);
  const astNodes = Array.isArray(ast?.nodes) ? ast.nodes.map(object) : [];
  const contractNode = astNodes.find((node) => node?.nodeType === "ContractDefinition" && node.name === target.contract_name);
  if (!contractNode) {
    return { status: "indeterminate", findings: [], reason: `contract AST not found: ${target.source_path}::${target.contract_name}` };
  }
  if ((contractNode.abstract === true || contractNode.fullyImplemented === false)
    && contractNode.contractKind !== "interface") {
    return { status: "not-applicable", findings: [], reason: "abstract contracts are not evaluated as deployable ERC-20 implementations" };
  }
  if (!Array.isArray(contractNode.linearizedBaseContracts)
    || !Number.isSafeInteger(contractNode.id)) {
    return { status: "indeterminate", findings: [], reason: "C3 ancestry is missing from the compiler AST" };
  }
  const contractsById = new Map<number, JsonObject>();
  for (const source of Object.values(outputSources)) {
    const sourceAst = object(object(source)?.ast);
    const nodes = Array.isArray(sourceAst?.nodes) ? sourceAst.nodes : [];
    for (const candidate of nodes) {
      const node = object(candidate);
      if (node?.nodeType === "ContractDefinition" && Number.isSafeInteger(node.id)) {
        contractsById.set(node.id as number, node);
      }
    }
  }
  const ancestorContracts = contractNode.linearizedBaseContracts
    .filter((id): id is number => Number.isSafeInteger(id))
    .map((id) => contractsById.get(id));
  if (ancestorContracts.length !== contractNode.linearizedBaseContracts.length
    || ancestorContracts.some((node) => !node)) {
    return { status: "indeterminate", findings: [], reason: "one or more inherited contract ASTs are unavailable" };
  }
  if (ancestorContracts.some((ancestor) => {
    const nodes = Array.isArray(ancestor?.nodes) ? ancestor.nodes.map(object) : [];
    return nodes.some((node) => node?.nodeType === "FunctionDefinition"
      && node.kind === "constructor"
      && containsInlineAssembly(node.body));
  })) {
    return { status: "indeterminate", findings: [], reason: "constructor assembly may return runtime code outside the compiler ABI model" };
  }
  const members = Array.isArray(contractNode.nodes) ? contractNode.nodes.map(object) : [];

  const contracts = object(outObj?.contracts);
  const sourceContracts = object(contracts?.[target.source_path]);
  const compiledContract = object(sourceContracts?.[target.contract_name]);
  const abi = compiledContract?.abi;
  if (!Array.isArray(abi) || !abi.every(isAbiEntry)) {
    return { status: "indeterminate", findings: [], reason: "compiled contract ABI is missing or malformed" };
  }
  const actualAbi = abi as AbiEntry[];
  if (members.some((node) => node?.nodeType === "FunctionDefinition" && node.kind === "fallback")
    || actualAbi.some((entry) => entry.type === "fallback")) {
    return { status: "indeterminate", findings: [], reason: "fallback may implement selectors absent from the declared ABI" };
  }
  const span = sourceOffset(contractNode.src);
  if (!span || span.start > Buffer.byteLength(sourceText, "utf8")) {
    return { status: "indeterminate", findings: [], reason: "contract declaration has no valid source span" };
  }

  const pointer = `/contracts/${jsonPointerPart(target.source_path)}/${jsonPointerPart(target.contract_name)}/abi`;
  const missing = REQUIRED.filter((requirement) => !actualAbi.some((entry) => matches(entry, requirement)));
  const findings: Finding[] = missing.map((requirement) => {
      const signature = `${requirement.name}(${requirement.inputs.map((item) => item.type).join(",")})`;
      const missingItem = `${requirement.type} ${signature}`;
      if (requirement.type === "event") {
        return {
          rule_id: "erc20-abi.event-declaration-not-listed",
          ecosystem: "solidity",
          detector: `chainfox-erc20-abi ${compilerVersion}`,
          severity: "informational",
          confidence: "low",
          trust_tier: "signal",
          evidence_level: "static-evidence",
          location: { file: target.source_path, line: lineAt(sourceText, span.start) },
          message: `${missingItem} is absent from the compiler ABI; this alone does not show that the contract fails to emit the required event`,
          raw: {
            target,
            compiler_version: compilerVersion,
            missing_item: requirement,
            observed_abi: actualAbi,
            contract_span: span,
          },
        };
      }
      return {
        rule_id: "erc20-abi.function-not-listed",
        ecosystem: "solidity",
        detector: `chainfox-erc20-abi ${compilerVersion}`,
        severity: "medium",
        confidence: "high",
        trust_tier: "signal",
        evidence_level: "static-evidence",
        location: { file: target.source_path, line: lineAt(sourceText, span.start) },
        message: `Compiler ABI for the selected contract does not list the mandatory ERC-20 item ${missingItem}; compiler-run provenance is not yet wired into the worker`,
        raw: {
          target,
          compiler_version: compilerVersion,
          compiler_abi_pointer: `solc-output.json${pointer}`,
          source_content_pointer: `solc-input.json#/sources/${jsonPointerPart(target.source_path)}/content`,
          missing_item: requirement,
          observed_abi: actualAbi,
          contract_span: span,
        },
      };
    });
  return { status: "complete", findings };
}

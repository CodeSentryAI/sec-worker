#!/usr/bin/env node
import path from "node:path";
import { runMultiDetectorScan } from "./multi_run.ts";

function parseArgs(argv: string[]): Map<string, string> {
  const args = new Map<string, string>();
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i]!;
    if (!token.startsWith("--") || args.has(token)) throw new Error(`invalid or duplicate argument: ${token}`);
    const value = argv[++i];
    if (!value || value.startsWith("--")) throw new Error(`missing value for ${token}`);
    args.set(token, value);
  }
  return args;
}

async function main(): Promise<void> {
  try {
    const args = parseArgs(process.argv.slice(2));
    const allowed = new Set(["--input", "--output", "--detectors"]);
    for (const key of args.keys()) if (!allowed.has(key)) throw new Error(`unknown argument: ${key}`);
    const input = args.get("--input");
    const output = args.get("--output");
    const detectorList = args.get("--detectors");
    if (!input || !output || !detectorList) {
      throw new Error("usage: sec-multi-detect --input <dir> --output <fresh-dir> --detectors <id,id,...>");
    }
    const ids = detectorList.split(",").map((id) => id.trim());
    const result = await runMultiDetectorScan({
      inputDir: path.resolve(input),
      outputDir: path.resolve(output),
      detectorIds: ids,
    });
    console.log(`status:     ${result.aggregateStatus}`);
    console.log(`findings:   ${result.trustTierCounts.total}`);
    console.log(`verified:   ${result.trustTierCounts.verified}`);
    console.log(`signals:    ${result.trustTierCounts.signal}`);
    console.log(`report:     ${path.join(result.outputDir, "report.json")}`);
    process.exitCode = result.exitCode;
  } catch (error) {
    console.error(`error: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 2;
  }
}

main();

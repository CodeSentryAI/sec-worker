#!/usr/bin/env node
/** Thin wrapper to run the oracle python scripts under the pinned bench venv. */
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { toolchains } from "../config.ts";

const ORACLE_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "bench", "oracle");

const [, , cmd, ...args] = process.argv;
const scripts: Record<string, string> = {
  export: "exporter.py",
  diff: "diff.py",
  mining: "detector_apis.py",
};

if (!cmd || !scripts[cmd]) {
  console.error(`usage: npm run oracle -- <export|diff|mining> [args...]
  export <corpus.json> <out-dir> [--repos a,b]   export oracle snapshots
  diff <dirA> <dirB> [--file cfg.json]           structural snapshot diff
  mining [out.json]                              detector API/fact coverage`);
  process.exit(2);
}

const child = spawn(path.join(toolchains.benchVenv, "bin", "python"), [path.join(ORACLE_DIR, scripts[cmd]!), ...args], {
  stdio: "inherit",
});
child.on("exit", (code) => process.exit(code ?? 1));

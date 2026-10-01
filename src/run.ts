#!/usr/bin/env node
/**
 * sec-detect — run one detector against an input directory inside the bwrap sandbox.
 *
 * usage:
 *   npm run detect -- --detector <lockbud-stable|pecatch> --input <dir> --output <dir>
 *       [--checkers <comma,list>] [--keep-staging]
 *
 * exit codes (mirrors lockbud-stable's detect.sh convention):
 *   0 = ran clean, no findings
 *   1 = ran fine, findings reported
 *   2 = error (prepare/parse failure, detector crash, timeout)
 */
import { mkdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { runDetector } from "./detectors/registry.ts";
import type { Finding } from "./types.ts";

function usage(): never {
  console.error("usage: sec-detect --detector <id> --input <dir> --output <dir> [--checkers a,b] [--keep-staging]");
  process.exit(2);
}

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (!a.startsWith("--")) usage();
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) {
      out[key] = true;
    } else {
      out[key] = next;
      i++;
    }
  }
  return out;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const detectorId = String(args.detector ?? "");
  const inputDir = String(args.input ?? "");
  const outputDir = String(args.output ?? "");
  if (!detectorId || !inputDir || !outputDir) usage();

  const inStat = await stat(inputDir).catch(() => null);
  if (!inStat?.isDirectory()) {
    console.error(`error: input is not a directory: ${inputDir}`);
    process.exit(2);
  }
  await mkdir(outputDir, { recursive: true });

  const inputAbs = path.resolve(inputDir);
  const outputAbs = path.resolve(outputDir);

  let outcome;
  try {
    outcome = await runDetector({
      detectorId,
      inputDir: inputAbs,
      outputDir: outputAbs,
      checkers: typeof args.checkers === "string" ? args.checkers.split(",").map((s) => s.trim()).filter(Boolean) : undefined,
      keepStaging: args["keep-staging"] === true,
    });
  } catch (e) {
    console.error(`error: ${e instanceof Error ? e.message : e}`);
    process.exit(2);
  }

  const runMeta = {
    detector: detectorId,
    detectorVersion: outcome.version,
    ok: outcome.ok,
    timedOut: outcome.timedOut,
    exitCode: outcome.exitCode,
    findingsCount: outcome.findings.length,
    reportPath: outcome.reportPath,
    durationMs: outcome.durationMs,
    finishedAt: new Date().toISOString(),
  };
  await writeFile(path.join(outputAbs, "run.json"), JSON.stringify(runMeta, null, 2));
  await writeFile(path.join(outputAbs, "findings.json"), JSON.stringify(outcome.findings, null, 2));

  console.log(`detector:   ${detectorId} (${outcome.version})`);
  console.log(`ok:         ${outcome.ok}${outcome.timedOut ? " (TIMED OUT)" : ""}`);
  console.log(`exit code:  ${outcome.exitCode}`);
  console.log(`duration:   ${outcome.durationMs} ms`);
  console.log(`findings:   ${outcome.findings.length}`);
  for (const f of outcome.findings as Finding[]) {
    const loc = `${f.location.file}${f.location.line ? `:${f.location.line}` : ""}`;
    console.log(`  [${f.severity}/${f.confidence}] ${f.rule_id} at ${loc}`);
  }
  if (!outcome.ok && outcome.stderrExcerpt) {
    console.error(`--- stderr tail ---\n${outcome.stderrExcerpt}`);
  }

  process.exit(!outcome.ok ? 2 : outcome.findings.length > 0 ? 1 : 0);
}

main();

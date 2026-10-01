#!/usr/bin/env node
/**
 * Benchmark harness for the A/B/C costs of Solidity static analysis:
 *   [A] acquisition  (repo copy = clone proxy)
 *   [B] compilation  (solc --standard-json over all sources)
 *   [C] analysis     (slither model build + detectors)
 *
 * Modes:
 *   cold    copy repo + compile + bundle + analyze          (first submission)
 *   repo    no copy, fresh compile + bundle + analyze       (same repo resubmitted)
 *   bundle  load cached bundle + analyze only               (same repo+commit+compiler)
 *
 * detector-only cost is captured inside every analyze run as detectors_repeat_s.
 *
 * usage:
 *   npm run bench -- --corpus bench/corpus.json --out bench/results \
 *        [--repos a,b] [--modes cold,repo,bundle] \
 *        [--compile-timeout 600] [--analyze-timeout 900]
 */
import { spawn } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { toolchains } from "../config.ts";
import { installedSolcVersions, satisfiesPragmas } from "../detectors/pecatch.ts";
import { listFilesRecursive } from "../util.ts";

const DRIVER = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "bench", "slither_driver.py");

interface CorpusEntry {
  path: string;
  sourceDir: string;
  solc?: string; // explicit version like "0.5.16", or "auto"
}

type Corpus = Record<string, CorpusEntry>;

interface PhaseRow {
  repo: string;
  mode: string;
  loc: number;
  files: number;
  contracts: number;
  functions: number;
  acquire_s: number;
  compile_s: number;
  bundle_mb: number;
  cache_load_s: number;
  model_s: number;
  detectors_s: number;
  detectors_repeat_s: number;
  analysis_rss_mb: number;
  avg_rss_mb: number;
  solc: string;
  errors: string[];
  model_stages: Record<string, { count: number; total_sec: number; avg_sec: number }>;
}

/** Analysis = model build + detectors (excludes cache IO and compile). */
function analysisS(r: PhaseRow): number {
  return r.model_s + r.detectors_s;
}

/** Throughput efficiency: completed analyses / second / GB of peak RAM. */
function analysesPerSecPerGb(r: PhaseRow): number {
  const t = analysisS(r);
  const gb = r.analysis_rss_mb / 1024;
  return t > 0 && gb > 0 ? 1 / (t * gb) : 0;
}

function parseArgs(argv: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i]!.startsWith("--")) {
      out[argv[i]!.slice(2)] = argv[i + 1] && !argv[i + 1]!.startsWith("--") ? argv[i + 1]! : "true";
      if (out[argv[i]!.slice(2)] !== "true") i++;
    }
  }
  return out;
}

function spawnDriver(task: object, timeoutMs: number): Promise<any> {
  return new Promise((resolve, reject) => {
    const child = spawn(path.join(toolchains.benchVenv, "bin", "python"), [DRIVER], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`driver timeout after ${timeoutMs}ms`));
    }, timeoutMs);
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    child.stdin.write(JSON.stringify(task));
    child.stdin.end();
    child.on("exit", (code) => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error(`driver rc=${code}: ${stderr.slice(-600)}`));
      try {
        resolve(JSON.parse(stdout));
      } catch (e) {
        reject(new Error(`driver output unparsable: ${stderr.slice(-400)}`));
      }
    });
  });
}

async function resolveSolc(spec: string | undefined, sourceAbs: string): Promise<{ solcPath: string; version: string }> {
  const installed = await installedSolcVersions();
  if (installed.length === 0) throw new Error("no solc versions installed");
  if (spec && spec !== "auto") {
    const p = path.join(toolchains.solcSelectDir, "artifacts", `solc-${spec}`, `solc-${spec}`);
    return { solcPath: p, version: spec };
  }
  // auto: highest installed version satisfying every pragma in the source tree
  const constraints: string[] = [];
  const solFiles = (await listFilesRecursive(sourceAbs)).filter((f) => f.endsWith(".sol"));
  for (const f of solFiles) {
    const text = await readFile(f, "utf8");
    for (const m of text.matchAll(/pragma\s+solidity\s+([^;]+);/g)) constraints.push(m[1]!.trim());
  }
  for (const v of [...installed].reverse()) {
    const [a, b, c] = v.split(".").map(Number);
    if (constraints.length === 0 || satisfiesPragmas([a!, b!, c!], constraints)) {
      return { solcPath: path.join(toolchains.solcSelectDir, "artifacts", `solc-${v}`, `solc-${v}`), version: v };
    }
  }
  throw new Error(`no installed solc satisfies [${[...new Set(constraints)].join("; ")}]; installed: ${installed.join(", ")}`);
}

function countSource(sourceAbs: string): Promise<{ files: number; loc: number }> {
  return listFilesRecursive(sourceAbs).then((files) => {
    const sol = files.filter((f) => f.endsWith(".sol"));
    return Promise.all(sol.map((f) => readFile(f, "utf8").then((t) => t.split("\n").length))).then((lines) => ({
      files: sol.length,
      loc: lines.reduce((a, b) => a + b, 0),
    }));
  });
}

async function runOne(entry: CorpusEntry, name: string, mode: string, outDir: string, opts: { compileTimeout: number; analyzeTimeout: number; bundleSource?: string }): Promise<PhaseRow> {
  const repoAbs = path.resolve(entry.path);
  const sourceAbs = path.join(repoAbs, entry.sourceDir);
  const { solcPath, version } = await resolveSolc(entry.solc, sourceAbs);
  const src = await countSource(sourceAbs);

  let acquire_s = 0;
  let targetDir = sourceAbs;
  let repoRoot = repoAbs;
  let workdir: string | null = null;

  if (mode === "cold") {
    workdir = await mkdtemp(path.join(tmpdir(), "sec-bench-"));
    const t0 = Date.now();
    await cp(repoAbs, path.join(workdir, "repo"), { recursive: true });
    acquire_s = (Date.now() - t0) / 1000;
    targetDir = path.join(workdir, "repo", entry.sourceDir);
    repoRoot = path.join(workdir, "repo");
  }

  const bundlePath = mode === "bundle"
    ? path.join(outDir, name, "repo", "bundle.pkl")
    : workdir
      ? path.join(workdir, "bundle.pkl")
      : path.join(outDir, name, "repo", "bundle.pkl");
  await mkdir(path.dirname(bundlePath), { recursive: true });

  if (mode === "bundle") {
    // fresh compile+bundle if no cached bundle exists yet (documents cache-miss path)
    try {
      await readFile(bundlePath);
    } catch {
      console.log(`  [${name}] no cached bundle; compiling first`);
      await runOne(entry, name, "repo", outDir, opts);
    }
  }

  const task = {
    name,
    mode: mode === "bundle" ? "analyze" : "compile+analyze",
    targetDir,
    repoRoot,
    solc: solcPath,
    bundlePath,
    timeoutCompile: opts.compileTimeout,
    timeoutAnalyze: opts.analyzeTimeout,
  };

  let result: any;
  try {
    result = await spawnDriver(task, (opts.compileTimeout + opts.analyzeTimeout + 60) * 1000);
  } catch (e) {
    const row: PhaseRow = {
      repo: name, mode, loc: src.loc, files: src.files, contracts: 0, functions: 0,
      acquire_s, compile_s: 0, bundle_mb: 0, cache_load_s: 0, model_s: 0, detectors_s: 0,
      detectors_repeat_s: 0, analysis_rss_mb: 0, avg_rss_mb: 0, solc: version,
      errors: [String(e instanceof Error ? e.message : e).slice(0, 300)], model_stages: {},
    };
    if (workdir) await rm(workdir, { recursive: true, force: true });
    return row;
  }

  const row: PhaseRow = {
    repo: name,
    mode,
    loc: src.loc,
    files: src.files,
    contracts: result.metrics?.contracts ?? 0,
    functions: result.metrics?.functions ?? 0,
    acquire_s,
    compile_s: result.phases?.compile_s ?? 0,
    bundle_mb: result.metrics?.bundle_mb ?? 0,
    cache_load_s: result.phases?.cache_load_s ?? 0,
    model_s: result.phases?.model_s ?? 0,
    detectors_s: result.phases?.detectors_s ?? 0,
    detectors_repeat_s: result.phases?.detectors_repeat_s ?? 0,
    analysis_rss_mb: result.metrics?.analysis_rss_mb ?? 0,
    avg_rss_mb: result.metrics?.avg_rss_mb ?? 0,
    solc: version,
    errors: result.errors ?? [],
    model_stages: result.phases?.model_stages ?? {},
  };
  await mkdir(path.join(outDir, name), { recursive: true });
  await writeFile(path.join(outDir, name, `${mode}.json`), JSON.stringify({ ...row, raw: result }, null, 2));
  if (workdir) await rm(workdir, { recursive: true, force: true });
  return row;
}

function fmt(n: number): string {
  if (n >= 100) return n.toFixed(0);
  if (n >= 10) return n.toFixed(1);
  return n.toFixed(2);
}

function summary(rows: PhaseRow[]): string {
  const head = "| repo | mode | loc | contracts | funcs | acquire_s | compile_s | bundle_mb | cache_s | model_s | det_s | det_only_s | rss_mb | c/s | loc/s | a/s/GB | notes |";
  const sep = "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|";
  const lines = rows.map((r) => {
    const notes = r.errors.length ? r.errors[0]!.slice(0, 80) : "";
    return `| ${r.repo} | ${r.mode} | ${r.loc} | ${r.contracts} | ${r.functions} | ${fmt(r.acquire_s)} | ${fmt(r.compile_s)} | ${r.bundle_mb} | ${fmt(r.cache_load_s)} | ${fmt(r.model_s)} | ${fmt(r.detectors_s)} | ${fmt(r.detectors_repeat_s)} | ${r.analysis_rss_mb.toFixed(0)} | ${fmt(r.contracts / analysisS(r))} | ${fmt(r.loc / analysisS(r))} | ${analysesPerSecPerGb(r).toFixed(3)} | ${notes} |`;
  });
  return [head, sep, ...lines].join("\n");
}

/** Model-stage breakdown from slither's PhaseTimer (bundle-cached runs).
 * Timings are inclusive; exclusive = inclusive − direct children (known tree:
 * parse_contracts ⊇ cfg_analyze_* parts; analyze_contracts ⊇ convert_to_slithir,
 * compute_dependency, compute_storage_layout). */
const STAGE_CHILDREN: Record<string, string[]> = {
  parse_contracts: ["cfg_analyze_all_enums", "cfg_analyze_first_part", "cfg_analyze_second_part", "cfg_analyze_third_part", "cfg_analyze_using_for"],
  analyze_contracts: ["convert_to_slithir", "compute_dependency", "compute_storage_layout"],
};

function stageProfile(rows: PhaseRow[]): string {
  const profiled = rows.filter((r) => r.mode === "bundle" && Object.keys(r.model_stages).length > 0);
  if (profiled.length === 0) return "";
  const stageNames = [...new Set(profiled.flatMap((r) => Object.keys(r.model_stages)))]
    .filter((s) => !s.startsWith("detector:"))
    .sort((a, b) => {
      const maxSec = (s: string) => Math.max(...profiled.map((r) => r.model_stages[s]?.total_sec ?? 0));
      return maxSec(b) - maxSec(a);
    });
  const head = "| stage | " + profiled.map((r) => `${r.repo} (${r.contracts}c) incl/excl s`).join(" | ") + " |";
  const sep = "|---|" + profiled.map(() => "---").join("|") + "|";
  const lines = stageNames.map((s) => {
    const cells = profiled.map((r) => {
      const st = r.model_stages[s];
      if (!st) return "—";
      const excl = st.total_sec - (STAGE_CHILDREN[s] ?? []).reduce((acc, c) => acc + (r.model_stages[c]?.total_sec ?? 0), 0);
      const exclStr = (STAGE_CHILDREN[s] ?? []).some((c) => r.model_stages[c]) ? ` / ${Math.max(excl, 0).toFixed(2)}` : "";
      return `${st.total_sec.toFixed(2)}${exclStr}${st.count > 1 ? ` (${st.count}x)` : ""}`;
    });
    return `| ${s} | ${cells.join(" | ")} |`;
  });
  const detRows = [...new Set(profiled.flatMap((r) => Object.keys(r.model_stages)))]
    .filter((s) => s.startsWith("detector:"))
    .sort((a, b) => {
      const maxSec = (s: string) => Math.max(...profiled.map((r) => r.model_stages[s]?.total_sec ?? 0));
      return maxSec(b) - maxSec(a);
    })
    .slice(0, 8);
  const detLines = detRows.map((s) => {
    const cells = profiled.map((r) => {
      const st = r.model_stages[s];
      return st ? `${(st.total_sec / 2).toFixed(2)}` : "—";
    });
    return `| ${s.replace("detector:", "")} (per run) | ${cells.join(" | ")} |`;
  });
  return [
    "\n## Model-stage profile (bundle-cached: load→model→detectors)",
    "Timings inclusive; `incl / excl` = inclusive minus direct children where the stage has nested phases.",
    head, sep, ...lines, "", "Top detectors (seconds per run):", ...detLines,
  ].join("\n");
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const corpusPath = path.resolve(args.corpus ?? "bench/corpus.json");
  const outDir = path.resolve(args.out ?? "bench/results");
  const modes = (args.modes ?? "cold,repo,bundle").split(",").map((s) => s.trim());
  const repos = args.repos ? args.repos.split(",").map((s) => s.trim()) : null;
  const opts = {
    compileTimeout: Number(args["compile-timeout"] ?? 600),
    analyzeTimeout: Number(args["analyze-timeout"] ?? 900),
  };

  const corpus: Corpus = JSON.parse(await readFile(corpusPath, "utf8"));
  const names = repos ?? Object.keys(corpus);
  await mkdir(outDir, { recursive: true });

  const rows: PhaseRow[] = [];
  for (const name of names) {
    const entry = corpus[name];
    if (!entry) {
      console.error(`unknown corpus entry: ${name}`);
      continue;
    }
    console.log(`== ${name} (${entry.solc ?? "auto"} solc) ==`);
    for (const mode of modes) {
      process.stdout.write(`  ${mode}... `);
      let row: PhaseRow;
      try {
        row = await runOne(entry, name, mode, outDir, opts);
      } catch (e) {
        row = {
          repo: name, mode, loc: 0, files: 0, contracts: 0, functions: 0,
          acquire_s: 0, compile_s: 0, bundle_mb: 0, cache_load_s: 0, model_s: 0,
          detectors_s: 0, detectors_repeat_s: 0, analysis_rss_mb: 0, avg_rss_mb: 0, solc: "?",
          errors: [String(e instanceof Error ? e.message : e).slice(0, 200)], model_stages: {},
        };
      }
      rows.push(row);
      console.log(
        `acq=${fmt(row.acquire_s)}s compile=${fmt(row.compile_s)}s cache=${fmt(row.cache_load_s)}s `
        + `model=${fmt(row.model_s)}s det=${fmt(row.detectors_s)}s det_only=${fmt(row.detectors_repeat_s)}s `
        + `rss=${row.analysis_rss_mb.toFixed(0)}MB ${row.errors.length ? "ERRORS" : ""}`,
      );
    }
  }

  await writeFile(path.join(outDir, "results.json"), JSON.stringify(rows, null, 2));
  await writeFile(path.join(outDir, "summary.md"), summary(rows) + "\n" + stageProfile(rows) + "\n");
  console.log(`\nresults: ${outDir}/results.json, ${outDir}/summary.md`);
}

main();

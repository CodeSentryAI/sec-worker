/** Public repo URL entry point. Acquisition remains disabled until a trusted
 * quota-enforcing adapter is implemented and wired by the service. */
import { pathToFileURL } from "node:url";
import path from "node:path";
import { RepoUrlError } from "./repo_url.ts";
import { OutputOverlapError, StaleOutputError, scanRepoUrlCore } from "./internal/scan_repo_url_core.ts";
import type { ScanRepoResult } from "./internal/scan_repo_url_core.ts";

export { OutputOverlapError, StaleOutputError };
export type { ScanRepoResult };

export interface ScanRepoOptions {
  repoUrl: string;
  outputDir: string;
  detectorId: string;
  checkers?: string[];
  scratchRoot?: string;
}

const internalSeams = new Set(["cloneRunner", "runPipeline", "removeScratch"]);

/**
 * Public API. Runtime-check injected properties too: JavaScript callers can
 * bypass TypeScript's structural type checks. In particular, a bare git clone
 * runner is not an acceptable quota enforcement boundary.
 */
export async function scanRepoUrl(opts: ScanRepoOptions): Promise<ScanRepoResult> {
  if (opts && typeof opts === "object") {
    for (const key of internalSeams) {
      if (key in opts) {
        throw new TypeError(`scanRepoUrl does not accept internal option: ${key}`);
      }
    }
  }
  return scanRepoUrlCore({
    repoUrl: opts.repoUrl,
    outputDir: opts.outputDir,
    detectorId: opts.detectorId,
    ...(opts.checkers ? { checkers: opts.checkers } : {}),
    ...(opts.scratchRoot ? { scratchRoot: opts.scratchRoot } : {}),
  });
}

function parseCliArgs(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (!a.startsWith("--")) throw new Error(`unexpected argument: ${a}`);
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) out[key] = true;
    else { out[key] = next; i++; }
  }
  return out;
}

function usage(): never {
  console.error("usage: sec-scan-repo --repo-url https://github.com/OWNER/REPO --output <dir> --detector <id> [--checkers a,b] [--scratch-root <dir>]");
  process.exit(2);
}

async function main(): Promise<void> {
  let args: Record<string, string | boolean>;
  try { args = parseCliArgs(process.argv.slice(2)); }
  catch (e) { console.error(`error: ${e instanceof Error ? e.message : e}`); process.exit(2); }

  const repoUrl = typeof args["repo-url"] === "string" ? args["repo-url"] : "";
  const outputDir = typeof args.output === "string" ? args.output : "";
  const detectorId = typeof args.detector === "string" ? args.detector : "";
  if (!repoUrl || !outputDir || !detectorId) usage();

  try {
    const res = await scanRepoUrl({
      repoUrl,
      outputDir,
      detectorId,
      ...(typeof args.checkers === "string"
        ? { checkers: args.checkers.split(",").map((s) => s.trim()).filter(Boolean) }
        : {}),
      ...(typeof args["scratch-root"] === "string" ? { scratchRoot: args["scratch-root"] } : {}),
    });
    console.log(`repo:       ${res.repo.canonicalUrl}@${res.commit.slice(0, 12)}`);
    console.log(`output:     ${res.outputDir}`);
    console.log(`source:     removed (${res.sourceRemoved})`);
    console.log(`ok:         ${res.ok}`);
    console.log(`exit code:  ${res.exitCode}`);
    console.log(`findings:   ${res.findingsCount}`);
    console.log(`verified:   ${res.verifiedCount}`);
    console.log(`signals:    ${res.signalCount}`);
    process.exit(res.exitCode);
  } catch (e) {
    if (e instanceof RepoUrlError) console.error(`error: rejected repository URL (${e.reason}): ${e.message}`);
    else if (e instanceof OutputOverlapError) console.error(`error: ${e.message}`);
    else if (e instanceof StaleOutputError) console.error(`error: ${e.message}`);
    else console.error(`error: ${e instanceof Error ? e.message : e}`);
    process.exit(2);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  void main();
}

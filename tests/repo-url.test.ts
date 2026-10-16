import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parseRepoUrl, RepoUrlError } from "../src/repo_url.ts";
import { CloneError, classifyCloneProcessFailure, cloneArgv, cloneEnv } from "../src/clone.ts";
import {
  OutputOverlapError,
  StaleOutputError,
  scanRepoUrl,
  type ScanRepoOptions,
} from "../src/scan_repo_url.ts";
import type { Finding } from "../src/types.ts";

const GOOD_URL = "https://github.com/acme/token.git";
const COMMIT = "0123456789abcdef0123456789abcdef01234567";

async function tempRoot(): Promise<string> {
  return mkdtemp(path.join(os.tmpdir(), "sec-repo-url-test-"));
}

const signal: Finding = {
  rule_id: "pecatch.unchecked",
  ecosystem: "solidity",
  detector: "pecatch 1.0",
  severity: "medium",
  confidence: "high",
  trust_tier: "signal",
  evidence_level: "static-evidence",
  location: { file: "src/Token.sol", line: 10, column: 5 },
  message: "unchecked arithmetic",
  raw: { original: true },
};

function options(root: string, overrides: Partial<ScanRepoOptions> = {}): ScanRepoOptions {
  return {
    repoUrl: GOOD_URL,
    outputDir: path.join(root, "out"),
    scratchRoot: path.join(root, "scratch"),
    detectorId: "pecatch",
    cloneRunner: async (_ref, destDir) => {
      await mkdir(destDir, { recursive: true });
      await writeFile(path.join(destDir, "Token.sol"), "contract Token {}\n");
      return { destDir, commit: COMMIT, stdout: "", stderr: "" };
    },
    runPipeline: async ({ inputDir, outputDir }) => {
      assert.equal((await readFile(path.join(inputDir, "Token.sol"), "utf8")).includes("contract Token"), true);
      const reportPath = path.join(outputDir, "raw.json");
      await writeFile(reportPath, "{}\n");
      return {
        version: "pecatch-test",
        ok: true,
        timedOut: false,
        exitCode: 0,
        findings: [signal],
        reportPath,
        stderrExcerpt: "",
        durationMs: 12,
      };
    },
    ...overrides,
  };
}

test("accepts only GitHub repository URLs with exactly owner/repo", () => {
  const parsed = parseRepoUrl(GOOD_URL);
  assert.equal(parsed.canonicalUrl, "https://github.com/acme/token");
  assert.equal(parsed.cloneUrl, "https://github.com/acme/token.git");
  assert.equal(parsed.slug, "acme/token");
  assert.equal(parseRepoUrl("https://github.com/acme/token").repo, "token");
});

test("rejects credentials, non-GitHub hosts, ports, query, fragment, and malformed paths", () => {
  const invalid = [
    "",
    "git@github.com:acme/token.git",
    "https://user:pass@github.com/acme/token",
    "https://evil.example/acme/token",
    "https://github.com:443/acme/token",
    "https://github.com/acme/token?tab=readme",
    "https://github.com/acme/token#readme",
    "https://github.com/acme",
    "https://github.com/acme/token/extra",
    "https://github.com/acme/token/",
    "https://github.com/acme//token",
    "https://github.com/../token",
    "HTTPS://github.com/acme/token",
    "https://GitHub.com/acme/token",
    "https://bad--owner/token/repo",
    "https://github.com/acme/token\\extra",
    "https://github.com/acme%2Fother/token",
  ];
  for (const url of invalid) {
    assert.throws(() => parseRepoUrl(url), RepoUrlError, url);
  }
});

test("clone argv is fixed, shallow, nonrecursive, HTTPS-only; environment drops inherited git config", () => {
  const ref = parseRepoUrl(GOOD_URL);
  const argv = cloneArgv(ref, "/tmp/private/src");
  assert.deepEqual(argv, [
    "clone", "--depth", "1", "--single-branch", "--no-recurse-submodules", "--no-tags",
    "-c", "core.hooksPath=/dev/null", "-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=never",
    "-c", "credential.helper=", "-c", "advice.detachedHead=false", "--", ref.cloneUrl, "/tmp/private/src",
  ]);
  assert.equal(argv.includes("--recurse-submodules"), false);
  const env = cloneEnv({ PATH: "/usr/bin", HOME: "/home/test", GIT_CONFIG_KEY_0: "url.https://attacker.invalid.insteadOf" } as NodeJS.ProcessEnv);
  assert.equal(env.GIT_ALLOW_PROTOCOL, "https");
  assert.equal(env.GIT_CONFIG_NOSYSTEM, "1");
  assert.equal(env.GIT_CONFIG_GLOBAL, "/dev/null");
  assert.equal(env.GIT_TERMINAL_PROMPT, "0");
  assert.equal(env.HOME, "/nonexistent");
  assert.equal(env.XDG_CONFIG_HOME, "/nonexistent");
  assert.equal("GIT_CONFIG_KEY_0" in env, false);
  assert.equal("GIT_CONFIG_COUNT" in env, false);
});

test("clone timeout classification uses structured process code, not stderr text", () => {
  assert.deepEqual(classifyCloneProcessFailure(Object.assign(new Error("timed out"), { code: "ETIMEDOUT" })), {
    reason: "CLONE_TIMEOUT",
  });
  assert.deepEqual(classifyCloneProcessFailure(Object.assign(new Error("ETIMEDOUT"), { code: "EIO" })), {
    reason: "CLONE_FAILED",
  });
  assert.deepEqual(classifyCloneProcessFailure(new Error("ETIMEDOUT") as NodeJS.ErrnoException), {
    reason: "CLONE_FAILED",
  });
});

test("end-to-end injected clone and pipeline preserve Signal tier and emit provenance", async () => {
  const root = await tempRoot();
  try {
    const opts = options(root);
    const seen: { url?: string; input?: string } = {};
    const cloneRunner = opts.cloneRunner!;
    const runPipeline = opts.runPipeline!;
    opts.cloneRunner = async (ref, dest) => { seen.url = ref.cloneUrl; return cloneRunner(ref, dest); };
    opts.runPipeline = async (request) => { seen.input = request.inputDir; return runPipeline(request); };

    const result = await scanRepoUrl(opts);
    assert.equal(seen.url, "https://github.com/acme/token.git");
    assert.ok(seen.input);
    await assert.rejects(readdir(path.dirname(seen.input!)), { code: "ENOENT" });
    assert.equal(result.sourceRemoved, true);
    assert.equal(result.exitCode, 1);
    assert.equal(result.signalCount, 1);
    assert.equal(result.verifiedCount, 0);
    assert.deepEqual(JSON.parse(await readFile(result.findingsPath, "utf8")), [signal]);
    const run = JSON.parse(await readFile(result.runPath, "utf8"));
    assert.equal(run.source.commit, COMMIT);
    assert.equal(run.source.depth, 1);
    assert.equal(run.source.submodules, false);
    assert.equal(run.source.sourceRetained, false);
    assert.equal(run.signalCount, 1);
    assert.equal(run.verifiedCount, 0);
    assert.equal(await readFile(path.join(result.outputDir, "raw.json"), "utf8"), "{}\n");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("pipeline result maps clean, findings, and detector failure to exit statuses 0/1/2", async () => {
  const root = await tempRoot();
  try {
    const clean = await scanRepoUrl(options(root, { outputDir: path.join(root, "clean"), runPipeline: async () => ({
      version: "v", ok: true, timedOut: false, exitCode: 0, findings: [], reportPath: "raw.json", stderrExcerpt: "", durationMs: 1,
    }) }));
    const findings = await scanRepoUrl(options(root, { outputDir: path.join(root, "findings"), runPipeline: async () => ({
      version: "v", ok: true, timedOut: false, exitCode: 0, findings: [signal], reportPath: "raw.json", stderrExcerpt: "", durationMs: 1,
    }) }));
    const failed = await scanRepoUrl(options(root, { outputDir: path.join(root, "failed"), runPipeline: async () => ({
      version: "v", ok: false, timedOut: true, exitCode: null, findings: [], reportPath: "raw.json", stderrExcerpt: "timeout", durationMs: 1,
    }) }));
    assert.equal(clean.exitCode, 0);
    assert.equal(findings.exitCode, 1);
    assert.equal(failed.exitCode, 2);
    assert.equal(failed.sourceRemoved, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("temporary source is removed when clone or pipeline throws", async () => {
  for (const stage of ["clone", "pipeline"] as const) {
    const root = await tempRoot();
    try {
      const opts = options(root, stage === "clone"
        ? { cloneRunner: async () => { throw new Error("clone broke"); } }
        : { runPipeline: async () => { throw new Error("pipeline broke"); } });
      await assert.rejects(scanRepoUrl(opts), new RegExp(`${stage} broke`));
      assert.deepEqual(await readdir(opts.scratchRoot!), []);
      const metadata = JSON.parse(await readFile(path.join(opts.outputDir, "run.json"), "utf8"));
      assert.equal(metadata.status, stage === "clone" ? "ACQUISITION_FAILED" : "ANALYSIS_FAILED");
      assert.equal(metadata.errorSummary, `${stage} broke`);
      assert.equal(metadata.exitCode, 2);
      assert.equal(metadata.ok, false);
      assert.equal(metadata.source.sourceRemoved, true);
      assert.equal(metadata.source.sourceRetained, false);
      assert.deepEqual(metadata.sourceCleanup, { status: "removed" });
      assert.equal(metadata.source.commit, stage === "clone" ? null : COMMIT);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
});

test("explicit resource-limited partial clone fails closed and never invokes detector", async () => {
  const root = await tempRoot();
  try {
    let detectorCalled = false;
    const opts = options(root, {
      cloneRunner: async (_ref, destDir) => {
        await mkdir(destDir, { recursive: true });
        await writeFile(path.join(destDir, "Partial.sol"), "contract Partial {}\n");
        throw new CloneError("checkout exceeded enforced disk quota", "adapter limit event", {
          reason: "RESOURCE_LIMIT",
          resource: "scratch_blocks",
          limit: 1024,
          observed: 1025,
        });
      },
      runPipeline: async () => {
        detectorCalled = true;
        throw new Error("detector must not run on partial checkout");
      },
    });

    await assert.rejects(scanRepoUrl(opts), /checkout exceeded enforced disk quota/);
    assert.equal(detectorCalled, false);
    assert.deepEqual(await readdir(opts.scratchRoot!), []);
    const findings = JSON.parse(await readFile(path.join(opts.outputDir, "findings.json"), "utf8"));
    assert.deepEqual(findings, []);
    const metadata = JSON.parse(await readFile(path.join(opts.outputDir, "run.json"), "utf8"));
    assert.equal(metadata.status, "ACQUISITION_FAILED");
    assert.equal(metadata.exitCode, 2);
    assert.equal(metadata.reason, "RESOURCE_LIMIT");
    assert.deepEqual(metadata.resourceLimit, { resource: "scratch_blocks", limit: 1024, observed: 1025 });
    assert.equal(metadata.source.commit, null);
    assert.equal(metadata.source.sourceRemoved, true);
    assert.equal(metadata.source.sourceRetained, false);
    assert.deepEqual(metadata.sourceCleanup, { status: "removed" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("temporary source is removed when output overlaps scratch root", async () => {
  const root = await tempRoot();
  try {
    const output = path.join(root, "overlap");
    const opts = options(root, { outputDir: output, scratchRoot: output });
    await assert.rejects(scanRepoUrl(opts), OutputOverlapError);
    assert.deepEqual(await readdir(output), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects stale output before cloning and preserves existing artifacts", async () => {
  const root = await tempRoot();
  try {
    const outputDir = path.join(root, "out");
    await mkdir(outputDir);
    await writeFile(path.join(outputDir, "old.json"), "old evidence\n");
    let cloned = false;
    const opts = options(root, { outputDir, cloneRunner: async () => { cloned = true; throw new Error("should not clone"); } });
    await assert.rejects(scanRepoUrl(opts), StaleOutputError);
    assert.equal(cloned, false);
    assert.equal(await readFile(path.join(outputDir, "old.json"), "utf8"), "old evidence\n");
    assert.deepEqual(await readdir(opts.scratchRoot!), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("cleanup failure never reports sourceRemoved=true", async () => {
  const root = await tempRoot();
  try {
    let scratch: string | undefined;
    const opts = options(root, {
      cloneRunner: async (_ref, destDir) => { scratch = path.dirname(destDir); return { destDir, commit: COMMIT, stdout: "", stderr: "" }; },
      runPipeline: async () => ({ version: "v", ok: true, timedOut: false, exitCode: 0, findings: [], reportPath: "raw.json", stderrExcerpt: "", durationMs: 1 }),
      removeScratch: async () => { throw new Error("cleanup denied"); },
    });
    await assert.rejects(scanRepoUrl(opts), /sourceRemoved=false/);
    assert.ok(scratch);
    assert.equal((await stat(scratch!)).isDirectory(), true);
    const metadata = JSON.parse(await readFile(path.join(opts.outputDir, "run.json"), "utf8"));
    assert.equal(metadata.source.sourceRemoved, false);
    assert.equal(metadata.source.sourceRetained, null);
    assert.deepEqual(metadata.sourceCleanup, { status: "failed", error: "cleanup denied" });
    assert.equal(metadata.detectorOk, true);
    assert.equal(metadata.status, "CLEANUP_FAILED");
    assert.equal(metadata.ok, false);
    assert.equal(metadata.exitCode, 2);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("realpath overlap check catches an output symlink into the scratch root", async () => {
  const root = await tempRoot();
  try {
    const scratchRoot = path.join(root, "scratch");
    await mkdir(scratchRoot);
    const outputAlias = path.join(root, "out-alias");
    await symlink(scratchRoot, outputAlias, "dir");
    const opts = options(root, { outputDir: outputAlias, scratchRoot });
    await assert.rejects(scanRepoUrl(opts), OutputOverlapError);
    assert.deepEqual(await readdir(scratchRoot), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

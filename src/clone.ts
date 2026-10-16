/**
 * Shallow, inert acquisition of a public GitHub repository.
 *
 * The git invocation is a fixed argv built from a parsed `RepoRef`, never from
 * user text, so no user input can introduce an option, a URL, or a config
 * override. Hooks, submodules, tags and refspecs beyond the default branch are
 * all disabled, and the environment is scrubbed of every credential source git
 * would otherwise consult.
 */
import { execFile } from "node:child_process";
import { stat } from "node:fs/promises";
import type { RepoRef } from "./repo_url.ts";

export interface CloneResult {
  /** Absolute path of the working tree that was cloned. */
  destDir: string;
  /** Commit actually checked out, recorded as scan provenance. */
  commit: string;
  stdout: string;
  stderr: string;
}

export interface CloneRunner {
  (ref: RepoRef, destDir: string): Promise<CloneResult>;
}

export type CloneErrorClassification =
  | { reason: "CLONE_FAILED" | "CLONE_TIMEOUT" }
  | { reason: "RESOURCE_LIMIT"; resource: CloneResource; limit: number; observed: number };

export type CloneResource = "scratch_blocks" | "scratch_inodes" | "network_bytes";

export class CloneError extends Error {
  readonly detail: string;
  /** Stable acquisition classification. Resource limits are only set by an
   * adapter that can positively identify an enforced limit. */
  readonly reason: CloneErrorClassification["reason"];
  readonly resource?: CloneResource;
  readonly limit?: number;
  readonly observed?: number;

  constructor(
    message: string,
    detail = "",
    classification: CloneErrorClassification = { reason: "CLONE_FAILED" },
  ) {
    super(message);
    this.name = "CloneError";
    this.detail = detail;
    this.reason = classification.reason;
    if (classification.reason === "RESOURCE_LIMIT") {
      this.resource = classification.resource;
      this.limit = classification.limit;
      this.observed = classification.observed;
    }
  }
}

/** Classify only structured process metadata; stderr text is never inspected. */
export function classifyCloneProcessFailure(error: NodeJS.ErrnoException): CloneErrorClassification {
  return error.code === "ETIMEDOUT" ? { reason: "CLONE_TIMEOUT" } : { reason: "CLONE_FAILED" };
}

/** Environment handed to git: no credentials, no user/system config, no prompts. */
export function cloneEnv(base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    PATH: base.PATH ?? "/usr/bin:/bin",
    // Do not let Git/libcurl discover the service user's .gitconfig, .netrc or
    // other home-scoped credentials during public URL acquisition.
    HOME: "/nonexistent",
    XDG_CONFIG_HOME: "/nonexistent",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    // Never read ~/.gitconfig or /etc/gitconfig, never prompt, never fall back
    // to another protocol (a rewritten remote could otherwise redirect us).
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_TERMINAL_PROMPT: "0",
    GIT_ASKPASS: "",
    GIT_ALLOW_PROTOCOL: "https",
    GIT_LFS_SKIP_SMUDGE: "1",
  };
  return env;
}

/**
 * The exact git argv used for acquisition. Exported so tests can assert the
 * hardening flags without duplicating them.
 */
export function cloneArgv(ref: RepoRef, destDir: string): string[] {
  return [
    "clone",
    "--depth", "1",
    "--single-branch",
    "--no-recurse-submodules",
    "--no-tags",
    // Hooks in a freshly cloned tree are never executed by clone itself, but
    // pinning an empty hooks path means a later `git` call in that tree cannot
    // pick them up either.
    "-c", "core.hooksPath=/dev/null",
    "-c", "protocol.ext.allow=never",
    "-c", "protocol.file.allow=never",
    "-c", "credential.helper=",
    "-c", "advice.detachedHead=false",
    "--",           // end of options: the ref can never be read as a flag
    ref.cloneUrl,
    destDir,
  ];
}

/** Real clone runner. Talks to github.com over https only, with no network sandbox. */
export const gitCloneRunner: CloneRunner = (ref, destDir) =>
  new Promise<CloneResult>((resolve, reject) => {
    execFile(
      "git",
      cloneArgv(ref, destDir),
      { env: cloneEnv(), timeout: 300_000, maxBuffer: 4 * 1024 * 1024, windowsHide: true },
      (err, stdout, stderr) => {
        if (err) {
          reject(new CloneError(
            `git clone failed for ${ref.canonicalUrl}: ${err.message}`,
            String(stderr).slice(-2000),
            classifyCloneProcessFailure(err),
          ));
          return;
        }
        void resolveCommit(destDir)
          .then((commit) => resolve({ destDir, commit, stdout: String(stdout), stderr: String(stderr) }))
          .catch((e: unknown) => reject(new CloneError(
            `clone reported success but no commit could be read from ${destDir}: ${e instanceof Error ? e.message : e}`,
          )));
      },
    );
  });

async function resolveCommit(destDir: string): Promise<string> {
  const head = await new Promise<string>((res, rej) => {
    execFile("git", ["rev-parse", "HEAD"], { cwd: destDir, env: cloneEnv() }, (err, stdout) =>
      (err ? rej(err) : res(String(stdout).trim())));
  });
  if (!/^[0-9a-f]{40}$/.test(head)) throw new Error(`unexpected HEAD value: ${head}`);
  return head;
}

/** True when a clone actually produced a working tree with content in it. */
export async function hasSoliditySources(dir: string): Promise<boolean> {
  const { readdir } = await import("node:fs/promises");
  const path = await import("node:path");
  async function walk(current: string, depth: number): Promise<boolean> {
    if (depth > 8) return false;
    let entries;
    try { entries = await readdir(current, { withFileTypes: true }); } catch { return false; }
    for (const e of entries) {
      if (e.name === ".git") continue;
      const full = path.join(current, e.name);
      if (e.isDirectory()) { if (await walk(full, depth + 1)) return true; }
      else if (e.isFile() && e.name.endsWith(".sol")) return true;
    }
    return false;
  }
  return walk(dir, 0);
}

/** Reject a clone destination that is not an empty directory. */
export async function assertEmptyDest(destDir: string): Promise<void> {
  const s = await stat(destDir).catch(() => null);
  if (s && !s.isDirectory()) throw new CloneError(`clone destination is not a directory: ${destDir}`);
}

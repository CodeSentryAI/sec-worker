import os from "node:os";
import path from "node:path";

/**
 * Toolchain locations on the host. Every directory listed here is bind-mounted
 * into the sandbox at its IDENTICAL absolute path so that venv shebangs and
 * baked rpaths keep resolving without any relocation logic.
 */
function home(rel: string): string {
  return path.join(os.homedir(), rel);
}

export const toolchains = {
  rust: process.env.SEC_RUST_TOOLCHAIN
    ?? home(".rustup/toolchains/nightly-2026-02-07-x86_64-unknown-linux-gnu"),
  lockbudBin: process.env.SEC_LOCKBUD_BIN
    ?? home("Projects/lockbud-stable/target/release/lockbud-stable"),
  pecatchVenv: process.env.SEC_PECATCH_VENV
    ?? home("sec-toolchains/venv-pecatch"),
  solcSelectDir: process.env.SEC_SOLC_SELECT_DIR
    ?? home(".solc-select"),
  pecatchSource: process.env.SEC_PECATCH_SOURCE
    ?? home("solidity-sec/code/peCatch/code"),
  benchVenv: process.env.SEC_BENCH_VENV
    ?? home("sec-toolchains/venv-bench"),
};

/** Gas checkers shipped by the peCatch artifact (register as slither detectors). */
export const PECATCH_CHECKERS = [
  "and-in-if",
  "implicit-return",
  "redundant-sload",
  "bool",
  "unchecked",
  "mem-call",
  "alloc-in-loop",
  "loop-invariant",
] as const;

export const DEFAULT_LIMITS = {
  rust: {
    memoryMb: 6144,
    cpuSeconds: 600,
    pids: 128,
    maxFileSizeMb: 512,
    wallSeconds: 900,
  },
  solidity: {
    memoryMb: 4096,
    cpuSeconds: 300,
    pids: 128,
    maxFileSizeMb: 256,
    wallSeconds: 600,
  },
} as const;

export const STDERR_EXCERPT_BYTES = 4000;

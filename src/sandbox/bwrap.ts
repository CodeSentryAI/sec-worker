import { spawn } from "node:child_process";
import type { SandboxMount, SandboxRequest, SandboxResult } from "../types.ts";

const BWRAP = process.env.SEC_BWRAP ?? "/usr/bin/bwrap";
const PRLIMIT = process.env.SEC_PRLIMIT ?? "/usr/bin/prlimit";

const BASE_RO_BINDS: SandboxMount[] = [
  { host: "/usr", sandbox: "/usr" },
  // Ubuntu 24.04 is usrmerged: /bin,/sbin,/lib,/lib64 are symlinks bwrap cannot
  // bind, so mount the real /usr/* trees at the classic paths binaries expect.
  { host: "/usr/bin", sandbox: "/bin", optional: true },
  { host: "/usr/sbin", sandbox: "/sbin", optional: true },
  { host: "/usr/lib", sandbox: "/lib", optional: true },
  { host: "/usr/lib64", sandbox: "/lib64", optional: true },
];

/**
 * Compose the full bwrap argv for a request.
 *
 * Isolation model:
 *  - all namespaces unshared (user, pid, net, ipc, uts, cgroup) for network:none
 *  - filesystem: only /usr,/lib*, explicit toolchain mounts, /work/input (RO),
 *    /work/output (RW). /etc, /home, /root, /mnt, /var, /run/user are NOT visible.
 *  - environment: cleared, then rebuilt from a minimal allowlist + request env.
 */
export function buildBwrapArgv(req: SandboxRequest): string[] {
  const ns = req.network === "host"
    ? ["--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try"]
    : ["--unshare-all"];

  const args: string[] = [
    ...ns,
    "--die-with-parent",
    "--new-session",
  ];

  for (const m of [...BASE_RO_BINDS, ...req.mounts]) {
    const flag = m.rw ? "--bind" : "--ro-bind";
    if (m.optional) args.push(`${flag}-try`, m.host, m.sandbox);
    else args.push(flag, m.host, m.sandbox);
  }

  args.push(
    "--proc", "/proc",
    "--dev", "/dev",
    "--tmpfs", "/tmp",
    "--tmpfs", "/run",
    "--clearenv",
    "--setenv", "PATH", "/usr/bin:/bin",
    "--setenv", "HOME", "/tmp",
    "--setenv", "TMPDIR", "/tmp",
    "--setenv", "LANG", "C.UTF-8",
    "--setenv", "LC_ALL", "C.UTF-8",
    "--setenv", "TERM", "dumb",
  );

  for (const [k, v] of Object.entries(req.env)) args.push("--setenv", k, v);

  if (req.cwd) args.push("--chdir", req.cwd);
  args.push("--", ...req.argv);
  return args;
}

function prlimitArgs(limits: SandboxRequest["limits"]): string[] {
  // RLIMIT_NPROC is deliberately NOT set here: unshare(CLONE_NEWUSER) charges
  // against the real host user's task count, so a low nproc breaks sandbox
  // startup on busy hosts. The pids limit is applied INSIDE the namespace
  // (see preparePayload) where it has a fresh per-namespace counter.
  return [
    `--as=${limits.memoryMb * 1024 * 1024}`,
    `--cpu=${limits.cpuSeconds}`,
    `--fsize=${limits.maxFileSizeMb * 1024 * 1024}`,
    "--",
  ];
}

/**
 * Apply the per-sandbox pids limit from inside the namespace and normalize the
 * payload to a bash invocation. Script-style requests keep their script;
 * argv-style requests are exec'd verbatim via the `exec "$@"` pattern.
 */
function preparePayload(req: SandboxRequest): string[] {
  const pidsPrefix = `ulimit -u ${Math.max(4, req.limits.pids)} 2>/dev/null || true; `;
  if (req.argv[0] === "/bin/sh" && req.argv[1] === "-c" && typeof req.argv[2] === "string") {
    return ["/bin/bash", "-c", `${pidsPrefix}${req.argv[2]}`];
  }
  return ["/bin/bash", "-c", `${pidsPrefix} exec "$@"`, "bash", ...req.argv];
}

function killTree(pid: number): void {
  try { process.kill(-pid, "SIGKILL"); } catch { /* already gone */ }
  try { process.kill(pid, "SIGKILL"); } catch { /* already gone */ }
}

function collect(stream: NodeJS.ReadableStream, cap: number): { text: () => string; truncated: () => boolean } {
  let size = 0;
  let over = false;
  const chunks: Buffer[] = [];
  stream.on("data", (c: Buffer) => {
    size += c.length;
    if (size > cap) { over = true; return; }
    chunks.push(c);
  });
  return {
    text: () => Buffer.concat(chunks).toString("utf8"),
    truncated: () => over,
  };
}

export async function runSandboxed(req: SandboxRequest): Promise<SandboxResult> {
  const cap = req.limits.outputCapBytes ?? 5 * 1024 * 1024;
  const argv = [PRLIMIT, ...prlimitArgs(req.limits), BWRAP, ...buildBwrapArgv({ ...req, argv: preparePayload(req) })];

  const child = spawn(argv[0]!, argv.slice(1), {
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });

  const stdout = collect(child.stdout!, cap);
  const stderr = collect(child.stderr!, cap);

  const started = Date.now();
  let timedOut = false;
  let settled = false;

  const timer = setTimeout(() => {
    timedOut = true;
    if (child.pid) killTree(child.pid);
  }, req.limits.wallSeconds * 1000);

  const exited = new Promise<void>((resolve) => {
    child.once("exit", () => { if (!settled) { settled = true; resolve(); } });
    child.once("error", () => { if (!settled) { settled = true; resolve(); } });
  });
  const pipes = Promise.all([
    new Promise<void>((r) => child.stdout!.once("end", () => r())),
    new Promise<void>((r) => child.stderr!.once("end", () => r())),
  ]);

  await Promise.all([exited, pipes]);
  clearTimeout(timer);
  // Detached spawn: the process group is the pid. Belt-and-braces cleanup; with
  // --unshare-pid, bwrap is pid 1 of the namespace, so its death reaps the rest.
  if (child.pid) killTree(child.pid);

  const durationMs = Date.now() - started;
  return {
    exitCode: child.exitCode,
    signal: child.signalCode,
    timedOut,
    stdout: stdout.text(),
    stderr: stderr.text(),
    durationMs,
    truncated: stdout.truncated() || stderr.truncated(),
  };
}

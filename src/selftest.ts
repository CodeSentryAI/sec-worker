#!/usr/bin/env node
/**
 * Sandbox containment self-test. Runs hostile probes INSIDE the bwrap sandbox
 * and asserts the expected containment. Run after any environment change:
 *
 *   npm run selftest
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { runSandboxed } from "./sandbox/bwrap.ts";
import type { SandboxRequest } from "./types.ts";

interface Probe {
  name: string;
  script: string;
  limits?: Partial<SandboxRequest["limits"]>;
  expect: (r: Awaited<ReturnType<typeof runSandboxed>>) => string | null; // null = pass
}

const PROBES: Probe[] = [
  {
    name: "basic execution (echo)",
    script: "echo BWRAP_OK",
    expect: (r) => (r.exitCode === 0 && r.stdout.trim() === "BWRAP_OK" ? null : `exit=${r.exitCode} stdout=${JSON.stringify(r.stdout)}`),
  },
  {
    name: "/etc not visible (shadow)",
    script: "test ! -e /etc/shadow",
    expect: (r) => (r.exitCode === 0 ? null : "/etc/shadow is visible"),
  },
  {
    name: "/home not visible",
    script: "test ! -e /home/chain-fox",
    expect: (r) => (r.exitCode === 0 ? null : "/home/chain-fox is visible"),
  },
  {
    name: "/mnt/c (Windows host) not visible",
    script: "test ! -e /mnt/c",
    expect: (r) => (r.exitCode === 0 ? null : "/mnt/c is visible"),
  },
  {
    name: "input directory is read-only",
    script: "touch /work/input/attacker-writes 2>/dev/null && exit 42 || exit 0",
    expect: (r) => (r.exitCode === 0 ? null : "write to RO input succeeded"),
  },
  {
    name: "output directory is writable",
    script: "touch /work/output/worker-writes && rm /work/output/worker-writes",
    expect: (r) => (r.exitCode === 0 ? null : `exit=${r.exitCode}`),
  },
  {
    name: "system dirs are read-only (/usr)",
    script: "touch /usr/bin/attacker-writes 2>/dev/null && exit 42 || exit 0",
    expect: (r) => (r.exitCode === 0 ? null : "write to /usr succeeded"),
  },
  {
    name: "environment is cleared (no host env leaks)",
    script: "env > /dev/null; test -z \"$(env | grep -E '^(SEC_|HTTPS?_PROXY=|AWS_|NVM_)' || true)\" && test \"$(printf %s \"$HOME\")\" = /tmp",
    expect: (r) => (r.exitCode === 0 ? null : "host environment leaked into sandbox"),
  },
  {
    name: "no network (TCP connect fails)",
    script: "bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null && exit 42 || exit 0",
    expect: (r) => (r.exitCode === 0 ? null : "network reachable inside sandbox"),
  },
  {
    name: "no network (DNS fails)",
    script: "getent hosts example.com >/dev/null 2>&1 && exit 42 || exit 0",
    expect: (r) => (r.exitCode === 0 ? null : "DNS resolution worked inside sandbox"),
  },
  {
    name: "fork bomb is bounded (nproc + wall clock)",
    script: "while true; do true & done",
    limits: { pids: 24, wallSeconds: 6, cpuSeconds: 5 },
    expect: (r) => (r.timedOut || r.exitCode !== 0 ? null : `fork bomb survived: exit=${r.exitCode}`),
  },
  {
    name: "wall-clock timeout enforced",
    script: "sleep 60",
    limits: { wallSeconds: 3, cpuSeconds: 60 },
    expect: (r) => (r.timedOut ? null : "sleep 60 was not killed at 3s"),
  },
  {
    name: "file size limit enforced (RLIMIT_FSIZE)",
    script: "dd if=/dev/zero of=/tmp/big bs=1M count=16 2>/dev/null; test $(stat -c %s /tmp/big 2>/dev/null || echo 0) -lt 16777216",
    limits: { maxFileSizeMb: 8, wallSeconds: 20 },
    expect: (r) => (r.exitCode === 0 ? null : "RLIMIT_FSIZE did not cap the file"),
  },
];

async function main(): Promise<void> {
  const staging = await mkdtemp(path.join(tmpdir(), "sec-selftest-"));
  const inputDir = path.join(staging, "input");
  const outputDir = path.join(staging, "output");
  const { mkdir } = await import("node:fs/promises");
  await mkdir(inputDir, { recursive: true });
  await mkdir(outputDir, { recursive: true });
  await writeFile(path.join(inputDir, "innocent.txt"), "hello");

  let failures = 0;
  for (const probe of PROBES) {
    const req: SandboxRequest = {
      argv: ["/bin/sh", "-c", probe.script],
      mounts: [
        { host: inputDir, sandbox: "/work/input" },
        { host: outputDir, sandbox: "/work/output", rw: true },
      ],
      env: {},
      cwd: "/work",
      network: "none",
      limits: {
        memoryMb: 2048,
        cpuSeconds: 60,
        pids: 512,
        maxFileSizeMb: 64,
        wallSeconds: 30,
        ...probe.limits,
      },
    };
    const r = await runSandboxed(req);
    const fail = probe.expect(r);
    if (fail) {
      failures++;
      console.log(`FAIL  ${probe.name} — ${fail}`);
    } else {
      console.log(`PASS  ${probe.name}`);
    }
  }

  await rm(staging, { recursive: true, force: true });
  console.log(failures === 0 ? `\nall ${PROBES.length} containment probes passed` : `\n${failures}/${PROBES.length} probes FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main();

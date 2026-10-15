import { test } from "node:test";
import assert from "node:assert/strict";
import { aggregateRunStatus } from "../src/run_status.ts";

const detector = { ok: true, timedOut: false, exitCode: 0, durationMs: 120 };

test("an ERC-20 compile timeout fails the whole run and contributes time", () => {
  assert.deepEqual(aggregateRunStatus(detector, {
    status: "indeterminate",
    timed_out: true,
    duration_ms: 800,
  }, 0), {
    ok: false,
    detectorOk: true,
    detectorExitCode: 0,
    timedOut: true,
    detectorTimedOut: false,
    detectorDurationMs: 120,
    erc20AbiDurationMs: 800,
    durationMs: 920,
    exitCode: 2,
  });
});

test("a not-applicable requested ERC-20 check cannot report overall success", () => {
  const status = aggregateRunStatus(detector, {
    status: "not-applicable",
    timed_out: false,
    duration_ms: 5,
  }, 0);
  assert.equal(status.ok, false);
  assert.equal(status.exitCode, 2);
  assert.equal(status.timedOut, false);
});

test("complete verifier runs preserve findings exit semantics and aggregate duration", () => {
  const status = aggregateRunStatus(detector, {
    status: "complete",
    timed_out: false,
    duration_ms: 80,
  }, 1);
  assert.equal(status.ok, true);
  assert.equal(status.exitCode, 1);
  assert.equal(status.durationMs, 200);
});

test("detector-only clean runs keep the original clean exit code", () => {
  const status = aggregateRunStatus(detector, undefined, 0);
  assert.equal(status.ok, true);
  assert.equal(status.exitCode, 0);
  assert.equal(status.durationMs, 120);
});

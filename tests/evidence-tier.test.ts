import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeReport as normalizeSlither } from "../src/detectors/pecatch.ts";
import { normalizeReport as normalizeLockbud } from "../src/detectors/lockbud.ts";
import type { Finding } from "../src/types.ts";

test("external Solidity detectors remain signals even with high confidence", () => {
  const findings = normalizeSlither({
    results: {
      detectors: [{
        check: "reentrancy-eth",
        impact: "High",
        confidence: "High",
        description: "Possible reentrancy",
        elements: [{ source_mapping: { filename_relative: "contracts/Vault.sol", lines: [42] } }],
      }],
    },
  }, "/input", "slither 0.11.6");

  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.trust_tier, "signal");
  assert.equal(findings[0]!.confidence, "high");
  assert.equal(findings[0]!.location.line, 42);
  assert.equal("verification" in findings[0]!, false);
});

test("Lockbud findings remain signals until a verifier supplies evidence", () => {
  const findings = normalizeLockbud({
    findings: [{
      lint: "double-lock",
      severity: "high",
      confidence: "high",
      title: "double lock",
      primary_location: { label: "src/lib.rs:12:4" },
    }],
  }, "lockbud 0.1.0");

  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.trust_tier, "signal");
  assert.equal(findings[0]!.location.file, "src/lib.rs");
});

test("verified findings require validator identity and at least one evidence reference", () => {
  const verified: Finding = {
    rule_id: "gas.repeated-sload",
    ecosystem: "solidity",
    detector: "chainfox-gas 0.1.0",
    severity: "low",
    confidence: "high",
    trust_tier: "verified",
    verification: {
      verifier_id: "foundry-gas-diff",
      verifier_version: "1",
      evidence: ["artifacts/gas-before-after.json"],
    },
    evidence_level: "static-evidence",
    location: { file: "Vault.sol", line: 42 },
    message: "Repeated storage read measured and validated",
    raw: {},
  };
  assert.equal(verified.trust_tier, "verified");
});

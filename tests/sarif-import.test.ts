import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { importSarif, normalizeSarif, runImportSarifCli } from "../src/sarif_import.ts";

const sarif = (runs: unknown[], version = "2.1.0") => ({ version, $schema: "https://json.schemastore.org/sarif-2.1.0.json", runs });
const run = (name: string, results: unknown[], extras: Record<string, unknown> = {}) => ({
  tool: { driver: { name, version: "1.2.3", rules: [{ id: "R1", name: "rule-one", shortDescription: { text: "Rule description" }, properties: { confidence: "medium" } }] } },
  results,
  ...extras,
});
const result = (overrides: Record<string, unknown> = {}) => ({
  ruleId: "R1",
  level: "warning",
  message: { text: "reported issue" },
  locations: [{ physicalLocation: { artifactLocation: { uri: "contracts/Token.sol" }, region: { startLine: 12, startColumn: 4 } } }],
  ...overrides,
});

test("normalizes SARIF finding with conservative signal trust and source span", () => {
  const imported = normalizeSarif(sarif([run("scanner", [result()])]), "abc123");
  assert.equal(imported.findings.length, 1);
  const finding = imported.findings[0]!;
  assert.equal(finding.rule_id, "R1");
  assert.equal(finding.detector, "scanner 1.2.3");
  assert.equal(finding.ecosystem, "solidity");
  assert.equal(finding.severity, "medium");
  assert.equal(finding.confidence, "medium");
  assert.equal(finding.trust_tier, "signal");
  assert.deepEqual(finding.location, { file: "contracts/Token.sol", line: 12, column: 4 });
  assert.deepEqual((finding.raw as any).sarif.payload, result());
  assert.equal((finding.raw as any).sarif.rule_metadata.id, "R1");
});

test("imports multiple runs and tools while resolving ruleIndex and retaining per-result provenance", () => {
  const second = {
    tool: { driver: { name: "second-tool", rules: [{ id: "S2", shortDescription: { text: "second rule" } }] } },
    results: [{ ruleIndex: 0, message: { text: "second result" } }],
  };
  const imported = normalizeSarif(sarif([run("first-tool", [result()]), second]), "hash");
  assert.equal(imported.metadata.runCount, 2);
  assert.deepEqual(imported.findings.map((f) => f.detector), ["first-tool 1.2.3", "second-tool"]);
  assert.deepEqual(imported.findings.map((f) => f.rule_id), ["R1", "S2"]);
  assert.deepEqual(imported.findings.map((f) => (f.raw as any).sarif.run_index), [0, 1]);
  assert.equal((imported.findings[1]!.raw as any).sarif.payload.message.text, "second result");
});

test("resolves result.rule through an extension component and preserves the resolved metadata", () => {
  const extendedRun = {
    tool: {
      driver: { name: "driver", rules: [{ id: "DUP", shortDescription: { text: "driver rule" } }] },
      extensions: [{ name: "extension", version: "4.0", rules: [{ id: "EXT", defaultConfiguration: { level: "error" }, shortDescription: { text: "extension rule" } }] }],
    },
    results: [{
      ruleId: "EXT",
      rule: { id: "EXT", index: 0, toolComponent: { name: "extension", index: 0 } },
      message: { text: "from extension" },
    }],
  };
  const finding = normalizeSarif(sarif([extendedRun]), "hash").findings[0]!;
  assert.equal(finding.rule_id, "EXT");
  assert.equal((finding.raw as any).sarif.rule_metadata.id, "EXT");
  assert.equal((finding.raw as any).sarif.rule_component.name, "extension");
  assert.equal((finding.raw as any).sarif.tool.extensions[0].version, "4.0");
  assert.equal(finding.severity, "high");
});

test("rejects conflicting and unresolvable rule references rather than selecting another rule", () => {
  const tool = {
    driver: { name: "driver", rules: [{ id: "A" }, { id: "B" }] },
    extensions: [{ name: "extension", rules: [{ id: "C" }] }],
  };
  const mk = (r: unknown) => sarif([{ tool, results: [{ ...result(), ...r as object }] }]);
  assert.throws(() => normalizeSarif(mk({ ruleId: "A", ruleIndex: 0, rule: { id: "B", index: 1 } }), "hash"), /conflicts with ruleId/);
  assert.throws(() => normalizeSarif(mk({ ruleId: "C", rule: { id: "C", index: 0, toolComponent: { name: "wrong", index: 0 } } }), "hash"), /conflicts with the resolved component/);
  assert.throws(() => normalizeSarif(mk({ ruleId: "C", rule: { id: "C", index: 7, toolComponent: { index: 0 } } }), "hash"), /does not reference a declared rule/);
});

test("matches hierarchical rule IDs with multiple slash components", () => {
  const input = sarif([{
    tool: { driver: { name: "scanner", rules: [{ id: "BASE" }] } },
    results: [{ ruleId: "BASE/feature/subfeature", ruleIndex: 0, message: { text: "hierarchical id" } }],
  }]);
  assert.equal(normalizeSarif(input, "hash").findings[0]!.rule_id, "BASE/feature/subfeature");
});

test("keeps findings with missing locations using explicit unknown path", () => {
  const imported = normalizeSarif(sarif([run("scanner", [result({ locations: undefined })])]), "hash");
  assert.deepEqual(imported.findings[0]!.location, { file: "<unknown>" });
  assert.equal(imported.metadata.resultCount, 1);
});

test("uses the first physical location even when logical location appears first", () => {
  const imported = normalizeSarif(sarif([run("scanner", [result({ locations: [
    { logicalLocations: [{ fullyQualifiedName: "Token.transfer" }] },
    { physicalLocation: { artifactLocation: { uri: "src/Token.sol" }, region: { startLine: 8 } } },
  ] })])]), "hash");
  assert.deepEqual(imported.findings[0]!.location, { file: "src/Token.sol", line: 8 });
});

test("preserves file URI authorities and does not decode escaped relative path separators", () => {
  const findings = normalizeSarif(sarif([run("scanner", [
    result({ locations: [{ physicalLocation: { artifactLocation: { uri: "file://buildhost/work/Token%20File.sol" } } }] }),
    result({ locations: [{ physicalLocation: { artifactLocation: { uri: "src/segment%2Fname.sol" } } }] }),
    result({ locations: [{ physicalLocation: { artifactLocation: { uri: "file:///work/a%2Fb.sol" } } }] }),
  ])]), "hash").findings;
  assert.equal(findings[0]!.location.file, "//buildhost/work/Token File.sol");
  assert.equal(findings[1]!.location.file, "src/segment%2Fname.sol");
  assert.equal(findings[2]!.location.file, "/work/a%2Fb.sol");
});

test("rejects file URI dot parents before URL normalization can hide them", () => {
  for (const uri of ["file:///workspace/a/../Token.sol", "file:///workspace/a/%2e%2e/Token.sol"]) {
    const input = sarif([run("scanner", [result({ locations: [{ physicalLocation: { artifactLocation: { uri } } }] })])]);
    assert.throws(() => normalizeSarif(input, "hash"), /file URI path containing '\.\.'/);
  }
});

test("resolves nested originalUriBaseIds and run artifact index locations", () => {
  const input = sarif([{
    tool: { driver: { name: "scanner" } },
    originalUriBaseIds: {
      ROOT: { uri: "file:///workspace/" },
      SRC: { uri: "src/", uriBaseId: "ROOT" },
    },
    artifacts: [{ location: { uri: "file:///workspace/src/Indexed.sol" } }],
    results: [
      result({ locations: [{ physicalLocation: { artifactLocation: { uri: "Token.sol", uriBaseId: "SRC" } } }] }),
      result({ locations: [{ physicalLocation: { artifactLocation: { index: 0 } } }] }),
      result({ locations: [{ physicalLocation: { artifactLocation: { uri: "file:///workspace/src/Indexed.sol", index: 0 } } }] }),
    ],
  }]);
  const findings = normalizeSarif(input, "hash").findings;
  assert.deepEqual(findings.map((f) => f.location.file), [
    "/workspace/src/Token.sol",
    "/workspace/src/Indexed.sol",
    "/workspace/src/Indexed.sol",
  ]);
});

test("resolves nested uriBaseId references without dot parents, including root-relative paths", () => {
  const input = sarif([{
    tool: { driver: { name: "scanner" } },
    originalUriBaseIds: {
      ROOT: { uri: "file:///workspace/a/" },
      SRC: { uri: "src/", uriBaseId: "ROOT" },
      DEEP: { uri: "deep/", uriBaseId: "SRC" },
      ROOTED: { uri: "/project/", uriBaseId: "ROOT" },
    },
    results: [
      result({ locations: [{ physicalLocation: { artifactLocation: { uri: "Token.sol", uriBaseId: "DEEP" } } }] }),
      result({ locations: [{ physicalLocation: { artifactLocation: { uri: "Token.sol", uriBaseId: "ROOTED" } } }] }),
    ],
  }]);
  assert.deepEqual(normalizeSarif(input, "hash").findings.map((f) => f.location.file), [
    "/workspace/a/src/deep/Token.sol",
    "/project/Token.sol",
  ]);
});

test("rejects relative dot parents before file URI base resolution or URI/index comparison", () => {
  const base = {
    tool: { driver: { name: "scanner" } },
    originalUriBaseIds: { ROOT: { uri: "file:///workspace/a/b/" } },
    artifacts: [{ location: { uri: "file:///workspace/a/Token.sol" } }],
    results: [result({ locations: [{ physicalLocation: { artifactLocation: { uri: "../Token.sol", uriBaseId: "ROOT", index: 0 } } }] })],
  };
  assert.throws(() => normalizeSarif(sarif([base]), "hash"), /relative URI path containing '\.\.'/);
  const nestedBase = {
    ...base,
    originalUriBaseIds: { ROOT: { uri: "file:///workspace/a/" }, SRC: { uri: "../src/", uriBaseId: "ROOT" } },
  };
  assert.throws(() => normalizeSarif(sarif([nestedBase]), "hash"), /relative URI path containing '\.\.'/);
});

test("resolves artifact parentIndex chains and preserves unresolved parent cycles or indexes", () => {
  const input = sarif([{
    tool: { driver: { name: "scanner" } },
    artifacts: [
      { location: { uri: "file:///workspace/contracts/" } },
      { location: { uri: "../src/", uriBaseId: undefined }, parentIndex: 0 },
      { location: { uri: "Token.sol" }, parentIndex: 1 },
      { location: { uri: "cyclic.sol" }, parentIndex: 4 },
      { location: { uri: "parent/" }, parentIndex: 3 },
      { location: { uri: "missing.sol" }, parentIndex: 99 },
    ],
    results: [0, 2, 3, 5].map((index) => result({ locations: [{ physicalLocation: { artifactLocation: { index } } }] })),
  }]);
  const files = normalizeSarif(input, "hash").findings.map((f) => f.location.file);
  assert.equal(files[0], "/workspace/contracts/");
  assert.equal(files[1], `sarif-container:${JSON.stringify([`sarif-container:${JSON.stringify(["/workspace/contracts/", "../src/"])}`, "Token.sol"])}`);
  assert.match(files[2]!, /^sarif-container:/);
  assert.match(files[2]!, /unresolved-artifact-cycle:/);
  assert.match(files[3]!, /^sarif-container:/);
  assert.match(files[3]!, /unresolved-artifact-index:99/);
});

test("archive member identity includes every container and cannot equal a top-level path", () => {
  const input = sarif([{
    tool: { driver: { name: "scanner" } },
    artifacts: [
      { location: { uri: "file:///workspace/bundle.zip" } },
      { location: { uri: "src/Token.sol" }, parentIndex: 0 },
      { location: { uri: "file:///workspace/src/Token.sol" } },
    ],
    results: [1, 2].map((index) => result({ locations: [{ physicalLocation: { artifactLocation: { index } } }] })),
  }]);
  const [member, topLevel] = normalizeSarif(input, "hash").findings.map((finding) => finding.location.file);
  assert.equal(member, `sarif-container:${JSON.stringify(["/workspace/bundle.zip", "src/Token.sol"])}`);
  assert.equal(topLevel, "/workspace/src/Token.sol");
  assert.notEqual(member, topLevel);
});

test("nested artifact URI and index compare the local member but emit full container identity", () => {
  const artifactLocation = { uri: "src/T.sol", index: 1 };
  const input = sarif([{
    tool: { driver: { name: "scanner" } },
    artifacts: [
      { location: { uri: "file:///work/a.zip" } },
      { location: { uri: "src/T.sol" }, parentIndex: 0 },
    ],
    results: [result({ locations: [{ physicalLocation: { artifactLocation } }] })],
  }]);
  assert.equal(normalizeSarif(input, "hash").findings[0]!.location.file, `sarif-container:${JSON.stringify(["/work/a.zip", "src/T.sol"])}`);
  artifactLocation.uri = "src/Other.sol";
  assert.throws(() => normalizeSarif(input, "hash"), /conflicts with the URI/);
});

test("container identity normalizes equivalent parent URIs and reserves its tagged namespace", () => {
  const base = {
    tool: { driver: { name: "scanner" } },
    artifacts: [
      { location: { uri: "file:///workspace/%54oken.zip" } },
      { location: { uri: "src/Member.sol" }, parentIndex: 0 },
    ],
    results: [result({ locations: [{ physicalLocation: { artifactLocation: { index: 1 } } }] })],
  };
  const first = normalizeSarif(sarif([base]), "hash").findings[0]!.location.file;
  base.artifacts[0]!.location.uri = "file:///workspace/Token.zip";
  const second = normalizeSarif(sarif([base]), "hash").findings[0]!.location.file;
  assert.equal(first, second);
  base.results[0]!.locations[0]!.physicalLocation.artifactLocation = { uri: first } as never;
  assert.throws(() => normalizeSarif(sarif([base]), "hash"), /reserved for imported artifact identities/);
});

test("compares equivalent encoded URI characters but preserves encoded separators", () => {
  const input = sarif([{
    tool: { driver: { name: "scanner" } },
    artifacts: [{ location: { uri: "file:///workspace/Token.sol" } }],
    results: [result({ locations: [{ physicalLocation: { artifactLocation: { uri: "file:///workspace/%54oken.sol", index: 0 } } }] })],
  }]);
  assert.equal(normalizeSarif(input, "hash").findings[0]!.location.file, "/workspace/Token.sol");
  input.runs[0]!.artifacts[0]!.location.uri = "file:///workspace/a%2Fb.sol";
  assert.throws(() => normalizeSarif(input, "hash"), /conflicts with the URI/);
});

test("percent escape case is equivalent while escaped percent cannot alias encoded slash", () => {
  const artifactLocation = { uri: "file:///work/a%2fB.sol", index: 0 };
  const input = sarif([{
    tool: { driver: { name: "scanner" } },
    artifacts: [{ location: { uri: "file:///work/a%2FB.sol" } }],
    results: [result({ locations: [{ physicalLocation: { artifactLocation } }] })],
  }]);
  assert.equal(normalizeSarif(input, "hash").findings[0]!.location.file, "/work/a%2FB.sol");
  artifactLocation.uri = "file:///work/a%252FB.sol";
  assert.throws(() => normalizeSarif(input, "hash"), /conflicts with the URI/);
  artifactLocation.uri = "file:///work/a%2FB.sol";
  input.runs[0]!.artifacts[0]!.location.uri = "file:///work/a%252FB.sol";
  assert.throws(() => normalizeSarif(input, "hash"), /conflicts with the URI/);
  artifactLocation.uri = "file:///work/a%252FB.sol";
  assert.equal(normalizeSarif(input, "hash").findings[0]!.location.file, "/work/a%252FB.sol");
});

test("retains driver versus extension rule component identity when rule IDs collide", () => {
  const input = sarif([{
    tool: {
      driver: { name: "driver", rules: [{ id: "DUP", shortDescription: { text: "driver rule" } }] },
      extensions: [{ name: "extension", rules: [{ id: "DUP", shortDescription: { text: "extension rule" } }] }],
    },
    results: [
      { ruleId: "DUP", ruleIndex: 0, rule: { id: "DUP", index: 0, toolComponent: { name: "driver" } }, message: { text: "driver finding" } },
      { ruleId: "DUP", ruleIndex: 0, rule: { id: "DUP", index: 0, toolComponent: { name: "extension", index: 0 } }, message: { text: "extension finding" } },
    ],
  }]);
  const findings = normalizeSarif(input, "hash").findings;
  assert.deepEqual(findings.map((f) => f.rule_id), ["DUP", "DUP"]);
  assert.deepEqual(findings.map((f) => f.rule_component), [
    { kind: "driver", name: "driver", descriptor_index: 0 },
    { kind: "extension", name: "extension", component_index: 0, descriptor_index: 0 },
  ]);
});

test("disambiguates same-name extensions without GUIDs using their component index", () => {
  const input = sarif([{
    tool: {
      driver: { name: "driver", rules: [] },
      extensions: [
        { name: "shared-extension", rules: [{ id: "RULE_A" }] },
        { name: "shared-extension", rules: [{ id: "RULE_B" }] },
      ],
    },
    results: [
      { ruleId: "RULE_A", rule: { id: "RULE_A", index: 0, toolComponent: { name: "shared-extension", index: 0 } }, message: { text: "first extension" } },
      { ruleId: "RULE_B", rule: { id: "RULE_B", index: 0, toolComponent: { name: "shared-extension", index: 1 } }, message: { text: "second extension" } },
    ],
  }]);
  const findings = normalizeSarif(input, "hash").findings;
  assert.deepEqual(findings.map((f) => f.rule_component), [
    { kind: "extension", name: "shared-extension", component_index: 0, descriptor_index: 0 },
    { kind: "extension", name: "shared-extension", component_index: 1, descriptor_index: 0 },
  ]);
});

test("duplicate descriptor IDs retain distinct normalized rule identities", () => {
  const input = sarif([{
    tool: { driver: { name: "scanner", rules: [{ id: "DUP" }, { id: "DUP" }] } },
    results: [0, 1].map((ruleIndex) => ({ ruleId: "DUP", ruleIndex, message: { text: "finding" } })),
  }]);
  const findings = normalizeSarif(input, "hash").findings;
  assert.deepEqual(findings.map((finding) => finding.rule_component?.descriptor_index), [0, 1]);
  assert.notDeepEqual(findings[0]!.rule_component, findings[1]!.rule_component);
});

test("preserves unresolved URI bases and artifact indexes as explicit source identities", () => {
  const input = sarif([{
    tool: { driver: { name: "scanner" } },
    results: [
      result({ locations: [{ physicalLocation: { artifactLocation: { uri: "Token.sol", uriBaseId: "MISSING" } } }] }),
      result({ locations: [{ physicalLocation: { artifactLocation: { index: 2 } } }] }),
      result({ locations: [{ physicalLocation: { artifactLocation: { uriBaseId: "MISSING" } } }] }),
    ],
  }]);
  assert.deepEqual(normalizeSarif(input, "hash").findings.map((f) => f.location.file), [
    "unresolved-uriBaseId:MISSING/Token.sol",
    "unresolved-artifact-index:2",
    "unresolved-uriBaseId:MISSING/",
  ]);
});

test("maps SARIF levels and security severity conservatively and never imports confidence as trust", () => {
  const results = [
    result({ level: "error", properties: { confidence: "HIGH", trust_tier: "verified" } }),
    result({ level: "note", properties: { "security-severity": "9.1", confidence: "moderate" } }),
    result({ level: "warning", properties: { "security-severity": "2.0", confidence: "unrecognized" } }),
    result({ kind: "review", level: "none", properties: { "security-severity": "not-a-score", confidence: 0.99 } }),
  ];
  const findings = normalizeSarif(sarif([run("scanner", results)]), "hash").findings;
  assert.deepEqual(findings.map((f) => f.severity), ["high", "critical", "low", "informational"]);
  assert.deepEqual(findings.map((f) => f.confidence), ["high", "medium", "low", "low"]);
  assert.ok(findings.every((f) => f.trust_tier === "signal"));
  assert.ok(findings.every((f) => !("verification" in f)));
});

test("uses rule defaultConfiguration.level when result level is omitted and explicit level takes precedence", () => {
  const input = sarif([{
    tool: { driver: { name: "scanner", rules: [
      { id: "DEFAULT_ERROR", defaultConfiguration: { level: "error" } },
      { id: "DEFAULT_NOTE", defaultConfiguration: { level: "note" } },
    ] } },
    results: [
      { ruleId: "DEFAULT_ERROR", ruleIndex: 0, message: { text: "error by default" } },
      { ruleId: "DEFAULT_NOTE", ruleIndex: 1, level: "warning", message: { text: "explicit warning" } },
    ],
  }]);
  assert.deepEqual(normalizeSarif(input, "hash").findings.map((f) => f.severity), ["high", "medium"]);
});

test("uses invocation ruleConfigurationOverrides for the referenced invocation", () => {
  const input = sarif([{
    tool: { driver: { name: "scanner", rules: [{ id: "R1", defaultConfiguration: { level: "error" } }] } },
    invocations: [
      { ruleConfigurationOverrides: [{ descriptor: { id: "R1", index: 0 }, configuration: { level: "note" } }] },
      { ruleConfigurationOverrides: [{ descriptor: { id: "R1", index: 0 }, configuration: { level: "warning" } }] },
    ],
    results: [
      { ruleId: "R1", ruleIndex: 0, provenance: { invocationIndex: 0 }, message: { text: "first invocation" } },
      { ruleId: "R1", ruleIndex: 0, provenance: { invocationIndex: 1 }, message: { text: "second invocation" } },
    ],
  }]);
  const findings = normalizeSarif(input, "hash").findings;
  assert.deepEqual(findings.map((f) => f.severity), ["low", "medium"]);
  assert.deepEqual(findings.map((f) => (f.raw as any).sarif.severity_resolution.source), [
    "invocation.ruleConfigurationOverrides",
    "invocation.ruleConfigurationOverrides",
  ]);
});

test("uses the sole invocation as the SARIF default when invocationIndex is omitted", () => {
  const input = sarif([{
    tool: { driver: { name: "scanner", rules: [{ id: "R1", defaultConfiguration: { level: "error" } }] } },
    invocations: [{ ruleConfigurationOverrides: [{ descriptor: { index: 0 }, configuration: { level: "note" } }] }],
    results: [{ ruleId: "R1", ruleIndex: 0, message: { text: "single invocation" } }],
  }]);
  const finding = normalizeSarif(input, "hash").findings[0]!;
  assert.equal(finding.severity, "low");
  assert.equal((finding.raw as any).sarif.severity_resolution.source, "invocation.ruleConfigurationOverrides");
});

test("fails closed when invocation severity configuration cannot be resolved", () => {
  const base = {
    tool: { driver: { name: "scanner", rules: [{ id: "R1" }] } },
    invocations: [{ ruleConfigurationOverrides: [{ descriptor: { id: "R1", index: 7 }, configuration: { level: "error" } }] }],
    results: [{ ruleId: "R1", ruleIndex: 0, provenance: { invocationIndex: 0 }, message: { text: "result" } }],
  };
  assert.throws(() => normalizeSarif(sarif([base]), "hash"), /does not reference a declared rule/);
  const malformed = structuredClone(base);
  malformed.invocations[0]!.ruleConfigurationOverrides = "bad" as never;
  assert.throws(() => normalizeSarif(sarif([malformed]), "hash"), /unsupported\/incomplete severity configuration/);
});

test("allows empty runs and strictly rejects invalid result level, kind, or message", () => {
  const empty = normalizeSarif(sarif([]), "hash");
  assert.equal(empty.metadata.runCount, 0);
  assert.equal(empty.metadata.resultCount, 0);
  assert.deepEqual(empty.findings, []);

  assert.throws(() => normalizeSarif(sarif([run("scanner", [result({ level: "urgent" })])]), "hash"), /level must be/);
  assert.throws(() => normalizeSarif(sarif([run("scanner", [result({ kind: "unknown" })])]), "hash"), /kind is not/);
  assert.throws(() => normalizeSarif(sarif([run("scanner", [result({ level: "error", kind: "pass" })])]), "hash"), /level must be none/);
  assert.throws(() => normalizeSarif(sarif([run("scanner", [result({ level: "none", kind: "fail" })])]), "hash"), /cannot be none/);
  assert.throws(() => normalizeSarif(sarif([run("scanner", [result({ level: "none" })])]), "hash"), /cannot be none/);
  assert.throws(() => normalizeSarif(sarif([run("scanner", [result({ message: { markdown: "**bad**" } })])]), "hash"), /markdown requires/);
  assert.throws(() => normalizeSarif(sarif([run("scanner", [result({ message: { id: "missing" } })])]), "hash"), /message.id cannot be resolved/);
});

test("resolves message ids and formats arguments, rejecting missing placeholders", () => {
  const descriptor = { id: "R1", messageStrings: { msg: { text: "Issue in {0}" } } };
  const findings = normalizeSarif(sarif([{
    tool: { driver: { name: "scanner", rules: [descriptor], globalMessageStrings: { global: { text: "Global {0}" } } } },
    results: [
      { ruleId: "R1", ruleIndex: 0, message: { id: "msg", arguments: ["Token"] } },
      { ruleId: "R1", ruleIndex: 0, message: { id: "global", arguments: ["vault"] } },
    ],
  }]), "hash").findings;
  assert.deepEqual(findings.map((f) => f.message), ["Issue in Token", "Global vault"]);
  assert.throws(() => normalizeSarif(sarif([{
    tool: { driver: { name: "scanner", rules: [descriptor] } },
    results: [{ ruleId: "R1", ruleIndex: 0, message: { id: "msg" } }],
  }]), "hash"), /missing placeholder/);
});

test("message.text takes precedence over an unresolved message.id", () => {
  const input = sarif([run("scanner", [result({ message: { text: "literal result", id: "missing" } })])]);
  assert.equal(normalizeSarif(input, "hash").findings[0]!.message, "literal result");
});

test("non-fail kinds force neutral severity despite a high security-severity property", () => {
  const findings = normalizeSarif(sarif([run("scanner", [result({
    kind: "review",
    level: "none",
    properties: { "security-severity": "10.0" },
  })])]), "hash").findings;
  assert.equal(findings[0]!.severity, "informational");
});

test("malformed and unsupported SARIF fail with explicit errors", () => {
  assert.throws(() => normalizeSarif({ version: "2.0.0", runs: [] }, "hash"), /unsupported SARIF version/);
  assert.throws(() => normalizeSarif(sarif([run("scanner", [{ level: "error", message: { text: "missing rule" } }])]), "hash"), /neither ruleId nor a resolvable rule reference/);
  assert.throws(() => normalizeSarif(sarif([run("scanner", [{ ruleId: "R1", message: { text: "first" } }, null])]), "hash"), /results\[1\] must be an object/);
});

test("CLI publishes no output directory on malformed input", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "sarif-import-"));
  const input = path.join(root, "bad.sarif");
  const output = path.join(root, "out");
  const bytes = Buffer.from('{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"broken"}},"results":[{"ruleId":"R1","message":{"text":"first"}},null]}]}\n');
  await writeFile(input, bytes);
  const oldError = console.error;
  const errors: string[] = [];
  console.error = (...args: unknown[]) => errors.push(args.join(" "));
  try {
    assert.equal(await runImportSarifCli(["--input", input, "--output", output]), 2);
  } finally {
    console.error = oldError;
  }
  assert.match(errors.join("\n"), /results\[1\] must be an object/);
  await assert.rejects(readFile(path.join(output, "report.sarif")));
  await assert.rejects(readFile(path.join(output, "findings.json")));
  await assert.rejects(readFile(path.join(output, "run.json")));
  await rm(root, { recursive: true, force: true });
});

test("invalid JSON is reported without publishing partial output", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "sarif-import-json-"));
  const input = path.join(root, "bad.json");
  const output = path.join(root, "out");
  const bytes = Buffer.from("{not-json\n");
  await writeFile(input, bytes);
  const oldError = console.error;
  const errors: string[] = [];
  console.error = (...args: unknown[]) => errors.push(args.join(" "));
  try {
    assert.equal(await runImportSarifCli(["--input", input, "--output", output]), 2);
  } finally {
    console.error = oldError;
  }
  assert.match(errors.join("\n"), /invalid JSON/);
  await assert.rejects(readFile(path.join(output, "report.sarif")));
  await rm(root, { recursive: true, force: true });
});

test("refuses stale normalized artifacts instead of leaving old findings beside a failed import", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "sarif-import-stale-"));
  const input = path.join(root, "bad.sarif");
  const output = path.join(root, "out");
  const oldFindings = Buffer.from('[{"rule_id":"stale"}]');
  await writeFile(input, "not-json");
  await mkdir(output);
  await writeFile(path.join(output, "findings.json"), oldFindings);
  const oldError = console.error;
  const errors: string[] = [];
  console.error = (...args: unknown[]) => errors.push(args.join(" "));
  try {
    assert.equal(await runImportSarifCli(["--input", input, "--output", output]), 2);
  } finally {
    console.error = oldError;
  }
  assert.match(errors.join("\n"), /output artifact already exists/);
  assert.deepEqual(await readFile(path.join(output, "findings.json")), oldFindings);
  await assert.rejects(readFile(path.join(output, "report.sarif")));
  await rm(root, { recursive: true, force: true });
});

test("successful CLI writes run, findings, and byte-for-byte original SARIF artifact", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "sarif-import-ok-"));
  const input = path.join(root, "input.sarif");
  const output = path.join(root, "out");
  const bytes = Buffer.from(`${JSON.stringify(sarif([run("scanner", [result()])]))}\n`);
  await writeFile(input, bytes);
  try {
    const child = spawnSync(process.execPath, ["--experimental-strip-types", path.resolve("src/import_sarif_cli.ts"), "--input", input, "--output", output], { encoding: "utf8" });
    assert.equal(child.status, 0, `${child.stdout}\n${child.stderr}`);
    assert.deepEqual(await readFile(path.join(output, "report.sarif")), bytes);
    const runMeta = JSON.parse(await readFile(path.join(output, "run.json"), "utf8"));
    const findings = JSON.parse(await readFile(path.join(output, "findings.json"), "utf8"));
    assert.equal(runMeta.resultCount, 1);
    assert.equal(runMeta.toolDrivers[0].name, "scanner");
    assert.equal(findings[0].trust_tier, "signal");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("successful CLI atomically replaces an empty existing output directory", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "sarif-import-empty-"));
  const input = path.join(root, "input.sarif");
  const output = path.join(root, "out");
  await mkdir(output);
  await writeFile(input, JSON.stringify(sarif([run("scanner", [result()])])));
  try {
    assert.equal(await runImportSarifCli(["--input", input, "--output", output]), 0);
    assert.equal(JSON.parse(await readFile(path.join(output, "run.json"), "utf8")).resultCount, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("publication failure removes all staged artifacts and leaves destination absent", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "sarif-import-publish-"));
  const input = path.join(root, "input.sarif");
  const output = path.join(root, "out");
  await writeFile(input, JSON.stringify(sarif([run("scanner", [result()])])));
  try {
    await assert.rejects(
      importSarif(input, output, async (staging) => {
        assert.deepEqual((await readdir(staging)).sort(), ["findings.json", "report.sarif", "run.json"]);
        throw new Error("simulated publication failure");
      }),
      /simulated publication failure/,
    );
    await assert.rejects(readFile(path.join(output, "report.sarif")));
    assert.deepEqual((await readdir(root)).sort(), ["input.sarif"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

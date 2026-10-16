import { readFile, mkdir, writeFile, lstat, mkdtemp, rename, rm, readdir } from "node:fs/promises";
import path from "node:path";
import type { Confidence, Finding, FindingRuleComponent, Severity, SecuritySignal } from "./types.ts";

type Obj = Record<string, unknown>;
export interface SarifImportResult {
  findings: Finding[];
  metadata: {
    importer: "sarif-2.1.0";
    status: "success";
    rawArtifact: string;
    rawSha256: string;
    sarifVersion: string;
    runCount: number;
    resultCount: number;
    toolDrivers: Array<{ runIndex: number; name: string; version?: string; informationUri?: string; rules: unknown[] }>;
  };
}

function isObject(value: unknown): value is Obj {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireObject(value: unknown, at: string): Obj {
  if (!isObject(value)) throw new Error(`${at} must be an object`);
  return value;
}

function stringField(value: unknown, at: string, optional = false): string | undefined {
  if (value === undefined && optional) return undefined;
  if (typeof value !== "string" || value.length === 0) throw new Error(`${at} must be a non-empty string`);
  return value;
}

function confidenceFrom(value: unknown): Confidence {
  if (typeof value !== "string") return "low";
  switch (value.trim().toLowerCase()) {
    case "high": case "certain": return "high";
    case "medium": case "moderate": return "medium";
    case "low": case "unknown": return "low";
    default: return "low";
  }
}

function severityFrom(level: unknown, properties: Obj): Severity {
  const securitySeverity = properties["security-severity"];
  if ((typeof securitySeverity === "string" || typeof securitySeverity === "number") && String(securitySeverity).trim() !== "") {
    const score = Number(securitySeverity);
    if (Number.isFinite(score) && score >= 0 && score <= 10) {
      if (score >= 9) return "critical";
      if (score >= 7) return "high";
      if (score >= 4) return "medium";
      if (score > 0) return "low";
      return "informational";
    }
  }
  switch (typeof level === "string" ? level.toLowerCase() : "") {
    case "error": return "high";
    case "warning": return "medium";
    case "note": return "low";
    case "none": return "informational";
    default: return "informational";
  }
}

function rejectUnsafeFileUri(uri: string): void {
  if (!/^file:/i.test(uri)) return;
  // Check the original spelling before URL removes dot segments. Escaped dots
  // are dots too; an escaped slash remains part of a segment.
  const pathPart = uri.replace(/^file:(?:\/\/[^/?#]*)?/i, "").split(/[?#]/, 1)[0]!;
  if (pathPart.split("/").some((part) => {
    try { return decodeURIComponent(part) === ".."; } catch { return false; }
  })) throw new Error("file URI path containing '..' is unsupported");
}

function decodeUriPreservingPercent(uri: string): string {
  // decodeURI would turn %25 into a literal %, so a double-encoded separator
  // (%252F) would become indistinguishable from an encoded separator (%2F).
  const canonicalEscapes = uri.replace(/%[0-9a-fA-F]{2}/g, (escape) => escape.toUpperCase());
  return decodeURI(canonicalEscapes.replace(/%25/g, "%2525"));
}

function normalizeUri(uri: string): string {
  // Keep escaped reserved characters and escaped percent signs distinct.
  // For file URIs retain a non-empty authority instead of collapsing it to pathname.
  if (/^file:/i.test(uri)) {
    rejectUnsafeFileUri(uri);
    try {
      const url = new URL(uri);
      const pathname = decodeUriPreservingPercent(url.pathname);
      return url.host ? `//${url.host}${pathname}` : pathname;
    } catch { return uri; }
  }
  try { return decodeUriPreservingPercent(uri); } catch { return uri; }
}

function resolveUriReference(reference: string, base?: string): string | undefined {
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(reference)) {
    if (/^sarif-container:/i.test(reference)) throw new Error("sarif-container URI scheme is reserved for imported artifact identities");
    rejectUnsafeFileUri(reference);
    return reference;
  }
  if (base === undefined) return undefined;
  const referencePath = reference.split(/[?#]/, 1)[0]!;
  if (referencePath.split("/").some((part) => {
    try { return decodeURIComponent(part) === ".."; } catch { return false; }
  })) throw new Error("relative URI path containing '..' is unsupported with a base");
  try {
    if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(base)) return new URL(reference, base).href;
    // RFC 3986 resolution also applies to relative base references. URL requires
    // an absolute base, so use a temporary authority and remove it afterwards.
    const resolved = new URL(reference, new URL(base, "https://sarif.invalid/"));
    if (resolved.origin !== "https://sarif.invalid") return resolved.href;
    const path = `${resolved.pathname}${resolved.search}${resolved.hash}`;
    return base.startsWith("/") || reference.startsWith("/") ? path : path.replace(/^\//, "");
  } catch { return undefined; }
}

function resolveUriBase(run: Obj, baseId: string, seen = new Set<string>()): string | undefined {
  if (seen.has(baseId)) return undefined;
  const basesValue = run.originalUriBaseIds;
  if (!isObject(basesValue)) return undefined;
  const baseValue = basesValue[baseId];
  if (!isObject(baseValue)) return undefined;
  seen.add(baseId);
  const uri = baseValue.uri;
  if (uri !== undefined && typeof uri !== "string") return undefined;
  const own = typeof uri === "string" ? uri : "";
  const parentId = baseValue.uriBaseId;
  if (parentId === undefined) return resolveUriReference(own);
  if (typeof parentId !== "string") return undefined;
  const parent = resolveUriBase(run, parentId, seen);
  return parent === undefined ? undefined : resolveUriReference(own, parent);
}

function containerMemberIdentity(parent: string, member: string): string {
  // The tagged tuple preserves the full archive/container chain and cannot
  // collapse into an unrelated filesystem path through URI resolution.
  return `sarif-container:${JSON.stringify([normalizeUri(parent), normalizeUri(member)])}`;
}

interface ResolvedArtifact { source: string | undefined; local: string | undefined }

function resolveArtifactIndex(run: Obj, index: number, resolving = new Set<number>()): ResolvedArtifact {
  const artifactsValue = run.artifacts;
  if (!Array.isArray(artifactsValue) || index >= artifactsValue.length) {
    const missing = `unresolved-artifact-index:${index}`;
    return { source: missing, local: missing };
  }
  if (resolving.has(index)) {
    const cycle = `unresolved-artifact-cycle:${index}`;
    return { source: cycle, local: cycle };
  }
  const artifact = requireObject(artifactsValue[index], `run.artifacts[${index}]`);
  if (artifact.location === undefined) {
    const missing = `unresolved-artifact-index:${index}`;
    return { source: missing, local: missing };
  }
  const location = requireObject(artifact.location, `run.artifacts[${index}].location`);
  const next = new Set(resolving);
  next.add(index);
  let parentUri: string | undefined;
  if (artifact.parentIndex !== undefined) {
    if (!Number.isInteger(artifact.parentIndex) || (artifact.parentIndex as number) < 0) {
      throw new Error(`run.artifacts[${index}].parentIndex must be a non-negative integer`);
    }
    const parentIndex = artifact.parentIndex as number;
    parentUri = next.has(parentIndex)
      ? `unresolved-artifact-cycle:${parentIndex}`
      : resolveArtifactIndex(run, parentIndex, next).source;
  }
  const memberUri = resolveArtifactUri(run, location, next);
  return {
    local: memberUri,
    source: parentUri === undefined ? memberUri : containerMemberIdentity(parentUri, memberUri ?? `unresolved-artifact-index:${index}`),
  };
}

function resolveArtifactUri(run: Obj, location: Obj, resolvingIndices = new Set<number>()): string | undefined {
  const uri = location.uri;
  if (uri !== undefined && typeof uri !== "string") throw new Error("artifactLocation.uri must be a string");
  const baseId = location.uriBaseId;
  if (baseId !== undefined && typeof baseId !== "string") throw new Error("artifactLocation.uriBaseId must be a string");
  let explicitUri: string | undefined;
  let explicitUriUnresolved = false;
  if (typeof uri === "string") {
    if (typeof baseId === "string") {
      if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(uri)) throw new Error("artifactLocation.uriBaseId must be absent when uri is absolute");
      const base = resolveUriBase(run, baseId);
      explicitUriUnresolved = base === undefined;
      explicitUri = explicitUriUnresolved ? `unresolved-uriBaseId:${baseId}/${uri}` : resolveUriReference(uri, base) ?? `unresolved-uriBaseId:${baseId}/${uri}`;
    } else {
      explicitUri = resolveUriReference(uri) ?? uri;
    }
  } else if (typeof baseId === "string") {
    const base = resolveUriBase(run, baseId);
    explicitUriUnresolved = base === undefined;
    explicitUri = base ?? `unresolved-uriBaseId:${baseId}/`;
  }

  const index = location.index;
  if (index === undefined) return explicitUri;
  if (!Number.isInteger(index) || (index as number) < 0) throw new Error("artifactLocation.index must be a non-negative integer");
  const indexed = resolveArtifactIndex(run, index as number, resolvingIndices);
  const indexedLocalUnresolved = indexed.local?.startsWith("unresolved-") ?? false;
  const indexedSourceUnresolved = indexed.source?.startsWith("unresolved-") ?? false;
  if (explicitUri !== undefined && indexed.local !== undefined && !explicitUriUnresolved && !indexedLocalUnresolved && normalizeUri(explicitUri) !== normalizeUri(indexed.local)) {
    throw new Error("artifactLocation.uri conflicts with the URI resolved from artifactLocation.index");
  }
  if (indexed.source !== undefined && !indexedSourceUnresolved) return indexed.source;
  return explicitUri ?? indexed.source ?? `unresolved-artifact-index:${index}`;
}

function primaryLocation(run: Obj, result: Obj): { file: string; line?: number; column?: number } {
  const locations = result.locations;
  if (locations === undefined) return { file: "<unknown>" };
  if (!Array.isArray(locations)) throw new Error("result.locations must be an array when present");
  let p: Obj | undefined;
  for (const [index, locationValue] of locations.entries()) {
    const candidate = requireObject(locationValue, `result.locations[${index}]`);
    if (candidate.physicalLocation === undefined) continue;
    p = requireObject(candidate.physicalLocation, `result.locations[${index}].physicalLocation`);
    break;
  }
  if (!p) return { file: "<unknown>" };
  const artifact = p.artifactLocation === undefined ? undefined : requireObject(p.artifactLocation, "physicalLocation.artifactLocation");
  const region = p.region === undefined ? undefined : requireObject(p.region, "physicalLocation.region");
  const uri = artifact === undefined ? undefined : resolveArtifactUri(run, artifact);
  let line: number | undefined;
  let column: number | undefined;
  if (region?.startLine !== undefined) {
    if (!Number.isInteger(region.startLine) || (region.startLine as number) < 1) throw new Error("physicalLocation.region.startLine must be a positive integer");
    line = region.startLine as number;
  }
  if (region?.startColumn !== undefined) {
    if (!Number.isInteger(region.startColumn) || (region.startColumn as number) < 1) throw new Error("physicalLocation.region.startColumn must be a positive integer");
    column = region.startColumn as number;
  }
  return {
    file: typeof uri === "string" && uri.length > 0 ? normalizeUri(uri) : "<unknown>",
    ...(line !== undefined ? { line } : {}),
    ...(column !== undefined ? { column } : {}),
  };
}

interface ResolvedRule { id: string; rule?: Obj; component: Obj; componentIdentity: FindingRuleComponent }

function toolComponentIdentity(tool: Obj, driver: Obj, component: Obj, at: string): FindingRuleComponent {
  const kind = component === driver ? "driver" : "extension";
  const name = stringField(component.name, `${at}.toolComponent.name`)!;
  const guid = component.guid === undefined ? undefined : stringField(component.guid, `${at}.toolComponent.guid`);
  const extensionsValue = tool.extensions === undefined ? [] : tool.extensions;
  if (!Array.isArray(extensionsValue)) throw new Error(`${at}.tool.extensions must be an array`);
  const componentIndex = kind === "extension"
    ? extensionsValue.findIndex((value) => value === component)
    : undefined;
  if (kind === "extension" && componentIndex === -1) throw new Error(`${at}.toolComponent cannot be assigned a stable extension index`);
  return {
    kind,
    name,
    ...(guid ? { guid } : {}),
    ...(componentIndex !== undefined ? { component_index: componentIndex } : {}),
  };
}

function ruleDescriptors(component: Obj, at: string): Obj[] {
  const rules = component.rules === undefined ? [] : component.rules;
  if (!Array.isArray(rules)) throw new Error(`${at}.rules must be an array`);
  return rules.map((value, index) => {
    const rule = requireObject(value, `${at}.rules[${index}]`);
    stringField(rule.id, `${at}.rules[${index}].id`);
    return rule;
  });
}

function resolveToolComponent(tool: Obj, driver: Obj, value: unknown, at: string): Obj {
  if (value === undefined) return driver;
  const ref = requireObject(value, `${at}.toolComponent`);
  const extensionsValue = tool.extensions === undefined ? [] : tool.extensions;
  if (!Array.isArray(extensionsValue)) throw new Error(`${at}.tool.extensions must be an array`);
  const extensions = extensionsValue.map((extension, i) => requireObject(extension, `${at}.tool.extensions[${i}]`));
  let component: Obj;
  if (ref.index !== undefined) {
    if (!Number.isInteger(ref.index) || (ref.index as number) < 0 || (ref.index as number) >= extensions.length) {
      throw new Error(`${at}.rule.toolComponent.index does not reference a declared extension`);
    }
    component = extensions[ref.index as number]!;
  } else if (ref.guid !== undefined) {
    const guid = stringField(ref.guid, `${at}.rule.toolComponent.guid`)!;
    const matches = [driver, ...extensions].filter((candidate) => candidate.guid === guid);
    if (matches.length !== 1) throw new Error(`${at}.rule.toolComponent.guid is missing or ambiguous`);
    component = matches[0]!;
  } else {
    component = driver;
  }
  if (ref.name !== undefined && stringField(ref.name, `${at}.rule.toolComponent.name`) !== component.name) {
    throw new Error(`${at}.rule.toolComponent.name conflicts with the resolved component`);
  }
  if (ref.guid !== undefined && component.guid !== ref.guid) throw new Error(`${at}.rule.toolComponent.guid conflicts with the resolved component`);
  return component;
}

function matchesDescriptorId(resultId: string, descriptorId: string): boolean {
  if (resultId === descriptorId) return true;
  return resultId.startsWith(`${descriptorId}/`) && resultId.length > descriptorId.length + 1;
}

function resolveRule(tool: Obj, driver: Obj, result: Obj, at: string): ResolvedRule {
  const resultId = stringField(result.ruleId, `${at}.ruleId`, true);
  const resultIndex = result.ruleIndex;
  if (resultIndex !== undefined && (!Number.isInteger(resultIndex) || (resultIndex as number) < 0)) {
    throw new Error(`${at}.ruleIndex must be a non-negative integer`);
  }

  const ref = result.rule === undefined ? undefined : requireObject(result.rule, `${at}.rule`);
  const referenceId = ref ? stringField(ref.id, `${at}.rule.id`, true) : undefined;
  const referenceIndex = ref?.index;
  if (referenceIndex !== undefined && (!Number.isInteger(referenceIndex) || (referenceIndex as number) < 0)) {
    throw new Error(`${at}.rule.index must be a non-negative integer`);
  }
  if (resultId !== undefined && referenceId !== undefined && resultId !== referenceId) {
    throw new Error(`${at}.rule.id conflicts with ruleId`);
  }
  if (resultIndex !== undefined && referenceIndex !== undefined && resultIndex !== referenceIndex) {
    throw new Error(`${at}.rule.index conflicts with ruleIndex`);
  }

  const component = resolveToolComponent(tool, driver, ref?.toolComponent, at);
  const descriptors = ruleDescriptors(component, `${at}.toolComponent`);
  const index = referenceIndex ?? resultIndex;
  const guid = ref?.guid === undefined ? undefined : stringField(ref.guid, `${at}.rule.guid`)!;
  let rule: Obj | undefined;
  if (index !== undefined) {
    if (index >= descriptors.length) throw new Error(`${at}.rule index does not reference a declared rule`);
    rule = descriptors[index as number]!;
  }
  if (guid !== undefined) {
    const byGuid = descriptors.filter((candidate) => candidate.guid === guid);
    if (byGuid.length !== 1) throw new Error(`${at}.rule.guid is missing or ambiguous in the resolved component`);
    if (rule && rule !== byGuid[0]) throw new Error(`${at}.rule.index and rule.guid identify different rules`);
    rule = byGuid[0];
  }

  let id = resultId ?? referenceId;
  if (rule) {
    const descriptorId = stringField(rule.id, `${at}.resolvedRule.id`)!;
    if (id !== undefined && !matchesDescriptorId(id, descriptorId)) {
      throw new Error(`${at}.ruleId does not identify the resolved rule`);
    }
    id ??= descriptorId;
  } else if (index !== undefined || guid !== undefined) {
    throw new Error(`${at}.rule reference cannot be resolved`);
  } else if (id !== undefined) {
    // ruleId-only results are valid without descriptor metadata. Attach metadata
    // only when the match is unique; duplicated ids require an explicit index.
    const sameId = descriptors.filter((candidate) => matchesDescriptorId(id!, String(candidate.id)));
    if (sameId.length > 1) throw new Error(`${at}.ruleId is ambiguous; ruleIndex or rule reference is required`);
    rule = sameId[0];
  }
  if (id === undefined) throw new Error(`${at} has neither ruleId nor a resolvable rule reference`);
  const componentIdentity = toolComponentIdentity(tool, driver, component, at);
  if (rule !== undefined) {
    componentIdentity.descriptor_index = descriptors.indexOf(rule);
    if (typeof rule.guid === "string") componentIdentity.descriptor_guid = rule.guid;
  }
  return { id, rule, component, componentIdentity };
}

function displayMessage(result: Obj, rule: Obj | undefined, component: Obj, at: string): string {
  const message = requireObject(result.message, `${at}.message`);
  const id = stringField(message.id, `${at}.message.id`, true);
  const text = message.text;
  if (text !== undefined && (typeof text !== "string" || text.trim().length === 0)) throw new Error(`${at}.message.text must be a non-empty string`);
  const markdown = message.markdown;
  if (markdown !== undefined && (typeof markdown !== "string" || markdown.trim().length === 0)) throw new Error(`${at}.message.markdown must be a non-empty string`);
  if (markdown !== undefined && text === undefined) throw new Error(`${at}.message.markdown requires a plain-text message.text`);
  if (text === undefined && id === undefined) throw new Error(`${at}.message requires text or id`);

  let idMessage: Obj | undefined;
  if (id !== undefined && text === undefined) {
    const strings = rule?.messageStrings === undefined ? undefined : requireObject(rule.messageStrings, `${at}.rule.messageStrings`);
    const globalStrings = component.globalMessageStrings === undefined ? undefined : requireObject(component.globalMessageStrings, `${at}.toolComponent.globalMessageStrings`);
    const candidate = strings?.[id] ?? globalStrings?.[id];
    if (candidate === undefined) throw new Error(`${at}.message.id cannot be resolved from rule or tool component messageStrings`);
    idMessage = requireObject(candidate, `${at}.messageStrings[${id}]`);
    if (typeof idMessage.text !== "string" || idMessage.text.trim().length === 0) throw new Error(`${at}.messageStrings[${id}].text must be a non-empty string`);
  }

  let args: unknown[] = [];
  if (message.arguments !== undefined) {
    if (!Array.isArray(message.arguments) || !message.arguments.every((arg) => typeof arg === "string")) {
      throw new Error(`${at}.message.arguments must be an array of strings`);
    }
    args = message.arguments;
  }
  const templates = [text, markdown, idMessage?.text, idMessage?.markdown].filter((s): s is string => typeof s === "string");
  for (const template of templates) {
    for (const match of template.matchAll(/(?<!\{)\{(\d+)\}(?!\})/g)) {
      if (Number(match[1]) >= args.length) throw new Error(`${at}.message.arguments is missing placeholder ${match[0]}`);
    }
  }
  const selected = typeof text === "string" ? text : idMessage!.text as string;
  return selected.replace(/\{\{|\}\}|\{(\d+)\}/g, (token, index: string | undefined) => {
    if (token === "{{") return "{";
    if (token === "}}") return "}";
    return String(args[Number(index)]);
  });
}

interface LevelResolution { level: string; source: string; }

function normalizedLevel(run: Obj, tool: Obj, driver: Obj, result: Obj, resolvedRule: ResolvedRule, at: string): LevelResolution {
  const validLevels = new Set(["warning", "error", "note", "none"]);
  const validKinds = new Set(["pass", "open", "informational", "notApplicable", "review", "fail"]);
  const kind = result.kind;
  if (kind !== undefined && (typeof kind !== "string" || !validKinds.has(kind))) throw new Error(`${at}.kind is not a SARIF 2.1.0 result kind`);
  let level = result.level;
  if (level !== undefined && (typeof level !== "string" || !validLevels.has(level))) throw new Error(`${at}.level must be warning, error, note, or none`);
  if (kind !== undefined && kind !== "fail") {
    if (level !== undefined && level !== "none") throw new Error(`${at}.level must be none when kind is ${kind}`);
    return { level: "none", source: "non-fail-kind" };
  }
  if (level === "none") throw new Error(`${at}.level cannot be none when kind defaults to fail`);
  if (level !== undefined) return { level, source: "result.level" };

  const provenance = result.provenance === undefined ? undefined : requireObject(result.provenance, `${at}.provenance`);
  const explicitInvocationIndex = provenance?.invocationIndex;
  if (explicitInvocationIndex !== undefined && (!Number.isInteger(explicitInvocationIndex) || (explicitInvocationIndex as number) < -1)) {
    throw new Error(`${at}.provenance.invocationIndex must be -1 or a non-negative integer`);
  }
  const invocationsValue = run.invocations;
  let invocation: Obj | undefined;
  let invocationIndex: number | undefined;
  if (invocationsValue === undefined) {
    if (explicitInvocationIndex !== undefined) throw new Error(`${at}.provenance.invocationIndex cannot resolve because run.invocations is absent`);
  } else {
    if (!Array.isArray(invocationsValue)) throw new Error(`${at}: unsupported/incomplete severity configuration: run.invocations must be an array`);
    invocationIndex = explicitInvocationIndex === undefined ? (invocationsValue.length === 1 ? 0 : -1) : explicitInvocationIndex as number;
    if (invocationIndex >= 0) {
      if (invocationIndex >= invocationsValue.length) throw new Error(`${at}: unsupported/incomplete severity configuration: provenance.invocationIndex is outside run.invocations`);
      invocation = requireObject(invocationsValue[invocationIndex], `run.invocations[${invocationIndex}]`);
    }
  }

  const overridesValue = invocation?.ruleConfigurationOverrides;
  if (overridesValue !== undefined && !Array.isArray(overridesValue)) {
    throw new Error(`${at}: unsupported/incomplete severity configuration: ruleConfigurationOverrides must be an array`);
  }
  let matchingOverride: Obj | undefined;
  if (Array.isArray(overridesValue) && resolvedRule.rule !== undefined) {
    for (const [index, value] of overridesValue.entries()) {
      const override = requireObject(value, `run.invocations[${invocationIndex}].ruleConfigurationOverrides[${index}]`);
      const descriptorRef = requireObject(override.descriptor, `run.invocations[${invocationIndex}].ruleConfigurationOverrides[${index}].descriptor`);
      const candidate = resolveRule(tool, driver, { rule: descriptorRef }, `${at}.ruleConfigurationOverrides[${index}]`);
      if (candidate.rule === undefined) {
        throw new Error(`${at}: unsupported/incomplete severity configuration: override descriptor cannot be resolved`);
      }
      if (candidate.rule === resolvedRule.rule && candidate.component === resolvedRule.component) {
        if (matchingOverride) throw new Error(`${at}: ambiguous severity configuration: multiple invocation overrides match this rule`);
        matchingOverride = override;
      }
    }
  }
  if (matchingOverride !== undefined) {
    if (!isObject(matchingOverride.configuration)) throw new Error(`${at}: unsupported/incomplete severity configuration: matching override has no configuration object`);
    const configuration = matchingOverride.configuration;
    level = configuration.level;
    if (level !== undefined && (typeof level !== "string" || !validLevels.has(level))) {
      throw new Error(`${at}: unsupported/incomplete severity configuration: override level must be warning, error, note, or none`);
    }
    if (level !== undefined) {
      if (level === "none") throw new Error(`${at}: invalid severity configuration: kind=fail cannot resolve to level none`);
      return { level, source: "invocation.ruleConfigurationOverrides" };
    }
  }

  if (resolvedRule.rule?.defaultConfiguration !== undefined) {
    const configuration = requireObject(resolvedRule.rule.defaultConfiguration, `${at}.rule.defaultConfiguration`);
    level = configuration.level;
    if (level !== undefined && (typeof level !== "string" || !validLevels.has(level))) {
      throw new Error(`${at}: unsupported/incomplete severity configuration: defaultConfiguration.level must be warning, error, note, or none`);
    }
    if (level !== undefined) {
      if (level === "none") throw new Error(`${at}: invalid severity configuration: kind=fail cannot resolve to level none`);
      return { level, source: "rule.defaultConfiguration" };
    }
  }
  return { level: "warning", source: "sarif-default" };
}

export function normalizeSarif(input: unknown, rawSha256: string, rawArtifact = "report.sarif"): SarifImportResult {
  const root = requireObject(input, "SARIF document");
  if (root.version !== "2.1.0") throw new Error(`unsupported SARIF version: ${String(root.version ?? "missing")}; expected 2.1.0`);
  if (!Array.isArray(root.runs)) throw new Error("SARIF document.runs must be an array");
  const findings: Finding[] = [];
  const toolDrivers: SarifImportResult["metadata"]["toolDrivers"] = [];
  let resultCount = 0;
  root.runs.forEach((runValue, runIndex) => {
    const run = requireObject(runValue, `runs[${runIndex}]`);
    const tool = requireObject(run.tool, `runs[${runIndex}].tool`);
    const driver = requireObject(tool.driver, `runs[${runIndex}].tool.driver`);
    const name = stringField(driver.name, `runs[${runIndex}].tool.driver.name`)!;
    const version = stringField(driver.version, `runs[${runIndex}].tool.driver.version`, true);
    const informationUri = stringField(driver.informationUri, `runs[${runIndex}].tool.driver.informationUri`, true);
    const rules = driver.rules === undefined ? [] : driver.rules;
    if (!Array.isArray(rules)) throw new Error(`runs[${runIndex}].tool.driver.rules must be an array`);
    // Validate and retain every rule's original metadata, even when no result uses it.
    rules.forEach((r, i) => {
      const rule = requireObject(r, `runs[${runIndex}].tool.driver.rules[${i}]`);
      stringField(rule.id, `runs[${runIndex}].tool.driver.rules[${i}].id`);
    });
    const extensions = tool.extensions === undefined ? [] : tool.extensions;
    if (!Array.isArray(extensions)) throw new Error(`runs[${runIndex}].tool.extensions must be an array`);
    extensions.forEach((extensionValue, extensionIndex) => {
      const extension = requireObject(extensionValue, `runs[${runIndex}].tool.extensions[${extensionIndex}]`);
      stringField(extension.name, `runs[${runIndex}].tool.extensions[${extensionIndex}].name`);
      ruleDescriptors(extension, `runs[${runIndex}].tool.extensions[${extensionIndex}]`);
    });
    toolDrivers.push({ runIndex, name, ...(version ? { version } : {}), ...(informationUri ? { informationUri } : {}), rules });
    const results = run.results === undefined ? [] : run.results;
    if (!Array.isArray(results)) throw new Error(`runs[${runIndex}].results must be an array`);
    results.forEach((resultValue, resultIndex) => {
      const at = `runs[${runIndex}].results[${resultIndex}]`;
      const result = requireObject(resultValue, at);
      const tool = requireObject(run.tool, `${at}.tool`);
      const driver = requireObject(tool.driver, `${at}.tool.driver`);
      const resolvedRule = resolveRule(tool, driver, result, at);
      const { id, rule } = resolvedRule;
      const resultProperties = result.properties === undefined ? {} : requireObject(result.properties, `${at}.properties`);
      const ruleProperties = rule?.properties === undefined ? {} : requireObject(rule.properties, `${at}.rule.properties`);
      const message = displayMessage(result, rule, resolvedRule.component, at);
      const location = primaryLocation(run, result);
      const properties = { ...ruleProperties, ...resultProperties };
      const levelResolution = normalizedLevel(run, tool, driver, result, resolvedRule, at);
      const severity = result.kind !== undefined && result.kind !== "fail"
        ? "informational"
        : severityFrom(levelResolution.level, properties);
      const detector = `${name}${version ? ` ${version}` : ""}`;
      const raw = {
        sarif: {
          artifact: rawArtifact,
          raw_sha256: rawSha256,
          run_index: runIndex,
          result_index: resultIndex,
          tool,
          tool_driver: driver,
          rule_component: resolvedRule.component,
          rule_metadata: rule,
          severity_resolution: levelResolution,
          payload: result,
        },
      };
      const finding: SecuritySignal = {
        rule_id: id,
        rule_component: resolvedRule.componentIdentity,
        ecosystem: "solidity",
        detector,
        severity,
        confidence: confidenceFrom(resultProperties.confidence ?? ruleProperties.confidence),
        trust_tier: "signal",
        evidence_level: "static-evidence",
        location,
        message,
        raw,
      };
      findings.push(finding);
      resultCount++;
    });
  });
  return {
    findings,
    metadata: {
      importer: "sarif-2.1.0",
      status: "success",
      rawArtifact,
      rawSha256,
      sarifVersion: "2.1.0",
      runCount: root.runs.length,
      resultCount,
      toolDrivers,
    },
  };
}

export async function importSarif(
  inputPath: string,
  outputDir: string,
  publishDirectory: (source: string, destination: string) => Promise<void> = rename,
): Promise<SarifImportResult> {
  const { createHash } = await import("node:crypto");
  const bytes = await readFile(inputPath);
  const rawArtifact = "report.sarif";
  const destination = path.resolve(outputDir);
  try {
    const existing = await lstat(destination);
    if (!existing.isDirectory()) throw new Error(`output path already exists: ${destination}`);
    const entries = await readdir(destination);
    if (entries.length > 0) throw new Error(`output artifact already exists: ${path.join(destination, entries[0]!)}`);
  } catch (error) {
    if (!(error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "ENOENT")) throw error;
  }
  const rawSha256 = createHash("sha256").update(bytes).digest("hex");
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new Error(`invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  const imported = normalizeSarif(parsed, rawSha256, rawArtifact);
  await mkdir(path.dirname(destination), { recursive: true });
  const staging = await mkdtemp(path.join(path.dirname(destination), ".sarif-import-"));
  try {
    await writeFile(path.join(staging, rawArtifact), bytes, { flag: "wx" });
    await writeFile(path.join(staging, "findings.json"), JSON.stringify(imported.findings, null, 2), { flag: "wx" });
    await writeFile(path.join(staging, "run.json"), JSON.stringify({ ...imported.metadata, input: path.resolve(inputPath), finishedAt: new Date().toISOString() }, null, 2), { flag: "wx" });
    await publishDirectory(staging, destination);
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    throw error;
  }
  return imported;
}

export function parseImportSarifArgs(argv: string[]): { input: string; output: string } {
  const values: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg !== "--input" && arg !== "--output") throw new Error(`unknown argument: ${arg}`);
    const value = argv[++i];
    if (!value || value.startsWith("--")) throw new Error(`${arg} requires a value`);
    if (values[arg]) throw new Error(`${arg} may only be specified once`);
    values[arg] = value;
  }
  if (!values["--input"] || !values["--output"]) throw new Error("usage: sec-worker import-sarif --input <report.sarif> --output <dir>");
  return { input: values["--input"], output: values["--output"] };
}

export async function runImportSarifCli(argv: string[]): Promise<number> {
  try {
    const args = parseImportSarifArgs(argv);
    const result = await importSarif(args.input, args.output);
    console.log(`SARIF:      ${result.metadata.sarifVersion}`);
    console.log(`runs:       ${result.metadata.runCount}`);
    console.log(`findings:   ${result.metadata.resultCount} (all SIGNAL)`);
    console.log(`raw report: ${path.join(path.resolve(args.output), result.metadata.rawArtifact)}`);
    return 0;
  } catch (error) {
    console.error(`error: SARIF import failed: ${error instanceof Error ? error.message : String(error)}`);
    return 2;
  }
}


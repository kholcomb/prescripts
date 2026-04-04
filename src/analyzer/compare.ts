import type { PackageReport, LifecycleScripts, Finding } from "../types.js";

export interface ScriptDiff {
  hook: string;
  before: string | null;
  after: string | null;
}

export interface CompareResult {
  name: string;
  fromVersion: string;
  toVersion: string;
  addedScripts: ScriptDiff[];
  removedScripts: ScriptDiff[];
  changedScripts: ScriptDiff[];
  newFindings: Finding[];
  resolvedFindings: Finding[];
  binaryHostChanged: boolean;
  fromBinaryHost: string | null;
  toBinaryHost: string | null;
}

function scriptKeys(scripts: LifecycleScripts): Set<string> {
  return new Set(Object.keys(scripts));
}

function findingKey(f: Finding): string {
  return `${f.category}::${f.source}::${f.pattern}`;
}

export function compareReports(
  from: PackageReport,
  to: PackageReport
): CompareResult {
  const fromScripts = from.lifecycleScripts;
  const toScripts = to.lifecycleScripts;
  const fromKeys = scriptKeys(fromScripts);
  const toKeys = scriptKeys(toScripts);

  const addedScripts: ScriptDiff[] = [];
  const removedScripts: ScriptDiff[] = [];
  const changedScripts: ScriptDiff[] = [];

  // Added hooks
  for (const hook of toKeys) {
    if (!fromKeys.has(hook)) {
      addedScripts.push({
        hook,
        before: null,
        after: toScripts[hook as keyof LifecycleScripts] ?? null,
      });
    }
  }

  // Removed hooks
  for (const hook of fromKeys) {
    if (!toKeys.has(hook)) {
      removedScripts.push({
        hook,
        before: fromScripts[hook as keyof LifecycleScripts] ?? null,
        after: null,
      });
    }
  }

  // Changed hooks
  for (const hook of fromKeys) {
    if (toKeys.has(hook)) {
      const before = fromScripts[hook as keyof LifecycleScripts] ?? null;
      const after = toScripts[hook as keyof LifecycleScripts] ?? null;
      if (before !== after) {
        changedScripts.push({ hook, before, after });
      }
    }
  }

  // New findings (in to but not in from)
  const fromFindingKeys = new Set(from.findings.map(findingKey));
  const newFindings = to.findings.filter(
    (f) => !fromFindingKeys.has(findingKey(f))
  );

  // Resolved findings (in from but not in to)
  const toFindingKeys = new Set(to.findings.map(findingKey));
  const resolvedFindings = from.findings.filter(
    (f) => !toFindingKeys.has(findingKey(f))
  );

  const fromBinaryHost = from.binaryDownload?.host ?? null;
  const toBinaryHost = to.binaryDownload?.host ?? null;
  const binaryHostChanged = fromBinaryHost !== toBinaryHost;

  return {
    name: from.name,
    fromVersion: from.version,
    toVersion: to.version,
    addedScripts,
    removedScripts,
    changedScripts,
    newFindings,
    resolvedFindings,
    binaryHostChanged,
    fromBinaryHost,
    toBinaryHost,
  };
}

/**
 * Lockfile diff engine.
 *
 * Compares two states of a project's lockfiles (base branch vs current) across
 * all detected ecosystems and returns per-package CompareResults for packages
 * whose version changed.
 *
 * Used by the `diff` CLI command and the init-ci --with-diff workflow.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { basename } from "node:path";
import { DiskCache } from "./cache/disk-cache.js";
import { detectEcosystems, scanAny } from "./ecosystem/index.js";
import { compareReports } from "./analyzer/compare.js";
import type { CompareResult } from "./analyzer/compare.js";
import type { PackageRef, ScanOptions, PackageReport } from "./types.js";
import type { EcosystemPlugin } from "./ecosystem/types.js";

const execFileAsync = promisify(execFile);

// ── Git helpers ───────────────────────────────────────────────────────────────

/**
 * Fetches the content of a file at a given git ref.
 * Returns null if the file did not exist at that ref.
 */
async function gitShow(ref: string, filePath: string): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync("git", ["show", `${ref}:${filePath}`]);
    return stdout;
  } catch {
    return null;
  }
}

// ── Version map helpers ───────────────────────────────────────────────────────

function refsToVersionMap(refs: PackageRef[]): Map<string, string> {
  const map = new Map<string, string>();
  for (const ref of refs) {
    // Last write wins for duplicate names — matches lockfile dedup behaviour
    map.set(ref.name, ref.version);
  }
  return map;
}

interface VersionDelta {
  name: string;
  fromVersion: string;
  toVersion: string;
}

function findDeltas(
  before: Map<string, string>,
  after: Map<string, string>
): { deltas: VersionDelta[]; additions: string[] } {
  const deltas: VersionDelta[] = [];
  const additions: string[] = [];
  for (const [name, toVersion] of after) {
    const fromVersion = before.get(name);
    if (!fromVersion) {
      additions.push(name);
    } else if (fromVersion !== toVersion) {
      deltas.push({ name, fromVersion, toVersion });
    }
  }
  return { deltas, additions };
}

// ── Per-ecosystem diff ────────────────────────────────────────────────────────

interface EcosystemDiffResult {
  comparisons: CompareResult[];
  added: PackageReport[];
}

async function diffEcosystem(
  plugin: EcosystemPlugin,
  projectDir: string,
  baseRef: string,
  opts: ScanOptions
): Promise<EcosystemDiffResult> {
  // 1. Get lockfile paths present in the current working tree
  const lockfilePaths = await plugin.getLockfilePaths(projectDir);
  if (lockfilePaths.length === 0) return { comparisons: [], added: [] };

  // 2. Parse current (after) state from disk
  const afterParsed = await plugin.parseLockfile(projectDir);
  if (!afterParsed) return { comparisons: [], added: [] };
  const afterMap = refsToVersionMap(afterParsed.refs);

  // 3. Parse base (before) state from git for each lockfile
  const beforeRefs: PackageRef[] = [];
  for (const relPath of lockfilePaths) {
    const content = await gitShow(baseRef, relPath);
    if (!content) continue;
    const refs = plugin.parseLockfileContent(content, basename(relPath));
    beforeRefs.push(...refs);
  }

  // If no base lockfile exists at all (new project / first PR), treat everything as added
  const beforeMap = refsToVersionMap(beforeRefs);
  const { deltas, additions } = findDeltas(beforeMap, afterMap);

  const cache = new DiskCache(opts.cacheDir);
  const comparisons: CompareResult[] = [];
  const added: PackageReport[] = [];

  await Promise.all([
    // 4. Scan both versions for each delta and compare
    ...deltas.map(async ({ name, fromVersion, toVersion }) => {
      const fromRef = beforeRefs.find(
        (r) => r.name === name && r.version === fromVersion
      ) ?? { name, version: fromVersion, resolved: "", integrity: null };

      const toRef = afterParsed.refs.find(
        (r) => r.name === name && r.version === toVersion
      ) ?? { name, version: toVersion, resolved: "", integrity: null };

      const [fromReport, toReport] = await Promise.all([
        scanAny(fromRef, plugin, opts, cache, projectDir).catch(() => null),
        scanAny(toRef, plugin, opts, cache, projectDir).catch(() => null),
      ]);

      const from: PackageReport = fromReport ?? emptyReport(fromRef, plugin.packageManager);
      const to: PackageReport = toReport ?? emptyReport(toRef, plugin.packageManager);
      comparisons.push(compareReports(from, to));
    }),

    // 5. Scan newly added packages
    ...additions.map(async (name) => {
      const ref = afterParsed.refs.find((r) => r.name === name);
      if (!ref) return;
      const report = await scanAny(ref, plugin, opts, cache, projectDir).catch(() => null);
      // Include even if scan returned null — emit a minimal report so the
      // addition is always visible in the diff output.
      added.push(report ?? emptyReport(ref, plugin.packageManager));
    }),
  ]);

  return { comparisons, added };
}

// ── Public API ────────────────────────────────────────────────────────────────

export interface DiffResult {
  baseRef: string;
  ecosystems: string[];
  comparisons: CompareResult[];
  /** Packages that appear in the current lockfile but not the base — new additions. */
  added: PackageReport[];
}

/**
 * Diffs all lockfiles in `projectDir` against `baseRef`.
 * Returns CompareResults for version changes and PackageReports for additions.
 */
export async function runDiffEngine(
  projectDir: string,
  baseRef: string,
  opts: ScanOptions
): Promise<DiffResult> {
  const plugins = await detectEcosystems(projectDir);

  const ecosystemResults = await Promise.all(
    plugins.map((plugin) => {
      plugin.init(opts);
      return diffEcosystem(plugin, projectDir, baseRef, opts);
    })
  );

  return {
    baseRef,
    ecosystems: plugins.map((p) => p.packageManager),
    comparisons: ecosystemResults.flatMap((r) => r.comparisons),
    added: ecosystemResults.flatMap((r) => r.added),
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

import type { PackageManager } from "./types.js";

function emptyReport(ref: PackageRef, packageManager: PackageManager): PackageReport {
  return {
    name: ref.name,
    version: ref.version,
    packageManager,
    source: { type: "registry", resolved: ref.resolved, integrity: ref.integrity, integrityVerified: false },
    provenance: null,
    lifecycleScripts: {},
    binaryDownload: null,
    advisories: [],
    findings: [],
    risk: "verified",
  };
}

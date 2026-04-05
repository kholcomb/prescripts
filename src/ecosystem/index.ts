/**
 * Ecosystem plugin registry and generic scan loop.
 *
 * Adding a new ecosystem:
 *   1. Implement EcosystemPlugin (src/ecosystem/<pm>.ts)
 *   2. Import the plugin instance and add it to ECOSYSTEM_PLUGINS below
 *   3. The scan loop (scanAny) and CLI integration work automatically
 */

import type {
  PackageRef,
  PackageReport,
  AdvisoryMatch,
  ScanOptions,
} from "../types.js";
import type { DiskCache } from "../cache/disk-cache.js";
import type { EcosystemPlugin } from "./types.js";
import { scanPackage } from "../analyzer/scanner.js";
import { scoreFindings, applyBinaryDownloaderCluster, computeRisk } from "../analyzer/confidence.js";
import { npmPlugin } from "./npm.js";
import { pipPlugin } from "./pip.js";

export { npmPlugin } from "./npm.js";
export { pipPlugin } from "./pip.js";
export type { EcosystemPlugin, ExtractionResult } from "./types.js";

/**
 * All registered ecosystem plugins, in detection-priority order.
 * detectEcosystems() tries each in sequence.
 */
export const ECOSYSTEM_PLUGINS: EcosystemPlugin[] = [
  npmPlugin,
  pipPlugin,
];

/**
 * Returns the plugins whose lockfiles are present in `dir`.
 * Multiple plugins may match (polyglot projects).
 */
export async function detectEcosystems(dir: string): Promise<EcosystemPlugin[]> {
  const results: EcosystemPlugin[] = [];
  for (const plugin of ECOSYSTEM_PLUGINS) {
    if (await plugin.detectLockfile(dir)) {
      results.push(plugin);
    }
  }
  return results;
}

/**
 * Generic scan loop — works for any EcosystemPlugin.
 *
 * Replaces the npm-specific scanRef and pip-specific scanPipRef.
 * All ecosystem variation is encapsulated in the plugin methods.
 */
export async function scanAny(
  ref: PackageRef,
  plugin: EcosystemPlugin,
  opts: ScanOptions,
  cache: DiskCache,
  projectDir: string,
  advisoryMap: Map<string, AdvisoryMatch[]> = new Map()
): Promise<PackageReport | null> {
  // Optional: check hosted API cache first (any ecosystem)
  if (opts.apiUrl) {
    try {
      const url = `${opts.apiUrl.replace(/\/$/, "")}/v1/package/${encodeURIComponent(ref.name)}/${encodeURIComponent(ref.version)}`;
      const res = await fetch(url, { signal: AbortSignal.timeout(opts.timeout) });
      if (res.ok) {
        return (await res.json()) as PackageReport;
      }
    } catch {
      // fall through to local analysis
    }
  }

  // 1. Fetch + extract the package archive
  const result = await plugin.fetchPackage(ref, opts, cache, projectDir);

  // 2. Extract install hooks
  const hooks = plugin.extractHooks(result);
  const binaryDownload = result.binaryDownload;

  // 3. Look up pre-fetched advisories for this package
  const advisories =
    (ref.integrity ? advisoryMap.get(`${ref.name}@${ref.integrity}`) : undefined) ??
    advisoryMap.get(`${ref.name}@${ref.version}`) ??
    [];

  // 4. Early exit if no hooks and no advisories to report
  if (!plugin.hasHooks(hooks) && !binaryDownload && advisories.length === 0) {
    return null;
  }

  // 5. Fetch provenance signals from the registry
  const prov = await plugin.fetchProvenance(ref, opts);

  // 6. Pattern scan on the extracted hook content
  const { findings: patternFindings } = scanPackage(hooks, result.fileMap, opts.severity);

  // 7. Ecosystem-specific findings (integrity, signatures, attestations, etc.)
  const extra = await plugin.extraFindings(ref, opts, result, prov, hooks);

  // 8. Combine: extra findings are prepended (higher-confidence, ecosystem-verified checks)
  const allFindings = [...extra, ...patternFindings];

  // 9. Cluster detection → confidence scoring → risk aggregation
  const clustered = applyBinaryDownloaderCluster(allFindings, binaryDownload);
  const scored = scoreFindings(clustered, prov.provenance, opts.trust);
  const risk = computeRisk(scored, advisories, prov.provenance);

  return {
    name: ref.name,
    version: ref.version,
    packageManager: plugin.packageManager,
    source: {
      type: result.sourceType,
      resolved: ref.resolved,
      integrity: ref.integrity,
      integrityVerified: result.integrityVerified,
    },
    provenance: prov.provenance,
    lifecycleScripts: hooks,
    binaryDownload,
    advisories,
    findings: scored,
    risk,
  };
}

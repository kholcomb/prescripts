import type { AdvisoryMatch, PackageRef, Severity } from "../types.js";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULNS_BASE = "https://api.osv.dev/v1/vulns";
const OSV_BATCH_CONCURRENCY = 20;

interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

interface OsvRange {
  type: string; // "SEMVER", "ECOSYSTEM", "GIT"
  events: OsvEvent[];
}

interface OsvAffected {
  ranges?: OsvRange[];
  versions?: string[];
}

interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  affected: OsvAffected[];
  database_specific?: { severity?: string };
}

// /v1/querybatch now returns only id stubs — full data requires individual GETs
interface OsvVulnStub {
  id: string;
  modified?: string;
}

interface OsvBatchResponse {
  results: Array<{ vulns?: OsvVulnStub[] }>;
}

// ── Semver helpers ─────────────────────────────────────────────────────────

function parseSemver(v: string): [number, number, number] | null {
  if (v === "0" || v === "") return [0, 0, 0];
  const m = v.trim().match(/^v?(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [parseInt(m[1]!, 10), parseInt(m[2]!, 10), parseInt(m[3]!, 10)];
}

function cmpSemver(a: string, b: string): number {
  const av = parseSemver(a);
  const bv = parseSemver(b);
  if (!av || !bv) return 0;
  for (let i = 0; i < 3; i++) {
    const d = av[i]! - bv[i]!;
    if (d !== 0) return d;
  }
  return 0;
}

// ── Range matching ─────────────────────────────────────────────────────────

function isAffectedByRange(version: string, range: OsvRange): boolean {
  // Walk events in order. introduced starts the interval; fixed/last_affected ends it.
  // Multiple introduced/fixed pairs within one range are OR'd per the OSV spec.
  let inRange = false;
  for (const event of range.events) {
    if (event.introduced !== undefined) {
      inRange = cmpSemver(version, event.introduced) >= 0;
    }
    if (inRange && event.fixed !== undefined) {
      if (cmpSemver(version, event.fixed) >= 0) inRange = false;
    }
    if (inRange && event.last_affected !== undefined) {
      if (cmpSemver(version, event.last_affected) > 0) inRange = false;
    }
  }
  return inRange;
}

function isAffected(version: string, vuln: OsvVuln): boolean {
  for (const affected of vuln.affected) {
    if (affected.versions?.includes(version)) return true;
    for (const range of affected.ranges ?? []) {
      if (
        (range.type === "SEMVER" || range.type === "ECOSYSTEM") &&
        isAffectedByRange(version, range)
      ) {
        return true;
      }
    }
  }
  return false;
}

// ── Field extraction ───────────────────────────────────────────────────────

function mapSeverity(vuln: OsvVuln): Severity {
  const s = vuln.database_specific?.severity?.toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "moderate" || s === "medium") return "medium";
  if (s === "low") return "low";
  return "medium";
}

function formatVulnerableVersions(vuln: OsvVuln): string {
  for (const affected of vuln.affected) {
    for (const range of affected.ranges ?? []) {
      if (range.type === "SEMVER" || range.type === "ECOSYSTEM") {
        const parts: string[] = [];
        for (const event of range.events) {
          if (event.introduced && event.introduced !== "0") parts.push(`>=${event.introduced}`);
          if (event.fixed) parts.push(`<${event.fixed}`);
          if (event.last_affected) parts.push(`<=${event.last_affected}`);
        }
        if (parts.length) return parts.join(" ");
      }
    }
    if (affected.versions?.length) {
      const sample = affected.versions.slice(0, 5).join(", ");
      return affected.versions.length > 5 ? `${sample}, …` : sample;
    }
  }
  return "*";
}

function findPatchedVersion(vuln: OsvVuln): string | null {
  for (const affected of vuln.affected) {
    for (const range of affected.ranges ?? []) {
      if (range.type === "SEMVER" || range.type === "ECOSYSTEM") {
        for (const event of range.events) {
          if (event.fixed) return `>=${event.fixed}`;
        }
      }
    }
  }
  return null;
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Fetch full vulnerability details for a single OSV ID.
 * Returns null on any failure (404, timeout, parse error).
 */
async function fetchVulnDetails(id: string): Promise<OsvVuln | null> {
  try {
    const res = await fetch(`${OSV_VULNS_BASE}/${id}`, {
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) return null;
    return (await res.json()) as OsvVuln;
  } catch {
    return null;
  }
}

/**
 * Queries the OSV batch API for known vulnerabilities in the given package refs.
 * `ecosystem` must match OSV's naming convention: "PyPI", "crates.io", "RubyGems".
 *
 * Uses a two-phase approach:
 *   1. POST /v1/querybatch → get vuln ID stubs per package
 *   2. GET /v1/vulns/{id} in parallel → get full affected-range data
 *
 * Returns a map keyed by "name@version" (and "name@integrity" when available),
 * matching the same contract as the npm advisory client.
 * Best-effort: never throws; returns an empty map on any failure.
 */
export async function fetchOsvAdvisories(
  refs: PackageRef[],
  ecosystem: string
): Promise<Map<string, AdvisoryMatch[]>> {
  const result = new Map<string, AdvisoryMatch[]>();

  const queryable = refs.filter((r) => r.version && r.version !== "latest");
  if (queryable.length === 0) return result;

  const queries = queryable.map((ref) => ({
    version: ref.version,
    package: { name: ref.name, ecosystem },
  }));

  try {
    // Phase 1: batch query for vuln ID stubs
    const batchRes = await fetch(OSV_BATCH_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries }),
      signal: AbortSignal.timeout(30_000),
    });

    if (!batchRes.ok) return result;

    const batchData = (await batchRes.json()) as OsvBatchResponse;

    // Collect unique IDs across all results
    const allIds = new Set<string>();
    for (const entry of batchData.results) {
      for (const stub of entry.vulns ?? []) {
        allIds.add(stub.id);
      }
    }
    if (allIds.size === 0) return result;

    // Phase 2: fetch full vuln details in parallel (bounded concurrency)
    const ids = [...allIds];
    const vulnMap = new Map<string, OsvVuln>();

    for (let i = 0; i < ids.length; i += OSV_BATCH_CONCURRENCY) {
      const chunk = ids.slice(i, i + OSV_BATCH_CONCURRENCY);
      const settled = await Promise.all(chunk.map(fetchVulnDetails));
      for (const vuln of settled) {
        if (vuln) vulnMap.set(vuln.id, vuln);
      }
    }

    // Match full data against each ref
    for (let i = 0; i < queryable.length; i++) {
      const ref = queryable[i]!;
      const stubs = batchData.results[i]?.vulns ?? [];
      if (stubs.length === 0) continue;

      const matching: OsvVuln[] = [];
      for (const stub of stubs) {
        const vuln = vulnMap.get(stub.id);
        if (vuln && isAffected(ref.version, vuln)) {
          matching.push(vuln);
        }
      }
      if (matching.length === 0) continue;

      const mapped: AdvisoryMatch[] = matching.map((v) => ({
        id: v.id,
        title: v.summary ?? v.id,
        severity: mapSeverity(v),
        url: `https://osv.dev/vulnerability/${v.id}`,
        vulnerableVersions: formatVulnerableVersions(v),
        patchedVersions: findPatchedVersion(v),
        cves: (v.aliases ?? []).filter((a) => a.startsWith("CVE-")),
        cvssScore: null,
      }));

      result.set(`${ref.name}@${ref.version}`, mapped);
      if (ref.integrity) {
        result.set(`${ref.name}@${ref.integrity}`, mapped);
      }
    }
  } catch {
    // Best-effort — never propagate advisory fetch failures
  }

  return result;
}

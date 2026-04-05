import type { AdvisoryMatch, PackageRef, Severity } from "../types.js";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";

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

interface OsvBatchResponse {
  results: Array<{ vulns?: OsvVuln[] }>;
}

// ── Semver helpers ─────────────────────────────────────────────────────────

function parseSemver(v: string): [number, number, number] | null {
  if (v === "0" || v === "") return [0, 0, 0];
  const m = v.trim().match(/^(\d+)\.(\d+)\.(\d+)/);
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
 * Queries the OSV batch API for known vulnerabilities in the given package refs.
 * `ecosystem` must match OSV's naming convention: "PyPI", "crates.io", "RubyGems".
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
    const res = await fetch(OSV_BATCH_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries }),
      signal: AbortSignal.timeout(30_000),
    });

    if (!res.ok) return result;

    const data = (await res.json()) as OsvBatchResponse;

    for (let i = 0; i < queryable.length; i++) {
      const ref = queryable[i]!;
      const vulns = data.results[i]?.vulns ?? [];
      if (vulns.length === 0) continue;

      // OSV returns all vulns for the package; filter to those that actually
      // cover this specific version via range or exact-version matching.
      const matching = vulns.filter((v) => isAffected(ref.version, v));
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

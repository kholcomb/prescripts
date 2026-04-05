import type { AdvisoryMatch, PackageRef, Severity } from "../types.js";

const ADVISORY_URL =
  "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk";

// npm uses "moderate" where we use "medium"
type NpmSeverity = "critical" | "high" | "moderate" | "low";

interface NpmAdvisory {
  id: number;
  title: string;
  severity: NpmSeverity;
  url: string;
  vulnerable_versions: string;
  patched_versions?: string;
  cves?: string[];
  cvss?: { score?: number };
}

function mapSeverity(s: NpmSeverity): Severity {
  return s === "moderate" ? "medium" : s;
}

// ─── Lightweight semver range checker ─────────────────────────────────────
// Handles the common npm advisory range formats:
//   <=X.Y.Z  <X.Y.Z  >=X.Y.Z  >X.Y.Z  =X.Y.Z  *
//   compound: >=X.Y.Z <Y.Y.Z
// Does not handle pre-release tags or tilde/caret ranges (rare in advisories).

function parseSemver(v: string): [number, number, number] | null {
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

function satisfiesRange(version: string, range: string): boolean {
  const r = range.trim();
  if (r === "*" || r === "" || r === ">=0.0.0") return true;

  // Split compound range on whitespace, each part is an operator+version
  for (const part of r.split(/\s+/)) {
    const m = part.match(/^(>=|<=|>|<|=?)(.+)$/);
    if (!m) continue;
    const op = m[1] || "=";
    const ver = m[2]!;
    const cmp = cmpSemver(version, ver);
    if (op === ">=" && cmp < 0) return false;
    if (op === "<=" && cmp > 0) return false;
    if (op === ">" && cmp <= 0) return false;
    if (op === "<" && cmp >= 0) return false;
    if (op === "=" && cmp !== 0) return false;
  }
  return true;
}

// ──────────────────────────────────────────────────────────────────────────

/**
 * Queries the npm bulk advisory API for all registry packages in refs.
 * Returns a map of "name@version" → matching advisories.
 * Advisories are matched per-version using vulnerable_versions range checking
 * so a flagged older version does not infect a patched newer version of the
 * same package in the same lockfile.
 *
 * Non-registry packages (git, local, private) are skipped.
 * Best-effort: never fails the scan.
 */
export async function fetchAdvisories(
  refs: PackageRef[],
  registryUrl: string
): Promise<Map<string, AdvisoryMatch[]>> {
  const result = new Map<string, AdvisoryMatch[]>();

  const isPublicRegistry = registryUrl
    .replace(/\/$/, "")
    .startsWith("https://registry.npmjs.org");

  if (!isPublicRegistry) return result;

  // Build bulk request body: { "pkg-name": ["version", ...] }
  // Track which versions we queried per name for post-filtering
  const body: Record<string, string[]> = {};
  for (const ref of refs) {
    if (!ref.version || ref.version === "latest") continue;
    if (!body[ref.name]) body[ref.name] = [];
    body[ref.name]!.push(ref.version);
  }

  if (Object.keys(body).length === 0) return result;

  try {
    const res = await fetch(ADVISORY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    });

    if (!res.ok) return result;

    const data = (await res.json()) as Record<string, NpmAdvisory[]>;

    for (const [name, advisories] of Object.entries(data)) {
      if (!Array.isArray(advisories) || advisories.length === 0) continue;
      const versions = body[name] ?? [];

      for (const version of versions) {
        // Only include advisories whose vulnerable_versions range covers this version
        const matching = advisories.filter((a) =>
          satisfiesRange(version, a.vulnerable_versions)
        );
        if (matching.length === 0) continue;

        const key = `${name}@${version}`;
        result.set(
          key,
          matching.map((a) => ({
            id: a.id,
            title: a.title,
            severity: mapSeverity(a.severity),
            url: a.url,
            vulnerableVersions: a.vulnerable_versions,
            patchedVersions: a.patched_versions ?? null,
            cves: a.cves ?? [],
            cvssScore: a.cvss?.score ?? null,
          }))
        );
      }
    }
  } catch {
    // Best-effort — never propagate advisory fetch failures
  }

  return result;
}

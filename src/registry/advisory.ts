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
  cves?: string[];
  cvss?: { score?: number };
}

function mapSeverity(s: NpmSeverity): Severity {
  return s === "moderate" ? "medium" : s;
}

/**
 * Queries the npm bulk advisory API for all registry packages in refs.
 * Returns a map of package name → matching advisories for the requested version.
 * Non-registry packages (git, local, private) are skipped — the advisory API
 * only covers public npm packages.
 *
 * This is best-effort: any network or parse failure returns an empty map so
 * the scan continues normally.
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

  // Build bulk request body: { "pkg-name": ["version"] }
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
      result.set(
        name,
        advisories.map((a) => ({
          id: a.id,
          title: a.title,
          severity: mapSeverity(a.severity),
          url: a.url,
          vulnerableVersions: a.vulnerable_versions,
          cves: a.cves ?? [],
          cvssScore: a.cvss?.score ?? null,
        }))
      );
    }
  } catch {
    // Best-effort — never propagate advisory fetch failures
  }

  return result;
}

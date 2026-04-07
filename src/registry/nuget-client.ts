/**
 * NuGet registry client.
 *
 * Uses two NuGet v3 API endpoints:
 *   - Registration: https://api.nuget.org/v3/registration5/{id}/{version}.json
 *     for per-version metadata (publishedAt, deprecated, download URL).
 *   - Search:  https://azuresearch-usnc.nuget.org/query
 *     for package-level stats (totalDownloads, version list).
 *
 * Package download:
 *   https://api.nuget.org/v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg
 *
 * All URL segments use lowercase package IDs (NuGet convention).
 *
 * Configurable via NUGET_SOURCE_URL env var (for corporate feeds / Artifactory).
 */

let nugetTimeout = 30_000;

export function setNugetTimeout(ms: number): void {
  nugetTimeout = ms;
}

function getRegistrationBase(): string {
  const override = process.env["NUGET_SOURCE_URL"];
  if (override) {
    return override.replace(/\/$/, "") + "/registration5-semver1";
  }
  return "https://api.nuget.org/v3/registration5-semver1";
}

function getFlatcontainerBase(): string {
  const override = process.env["NUGET_SOURCE_URL"];
  if (override) {
    return override.replace(/\/$/, "") + "/v3-flatcontainer";
  }
  return "https://api.nuget.org/v3-flatcontainer";
}

const SEARCH_BASE = "https://azuresearch-usnc.nuget.org/query";

async function fetchNugetJson(url: string): Promise<unknown | null> {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(nugetTimeout),
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

// ── API response shapes ────────────────────────────────────────────────────────

interface RegistrationLeaf {
  /** ISO-8601 publish date — top-level field in the leaf response. */
  published?: string;
  listed?: boolean;
  deprecation?: unknown;
  packageContent?: string;
  catalogEntry?: {
    deprecation?: unknown;
  };
}

interface SearchData {
  id?: string;
  version?: string;
  totalDownloads?: number;
  versions?: Array<{ version?: string; downloads?: number }>;
}

interface SearchResponse {
  data?: SearchData[];
}

// ── Public types ──────────────────────────────────────────────────────────────

export interface NugetVersionInfo {
  /** Download URL for the .nupkg file. */
  nupkgUrl: string;
  /** ISO-8601 timestamp of this version's release. */
  uploadTime: string | null;
  /** true if the package is deprecated/unlisted. */
  deprecated: boolean;
  /** Total download count across all versions (not weekly). */
  totalDownloads: number | null;
  /** Total number of listed versions. */
  totalVersions: number;
  /** ISO-8601 timestamp of the earliest published version. */
  firstUploadTime: string | null;
}

/**
 * Fetch metadata for a specific NuGet package version.
 * Returns null if the package is not found on NuGet.org.
 */
export async function fetchNugetMeta(
  name: string,
  version: string
): Promise<NugetVersionInfo | null> {
  const lowerId = name.toLowerCase();
  const lowerVersion = version.toLowerCase();

  const registrationBase = getRegistrationBase();
  const flatBase = getFlatcontainerBase();

  const nupkgUrl = `${flatBase}/${lowerId}/${lowerVersion}/${lowerId}.${lowerVersion}.nupkg`;

  // Phase 1: parallel fetches — version registration + search stats
  const registrationUrl = `${registrationBase}/${lowerId}/${lowerVersion}.json`;
  const searchUrl = `${SEARCH_BASE}?q=packageid:${encodeURIComponent(name)}&take=1&prerelease=true`;

  const [regData, searchData] = await Promise.all([
    fetchNugetJson(registrationUrl) as Promise<RegistrationLeaf | null>,
    fetchNugetJson(searchUrl) as Promise<SearchResponse | null>,
  ]);

  // Parse version-specific fields
  const uploadTime = regData?.published
    ? new Date(regData.published).toISOString()
    : null;
  const deprecated = !!(regData?.deprecation ?? regData?.catalogEntry?.deprecation) || regData?.listed === false;

  // Parse search-level stats
  const searchPkg = searchData?.data?.[0];
  const totalDownloads = searchPkg?.totalDownloads ?? null;
  const versions = searchPkg?.versions ?? [];
  const totalVersions = versions.length > 0 ? versions.length : 1;

  // Phase 2: first version publish time (sequential — same endpoint family)
  let firstUploadTime: string | null = null;
  const firstVersion = versions[0]?.version;
  if (firstVersion && firstVersion.toLowerCase() !== lowerVersion) {
    const firstRegUrl = `${registrationBase}/${lowerId}/${firstVersion.toLowerCase()}.json`;
    const firstRegData = (await fetchNugetJson(firstRegUrl)) as RegistrationLeaf | null;
    firstUploadTime = firstRegData?.published
      ? new Date(firstRegData.published).toISOString()
      : null;
  } else if (firstVersion?.toLowerCase() === lowerVersion) {
    firstUploadTime = uploadTime;
  }

  return {
    nupkgUrl,
    uploadTime,
    deprecated,
    totalDownloads,
    totalVersions,
    firstUploadTime,
  };
}

/**
 * Download raw .nupkg bytes.
 */
export async function fetchNupkgBytes(url: string): Promise<Buffer | null> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(nugetTimeout) });
    if (!res.ok) return null;
    return Buffer.from(await res.arrayBuffer());
  } catch {
    return null;
  }
}

/**
 * Resolve "latest" to the newest stable version from NuGet.
 */
export async function resolveNugetLatestVersion(name: string): Promise<string | null> {
  const searchUrl = `${SEARCH_BASE}?q=packageid:${encodeURIComponent(name)}&take=1`;
  const data = (await fetchNugetJson(searchUrl)) as SearchResponse | null;
  return data?.data?.[0]?.version ?? null;
}

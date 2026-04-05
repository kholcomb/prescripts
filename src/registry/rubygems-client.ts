/**
 * RubyGems API client.
 *
 * API reference: https://guides.rubygems.org/rubygems-org-api/
 *
 * GET https://rubygems.org/api/v1/gems/<name>.json       → latest version info
 * GET https://rubygems.org/api/v1/versions/<name>.json   → all versions
 *
 * Download URL: https://rubygems.org/gems/<name>-<version>.gem
 * .gem files are TAR archives containing data.tar.gz and metadata.gz.
 */

const GEMS_BASE = "https://rubygems.org/api/v1";
const DOWNLOAD_BASE = "https://rubygems.org/gems";

let gemsTimeout = 30_000;

export function setGemsTimeout(ms: number): void {
  gemsTimeout = ms;
}

export interface GemsVersionInfo {
  /** Download URL for the .gem file. */
  downloadUrl: string;
  /** SHA-256 digest in "sha256:<hex>" format, if available. */
  sha256: string | null;
  /** ISO-8601 upload time. */
  uploadTime: string | null;
  /** Whether this version was yanked. */
  yanked: boolean;
  /** Total distinct versions. */
  totalVersions: number;
  /** Upload time of the earliest version. */
  firstUploadTime: string | null;
  /** Author field from gem metadata. */
  authors: string | null;
}

interface GemVersionEntry {
  number: string;
  created_at: string;
  yanked: boolean;
  sha: string | null;
}

interface GemLatestResponse {
  name: string;
  version: string;
  authors: string;
  created_at: string;
  yanked: boolean;
  sha: string | null;
}

async function fetchGemsJson(url: string): Promise<unknown | null> {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(gemsTimeout),
      headers: { "Accept": "application/json" },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/**
 * Fetch RubyGems metadata for a specific gem version.
 */
export async function fetchGemsMeta(
  name: string,
  version: string
): Promise<GemsVersionInfo | null> {
  const isLatest = !version || version === "latest";

  // Fetch the latest info endpoint (always useful for authors + yanked status)
  const [latestData, allVersions] = await Promise.all([
    fetchGemsJson(`${GEMS_BASE}/gems/${encodeURIComponent(name)}.json`) as Promise<GemLatestResponse | null>,
    fetchGemsJson(`${GEMS_BASE}/versions/${encodeURIComponent(name)}.json`) as Promise<GemVersionEntry[] | null>,
  ]);

  if (!latestData) return null;

  const resolvedVersion = isLatest ? latestData.version : version;

  // Find the specific version in the versions list
  const versionEntry = Array.isArray(allVersions)
    ? allVersions.find((v) => v.number === resolvedVersion) ?? null
    : null;

  const sha = versionEntry?.sha ?? (isLatest ? latestData.sha : null);
  const createdAt = versionEntry?.created_at ?? (isLatest ? latestData.created_at : null);
  const yanked = versionEntry?.yanked ?? (isLatest ? latestData.yanked : false);

  // Find earliest version upload time
  let firstUploadTime: string | null = null;
  if (Array.isArray(allVersions) && allVersions.length > 0) {
    firstUploadTime = allVersions.reduce<string | null>((earliest, v) => {
      if (!v.created_at) return earliest;
      if (!earliest || v.created_at < earliest) return v.created_at;
      return earliest;
    }, null);
  }

  return {
    downloadUrl: `${DOWNLOAD_BASE}/${encodeURIComponent(name)}-${encodeURIComponent(resolvedVersion)}.gem`,
    sha256: sha ? `sha256:${sha}` : null,
    uploadTime: createdAt ?? null,
    yanked,
    totalVersions: Array.isArray(allVersions) ? allVersions.length : 1,
    firstUploadTime,
    authors: latestData.authors ?? null,
  };
}

/**
 * Resolve "latest" to a concrete version string.
 */
export async function resolveGemLatestVersion(name: string): Promise<string | null> {
  const data = (await fetchGemsJson(
    `${GEMS_BASE}/gems/${encodeURIComponent(name)}.json`
  )) as GemLatestResponse | null;
  return data?.version ?? null;
}

/**
 * Fetch the current owner handles for a gem.
 * Returns an empty array on any failure (owners are best-effort).
 *
 * Endpoint: GET https://rubygems.org/api/v1/gems/<name>/owners.json
 */
export async function fetchGemsOwners(name: string): Promise<string[]> {
  const data = await fetchGemsJson(
    `${GEMS_BASE}/gems/${encodeURIComponent(name)}/owners.json`
  ) as Array<{ handle?: string }> | null;

  if (!Array.isArray(data)) return [];
  return data
    .map((o) => o.handle)
    .filter((h): h is string => typeof h === "string" && h.length > 0);
}

/**
 * Download raw .gem bytes.
 */
export async function fetchGemBytes(url: string, timeout: number): Promise<Buffer> {
  const res = await fetch(url, { signal: AbortSignal.timeout(timeout) });
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

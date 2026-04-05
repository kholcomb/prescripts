/**
 * PyPI JSON API client.
 *
 * API reference: https://warehouse.pypa.io/api-reference/json.html
 *
 * GET https://pypi.org/pypi/<name>/json           → latest release + all versions
 * GET https://pypi.org/pypi/<name>/<version>/json → specific version
 */

let pypiTimeout = 30_000;

export function setPyPITimeout(ms: number): void {
  pypiTimeout = ms;
}

export interface PyPIVersionInfo {
  /** URL of the sdist (.tar.gz) tarball for this version, or wheel if no sdist. */
  tarballUrl: string;
  /** sha256 hex digest from PyPI file listing, in "sha256:<hex>" format. */
  sha256: string | null;
  /** ISO-8601 upload time for this version. */
  uploadTime: string | null;
  /** Whether this release has been yanked (PyPI equivalent of npm deprecation). */
  yanked: boolean;
  yankedReason: string | null;
  /** Total number of distinct releases for this package. */
  totalVersions: number;
  /** Upload time of the earliest release. */
  firstUploadTime: string | null;
  /** Maintainer field from pyproject metadata (a string, not an array). */
  maintainer: string | null;
  /** Author field as fallback identity. */
  author: string | null;
}

interface PyPIFileEntry {
  filename: string;
  url: string;
  digests: { sha256?: string; md5?: string };
  packagetype: "sdist" | "bdist_wheel" | string;
  yanked: boolean;
  yanked_reason: string | null;
  upload_time_iso_8601: string;
}

interface PyPIResponse {
  info: {
    name: string;
    version: string;
    yanked: boolean;
    yanked_reason: string | null;
    author: string | null;
    author_email: string | null;
    maintainer: string | null;
    maintainer_email: string | null;
  };
  releases: Record<string, PyPIFileEntry[]>;
  urls: PyPIFileEntry[];  // files for the requested version
}

async function fetchPyPI(url: string): Promise<PyPIResponse | null> {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(pypiTimeout),
      headers: { "Accept": "application/json" },
    });
    if (!res.ok) return null;
    return (await res.json()) as PyPIResponse;
  } catch {
    return null;
  }
}

/**
 * Choose the best file to download for security analysis:
 *   1. sdist (.tar.gz) — contains setup.py, pyproject.toml; most useful for scanning
 *   2. wheel (.whl)    — fallback if no sdist available
 */
function chooseBestFile(files: PyPIFileEntry[]): PyPIFileEntry | null {
  if (files.length === 0) return null;
  const sdist = files.find((f) => f.packagetype === "sdist");
  if (sdist) return sdist;
  // Fallback: any wheel (prefer non-platform-specific "none-any" wheels)
  const anyWheel = files.find((f) => f.filename.endsWith("-none-any.whl"));
  if (anyWheel) return anyWheel;
  return files.find((f) => f.filename.endsWith(".whl")) ?? null;
}

/**
 * Find the earliest upload time across all releases.
 */
function firstUploadTime(releases: Record<string, PyPIFileEntry[]>): string | null {
  let earliest: string | null = null;
  for (const files of Object.values(releases)) {
    for (const f of files) {
      if (!f.upload_time_iso_8601) continue;
      if (!earliest || f.upload_time_iso_8601 < earliest) {
        earliest = f.upload_time_iso_8601;
      }
    }
  }
  return earliest;
}

/**
 * Fetch PyPI metadata for a specific package version.
 *
 * If version is "latest", fetches the latest release.
 *
 * The version-specific endpoint (/pypi/<name>/<version>/json) does NOT include
 * `releases`; we also fetch the package-level endpoint for total version count
 * and first upload time.
 */
export async function fetchPyPIMeta(
  name: string,
  version: string
): Promise<PyPIVersionInfo | null> {
  const isLatest = !version || version === "latest";

  // Package-level endpoint always has `releases`; version endpoint has `urls` for that version
  const pkgUrl = `https://pypi.org/pypi/${encodeURIComponent(name)}/json`;
  const verUrl = isLatest
    ? pkgUrl
    : `https://pypi.org/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`;

  // Fetch both in parallel (version-specific for file URLs, package-level for release history)
  const [verData, pkgData] = await Promise.all([
    fetchPyPI(verUrl),
    isLatest ? Promise.resolve(null) : fetchPyPI(pkgUrl),
  ]);

  if (!verData) return null;

  const files = verData.urls;
  const best = chooseBestFile(files);
  if (!best) return null;

  // Use package-level data for history; fall back to version-level if it includes releases
  const historyData = pkgData ?? verData;
  const releases = historyData.releases ?? {};
  const totalVersions = Object.keys(releases).length;
  const first = Object.keys(releases).length > 0 ? firstUploadTime(releases) : null;

  return {
    tarballUrl: best.url,
    sha256: best.digests.sha256 ? `sha256:${best.digests.sha256}` : null,
    uploadTime: best.upload_time_iso_8601 ?? null,
    yanked: verData.info.yanked || best.yanked,
    yankedReason: verData.info.yanked_reason || best.yanked_reason || null,
    totalVersions,
    firstUploadTime: first,
    maintainer: verData.info.maintainer || null,
    author: verData.info.author || null,
  };
}

/**
 * Resolve "latest" to a concrete version number.
 */
export async function resolvePyPILatestVersion(name: string): Promise<string | null> {
  const url = `https://pypi.org/pypi/${encodeURIComponent(name)}/json`;
  const data = await fetchPyPI(url);
  return data?.info.version ?? null;
}

/**
 * crates.io API client.
 *
 * API reference: https://doc.rust-lang.org/cargo/reference/registry-web-api.html
 *
 * crates.io requires a User-Agent header identifying the client.
 * Without it, requests return 403.
 *
 * Version-specific:  GET https://crates.io/api/v1/crates/<name>/<version>
 * Package-level:     GET https://crates.io/api/v1/crates/<name>
 *
 * Download URL format: https://static.crates.io/crates/<name>/<name>-<version>.crate
 * .crate files are standard .tar.gz archives with a <name>-<version>/ top-level prefix.
 */

const CRATES_BASE = "https://crates.io/api/v1/crates";
const STATIC_BASE = "https://static.crates.io/crates";

// crates.io requires a descriptive User-Agent — anonymous requests get 403
const USER_AGENT = "prescripts/0.1 (supply chain security scanner; https://github.com/prescripts)";

let cratesTimeout = 30_000;

export function setCratesTimeout(ms: number): void {
  cratesTimeout = ms;
}

export interface CratesVersionInfo {
  /** Download URL for the .crate tarball. */
  downloadUrl: string;
  /** sha256 hex digest in "sha256:<hex>" format (from crates.io). */
  sha256: string | null;
  /** ISO-8601 upload time for this version. */
  uploadTime: string | null;
  /** Whether this version has been yanked. */
  yanked: boolean;
  /** Total distinct versions published. */
  totalVersions: number;
  /** Upload time of the first version. */
  firstUploadTime: string | null;
  /** crates.io login of the user who published this specific version. null if unknown. */
  publisher: string | null;
  /**
   * Unique set of publisher logins for all versions published before this one,
   * ordered by upload time. Used to compute publisherIsNewToPackage.
   */
  previousPublishers: string[];
}

interface CratesVersionResponse {
  version: {
    num: string;
    dl_path: string;
    checksum: string | null;
    created_at: string;
    yanked: boolean;
    published_by: { login: string; name: string | null } | null;
  };
}

interface CrateVersionEntry {
  num: string;
  created_at: string;
  yanked: boolean;
  checksum?: string;
  published_by: { login: string; name: string | null } | null;
}

interface CrateResponse {
  crate: {
    name: string;
    newest_version: string;
    created_at: string;
    versions: number[];
  };
  versions: CrateVersionEntry[];
}

interface CrateOwnersResponse {
  users: Array<{
    login: string;
    kind: string;
    name: string | null;
  }>;
}

async function fetchCratesJson(url: string): Promise<unknown | null> {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(cratesTimeout),
      headers: {
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
      },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/**
 * Fetch crates.io metadata for a specific crate version.
 */
export async function fetchCratesMeta(
  name: string,
  version: string
): Promise<CratesVersionInfo | null> {
  const isLatest = !version || version === "latest";
  const pkgUrl = `${CRATES_BASE}/${encodeURIComponent(name)}`;

  // Always fetch the package-level endpoint (gives version history + latest info)
  const pkgData = (await fetchCratesJson(pkgUrl)) as CrateResponse | null;
  if (!pkgData?.crate) return null;

  // Resolve "latest" to the newest version
  const resolvedVersion = isLatest ? pkgData.crate.newest_version : version;

  // Find the specific version in the versions array (avoids a second request)
  const versionEntry = pkgData.versions?.find((v) => v.num === resolvedVersion);

  const allVersions = pkgData.versions ?? [];

  if (!versionEntry) {
    // Fall back to version-specific endpoint if not in the list
    const verUrl = `${CRATES_BASE}/${encodeURIComponent(name)}/${encodeURIComponent(resolvedVersion)}`;
    const verData = (await fetchCratesJson(verUrl)) as CratesVersionResponse | null;
    if (!verData?.version) return null;

    return buildVersionInfo(name, resolvedVersion, {
      checksum: verData.version.checksum,
      created_at: verData.version.created_at,
      yanked: verData.version.yanked,
      published_by: verData.version.published_by,
      totalVersions: allVersions.length || 1,
      firstCreatedAt: pkgData.crate.created_at,
      allVersions,
    });
  }

  return buildVersionInfo(name, resolvedVersion, {
    checksum: versionEntry.checksum ?? null,
    created_at: versionEntry.created_at,
    yanked: versionEntry.yanked,
    published_by: versionEntry.published_by,
    totalVersions: allVersions.length || 1,
    firstCreatedAt: pkgData.crate.created_at,
    allVersions,
  });
}

function buildVersionInfo(
  name: string,
  version: string,
  data: {
    checksum: string | null | undefined;
    created_at: string;
    yanked: boolean;
    published_by: { login: string; name: string | null } | null;
    totalVersions: number;
    firstCreatedAt: string;
    allVersions: CrateVersionEntry[];
  }
): CratesVersionInfo {
  const downloadUrl = `${STATIC_BASE}/${encodeURIComponent(name)}/${encodeURIComponent(name)}-${encodeURIComponent(version)}.crate`;

  const publisher = data.published_by?.login ?? null;

  // Collect unique publishers for all versions older than the current one
  const previousPublishers = Array.from(new Set(
    data.allVersions
      .filter((v) => v.num !== version && v.created_at < data.created_at)
      .map((v) => v.published_by?.login)
      .filter((login): login is string => typeof login === "string")
  ));

  return {
    downloadUrl,
    sha256: data.checksum ? `sha256:${data.checksum}` : null,
    uploadTime: data.created_at ?? null,
    yanked: data.yanked,
    totalVersions: data.totalVersions,
    firstUploadTime: data.firstCreatedAt ?? null,
    publisher,
    previousPublishers,
  };
}

/**
 * Fetch the current owner logins for a crate.
 * Returns an empty array on any failure (owners are best-effort).
 */
export async function fetchCratesOwners(name: string): Promise<string[]> {
  const data = (await fetchCratesJson(
    `${CRATES_BASE}/${encodeURIComponent(name)}/owners`
  )) as CrateOwnersResponse | null;

  if (!Array.isArray(data?.users)) return [];
  return data.users
    .map((u) => u.login)
    .filter((login): login is string => typeof login === "string");
}

/**
 * Resolve "latest" to a concrete version string.
 */
export async function resolveCratesLatestVersion(name: string): Promise<string | null> {
  const data = (await fetchCratesJson(`${CRATES_BASE}/${encodeURIComponent(name)}`)) as CrateResponse | null;
  return data?.crate?.newest_version ?? null;
}

/**
 * Download raw .crate bytes.
 */
export async function fetchCrateBytes(url: string, timeout: number): Promise<Buffer> {
  const res = await fetch(url, {
    signal: AbortSignal.timeout(timeout),
    headers: { "User-Agent": USER_AGENT },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

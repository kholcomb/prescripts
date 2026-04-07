/**
 * Go module proxy client.
 *
 * Uses the Go module proxy protocol (GOPROXY).
 * Default proxy: https://proxy.golang.org
 * Configurable via GOPROXY environment variable.
 *
 * Endpoints:
 *   Info:     GET /{module}/@v/{version}.info → { Version, Time }
 *   Versions: GET /{module}/@v/list           → newline-separated version list
 *   Download: GET /{module}/@v/{version}.zip  → module zip archive
 *
 * Module paths use "/" separators. Capital letters in module paths are
 * escaped with "!" prefix (e.g. "github.com/BurntSushi/toml" →
 * "github.com/!burnt!sushi/toml") per the Go module proxy protocol.
 */

let goTimeout = 30_000;

export function setGoTimeout(ms: number): void {
  goTimeout = ms;
}

/**
 * Encode a module path or version for use in a proxy URL.
 * Capital letters are escaped as "!<lowercase>" per the Go proxy protocol.
 */
export function encodeModulePath(s: string): string {
  return s.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);
}

function getProxyBase(): string {
  const env = process.env["GOPROXY"] ?? "";
  // GOPROXY may be a comma-separated list; take the first non-"off"/"direct" entry
  const first = env.split(",").map((s) => s.trim()).find((s) => s && s !== "off" && s !== "direct");
  return (first ?? "https://proxy.golang.org").replace(/\/$/, "");
}

async function fetchGoJson(url: string): Promise<unknown | null> {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(goTimeout),
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

async function fetchGoText(url: string): Promise<string | null> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(goTimeout) });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  }
}

export interface GoVersionInfo {
  /** ISO-8601 timestamp of this version. */
  publishedAt: string | null;
  /** Total number of known versions. */
  totalVersions: number;
  /** Timestamp of the earliest known version. */
  firstPublishedAt: string | null;
}

/**
 * Fetch metadata for a specific Go module version.
 */
export async function fetchGoVersionInfo(
  moduleName: string,
  version: string
): Promise<GoVersionInfo | null> {
  const base = getProxyBase();
  const encodedModule = encodeModulePath(moduleName);
  const encodedVersion = encodeModulePath(version);

  const infoUrl = `${base}/${encodedModule}/@v/${encodedVersion}.info`;
  const listUrl = `${base}/${encodedModule}/@v/list`;

  const [infoData, listText] = await Promise.all([
    fetchGoJson(infoUrl),
    fetchGoText(listUrl),
  ]);

  if (!infoData) return null;

  const info = infoData as { Version?: string; Time?: string };
  const publishedAt = info.Time ?? null;

  // Parse the version list to get total count and earliest version
  const versions = listText
    ? listText.split("\n").map((v) => v.trim()).filter(Boolean)
    : [];

  // Fetch timestamps for first and last to get firstPublishedAt
  // Only fetch if we have a list; avoid a second round-trip when not needed
  let firstPublishedAt: string | null = null;
  if (versions.length > 0 && versions[0] !== version) {
    const firstVersion = versions[0]!;
    const firstInfoUrl = `${base}/${encodedModule}/@v/${encodeModulePath(firstVersion)}.info`;
    const firstInfo = (await fetchGoJson(firstInfoUrl)) as { Time?: string } | null;
    firstPublishedAt = firstInfo?.Time ?? null;
  } else {
    firstPublishedAt = publishedAt; // only one version
  }

  return {
    publishedAt,
    totalVersions: versions.length > 0 ? versions.length : 1,
    firstPublishedAt,
  };
}

/**
 * Resolve "latest" to the most recent tagged version from the module proxy.
 */
export async function resolveGoLatestVersion(moduleName: string): Promise<string | null> {
  const base = getProxyBase();
  const encodedModule = encodeModulePath(moduleName);
  const listText = await fetchGoText(`${base}/${encodedModule}/@v/list`);
  if (!listText) return null;
  const versions = listText.split("\n").map((v) => v.trim()).filter(Boolean);
  return versions[versions.length - 1] ?? null;
}

/**
 * Download the raw bytes of a Go module zip archive.
 */
export async function fetchGoModuleBytes(
  moduleName: string,
  version: string
): Promise<Buffer | null> {
  const base = getProxyBase();
  const encodedModule = encodeModulePath(moduleName);
  const encodedVersion = encodeModulePath(version);
  const url = `${base}/${encodedModule}/@v/${encodedVersion}.zip`;

  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(goTimeout) });
    if (!res.ok) return null;
    return Buffer.from(await res.arrayBuffer());
  } catch {
    return null;
  }
}

/**
 * Build the canonical download URL for a Go module version zip.
 */
export function goModuleDownloadUrl(moduleName: string, version: string): string {
  const base = getProxyBase();
  const encodedModule = encodeModulePath(moduleName);
  const encodedVersion = encodeModulePath(version);
  return `${base}/${encodedModule}/@v/${encodedVersion}.zip`;
}

/**
 * Maven Central registry client.
 *
 * Uses two endpoints:
 *   - Maven Central Repository: https://repo.maven.apache.org/maven2/
 *     for downloading POM files, JARs, and SHA hashes.
 *   - Maven Central Search API: https://search.maven.org/solrsearch/select
 *     for version metadata (version counts, timestamps).
 *
 * Configurable via MAVEN_CENTRAL_URL environment variable (for corporate mirrors).
 *
 * Maven coordinate → path mapping:
 *   groupId:artifactId:version → {g.replace('.','/')}/{a}/{v}/{a}-{v}.jar
 *   e.g. com.google.guava:guava:31.1-jre →
 *        com/google/guava/guava/31.1-jre/guava-31.1-jre.jar
 */

let mavenTimeout = 30_000;

export function setMavenTimeout(ms: number): void {
  mavenTimeout = ms;
}

function getRepoBase(): string {
  return (process.env["MAVEN_CENTRAL_URL"] ?? "https://repo.maven.apache.org/maven2").replace(/\/$/, "");
}

const SEARCH_BASE = "https://search.maven.org/solrsearch/select";

/**
 * Convert a Maven groupId:artifactId:version triplet to a URL path component.
 * e.g. "com.google.guava:guava:31.1-jre" →
 *      "com/google/guava/guava/31.1-jre/guava-31.1-jre"
 */
export function mavenCoordToPath(name: string, version: string): string {
  const [groupId, artifactId] = name.split(":");
  if (!groupId || !artifactId) throw new Error(`Invalid Maven coordinate: ${name}`);
  const groupPath = groupId.replace(/\./g, "/");
  return `${groupPath}/${artifactId}/${version}/${artifactId}-${version}`;
}

export interface MavenVersionInfo {
  /** Download URL for the JAR file. */
  jarUrl: string;
  /** POM file URL. */
  pomUrl: string;
  /** Expected SHA-256 hex (if available), in "sha256:<hex>" format. */
  sha256: string | null;
  /** ISO-8601 timestamp of this version's release. */
  uploadTime: string | null;
  /** Total number of versions for this artifact. */
  totalVersions: number;
  /** ISO-8601 timestamp of the earliest version. */
  firstUploadTime: string | null;
}

async function fetchMavenText(url: string): Promise<string | null> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(mavenTimeout) });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  }
}

async function fetchMavenJson(url: string): Promise<unknown | null> {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(mavenTimeout),
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

interface SearchResponse {
  response?: {
    numFound?: number;
    docs?: Array<{
      g?: string;
      a?: string;
      v?: string;
      latestVersion?: string;
      versionCount?: number;
      timestamp?: number; // milliseconds since epoch
    }>;
  };
}

/**
 * Fetch version metadata from Maven Central.
 */
export async function fetchMavenMeta(
  name: string,
  version: string
): Promise<MavenVersionInfo | null> {
  const [groupId, artifactId] = name.split(":");
  if (!groupId || !artifactId) return null;

  const base = getRepoBase();
  const coordPath = mavenCoordToPath(name, version);

  const jarUrl = `${base}/${coordPath}.jar`;
  const pomUrl = `${base}/${coordPath}.pom`;

  const metadataUrl = `${base}/${groupId.replace(/\./g, "/")}/${artifactId}/maven-metadata.xml`;

  // Phase 1: parallel fetches to two different servers (no rate-limit concern)
  const [sha256Text, sha1Text, metadataXml] = await Promise.all([
    fetchMavenText(`${base}/${coordPath}.jar.sha256`),
    fetchMavenText(`${base}/${coordPath}.jar.sha1`),
    fetchMavenText(metadataUrl),
  ]);

  let sha256: string | null = null;
  if (sha256Text?.trim()) {
    sha256 = `sha256:${sha256Text.trim().split(/\s/)[0]}`;
  } else if (sha1Text?.trim()) {
    sha256 = `sha1:${sha1Text.trim().split(/\s/)[0]}`;
  }

  // Phase 2: sequential Search API calls to avoid rate-limiting search.maven.org
  // Main core: versionCount + latest-release timestamp (used as publishedAt)
  const mainCoreUrl = `${SEARCH_BASE}?q=g:${encodeURIComponent(groupId)}+a:${encodeURIComponent(artifactId)}&rows=1&wt=json`;
  const mainCoreData = (await fetchMavenJson(mainCoreUrl)) as SearchResponse | null;
  const mainDoc = mainCoreData?.response?.docs?.[0];
  const totalVersions = mainDoc?.versionCount ?? 1;
  // For velocity, use the latest-release time; this is the package's current activity level
  const isLatest = !version || version === "latest";
  const uploadTime = mainDoc?.timestamp ? new Date(mainDoc.timestamp).toISOString() : null;

  // First-version timestamp: get oldest version name from metadata, then look it up
  const firstVersion = metadataXml ? parseFirstVersionFromMetadata(metadataXml) : null;
  let firstUploadTime: string | null = null;
  if (firstVersion && firstVersion !== version) {
    const firstVersionUrl = `${SEARCH_BASE}?q=g:${encodeURIComponent(groupId)}+a:${encodeURIComponent(artifactId)}+v:${encodeURIComponent(firstVersion)}&rows=1&wt=json&core=gav`;
    const firstVersionData = (await fetchMavenJson(firstVersionUrl)) as SearchResponse | null;
    const firstTs = firstVersionData?.response?.docs?.[0]?.timestamp;
    firstUploadTime = firstTs ? new Date(firstTs).toISOString() : null;
  }

  void isLatest; // used above for clarity — uploadTime always comes from mainDoc

  return {
    jarUrl,
    pomUrl,
    sha256,
    uploadTime,
    totalVersions,
    firstUploadTime,
  };
}

/**
 * Extract the first (oldest) version string from maven-metadata.xml.
 * The <versions> block lists versions in release order — first entry is oldest.
 */
function parseFirstVersionFromMetadata(xml: string): string | null {
  const block = xml.match(/<versions>([\s\S]*?)<\/versions>/)?.[1] ?? "";
  const m = block.match(/<version>([^<]+)<\/version>/);
  return m?.[1]?.trim() ?? null;
}

/**
 * Fetch the POM file content for a dependency.
 */
export async function fetchMavenPom(name: string, version: string): Promise<string | null> {
  const base = getRepoBase();
  const coordPath = mavenCoordToPath(name, version);
  return fetchMavenText(`${base}/${coordPath}.pom`);
}

/**
 * Download raw JAR bytes.
 */
export async function fetchJarBytes(url: string): Promise<Buffer | null> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(mavenTimeout) });
    if (!res.ok) return null;
    return Buffer.from(await res.arrayBuffer());
  } catch {
    return null;
  }
}

/**
 * Resolve "latest" to the newest version from Maven Central.
 */
export async function resolveMavenLatestVersion(name: string): Promise<string | null> {
  const [groupId, artifactId] = name.split(":");
  if (!groupId || !artifactId) return null;

  const searchUrl = `${SEARCH_BASE}?q=g:${encodeURIComponent(groupId)}+a:${encodeURIComponent(artifactId)}&rows=1&wt=json`;
  const data = (await fetchMavenJson(searchUrl)) as SearchResponse | null;
  return data?.response?.docs?.[0]?.latestVersion ?? null;
}


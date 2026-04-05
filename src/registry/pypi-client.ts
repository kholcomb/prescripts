/**
 * PyPI JSON API client.
 *
 * API reference: https://warehouse.pypa.io/api-reference/json.html
 *
 * GET https://pypi.org/pypi/<name>/json           → latest release + all versions
 * GET https://pypi.org/pypi/<name>/<version>/json → specific version
 *
 * Corporate proxy / private index support
 * ────────────────────────────────────────
 * PIP_INDEX_URL (or PIP_EXTRA_INDEX_URL):
 *   Set to a private PyPI mirror (Artifactory, Nexus, Devpi, etc.).
 *   Example: https://pypi.corp.example.com/simple/
 *   We derive the JSON API base by stripping the trailing "/simple/" suffix
 *   and using the root as the base for /pypi/<name>/<version>/json requests.
 *
 * HTTPS_PROXY / HTTP_PROXY:
 *   Standard proxy env vars. Node.js's built-in fetch() ignores these; we
 *   implement CONNECT-tunnel proxy support using http/https modules directly.
 *
 * NO_PROXY:
 *   Comma-separated list of hostnames/CIDRs to bypass the proxy. We respect
 *   this to avoid routing internal requests through an external proxy.
 */

let pypiTimeout = 30_000;

export function setPyPITimeout(ms: number): void {
  pypiTimeout = ms;
}

// ── Proxy and index configuration ─────────────────────────────────────────────

/**
 * Returns the base URL for the PyPI JSON API, respecting PIP_INDEX_URL.
 *
 * PIP_INDEX_URL typically points to a /simple/ endpoint; we derive the JSON
 * API base by removing the /simple/ suffix (or similar path suffix) and
 * falling back to pypi.org if the index doesn't serve the JSON API.
 */
function getPyPIBase(): string {
  const indexUrl =
    process.env["PIP_INDEX_URL"] ?? process.env["PIP_EXTRA_INDEX_URL"];

  if (!indexUrl) return "https://pypi.org";

  // Strip trailing /simple/ or /simple (PEP 503 simple index suffix)
  const base = indexUrl.replace(/\/simple\/?$/, "").replace(/\/$/, "");
  return base;
}

/**
 * Returns the proxy URL from environment, or null if no proxy is configured.
 * Respects NO_PROXY for the given hostname.
 */
function getProxyUrl(targetHost: string): string | null {
  const noProxy = process.env["NO_PROXY"] ?? process.env["no_proxy"] ?? "";
  if (noProxy) {
    const noProxyEntries = noProxy.split(",").map((s) => s.trim().toLowerCase());
    const host = targetHost.toLowerCase();
    for (const entry of noProxyEntries) {
      if (entry === "*" || host === entry || host.endsWith(`.${entry}`)) {
        return null;
      }
    }
  }

  return (
    process.env["HTTPS_PROXY"] ??
    process.env["https_proxy"] ??
    process.env["HTTP_PROXY"] ??
    process.env["http_proxy"] ??
    null
  );
}

/**
 * Fetch a URL respecting HTTPS_PROXY/HTTP_PROXY/NO_PROXY environment variables.
 *
 * Node.js built-in fetch() ignores proxy env vars. When a proxy is configured,
 * we implement an HTTP CONNECT tunnel using node:http + node:tls, then make
 * the HTTPS request over that tunnel.
 */
async function fetchWithProxy(
  url: string,
  options: { timeout: number; headers?: Record<string, string> }
): Promise<Response> {
  const parsed = new URL(url);
  const proxyUrl = getProxyUrl(parsed.hostname);

  if (!proxyUrl) {
    return fetch(url, {
      signal: AbortSignal.timeout(options.timeout),
      ...(options.headers ? { headers: options.headers } : {}),
    });
  }

  return fetchViaConnectProxy(url, proxyUrl, options);
}

/**
 * Fetch via HTTP CONNECT proxy tunnel.
 *
 *   1. Send HTTP CONNECT to the proxy → establishes a TCP tunnel to the target
 *   2. Upgrade the tunneled TCP socket to TLS via tls.connect()
 *   3. Make the HTTPS request over the TLS socket using createConnection option
 */
async function fetchViaConnectProxy(
  url: string,
  proxyUrl: string,
  options: { timeout: number; headers?: Record<string, string> }
): Promise<Response> {
  const { request: httpRequest } = await import("node:http");
  const { request: httpsRequest } = await import("node:https");
  const { connect: tlsConnect } = await import("node:tls");

  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const proxy = new URL(proxyUrl);
    const targetHost = target.hostname;
    const targetPort = parseInt(target.port || "443", 10);

    const connectHeaders: Record<string, string> = {
      "Host": `${targetHost}:${targetPort}`,
    };
    if (proxy.username) {
      const auth = Buffer.from(`${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`).toString("base64");
      connectHeaders["Proxy-Authorization"] = `Basic ${auth}`;
    }

    const timer = setTimeout(() => {
      connectReq.destroy();
      reject(new Error(`Proxy CONNECT timeout to ${targetHost}:${targetPort} via ${proxyUrl}`));
    }, options.timeout);

    const connectReq = httpRequest({
      hostname: proxy.hostname,
      port: parseInt(proxy.port || "8080", 10),
      method: "CONNECT",
      path: `${targetHost}:${targetPort}`,
      headers: connectHeaders,
    });

    connectReq.on("connect", (_res, socket) => {
      // Upgrade the TCP tunnel socket to TLS
      const tlsSocket = tlsConnect({
        socket,
        servername: targetHost,
        rejectUnauthorized: true,
      });

      tlsSocket.on("secureConnect", () => {
        // TLS handshake complete — make the actual HTTPS request
        const req = httpsRequest({
          createConnection: () => tlsSocket,
          hostname: targetHost,
          port: targetPort,
          path: target.pathname + target.search,
          method: "GET",
          headers: {
            "Host": targetHost,
            "Accept": "application/json",
            ...options.headers,
          },
        }, (res) => {
          clearTimeout(timer);
          const chunks: Buffer[] = [];
          res.on("data", (chunk: Buffer) => chunks.push(chunk));
          res.on("end", () => {
            const body = Buffer.concat(chunks);
            resolve(new Response(body, {
              status: res.statusCode ?? 200,
            }));
          });
          res.on("error", reject);
        });

        req.on("error", reject);
        req.end();
      });

      tlsSocket.on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });

    connectReq.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });

    connectReq.end();
  });
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
  /**
   * The version string of the release published immediately before this one,
   * by upload time. null when this is the first or only release, or when the
   * upload time cannot be determined. Used for attestationRegressed detection.
   */
  previousVersion: string | null;
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
    const res = await fetchWithProxy(url, {
      timeout: pypiTimeout,
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
 * Find the version published immediately before `currentVersion` by upload time.
 * Returns null when this is the first/only release or upload times are unavailable.
 */
function findPreviousVersion(
  releases: Record<string, PyPIFileEntry[]>,
  currentVersion: string,
  currentUploadTime: string
): string | null {
  const candidates: Array<{ version: string; uploadTime: string }> = [];

  for (const [ver, files] of Object.entries(releases)) {
    if (ver === currentVersion || files.length === 0) continue;
    // Use the earliest file upload time as the version's publish time
    const earliest = files.reduce<string | null>((min, f) => {
      if (!f.upload_time_iso_8601) return min;
      return min === null || f.upload_time_iso_8601 < min ? f.upload_time_iso_8601 : min;
    }, null);
    if (earliest && earliest < currentUploadTime) {
      candidates.push({ version: ver, uploadTime: earliest });
    }
  }

  if (candidates.length === 0) return null;

  // The predecessor is the candidate with the latest upload time before the current
  candidates.sort((a, b) => a.uploadTime.localeCompare(b.uploadTime));
  return candidates[candidates.length - 1]!.version;
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
  const base = getPyPIBase();

  // Package-level endpoint always has `releases`; version endpoint has `urls` for that version
  const pkgUrl = `${base}/pypi/${encodeURIComponent(name)}/json`;
  const verUrl = isLatest
    ? pkgUrl
    : `${base}/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`;

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
  const uploadTime = best.upload_time_iso_8601 ?? null;
  const previousVersion = uploadTime
    ? findPreviousVersion(releases, version, uploadTime)
    : null;

  return {
    tarballUrl: best.url,
    sha256: best.digests.sha256 ? `sha256:${best.digests.sha256}` : null,
    uploadTime,
    yanked: verData.info.yanked || best.yanked,
    yankedReason: verData.info.yanked_reason || best.yanked_reason || null,
    totalVersions,
    firstUploadTime: first,
    maintainer: verData.info.maintainer || null,
    author: verData.info.author || null,
    previousVersion,
  };
}

/**
 * Resolve "latest" to a concrete version number.
 */
/**
 * Download raw bytes from a URL via proxy if configured.
 * Used by the Python tarball extractor so downloads respect the same proxy as metadata.
 */
export async function fetchWithProxyRaw(url: string, timeout: number): Promise<Buffer> {
  const res = await fetchWithProxy(url, { timeout });
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

/**
 * Fetches the raw PEP 740 provenance document for a specific release file.
 *
 * Endpoint: GET https://pypi.org/integrity/<project>/<version>/<filename>/provenance
 * Requires Accept: application/vnd.pypi.integrity.v1+json
 *
 * Returns the parsed JSON body as an opaque value (parsing is the caller's
 * responsibility) or null on any failure (including 404 when no attestation exists).
 *
 * Always hits the public PyPI integrity API — attestation data is published to
 * pypi.org regardless of which index a package was installed from. A 404 simply
 * means this release has no attestation, not that the package is from a mirror.
 */
export async function fetchPyPIProvenance(
  name: string,
  version: string,
  filename: string
): Promise<unknown | null> {
  const url = `https://pypi.org/integrity/${encodeURIComponent(name)}/${encodeURIComponent(version)}/${encodeURIComponent(filename)}/provenance`;

  try {
    const res = await fetchWithProxy(url, {
      timeout: pypiTimeout,
      headers: { "Accept": "application/vnd.pypi.integrity.v1+json" },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

export async function resolvePyPILatestVersion(name: string): Promise<string | null> {
  const base = getPyPIBase();
  const url = `${base}/pypi/${encodeURIComponent(name)}/json`;
  const data = await fetchPyPI(url);
  return data?.info.version ?? null;
}

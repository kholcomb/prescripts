import pRetry, { AbortError } from "p-retry";
import { withLimit } from "./rate-limiter.js";

let registryBase = "https://registry.npmjs.org";
let requestTimeout = 30_000;

export function setRegistry(url: string): void {
  registryBase = url.replace(/\/$/, "");
}

export function setTimeout_(ms: number): void {
  requestTimeout = ms;
}

function registryUrl(name: string): string {
  // Scoped packages need the slash encoded in the URL path
  const encoded = name.startsWith("@")
    ? `@${encodeURIComponent(name.slice(1))}`
    : encodeURIComponent(name);
  return `${registryBase}/${encoded}`;
}

function versionUrl(name: string, version: string): string {
  const encoded = name.startsWith("@")
    ? `@${encodeURIComponent(name.slice(1))}`
    : encodeURIComponent(name);
  return `${registryBase}/${encoded}/${encodeURIComponent(version)}`;
}

async function fetchWithTimeout(
  url: string,
  init?: RequestInit
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), requestTimeout);
  try {
    const res = await fetch(url, { ...init, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(timer);
  }
}

export interface VersionMeta {
  tarballUrl: string;
  integrity: string | null;
  shasum: string | null;
}

export async function fetchVersionMeta(
  name: string,
  version: string
): Promise<VersionMeta> {
  return withLimit(() =>
    pRetry(
      async () => {
        const res = await fetchWithTimeout(versionUrl(name, version));
        if (res.status === 404) {
          throw new AbortError(
            `Package ${name}@${version} not found in registry`
          );
        }
        if (res.status === 401 || res.status === 403) {
          throw new AbortError(
            `Auth required for ${name}@${version}: ${res.status}`
          );
        }
        if (!res.ok) throw new Error(`Registry HTTP ${res.status} for ${name}@${version}`);
        const data = (await res.json()) as {
          dist?: { tarball?: string; integrity?: string; shasum?: string };
        };
        return {
          tarballUrl: data.dist?.tarball ?? "",
          integrity: data.dist?.integrity ?? null,
          shasum: data.dist?.shasum ?? null,
        };
      },
      {
        retries: 3,
        factor: 2,
        minTimeout: 500,
        maxTimeout: 10_000,
        onFailedAttempt: (err) => {
          if (err.retriesLeft === 0) return;
        },
      }
    )
  );
}

export async function fetchTarball(url: string): Promise<Buffer> {
  return withLimit(() =>
    pRetry(
      async () => {
        const res = await fetchWithTimeout(url);
        if (!res.ok) throw new Error(`Tarball fetch HTTP ${res.status}: ${url}`);
        const ab = await res.arrayBuffer();
        return Buffer.from(ab);
      },
      { retries: 3, factor: 2, minTimeout: 500, maxTimeout: 10_000 }
    )
  );
}

export interface FullPackageMeta {
  versions: Record<
    string,
    { dist?: { tarball?: string; integrity?: string } }
  >;
  time?: Record<string, string>;
  "dist-tags"?: Record<string, string>;
}

export async function fetchFullMeta(name: string): Promise<FullPackageMeta> {
  return withLimit(() =>
    pRetry(
      async () => {
        const res = await fetchWithTimeout(registryUrl(name));
        if (res.status === 404) {
          throw new AbortError(`Package ${name} not found`);
        }
        if (!res.ok) throw new Error(`Registry HTTP ${res.status} for ${name}`);
        return (await res.json()) as FullPackageMeta;
      },
      { retries: 3, factor: 2, minTimeout: 500, maxTimeout: 10_000 }
    )
  );
}

export async function fetchDownloads(
  name: string
): Promise<number | null> {
  try {
    const encoded = encodeURIComponent(name);
    const res = await fetchWithTimeout(
      `https://api.npmjs.org/downloads/point/last-week/${encoded}`
    );
    if (!res.ok) return null;
    const data = (await res.json()) as { downloads?: number };
    return data.downloads ?? null;
  } catch {
    return null;
  }
}

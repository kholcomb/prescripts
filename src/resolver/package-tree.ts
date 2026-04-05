import { fetchFullMeta, fetchVersionMeta } from "../registry/client.js";
import type { PackageRef } from "../types.js";

// Resolve a semver range against available versions.
// Uses a simple "highest matching version" strategy sufficient for scanning.
function resolveRange(
  range: string,
  available: string[]
): string | null {
  // Strip common prefix operators for comparison
  const clean = range.replace(/^[\^~>=<]/, "").trim();

  // Exact version
  if (available.includes(range)) return range;
  if (available.includes(clean)) return clean;

  // "latest" tag — return last in list
  if (range === "latest" || range === "*") {
    return available[available.length - 1] ?? null;
  }

  // Find versions that start with the cleaned prefix (handles ^1.2 → 1.x.x)
  const [major, minor] = clean.split(".");
  const matching = available.filter((v) => {
    const parts = v.split(".");
    if (range.startsWith("^")) {
      return parts[0] === major;
    }
    if (range.startsWith("~")) {
      return parts[0] === major && parts[1] === minor;
    }
    return v.startsWith(clean);
  });

  return matching[matching.length - 1] ?? null;
}

export async function resolveTree(
  name: string,
  version: string,
  maxDepth: number
): Promise<PackageRef[]> {
  const seen = new Map<string, PackageRef>();
  await resolveRecursive(name, version, maxDepth, 0, seen);
  return Array.from(seen.values());
}

async function resolveRecursive(
  name: string,
  versionRange: string,
  maxDepth: number,
  depth: number,
  seen: Map<string, PackageRef>
): Promise<void> {
  if (depth > maxDepth) return;

  let resolvedVersion = versionRange;
  let cachedMeta: Awaited<ReturnType<typeof fetchFullMeta>> | null = null;

  // If it looks like a range rather than an exact version, resolve it
  if (versionRange.match(/[^.\d]/) || versionRange === "latest") {
    try {
      cachedMeta = await fetchFullMeta(name);
      const available = Object.keys(cachedMeta.versions);
      const resolved = resolveRange(versionRange, available);
      if (!resolved) return;
      resolvedVersion = resolved;
    } catch {
      return;
    }
  }

  const key = `${name}@${resolvedVersion}`;
  if (seen.has(key)) return;

  try {
    const versionMeta = await fetchVersionMeta(name, resolvedVersion);
    seen.set(key, {
      name,
      version: resolvedVersion,
      resolved: versionMeta.tarballUrl,
      integrity: versionMeta.integrity,
    });
  } catch {
    return;
  }

  // Reuse cached full meta if already fetched for range resolution, otherwise fetch now
  try {
    const meta = cachedMeta ?? (await fetchFullMeta(name));
    const versionData = meta.versions[resolvedVersion] as
      | { dependencies?: Record<string, string>; optionalDependencies?: Record<string, string> }
      | undefined;
    const deps = {
      ...(versionData?.dependencies ?? {}),
      ...(versionData?.optionalDependencies ?? {}),
    };

    await Promise.all(
      Object.entries(deps).map(([depName, depRange]) =>
        resolveRecursive(depName, depRange, maxDepth, depth + 1, seen)
      )
    );
  } catch {
    // ignore dep resolution failures; we still have the package itself
  }
}

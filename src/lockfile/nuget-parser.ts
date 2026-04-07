/**
 * NuGet lockfile and project file parsers.
 *
 * NuGet supports several file formats:
 *
 * ── packages.lock.json ────────────────────────────────────────────────────────
 * Opt-in lockfile (RestorePackagesWithLockFile=true). JSON with TFM-keyed
 * dependency maps. Contains resolved version and SHA-512 content hash for
 * integrity verification.
 *
 * ── *.csproj / *.fsproj / *.vbproj ──────────────────────────────────────────
 * Project files with SDK-style <PackageReference Include="Name" Version="X" />.
 * Best-effort regex extraction. Missing Version attribute (CPM mode) is counted
 * as versionless if no Directory.Packages.props is present to resolve it.
 *
 * ── packages.config ──────────────────────────────────────────────────────────
 * Legacy XML format: <package id="Name" version="X" targetFramework="..." />
 *
 * ── Directory.Packages.props ─────────────────────────────────────────────────
 * Central Package Management (CPM): <PackageVersion Include="Name" Version="X" />
 * When present, project file <PackageReference> entries without Version are
 * resolved against this file.
 *
 * Package naming: NuGet IDs are case-insensitive. Stored as-is from the source
 * file; lowercased only when constructing registry URLs.
 */

import { access, readFile, readdir } from "node:fs/promises";
import { join, extname } from "node:path";
import type { PackageRef } from "../types.js";

// ── File detection ────────────────────────────────────────────────────────────

const NUGET_EXACT_CANDIDATES = [
  "packages.lock.json",
  "packages.config",
  "Directory.Packages.props",
] as const;

const NUGET_PROJ_EXTENSIONS = new Set([".csproj", ".fsproj", ".vbproj"]);

export async function hasNugetFiles(dir: string): Promise<boolean> {
  for (const name of NUGET_EXACT_CANDIDATES) {
    try {
      await access(join(dir, name));
      return true;
    } catch { /* not present */ }
  }
  try {
    const entries = await readdir(dir);
    return entries.some((e) => NUGET_PROJ_EXTENSIONS.has(extname(e)));
  } catch {
    return false;
  }
}

export async function getNugetLockfilePaths(dir: string): Promise<string[]> {
  const paths: string[] = [];
  for (const name of NUGET_EXACT_CANDIDATES) {
    try {
      await access(join(dir, name));
      paths.push(name);
    } catch { /* not present */ }
  }
  try {
    const entries = await readdir(dir);
    for (const e of entries) {
      if (NUGET_PROJ_EXTENSIONS.has(extname(e))) paths.push(e);
    }
  } catch { /* not present */ }
  return paths;
}

// ── packages.lock.json parser ─────────────────────────────────────────────────

interface PackagesLockEntry {
  type?: string;
  resolved?: string;
  contentHash?: string;
}

interface PackagesLockJson {
  version?: number;
  dependencies?: Record<string, Record<string, PackagesLockEntry>>;
}

/**
 * Parse packages.lock.json. All dependency types (Direct, Transitive,
 * CentralTransitive) are included — they all end up in the build.
 * contentHash ("sha512-<base64>") is used as integrity if present.
 */
export function parsePackagesLockJson(raw: string): { refs: PackageRef[]; versionlessCount: number } {
  let parsed: PackagesLockJson;
  try {
    parsed = JSON.parse(raw) as PackagesLockJson;
  } catch {
    return { refs: [], versionlessCount: 0 };
  }

  const refs: PackageRef[] = [];
  const seen = new Set<string>();

  for (const tfmDeps of Object.values(parsed.dependencies ?? {})) {
    for (const [pkgName, entry] of Object.entries(tfmDeps)) {
      const version = entry.resolved;
      if (!version) continue;

      const key = `${pkgName}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);

      refs.push({
        name: pkgName,
        version,
        resolved: "",
        integrity: entry.contentHash ?? null,
      });
    }
  }

  return { refs, versionlessCount: 0 };
}

// ── *.csproj / *.fsproj / *.vbproj parser ────────────────────────────────────

/**
 * Parse SDK-style project files for <PackageReference> elements.
 * Handles both self-closing and paired tags. Missing Version is counted as
 * versionless (CPM mode — resolved externally via Directory.Packages.props).
 */
export function parseCsprojContent(raw: string): { refs: PackageRef[]; versionlessCount: number } {
  const refs: PackageRef[] = [];
  const seen = new Set<string>();
  let versionlessCount = 0;

  // Match <PackageReference ... /> or <PackageReference ...>
  // Both attribute orders are valid in XML so extract Include and Version separately.
  const tagRe = /<PackageReference\b([^>]+)>/g;
  let m: RegExpExecArray | null;

  while ((m = tagRe.exec(raw)) !== null) {
    const attrs = m[1] ?? "";

    const includeM = attrs.match(/\bInclude="([^"]+)"/i);
    const versionM = attrs.match(/\bVersion="([^"]+)"/i);

    const name = includeM?.[1]?.trim();
    const version = versionM?.[1]?.trim();

    if (!name) continue;
    if (!version) {
      versionlessCount++;
      continue;
    }

    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);

    refs.push({ name, version, resolved: "", integrity: null });
  }

  return { refs, versionlessCount };
}

// ── packages.config parser ────────────────────────────────────────────────────

/**
 * Parse legacy packages.config format.
 */
export function parsePackagesConfig(raw: string): { refs: PackageRef[]; versionlessCount: number } {
  const refs: PackageRef[] = [];
  const seen = new Set<string>();

  const re = /<package\b([^>]+)>/g;
  let m: RegExpExecArray | null;

  while ((m = re.exec(raw)) !== null) {
    const attrs = m[1] ?? "";
    const idM = attrs.match(/\bid="([^"]+)"/i);
    const verM = attrs.match(/\bversion="([^"]+)"/i);

    const name = idM?.[1]?.trim();
    const version = verM?.[1]?.trim();

    if (!name || !version) continue;

    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);

    refs.push({ name, version, resolved: "", integrity: null });
  }

  return { refs, versionlessCount: 0 };
}

// ── Directory.Packages.props parser ──────────────────────────────────────────

/**
 * Parse Central Package Management file.
 * <PackageVersion Include="Name" Version="X.Y.Z" />
 */
export function parseDirectoryPackagesProps(raw: string): { refs: PackageRef[]; versionlessCount: number } {
  const refs: PackageRef[] = [];
  const seen = new Set<string>();

  const re = /<PackageVersion\b([^>]+)>/g;
  let m: RegExpExecArray | null;

  while ((m = re.exec(raw)) !== null) {
    const attrs = m[1] ?? "";
    const includeM = attrs.match(/\bInclude="([^"]+)"/i);
    const versionM = attrs.match(/\bVersion="([^"]+)"/i);

    const name = includeM?.[1]?.trim();
    const version = versionM?.[1]?.trim();

    if (!name || !version) continue;

    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);

    refs.push({ name, version, resolved: "", integrity: null });
  }

  return { refs, versionlessCount: 0 };
}

// ── Unified dispatch ──────────────────────────────────────────────────────────

/**
 * Parse NuGet file content by filename.
 */
export function parseNugetLockfileContent(
  content: string,
  filename: string
): { refs: PackageRef[]; versionlessCount: number } {
  if (filename === "packages.lock.json") return parsePackagesLockJson(content);
  if (filename === "packages.config") return parsePackagesConfig(content);
  if (filename === "Directory.Packages.props") return parseDirectoryPackagesProps(content);
  const ext = extname(filename);
  if (NUGET_PROJ_EXTENSIONS.has(ext)) return parseCsprojContent(content);
  return { refs: [], versionlessCount: 0 };
}

// ── Async lockfile reader ─────────────────────────────────────────────────────

/**
 * Read all NuGet project/lockfiles in `dir`, merge and deduplicate refs.
 *
 * packages.lock.json is the authoritative source when present (has integrity
 * hashes and resolved versions). Project files are fallbacks.
 *
 * When CPM is in use (Directory.Packages.props present), csproj files may have
 * versionless PackageReference entries that are resolved by the props file.
 */
export async function parseNugetLockfile(
  dir: string
): Promise<{ refs: PackageRef[]; lockfileDir: string; warnings?: string[] } | null> {
  const filenames = await getNugetLockfilePaths(dir);
  if (filenames.length === 0) return null;

  // Build CPM version map from Directory.Packages.props if present
  const cpmVersions = new Map<string, string>(); // lowercase name → version
  if (filenames.includes("Directory.Packages.props")) {
    try {
      const raw = await readFile(join(dir, "Directory.Packages.props"), "utf-8");
      const { refs } = parseDirectoryPackagesProps(raw);
      for (const ref of refs) {
        cpmVersions.set(ref.name.toLowerCase(), ref.version);
      }
    } catch { /* skip */ }
  }

  const allRefs: PackageRef[] = [];
  const seen = new Set<string>();
  let totalVersionless = 0;

  for (const filename of filenames) {
    let raw: string;
    try {
      raw = await readFile(join(dir, filename), "utf-8");
    } catch {
      continue;
    }

    const { refs, versionlessCount } = parseNugetLockfileContent(raw, filename);

    // For versionless csproj entries, try to resolve from CPM map
    if (versionlessCount > 0 && cpmVersions.size > 0) {
      // Re-parse to get names of versionless entries
      const tagRe = /<PackageReference\b([^>]+)>/g;
      let m: RegExpExecArray | null;
      while ((m = tagRe.exec(raw)) !== null) {
        const attrs = m[1] ?? "";
        const includeM = attrs.match(/\bInclude="([^"]+)"/i);
        const versionM = attrs.match(/\bVersion="([^"]+)"/i);
        const name = includeM?.[1]?.trim();
        if (!name || versionM) continue; // already handled in main parse

        const resolvedVersion = cpmVersions.get(name.toLowerCase());
        if (resolvedVersion) {
          const key = `${name}@${resolvedVersion}`;
          if (!seen.has(key)) {
            seen.add(key);
            allRefs.push({ name, version: resolvedVersion, resolved: "", integrity: null });
          }
        } else {
          totalVersionless++;
        }
      }
    } else {
      totalVersionless += versionlessCount;
    }

    for (const ref of refs) {
      const key = `${ref.name}@${ref.version}`;
      if (!seen.has(key)) {
        seen.add(key);
        allRefs.push(ref);
      }
    }
  }

  if (allRefs.length === 0 && totalVersionless === 0) return null;

  if (totalVersionless > 0) {
    const noun = totalVersionless === 1 ? "dependency" : "dependencies";
    return {
      refs: allRefs,
      lockfileDir: dir,
      warnings: [`${totalVersionless} NuGet ${noun} skipped: no explicit version (Central Package Management). Results may be incomplete.`],
    };
  }

  return { refs: allRefs, lockfileDir: dir };
}

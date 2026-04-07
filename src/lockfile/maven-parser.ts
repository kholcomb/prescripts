/**
 * Maven and Gradle dependency parsers.
 *
 * Maven has no native lockfile — pom.xml is the dependency manifest.
 * Gradle adds gradle.lockfile as a proper lockfile when dependency locking
 * is enabled. build.gradle / build.gradle.kts are parsed as a best-effort
 * fallback.
 *
 * Package naming convention: "groupId:artifactId" (Maven coordinates).
 *
 * ── pom.xml ──────────────────────────────────────────────────────────────────
 * XML file with <dependencies> blocks. We extract groupId, artifactId, version.
 * Scopes "test" and "provided" are skipped (they don't ship with the artifact).
 * Range versions ([1.0,2.0), (,1.5]) are skipped — they can't be resolved
 * without running the Maven resolver.
 *
 * ── gradle.lockfile ──────────────────────────────────────────────────────────
 * Gradle dependency locking format. One dependency per line:
 *   group:artifact:version=configuration1,configuration2,...
 * Lines starting with "#" are comments.
 *
 * ── build.gradle / build.gradle.kts ─────────────────────────────────────────
 * Best-effort regex extraction of implementation/api/compileOnly declarations:
 *   implementation 'com.google.guava:guava:31.1-jre'
 *   implementation("com.google.guava:guava:31.1-jre")
 * This does not handle dynamic versions ($guavaVersion), variable substitution,
 * or BOM imports — those refs are silently skipped.
 *
 * ── Multi-module support ──────────────────────────────────────────────────────
 * Maven aggregator pom.xml declares sub-modules via <modules><module>path</module>...
 * Gradle multi-project roots declare sub-projects in settings.gradle / settings.gradle.kts
 * via include(':module') or include 'module'. parseMavenLockfile() recursively scans
 * all discovered sub-module directories (max depth 5) and merges their refs.
 */

import { access, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { PackageRef } from "../types.js";

// ── File detection ────────────────────────────────────────────────────────────

const MAVEN_CANDIDATES = [
  "pom.xml",
  "gradle.lockfile",
  "build.gradle",
  "build.gradle.kts",
  // Gradle multi-project roots only have a settings file at the root level
  "settings.gradle",
  "settings.gradle.kts",
] as const;

export async function hasMavenOrGradleFiles(dir: string): Promise<boolean> {
  const checks = MAVEN_CANDIDATES.map((f) => access(join(dir, f)));
  const results = await Promise.allSettled(checks);
  return results.some((r) => r.status === "fulfilled");
}

export async function getMavenLockfilePaths(dir: string): Promise<string[]> {
  const paths: string[] = [];
  for (const candidate of MAVEN_CANDIDATES) {
    try {
      await access(join(dir, candidate));
      paths.push(candidate);
    } catch { /* not present */ }
  }
  return paths;
}

// ── pom.xml parser ────────────────────────────────────────────────────────────

const SKIP_SCOPES = new Set(["test", "provided", "system"]);

// Range version indicators: [, (, , in version
const RANGE_RE = /[\[(,)]/;

/**
 * Parse a pom.xml string and return PackageRef[].
 * Skips test/provided/system scope and range versions.
 */
export function parsePomContent(raw: string): PackageRef[] {
  const refs: PackageRef[] = [];
  const seen = new Set<string>();

  // Extract all <dependency> blocks (handles nested indentation)
  const depBlockRe = /<dependency>([\s\S]*?)<\/dependency>/g;
  let match: RegExpExecArray | null;

  while ((match = depBlockRe.exec(raw)) !== null) {
    const block = match[1] ?? "";

    const groupId = extractXmlTag(block, "groupId");
    const artifactId = extractXmlTag(block, "artifactId");
    const version = extractXmlTag(block, "version");
    const scope = extractXmlTag(block, "scope");

    if (!groupId || !artifactId) continue;

    // Skip scopes we don't care about
    if (scope && SKIP_SCOPES.has(scope.toLowerCase())) continue;

    // Skip if version is missing or is a range/property
    if (!version) continue;
    if (RANGE_RE.test(version)) continue;    // e.g. [1.0,2.0)
    if (version.startsWith("${")) continue;  // Maven property: ${someVersion}

    const name = `${groupId}:${artifactId}`;
    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);

    refs.push({ name, version, resolved: "", integrity: null });
  }

  return refs;
}

function extractXmlTag(block: string, tag: string): string | null {
  const re = new RegExp(`<${tag}[^>]*>([^<]+)</${tag}>`);
  const m = re.exec(block);
  return m?.[1]?.trim() ?? null;
}

// ── gradle.lockfile parser ────────────────────────────────────────────────────

/**
 * Parse a gradle.lockfile string.
 * Format: group:artifact:version=config1,config2,...
 */
export function parseGradleLockfileContent(raw: string): PackageRef[] {
  const refs: PackageRef[] = [];
  const seen = new Set<string>();

  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    // Strip the "=configurations" part
    const eqIdx = trimmed.indexOf("=");
    const depPart = eqIdx >= 0 ? trimmed.slice(0, eqIdx) : trimmed;

    const parts = depPart.split(":");
    if (parts.length < 3) continue;

    const groupId = parts[0]?.trim();
    const artifactId = parts[1]?.trim();
    const version = parts[2]?.trim();

    if (!groupId || !artifactId || !version) continue;
    if (RANGE_RE.test(version)) continue;

    const name = `${groupId}:${artifactId}`;
    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);

    refs.push({ name, version, resolved: "", integrity: null });
  }

  return refs;
}

// ── build.gradle / build.gradle.kts parser ────────────────────────────────────

/**
 * Best-effort extraction of dependencies from a Groovy/Kotlin Gradle script.
 * Only handles literal string declarations; variable substitution is skipped.
 */
export function parseBuildGradleContent(raw: string): PackageRef[] {
  const refs: PackageRef[] = [];
  const seen = new Set<string>();

  // Regex created inside the function to avoid shared lastIndex state across calls.
  // Matches: implementation 'g:a:v', api("g:a:v"), compileOnly 'g:a:v', etc.
  // (?:\s*\(|\s+) handles both call-style parens and space-separated forms.
  const re =
    /\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|annotationProcessor)(?:\s*\(|\s+)['"]([^'"]+)['"]/g;

  let match: RegExpExecArray | null;
  while ((match = re.exec(raw)) !== null) {
    const coord = match[1] ?? "";
    const parts = coord.split(":");
    if (parts.length < 3) continue;

    const groupId = parts[0]?.trim();
    const artifactId = parts[1]?.trim();
    const version = parts[2]?.trim();

    if (!groupId || !artifactId || !version) continue;
    if (RANGE_RE.test(version)) continue;
    if (version.startsWith("$")) continue; // Gradle variable interpolation

    const name = `${groupId}:${artifactId}`;
    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);

    refs.push({ name, version, resolved: "", integrity: null });
  }

  return refs;
}

// ── Multi-module helpers ──────────────────────────────────────────────────────

/**
 * Extract sub-module relative paths from a Maven aggregator pom.xml.
 * Reads the <modules><module>path</module>...</modules> block.
 */
export function extractPomModules(raw: string): string[] {
  const block = raw.match(/<modules>([\s\S]*?)<\/modules>/)?.[1] ?? "";
  const paths: string[] = [];
  const re = /<module>([^<]+)<\/module>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(block)) !== null) {
    const p = m[1]!.trim();
    if (p) paths.push(p);
  }
  return paths;
}

/**
 * Extract sub-project relative paths from a Gradle settings file.
 * Handles both Groovy and Kotlin DSL forms:
 *   include ':core', ':web'          (Groovy, colon prefix)
 *   include("core", "web")           (Kotlin/Groovy, no colon)
 *   include(":sub:nested")           (nested → "sub/nested")
 */
export function extractGradleSubprojects(raw: string): string[] {
  const paths: string[] = [];
  const seen = new Set<string>();
  // Find each `include` statement (to end of line / semicolon), then extract
  // all quoted strings from the arguments — handles both forms:
  //   include ':core', ':web', ':cli'       (Groovy multi-arg)
  //   include(":core")                      (Kotlin / Groovy single-arg)
  const includeRe = /\binclude\b([^\n;]+)/g;
  let im: RegExpExecArray | null;
  while ((im = includeRe.exec(raw)) !== null) {
    const argStr = im[1]!;
    const quotedRe = /['"]([^'"]+)['"]/g;
    let qm: RegExpExecArray | null;
    while ((qm = quotedRe.exec(argStr)) !== null) {
      // Strip leading colon, convert ':sub:nested' → 'sub/nested'
      const p = qm[1]!.replace(/^:/, "").replace(/:/g, "/").trim();
      if (p && !seen.has(p)) {
        seen.add(p);
        paths.push(p);
      }
    }
  }
  return paths;
}

// ── Unified lockfile parser ───────────────────────────────────────────────────

/**
 * Parse lockfile content by filename.
 */
export function parseMavenLockfileContent(content: string, filename: string): PackageRef[] {
  if (filename === "pom.xml") return parsePomContent(content);
  if (filename === "gradle.lockfile") return parseGradleLockfileContent(content);
  if (filename === "build.gradle" || filename === "build.gradle.kts") {
    return parseBuildGradleContent(content);
  }
  return [];
}

const MAX_MODULE_DEPTH = 5;

/**
 * Find and parse all Maven/Gradle files in `dir`, recursively following
 * sub-module declarations from pom.xml <modules> and settings.gradle include().
 * Results are merged and deduped by name@version across all modules.
 */
export async function parseMavenLockfile(
  dir: string,
  _depth = 0
): Promise<{ refs: PackageRef[]; lockfileDir: string } | null> {
  const filenames = await getMavenLockfilePaths(dir);
  if (filenames.length === 0) return null;

  const seen = new Set<string>();
  const allRefs: PackageRef[] = [];

  // Track raw content for sub-module discovery
  const rawByFile = new Map<string, string>();

  for (const filename of filenames) {
    let raw: string;
    try {
      raw = await readFile(join(dir, filename), "utf-8");
    } catch {
      continue;
    }
    rawByFile.set(filename, raw);
    for (const ref of parseMavenLockfileContent(raw, filename)) {
      const key = `${ref.name}@${ref.version}`;
      if (!seen.has(key)) {
        seen.add(key);
        allRefs.push(ref);
      }
    }
  }

  // Discover sub-module paths
  if (_depth < MAX_MODULE_DEPTH) {
    const subPaths = new Set<string>();

    const pomRaw = rawByFile.get("pom.xml");
    if (pomRaw) {
      for (const p of extractPomModules(pomRaw)) subPaths.add(p);
    }

    for (const settingsFile of ["settings.gradle", "settings.gradle.kts"] as const) {
      const settingsRaw = rawByFile.get(settingsFile);
      if (settingsRaw) {
        for (const p of extractGradleSubprojects(settingsRaw)) subPaths.add(p);
      }
    }

    // Recursively scan each sub-module directory
    await Promise.all(
      [...subPaths].map(async (subPath) => {
        const subResult = await parseMavenLockfile(join(dir, subPath), _depth + 1);
        if (!subResult) return;
        for (const ref of subResult.refs) {
          const key = `${ref.name}@${ref.version}`;
          if (!seen.has(key)) {
            seen.add(key);
            allRefs.push(ref);
          }
        }
      })
    );
  }

  if (allRefs.length === 0) return null;
  return { refs: allRefs, lockfileDir: dir };
}

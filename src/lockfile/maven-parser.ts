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
 * ── gradle/libs.versions.toml ────────────────────────────────────────────────
 * Gradle version catalog. Centralizes dependency versions outside build scripts.
 * [versions] block defines named version strings; [libraries] block declares
 * group:artifact coordinates and references those version aliases via version.ref.
 * Inline version = "..." is also supported. [bundles] and [plugins] are ignored.
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
  // Gradle version catalog — canonical location is gradle/libs.versions.toml,
  // but some projects place it at the repo root.
  "gradle/libs.versions.toml",
  "libs.versions.toml",
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
 * versionlessCount is the number of non-test deps that had no explicit version
 * (BOM/parent-managed) — callers use this to emit incomplete-scan warnings.
 */
export function parsePomContent(raw: string): { refs: PackageRef[]; versionlessCount: number } {
  const refs: PackageRef[] = [];
  const seen = new Set<string>();
  let versionlessCount = 0;

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

    // Skip if version is missing or is a range/property — but count them
    if (!version || version.startsWith("${")) {
      versionlessCount++;
      continue;
    }
    if (RANGE_RE.test(version)) continue;    // e.g. [1.0,2.0)

    const name = `${groupId}:${artifactId}`;
    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);

    refs.push({ name, version, resolved: "", integrity: null });
  }

  return { refs, versionlessCount };
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

// ── Gradle version catalog parser (libs.versions.toml) ───────────────────────

/**
 * Parse a Gradle version catalog (libs.versions.toml).
 *
 * Handles the [versions] and [libraries] sections only; [bundles] and [plugins]
 * are ignored. Library entries support two forms:
 *
 *   # inline version
 *   logback = { module = "ch.qos.logback:logback-classic", version = "1.4.11" }
 *
 *   # version reference
 *   jackson = { group = "com.fasterxml.jackson.core", name = "jackson-databind", version.ref = "jackson" }
 *
 * Multi-line TOML is not supported — version catalog files always use single-line
 * inline tables in practice.
 */
export function parseVersionCatalogContent(raw: string): { refs: PackageRef[]; versionlessCount: number } {
  const refs: PackageRef[] = [];
  const seen = new Set<string>();
  let versionlessCount = 0;

  // Pass 1: collect [versions] → version alias map
  const versionMap = new Map<string, string>();
  let section = "";
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const sectionM = trimmed.match(/^\[(\w+)\]$/);
    if (sectionM) { section = sectionM[1]!; continue; }

    if (section === "versions") {
      // key = "value"  or  key = { require = "value", ... }
      const m = trimmed.match(/^[\w-]+\s*=\s*"([^"]+)"/);
      if (m) {
        const key = trimmed.split(/\s*=/)[0]!.trim();
        versionMap.set(key, m[1]!);
      }
    }
  }

  // Pass 2: collect [libraries]
  section = "";
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const sectionM = trimmed.match(/^\[(\w+)\]$/);
    if (sectionM) { section = sectionM[1]!; continue; }

    if (section !== "libraries") continue;

    // Resolve group:artifact
    let groupId: string | null = null;
    let artifactId: string | null = null;

    const moduleM = trimmed.match(/\bmodule\s*=\s*"([^"]+)"/);
    if (moduleM) {
      const [g, a] = moduleM[1]!.split(":");
      groupId = g ?? null;
      artifactId = a ?? null;
    } else {
      const groupM = trimmed.match(/\bgroup\s*=\s*"([^"]+)"/);
      const nameM = trimmed.match(/\bname\s*=\s*"([^"]+)"/);
      groupId = groupM?.[1] ?? null;
      artifactId = nameM?.[1] ?? null;
    }

    if (!groupId || !artifactId) continue;

    // Resolve version: prefer version.ref, fall back to inline version = "..."
    let version: string | null = null;
    const versionRefM = trimmed.match(/\bversion\.ref\s*=\s*"([^"]+)"/);
    if (versionRefM) {
      version = versionMap.get(versionRefM[1]!) ?? null;
    } else {
      // Match `version = "..."` but not `version.ref = "..."`
      const versionM = trimmed.match(/\bversion\s*=\s*"([^"]+)"/);
      if (versionM && !trimmed.includes("version.ref")) {
        version = versionM[1]!;
      }
    }

    if (!version) {
      versionlessCount++;
      continue;
    }
    if (RANGE_RE.test(version)) continue;

    const name = `${groupId}:${artifactId}`;
    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    refs.push({ name, version, resolved: "", integrity: null });
  }

  return { refs, versionlessCount };
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
 * Returns { refs, versionlessCount } — versionlessCount is non-zero only for pom.xml
 * and libs.versions.toml (BOM-managed / no-version entries).
 */
export function parseMavenLockfileContent(
  content: string,
  filename: string
): { refs: PackageRef[]; versionlessCount: number } {
  if (filename === "pom.xml") return parsePomContent(content);
  if (filename === "gradle.lockfile") return { refs: parseGradleLockfileContent(content), versionlessCount: 0 };
  if (filename === "build.gradle" || filename === "build.gradle.kts") {
    return { refs: parseBuildGradleContent(content), versionlessCount: 0 };
  }
  if (filename.endsWith("libs.versions.toml")) return parseVersionCatalogContent(content);
  return { refs: [], versionlessCount: 0 };
}

const MAX_MODULE_DEPTH = 5;

// Internal recursive helper — carries raw versionlessCount rather than a
// formatted string so the top-level call can produce one consolidated warning.
async function parseMavenLockfileInternal(
  dir: string,
  seen: Set<string>,
  depth: number
): Promise<{ refs: PackageRef[]; versionlessCount: number }> {
  const filenames = await getMavenLockfilePaths(dir);
  if (filenames.length === 0) return { refs: [], versionlessCount: 0 };

  const allRefs: PackageRef[] = [];
  let versionlessCount = 0;
  const rawByFile = new Map<string, string>();

  for (const filename of filenames) {
    let raw: string;
    try {
      raw = await readFile(join(dir, filename), "utf-8");
    } catch {
      continue;
    }
    rawByFile.set(filename, raw);
    const parsed = parseMavenLockfileContent(raw, filename);
    versionlessCount += parsed.versionlessCount;
    for (const ref of parsed.refs) {
      const key = `${ref.name}@${ref.version}`;
      if (!seen.has(key)) {
        seen.add(key);
        allRefs.push(ref);
      }
    }
  }

  if (depth < MAX_MODULE_DEPTH) {
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

    const subResults = await Promise.all(
      [...subPaths].map((subPath) =>
        parseMavenLockfileInternal(join(dir, subPath), seen, depth + 1)
      )
    );
    for (const sub of subResults) {
      versionlessCount += sub.versionlessCount;
      allRefs.push(...sub.refs); // already deduped via shared `seen`
    }
  }

  return { refs: allRefs, versionlessCount };
}

/**
 * Find and parse all Maven/Gradle files in `dir`, recursively following
 * sub-module declarations from pom.xml <modules> and settings.gradle include().
 * Results are merged and deduped by name@version across all modules.
 *
 * Returns a `warnings` array when BOM/parent-managed dependencies were skipped
 * (versionless deps in pom.xml) so callers can surface an incomplete-scan notice.
 */
export async function parseMavenLockfile(
  dir: string
): Promise<{ refs: PackageRef[]; lockfileDir: string; warnings?: string[] } | null> {
  const seen = new Set<string>();
  const { refs, versionlessCount } = await parseMavenLockfileInternal(dir, seen, 0);

  if (refs.length === 0 && versionlessCount === 0) return null;

  if (versionlessCount > 0) {
    const noun = versionlessCount === 1 ? "dependency" : "dependencies";
    return {
      refs,
      lockfileDir: dir,
      warnings: [`${versionlessCount} Maven ${noun} skipped: no explicit version (BOM/parent POM managed). Results may be incomplete.`],
    };
  }

  return { refs, lockfileDir: dir };
}

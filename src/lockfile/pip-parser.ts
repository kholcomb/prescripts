/**
 * Parses pip lockfiles into PackageRef arrays.
 *
 * Supports:
 *   - uv.lock      (TOML [[package]] blocks with sha256 hashes — preferred)
 *   - poetry.lock  (TOML [[package]] blocks with sha256 hashes)
 *   - requirements.txt (PEP 508 pinned: name==version, name[extra]==version)
 *
 * uv.lock and poetry.lock provide sha256 in `sha256:<hex>` format matching
 * PyPI's API hash representation. requirements.txt has no integrity hashes.
 */

import { readFile, readdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import type { PackageRef } from "../types.js";

export interface ParseResult {
  refs: PackageRef[];
  lockfileDir: string;
}

// ── uv.lock ───────────────────────────────────────────────────────────────────

/**
 * Parse a uv.lock file (TOML with [[package]] blocks).
 *
 * uv.lock format:
 *   version = 1
 *   [[package]]
 *   name = "requests"
 *   version = "2.32.3"
 *   source = { registry = "https://pypi.org/simple" }
 *   sdist = { url = "...", hash = "sha256:70761...", size = 131268 }
 *   wheels = [
 *       { url = "...", hash = "sha256:9823...", size = 88776 },
 *   ]
 *
 * Only registry packages are included. git/path/url sources are skipped
 * (no corresponding PyPI metadata to fetch).
 */
export function parseUvLock(raw: string): PackageRef[] {
  const refs: PackageRef[] = [];
  const blocks = raw.split(/\[\[package\]\]/);

  for (const block of blocks) {
    if (!block.trim()) continue;

    const nameMatch = /^name\s*=\s*"([^"]+)"/m.exec(block);
    const versionMatch = /^version\s*=\s*"([^"]+)"/m.exec(block);
    const sourceMatch = /^source\s*=\s*\{([^}]+)\}/m.exec(block);

    if (!nameMatch || !versionMatch) continue;

    const name = nameMatch[1]!.toLowerCase().replace(/_/g, "-");
    const version = versionMatch[1]!;

    // Only include registry packages (skip git/path/url sources for now)
    if (sourceMatch) {
      const sourceContent = sourceMatch[1]!;
      if (!sourceContent.includes("registry")) continue;
    } else {
      // No source field → likely the root package, skip
      continue;
    }

    // Extract first sha256 hash in the block (from sdist or wheels[0])
    const hashMatch = /hash\s*=\s*"(sha256:[a-fA-F0-9]{64})"/m.exec(block);
    const integrity = hashMatch ? hashMatch[1]! : null;

    refs.push({ name, version, resolved: "", integrity });
  }

  return refs;
}

// ── poetry.lock ───────────────────────────────────────────────────────────────

/**
 * Parse a poetry.lock file.
 *
 * poetry.lock is TOML but we only need the [[package]] blocks.
 * Each block has: name, version, and optionally [package.files] with sha256 hashes.
 *
 * We parse it with a simple line-oriented state machine rather than a full TOML
 * parser to avoid adding a dependency.
 */
export function parsePoetryLock(raw: string): PackageRef[] {
  const refs: PackageRef[] = [];
  const lines = raw.split("\n");

  let inPackage = false;
  let inFiles = false;
  let currentName: string | null = null;
  let currentVersion: string | null = null;
  let currentHash: string | null = null;

  function flush() {
    if (currentName && currentVersion) {
      refs.push({
        name: currentName,
        version: currentVersion,
        resolved: "",
        integrity: currentHash,
      });
    }
    currentName = null;
    currentVersion = null;
    currentHash = null;
    inFiles = false;
  }

  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed === "[[package]]") {
      flush();
      inPackage = true;
      continue;
    }

    if (trimmed.startsWith("[[") || trimmed.startsWith("[metadata")) {
      flush();
      inPackage = false;
      continue;
    }

    if (!inPackage) continue;

    // Detect [package.files] subsection
    if (trimmed === "[package.files]" || trimmed === "[package.extras]" ||
        trimmed === "[package.dependencies]" || trimmed === "[package.source]") {
      inFiles = trimmed === "[package.files]";
      continue;
    }

    if (trimmed.startsWith("[package.")) {
      inFiles = false;
      continue;
    }

    // Parse name and version outside subsections
    if (!inFiles) {
      const nameMatch = trimmed.match(/^name\s*=\s*"([^"]+)"/);
      if (nameMatch) {
        currentName = nameMatch[1]!.toLowerCase().replace(/_/g, "-");
        continue;
      }
      const versionMatch = trimmed.match(/^version\s*=\s*"([^"]+)"/);
      if (versionMatch) {
        currentVersion = versionMatch[1]!;
        continue;
      }
    }

    // Collect first sha256 hash from the files section
    if (inFiles && !currentHash) {
      // Format: {file = "requests-2.28.0.tar.gz", hash = "sha256:abc123..."}
      const hashMatch = trimmed.match(/hash\s*=\s*"(sha256:[a-fA-F0-9]{64})"/);
      if (hashMatch) {
        currentHash = hashMatch[1]!;
      }
    }
  }

  flush();
  return refs;
}

// ── requirements.txt ─────────────────────────────────────────────────────────

/**
 * Join backslash-continued lines before parsing.
 * Per the pip spec, a line ending in `\` continues on the next line.
 */
function joinContinuations(raw: string): string {
  return raw.replace(/\\\n/g, " ");
}

/**
 * Parse a requirements.txt file into PackageRefs.
 *
 * Handles:
 *   name==1.2.3                     exact pin
 *   name[extra]==1.2.3              extras
 *   name>=1.2.3,<2.0                version ranges
 *   name==1.2.3 --hash=sha256:abc   hash-pinned (pip --require-hashes)
 *   # comments, blank lines         skipped
 *   -r other.txt, -c constraints    skipped (followed separately by caller)
 *   https://..., git+https://...    skipped (no PyPI lookup)
 *   \ line continuations            joined before parsing
 */
export function parseRequirementsTxt(raw: string): PackageRef[] {
  const refs: PackageRef[] = [];

  for (const rawLine of joinContinuations(raw).split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    // Options and URL schemes — not installable from PyPI
    if (
      line.startsWith("-") ||
      /^https?:\/\//i.test(line) ||
      /^(git|svn|hg|bzr)\+/i.test(line) ||
      line.startsWith("file://") ||
      line.startsWith("./") ||
      line.startsWith("../")
    ) continue;

    // Strip inline comment (space + # not inside a marker)
    const withoutComment = line.replace(/\s+#[^'"\[]*$/, "").trim();

    // Extract --hash=sha256:<hex> values (may be multiple, take first sha256)
    const hashMatch = /--hash=sha256:([a-fA-F0-9]{64})/i.exec(withoutComment);
    const integrity = hashMatch ? `sha256:${hashMatch[1]!}` : null;

    // Strip --options (hash directives, --global-option, etc.) from the spec
    const specOnly = withoutComment.replace(/\s+--\S+/g, "").trim();

    // Strip environment markers (everything after unquoted `;`)
    const withoutMarker = specOnly.split(/\s*;\s*/)[0]!.trim();

    // Extract name and version: name[extra]<op>version[,<op>version...]
    const match = withoutMarker.match(
      /^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)(?:\[[^\]]*\])?([=!<>~,][^\s]+)?$/
    );
    if (!match) continue;

    const name = match[1]!.toLowerCase().replace(/_/g, "-");
    const versionSpec = match[3]?.trim() ?? "";

    // Extract the first exact version from the spec string
    const exactMatch = /(?:^|,)==([^,!\s]+)/.exec(versionSpec);
    const version = exactMatch ? exactMatch[1]! : versionSpec.replace(/^[=!<>~]+/, "") || "unknown";

    refs.push({ name, version, resolved: "", integrity });
  }
  return refs;
}

// ── Project-wide requirements file discovery ──────────────────────────────────

// Directories to skip during recursive search
const SKIP_DIRS = new Set([
  "node_modules", ".git", ".hg", ".svn",
  ".venv", "venv", "env", ".env",
  "__pycache__", ".tox", ".nox",
  "dist", "build", ".eggs", "*.egg-info",
  ".mypy_cache", ".pytest_cache", ".ruff_cache",
]);

/**
 * Recursively finds all requirements*.txt files anywhere under `dir`.
 * Returns absolute paths sorted so root-level files come first.
 */
export async function findRequirementsFiles(dir: string): Promise<string[]> {
  const found: string[] = [];

  async function walk(current: string, depth: number, insideReqDir: boolean): Promise<void> {
    if (depth > 8) return; // guard against deep or circular trees
    let entries: import("node:fs").Dirent[];
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name) || entry.name.endsWith(".egg-info")) continue;
        // Any directory named "requirements" marks its contents as req files
        const isReqDir = entry.name.toLowerCase() === "requirements";
        await walk(join(current, entry.name), depth + 1, insideReqDir || isReqDir);
      } else if (entry.isFile() && entry.name.endsWith(".txt")) {
        // Include if: named requirements*.txt anywhere, OR any .txt inside a requirements/ dir
        if (insideReqDir || /^requirements/i.test(entry.name)) {
          found.push(join(current, entry.name));
        }
      }
    }
  }

  await walk(dir, 0, false);

  // Sort: root-level files first, then by path depth, then alphabetically
  found.sort((a, b) => {
    const aDepth = a.split("/").length;
    const bDepth = b.split("/").length;
    return aDepth !== bDepth ? aDepth - bDepth : a.localeCompare(b);
  });

  return found;
}

// ── Content-string parser (for git-fetched lockfiles) ────────────────────────

/**
 * Parses pip lockfile content from a string.
 * `filename` is the basename of the lockfile (e.g. "uv.lock", "poetry.lock",
 * "requirements.txt") and selects the right sub-parser.
 */
export function parsePipLockfileContent(raw: string, filename: string): PackageRef[] {
  if (filename === "uv.lock") return parseUvLock(raw);
  if (filename === "poetry.lock") return parsePoetryLock(raw);
  return parseRequirementsTxt(raw);
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Detects and parses pip lockfiles in the given directory.
 * Returns null if no pip lockfile is found.
 *
 * Preference: uv.lock (modern, has hashes) > poetry.lock (has hashes) > requirements*.txt
 *
 * For requirements files: discovers all requirements*.txt files anywhere in the
 * project tree and combines their packages (deduplicating by name@version).
 */
export async function parsePipLockfile(dir: string): Promise<ParseResult | null> {
  // 1. uv.lock (preferred — modern, has hashes)
  try {
    const raw = await readFile(join(dir, "uv.lock"), "utf-8");
    const refs = parseUvLock(raw);
    if (refs.length > 0) {
      return { refs, lockfileDir: dir };
    }
  } catch {
    // not found
  }

  // 2. poetry.lock (has hashes)
  try {
    const raw = await readFile(join(dir, "poetry.lock"), "utf-8");
    const refs = parsePoetryLock(raw);
    if (refs.length > 0) {
      return { refs, lockfileDir: dir };
    }
  } catch {
    // not found
  }

  // 3. All requirements*.txt files anywhere in the project tree
  const files = await findRequirementsFiles(dir);
  if (files.length === 0) return null;

  const seen = new Map<string, PackageRef>(); // key: "name@version"
  for (const file of files) {
    try {
      const raw = await readFile(file, "utf-8");
      for (const ref of parseRequirementsTxt(raw)) {
        const key = `${ref.name}@${ref.version}`;
        if (!seen.has(key)) seen.set(key, ref);
      }
    } catch {
      // unreadable — skip
    }
  }

  if (seen.size === 0) return null;
  return { refs: Array.from(seen.values()), lockfileDir: dir };
}

/**
 * Returns true if the directory contains a pip lockfile.
 */
export async function hasPipLockfile(dir: string): Promise<boolean> {
  for (const candidate of ["uv.lock", "poetry.lock"]) {
    try {
      await readFile(join(dir, candidate), "utf-8");
      return true;
    } catch {
      // not found
    }
  }
  const files = await findRequirementsFiles(dir);
  return files.length > 0;
}

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

import { readFile } from "node:fs/promises";
import { join } from "node:path";
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
function parseUvLock(raw: string): PackageRef[] {
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
function parsePoetryLock(raw: string): PackageRef[] {
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
 * Parse a requirements.txt file into PackageRefs.
 *
 * Handles:
 *   name==1.2.3          exact pins (most common in lockfiles)
 *   name[extra]==1.2.3   extras
 *   name>=1.2.3          ranges (included but warn: not an exact pin)
 *   # comments, blank lines, -r includes, -i index-url (skipped)
 */
function parseRequirementsTxt(raw: string): PackageRef[] {
  const refs: PackageRef[] = [];
  for (const rawLine of raw.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;

    // Strip inline comments
    const withoutComment = line.split(" #")[0]!.trim();
    // Strip environment markers (e.g. requests>=2.0 ; python_version>"3.0")
    const withoutMarker = withoutComment.split(";")[0]!.trim();

    // Extract name and optional version: name[extra]<op>version
    // Matches: requests==2.28.0, requests[security]==2.28.0, requests>=2.28.0, etc.
    const match = withoutMarker.match(
      /^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)(?:\[[^\]]*\])?(?:==|>=|~=|!=|<=|>|<)(.+)$/
    );
    if (!match) continue;

    const name = match[1]!.toLowerCase().replace(/_/g, "-");
    const version = match[3]!.trim();

    refs.push({ name, version, resolved: "", integrity: null });
  }
  return refs;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Detects and parses pip lockfiles in the given directory.
 * Returns null if no pip lockfile is found.
 *
 * Preference: uv.lock (modern, has hashes) > poetry.lock (has hashes) > requirements.txt
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

  // 3. requirements.txt (no hashes — fallback)
  for (const filename of ["requirements.txt", "requirements/base.txt", "requirements/prod.txt"]) {
    try {
      const raw = await readFile(join(dir, filename), "utf-8");
      const refs = parseRequirementsTxt(raw);
      if (refs.length > 0) {
        return { refs, lockfileDir: dir };
      }
    } catch {
      // not found
    }
  }

  return null;
}

/**
 * Returns true if the directory contains a pip lockfile.
 */
export async function hasPipLockfile(dir: string): Promise<boolean> {
  for (const filename of [
    "uv.lock",
    "poetry.lock",
    "requirements.txt",
    "requirements/base.txt",
    "requirements/prod.txt",
  ]) {
    try {
      await readFile(join(dir, filename), "utf-8");
      return true;
    } catch {
      // not found
    }
  }
  return false;
}

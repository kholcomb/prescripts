/**
 * Gemfile.lock parser.
 *
 * Gemfile.lock format (Bundler):
 *
 *   GEM
 *     remote: https://rubygems.org/
 *     specs:
 *       actioncable (7.0.4)
 *         actionpack (= 7.0.4)
 *         activesupport (= 7.0.4)
 *       actionmailer (7.0.4)
 *         ...
 *   PLATFORMS
 *     ...
 *   DEPENDENCIES
 *     ...
 *
 * Top-level specs (4-space indent) are the resolved packages.
 * Nested lines (6+ space indent) are dependencies of those specs — skip them.
 *
 * GIT sections also appear when a gem is sourced from a git repo:
 *   GIT
 *     remote: https://github.com/...
 *     specs:
 *       my-gem (0.1.0)
 * We include git-sourced gems but mark them without integrity.
 */

import { access, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { PackageRef } from "../types.js";

export async function hasGemfileLock(dir: string): Promise<boolean> {
  try {
    await access(join(dir, "Gemfile.lock"));
    return true;
  } catch {
    return false;
  }
}

export function parseGemfileLockContent(raw: string): PackageRef[] {
  const refs: PackageRef[] = [];
  const seen = new Set<string>(); // deduplicate name@version

  const lines = raw.split("\n");
  let inSpecs = false;

  for (const line of lines) {
    // Detect start of a specs block (GEM or GIT section)
    if (/^\s{4}specs:\s*$/.test(line)) {
      inSpecs = true;
      continue;
    }

    // Exit specs block on a blank line or a new section header
    if (inSpecs && (line.trim() === "" || /^[A-Z]/.test(line))) {
      inSpecs = false;
      continue;
    }

    if (!inSpecs) continue;

    // Top-level spec: exactly 4 spaces of indentation
    // Format: "    <name> (<version>)"
    const topLevel = /^    (\S+)\s+\(([^)]+)\)\s*$/.exec(line);
    if (topLevel) {
      const name = topLevel[1]!;
      const version = topLevel[2]!;
      const key = `${name}@${version}`;
      if (!seen.has(key)) {
        seen.add(key);
        refs.push({
          name,
          version,
          resolved: "",
          integrity: null,
        });
      }
    }
  }

  return refs;
}

export async function parseGemfileLock(
  dir: string
): Promise<{ refs: PackageRef[] } | null> {
  const lockPath = join(dir, "Gemfile.lock");
  let raw: string;
  try {
    raw = await readFile(lockPath, "utf-8");
  } catch {
    return null;
  }

  const refs = parseGemfileLockContent(raw);
  return refs.length > 0 ? { refs } : null;
}

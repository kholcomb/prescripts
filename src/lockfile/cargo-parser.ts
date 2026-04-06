/**
 * Cargo.lock parser.
 *
 * Cargo.lock is a TOML file with [[package]] blocks. We use a regex-based
 * line-oriented parser rather than a full TOML library since only a few
 * fields are needed.
 *
 * Supported lockfile versions: 2 and 3 (v1 is deprecated and rare).
 *
 * Example block:
 *   [[package]]
 *   name = "libc"
 *   version = "0.2.147"
 *   source = "registry+https://github.com/rust-lang/crates.io-index"
 *   checksum = "b4668fb0ea861c1df094127ac5f1da3409a82116a4ba74fca2e58ef927159111"
 */

import { access, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { PackageRef } from "../types.js";

export async function hasCargoLockfile(dir: string): Promise<boolean> {
  try {
    await access(join(dir, "Cargo.lock"));
    return true;
  } catch {
    return false;
  }
}

export function parseCargoLockfileContent(raw: string): PackageRef[] {
  const refs: PackageRef[] = [];

  // Split on [[package]] markers to get individual blocks
  const blocks = raw.split(/\[\[package\]\]/);

  for (const block of blocks) {
    if (!block.trim()) continue;

    const name = extractTomlString(block, "name");
    const version = extractTomlString(block, "version");
    const source = extractTomlString(block, "source");
    const checksum = extractTomlString(block, "checksum");

    if (!name || !version) continue;

    // Skip workspace-local path dependencies (no source field or path+ source)
    if (!source || source.startsWith("path+")) continue;

    // Integrity: crates.io checksum is a bare sha256 hex — normalize to "sha256:<hex>"
    const integrity = checksum ? `sha256:${checksum}` : null;

    refs.push({
      name,
      version,
      // resolved URL is built in the cargo plugin from the registry API
      resolved: "",
      integrity,
    });
  }

  return refs;
}

export async function parseCargoLockfile(
  dir: string
): Promise<{ refs: PackageRef[] } | null> {
  const lockPath = join(dir, "Cargo.lock");
  let raw: string;
  try {
    raw = await readFile(lockPath, "utf-8");
  } catch {
    return null;
  }

  const refs = parseCargoLockfileContent(raw);
  return { refs };
}

/**
 * Extracts a TOML string value for a given key from a block.
 * Handles: key = "value" and key = 'value'
 */
function extractTomlString(block: string, key: string): string | null {
  const re = new RegExp(`^${key}\\s*=\\s*["']([^"']+)["']`, "m");
  const match = re.exec(block);
  return match ? (match[1] ?? null) : null;
}

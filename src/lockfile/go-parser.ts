/**
 * Go modules lockfile parser.
 *
 * Go modules use two files:
 *   - go.mod  — module manifest declaring direct and indirect dependencies
 *   - go.sum  — integrity lockfile with cryptographic hashes for every dependency
 *
 * go.sum format (one or two lines per module version):
 *   github.com/foo/bar v1.2.3 h1:BASE64HASH=
 *   github.com/foo/bar v1.2.3/go.mod h1:MODHASH=
 *
 * The h1: prefix denotes the "Hash1" scheme — a Merkle tree hash of the module
 * zip contents as defined by the Go Sum Database specification. We store it as
 * the integrity field verbatim (e.g. "h1:abc123=").
 *
 * go.mod format (relevant directives):
 *   require github.com/foo/bar v1.2.3
 *   require (
 *     github.com/baz/qux v0.4.1
 *     github.com/indirect/dep v2.0.0 // indirect
 *   )
 *   replace github.com/old/path => ./local/path       <- skip (local dev path)
 *   replace github.com/old/path => github.com/fork v1 <- remote fork (security signal)
 *   retract v1.0.0                                     <- yanked version
 *
 * go.sum is preferred when available (provides integrity hashes). When absent
 * (vendor workflow, new modules, zero-dep modules), go.mod require directives
 * are parsed directly with integrity: null and integrityVerified: false.
 */

import { access, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { PackageRef } from "../types.js";

export interface ReplaceFork {
  /** Original module path declared in require (e.g. "golang.org/x/net"). */
  original: string;
  /** Replacement module path (e.g. "github.com/attacker/x-net"). */
  fork: string;
  /** Version of the replacement module. */
  forkVersion: string;
}

/**
 * Extract remote `replace` directives from go.mod content.
 * Returns only forks that point to a remote module (not local ./paths).
 * Format: replace <original> [v?] => <fork> <forkVersion>
 */
export function extractGoReplaceForks(raw: string): ReplaceFork[] {
  const forks: ReplaceFork[] = [];
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    // Matches: replace ORIGINAL [ORIGVER] => FORK FORKVER
    // The fork path must look like a module path (contains a dot, not a ./path)
    const m = trimmed.match(/^replace\s+(\S+)(?:\s+v\S+)?\s+=>\s+(\S+)\s+(v\S+)/);
    if (!m) continue;
    const [, original, fork, forkVersion] = m;
    if (!original || !fork || !forkVersion) continue;
    // Skip local path replacements (./relative or /absolute)
    if (fork.startsWith(".") || fork.startsWith("/")) continue;
    forks.push({ original, fork, forkVersion });
  }
  return forks;
}

export async function hasGoLockfile(dir: string): Promise<boolean> {
  try {
    await access(join(dir, "go.mod"));
    return true;
  } catch {
    return false;
  }
}

/**
 * Parse go.sum content into PackageRef[].
 *
 * We use go.sum as the primary source of packages + integrity, and go.mod to
 * check for `replace` directives. Local replace targets are skipped entirely.
 * Remote fork replacements are included with `ref.replaces` set to the original
 * module path so callers can surface the substitution as a security finding.
 */
export function parseGoSumContent(sumRaw: string, modRaw?: string): PackageRef[] {
  // Collect local replace targets from go.mod so we can skip them
  const localReplaces = new Set<string>();
  if (modRaw) {
    for (const line of modRaw.split("\n")) {
      const m = line.trim().match(/^replace\s+(\S+)\s*(?:v\S+\s*)?=>\s*\.[\\/]/);
      if (m?.[1]) localReplaces.add(m[1]);
    }
  }

  // Build remote fork map: fork module path → original module path
  // (go.sum lists the fork, not the original)
  const forkToOriginal = new Map<string, string>();
  if (modRaw) {
    for (const { original, fork } of extractGoReplaceForks(modRaw)) {
      forkToOriginal.set(fork, original);
    }
  }

  // Collect retracted versions from go.mod
  const retracted = new Set<string>();
  if (modRaw) {
    for (const line of modRaw.split("\n")) {
      const m = line.trim().match(/^retract\s+(\S+)/);
      if (m?.[1]) retracted.add(m[1]);
    }
  }

  const seen = new Map<string, PackageRef>();

  for (const line of sumRaw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Format: "module version hash" or "module version/go.mod hash"
    // We only want the zip hash (no "/go.mod" suffix)
    const parts = trimmed.split(/\s+/);
    if (parts.length !== 3) continue;

    const [moduleName, versionField, hash] = parts;
    if (!moduleName || !versionField || !hash) continue;

    // Skip go.mod-only entries — we want the zip hash
    if (versionField.endsWith("/go.mod")) continue;

    const version = versionField;

    // Skip local-replace targets
    if (localReplaces.has(moduleName)) continue;

    const key = `${moduleName}@${version}`;
    if (seen.has(key)) continue;

    // h1: is the standard hash prefix; accept it verbatim as integrity
    const integrity = hash.startsWith("h1:") ? hash : null;

    const ref: PackageRef = {
      name: moduleName,
      version,
      resolved: "",  // resolved to proxy URL in the plugin
      integrity,
    };

    // Annotate fork replacements so the plugin can emit a security finding
    const originalModule = forkToOriginal.get(moduleName);
    if (originalModule) ref.replaces = originalModule;

    seen.set(key, ref);
  }

  // Filter out retracted versions
  const refs = Array.from(seen.values()).filter(
    (r) => !retracted.has(r.version)
  );

  return refs;
}

/**
 * Parse go.mod content into PackageRef[] when go.sum is unavailable.
 * Handles both block-form and single-line require directives.
 * Results have integrity: null (no hash source available).
 *
 * Remote `replace` directives: the original module is replaced by a fork.
 * We emit the fork as the PackageRef with `replaces` set to the original path.
 */
export function parseGoModContent(raw: string): PackageRef[] {
  const refs: PackageRef[] = [];
  const seen = new Set<string>();

  // Collect local replace targets to skip them
  const localReplaces = new Set<string>();
  for (const line of raw.split("\n")) {
    const m = line.trim().match(/^replace\s+(\S+)\s*(?:v\S+\s*)?=>\s*\.[\\/]/);
    if (m?.[1]) localReplaces.add(m[1]);
  }

  // Collect remote fork replacements: original → { fork, forkVersion }
  const remoteForks = new Map<string, { fork: string; forkVersion: string }>();
  for (const { original, fork, forkVersion } of extractGoReplaceForks(raw)) {
    remoteForks.set(original, { fork, forkVersion });
  }

  // Collect retracted versions
  const retracted = new Set<string>();
  for (const line of raw.split("\n")) {
    const m = line.trim().match(/^retract\s+(v\S+)/);
    if (m?.[1]) retracted.add(m[1]);
  }

  let inRequireBlock = false;

  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("//")) continue;

    if (/^require\s*\(/.test(trimmed)) {
      inRequireBlock = true;
      continue;
    }
    if (inRequireBlock && trimmed === ")") {
      inRequireBlock = false;
      continue;
    }

    let name: string | undefined;
    let version: string | undefined;

    if (inRequireBlock) {
      // "github.com/foo/bar v1.2.3" or "github.com/foo/bar v1.2.3 // indirect"
      const m = trimmed.match(/^(\S+)\s+(v\S+)/);
      name = m?.[1];
      version = m?.[2];
    } else {
      // "require github.com/foo/bar v1.2.3"
      const m = trimmed.match(/^require\s+(\S+)\s+(v\S+)/);
      name = m?.[1];
      version = m?.[2];
    }

    if (!name || !version) continue;
    if (localReplaces.has(name)) continue;
    if (retracted.has(version)) continue;

    // Apply remote fork replacement: swap name+version to the fork module
    const forkInfo = remoteForks.get(name);
    const resolvedName = forkInfo ? forkInfo.fork : name;
    const resolvedVersion = forkInfo ? forkInfo.forkVersion : version;
    const replaces = forkInfo ? name : undefined;

    const key = `${resolvedName}@${resolvedVersion}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const ref: PackageRef = { name: resolvedName, version: resolvedVersion, resolved: "", integrity: null };
    if (replaces) ref.replaces = replaces;
    refs.push(ref);
  }

  return refs;
}

export async function parseGoLockfile(
  dir: string
): Promise<{ refs: PackageRef[]; lockfileDir: string } | null> {
  const sumPath = join(dir, "go.sum");
  const modPath = join(dir, "go.mod");

  let modRaw: string;
  try {
    modRaw = await readFile(modPath, "utf-8");
  } catch {
    return null; // no go.mod → not a Go module
  }

  // go.sum preferred: provides integrity hashes for all resolved dependencies
  try {
    const sumRaw = await readFile(sumPath, "utf-8");
    const refs = parseGoSumContent(sumRaw, modRaw);
    return { refs, lockfileDir: dir };
  } catch {
    // go.sum absent (vendor mode, new module, zero-dep module) — fall back to go.mod
    const refs = parseGoModContent(modRaw);
    if (refs.length === 0) return null;
    return { refs, lockfileDir: dir };
  }
}

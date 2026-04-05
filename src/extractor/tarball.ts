import { createHash } from "node:crypto";
import { mkdtemp, writeFile, readFile, readdir, stat, lstat, mkdir } from "node:fs/promises";
import type { Stats } from "node:fs";
import { join, extname, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import * as tar from "tar";
import { fetchTarball } from "../registry/client.js";
import type { ExtractedPackage } from "../types.js";

const ALLOWED_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".ts", ".sh"]);
const MAX_FILE_SIZE = 100 * 1024; // 100KB

// Only allow regular files and directories — reject symlinks, hard links, devices, FIFOs.
const SAFE_TAR_TYPES = new Set(["File", "OldFile", "ContiguousFile", "Directory"]);

/**
 * Returns a tar filter that rejects:
 *  - non-regular-file/directory entry types (symlinks, hard links, devices)
 *  - absolute paths
 *  - paths containing ".." traversal sequences
 *  - paths whose resolved destination escapes extractDir (zip-slip defence)
 */
function makeTarFilter(extractDir: string): (path: string, entry: tar.ReadEntry | Stats) => boolean {
  const resolvedRoot = resolve(extractDir);
  return (entryPath: string, entry: tar.ReadEntry | Stats): boolean => {
    // Stats entries represent existing filesystem files, not archive entries — reject
    if (!("type" in entry)) return false;
    // Only allow regular files and directories; reject symlinks, hard links, devices
    if (!SAFE_TAR_TYPES.has(entry.type)) return false;
    if (entryPath.startsWith("/") || entryPath.includes("..")) return false;
    const dest = resolve(resolvedRoot, entryPath);
    return dest === resolvedRoot || dest.startsWith(resolvedRoot + sep);
  };
}

async function collectFiles(
  dir: string,
  base: string,
  fileMap: Map<string, string>
): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    const relPath = base ? `${base}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      await collectFiles(fullPath, relPath, fileMap);
    } else if (entry.isFile()) {
      if (!ALLOWED_EXTENSIONS.has(extname(entry.name))) continue;
      try {
        const info = await stat(fullPath);
        if (info.size > MAX_FILE_SIZE) continue;
        const content = await readFile(fullPath, "utf-8");
        fileMap.set(relPath, content);
      } catch {
        // skip unreadable files
      }
    }
  }
}

export async function extractTarball(
  tarballUrl: string,
  expectedIntegrity: string | null,
  authToken?: string | null
): Promise<{ extracted: ExtractedPackage; integrityVerified: boolean; computedIntegrity: string }> {
  const bytes = await fetchTarball(tarballUrl, authToken);

  // Always compute sha512 — used for both integrity verification and attestation subject check
  const sha512B64 = createHash("sha512").update(bytes).digest("base64");
  const computedIntegrity = `sha512-${sha512B64}`;

  let integrityVerified = false;
  if (expectedIntegrity) {
    if (expectedIntegrity.startsWith("sha512-")) {
      integrityVerified = computedIntegrity === expectedIntegrity;
    } else {
      // Legacy sha1 support
      const [algo, expected] = expectedIntegrity.split("-");
      if (algo && expected) {
        const hashAlgo = algo === "sha1" ? "sha1" : null;
        if (hashAlgo) {
          const actual = createHash(hashAlgo).update(bytes).digest("base64");
          integrityVerified = actual === expected;
        }
      }
    }
  }

  const tempDir = await mkdtemp(join(tmpdir(), "npm-prescripts-"));
  const tgzPath = join(tempDir, "pkg.tgz");
  await writeFile(tgzPath, bytes);

  const extractDir = join(tempDir, "extracted");
  await mkdir(extractDir);

  await tar.extract({
    file: tgzPath,
    cwd: extractDir,
    strip: 1,
    filter: makeTarFilter(extractDir),
  });

  const pkgJsonPath = join(extractDir, "package.json");
  // lstat (not stat) so symlinks are not followed — isFile() returns false for symlinks
  const pkgJsonStat = await lstat(pkgJsonPath);
  if (!pkgJsonStat.isFile()) {
    throw new Error("package.json is not a regular file");
  }
  const pkgJsonRaw = await readFile(pkgJsonPath, "utf-8");
  const packageJson = JSON.parse(pkgJsonRaw) as Record<string, unknown>;

  const fileMap = new Map<string, string>();
  await collectFiles(extractDir, "", fileMap);

  return { extracted: { packageJson, fileMap }, integrityVerified, computedIntegrity };
}

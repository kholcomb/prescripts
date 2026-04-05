import { createHash } from "node:crypto";
import { mkdtemp, writeFile, readFile, readdir } from "node:fs/promises";
import { join, extname } from "node:path";
import { tmpdir } from "node:os";
import * as tar from "tar";
import { fetchTarball } from "../registry/client.js";
import type { ExtractedPackage } from "../types.js";

const ALLOWED_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".ts", ".sh"]);
const MAX_FILE_SIZE = 100 * 1024; // 100KB

function isSafeEntry(entryPath: string): boolean {
  return !entryPath.includes("..") && !entryPath.startsWith("/");
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
        const stat = await import("node:fs/promises").then((m) =>
          m.stat(fullPath)
        );
        if (stat.size > MAX_FILE_SIZE) continue;
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
  await import("node:fs/promises").then((m) => m.mkdir(extractDir));

  await tar.extract({
    file: tgzPath,
    cwd: extractDir,
    strip: 1,
    filter: (path: string) => isSafeEntry(path),
  });

  const pkgJsonPath = join(extractDir, "package.json");
  const pkgJsonRaw = await readFile(pkgJsonPath, "utf-8");
  const packageJson = JSON.parse(pkgJsonRaw) as Record<string, unknown>;

  const fileMap = new Map<string, string>();
  await collectFiles(extractDir, "", fileMap);

  return { extracted: { packageJson, fileMap }, integrityVerified, computedIntegrity };
}

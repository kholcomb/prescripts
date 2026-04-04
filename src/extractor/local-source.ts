import { readFile, readdir } from "node:fs/promises";
import { join, resolve, extname } from "node:path";
import type { ExtractedPackage } from "../types.js";

const ALLOWED_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".ts", ".sh"]);
const MAX_FILE_SIZE = 100 * 1024;

async function collectFiles(
  dir: string,
  base: string,
  fileMap: Map<string, string>
): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === "node_modules") continue;
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

export async function extractLocalSource(
  resolved: string,
  projectDir: string
): Promise<{ extracted: ExtractedPackage; integrityVerified: boolean }> {
  // resolved is like "file:../local-pkg" — resolve relative to project dir
  const relPath = resolved.replace(/^file:/, "");
  const localDir = resolve(projectDir, relPath);

  const pkgJsonPath = join(localDir, "package.json");
  const pkgJsonRaw = await readFile(pkgJsonPath, "utf-8");
  const packageJson = JSON.parse(pkgJsonRaw) as Record<string, unknown>;

  const fileMap = new Map<string, string>();
  await collectFiles(localDir, "", fileMap);

  return {
    extracted: { packageJson, fileMap },
    integrityVerified: false, // local sources are implicitly trusted; no hash to verify
  };
}

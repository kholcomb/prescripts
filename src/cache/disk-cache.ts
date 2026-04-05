import {
  mkdir,
  readFile,
  writeFile,
  access,
} from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import type { CachedMeta, ExtractedPackage, SourceType } from "../types.js";

function defaultCacheDir(): string {
  const xdg = process.env["XDG_CACHE_HOME"];
  return xdg ? join(xdg, "npm-prescripts") : join(homedir(), ".cache", "npm-prescripts");
}

function cacheKey(name: string, integrity: string | null, version: string): string {
  // Require ":" to distinguish real integrity hashes (sha512-xxx, sha256:xxx) from
  // bare version strings that some callers pass as a fallback. Without this check,
  // packages like requests@2.31.0 and boto3@2.31.0 (both with no hash) would share
  // the same cache directory ("2.31.0"), causing cross-package cache collisions.
  if (integrity && integrity.includes(":")) {
    return integrity.replace(/^sha\d+:/, "sha-").replace(/[/+=]/g, "_");
  }
  // Fallback for packages without integrity (shouldn't happen in modern lockfiles)
  const safeName = name.replace(/\//g, "__").replace(/@/g, "at-");
  return `${safeName}@${version}`;
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

export class DiskCache {
  private readonly cacheDir: string;

  constructor(cacheDir?: string | null) {
    this.cacheDir = cacheDir ?? defaultCacheDir();
  }

  private entryDir(
    name: string,
    integrity: string | null,
    version: string
  ): string {
    return join(this.cacheDir, cacheKey(name, integrity, version));
  }

  async isCached(
    name: string,
    integrity: string | null,
    version: string
  ): Promise<boolean> {
    const dir = this.entryDir(name, integrity, version);
    return exists(join(dir, "meta.json"));
  }

  async read(
    name: string,
    integrity: string | null,
    version: string
  ): Promise<{ meta: CachedMeta; extracted: ExtractedPackage } | null> {
    const dir = this.entryDir(name, integrity, version);
    try {
      const metaRaw = await readFile(join(dir, "meta.json"), "utf-8");
      const meta = JSON.parse(metaRaw) as CachedMeta;
      const pkgJsonRaw = await readFile(join(dir, "package.json"), "utf-8");
      const packageJson = JSON.parse(pkgJsonRaw) as Record<string, unknown>;

      const fileMap = new Map<string, string>();
      const filesDir = join(dir, "files");
      if (await exists(filesDir)) {
        await loadFiles(filesDir, "", fileMap);
      }

      return { meta, extracted: { packageJson, fileMap } };
    } catch {
      return null;
    }
  }

  async write(
    name: string,
    version: string,
    integrity: string | null,
    sourceType: SourceType,
    extracted: ExtractedPackage
  ): Promise<void> {
    const dir = this.entryDir(name, integrity, version);
    await mkdir(dir, { recursive: true });

    const meta: CachedMeta = {
      name,
      version,
      cachedAt: new Date().toISOString(),
      sourceType,
      integrity,
    };

    await writeFile(join(dir, "meta.json"), JSON.stringify(meta, null, 2));
    await writeFile(
      join(dir, "package.json"),
      JSON.stringify(extracted.packageJson, null, 2)
    );

    if (extracted.fileMap.size > 0) {
      const filesDir = join(dir, "files");
      await mkdir(filesDir, { recursive: true });
      for (const [relPath, content] of extracted.fileMap) {
        const filePath = join(filesDir, relPath);
        await mkdir(join(filePath, ".."), { recursive: true });
        await writeFile(filePath, content, "utf-8");
      }
    }
  }
}

async function loadFiles(
  dir: string,
  base: string,
  fileMap: Map<string, string>
): Promise<void> {
  const { readdir } = await import("node:fs/promises");
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    const relPath = base ? `${base}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      await loadFiles(fullPath, relPath, fileMap);
    } else if (entry.isFile()) {
      try {
        const content = await readFile(fullPath, "utf-8");
        fileMap.set(relPath, content);
      } catch {
        // skip
      }
    }
  }
}

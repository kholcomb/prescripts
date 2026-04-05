import { readFile, access } from "node:fs/promises";
import { join, dirname } from "node:path";

const LOCKFILES = ["npm-shrinkwrap.json", "package-lock.json"];

/**
 * Walks up from `dir` looking for a directory that contains a lockfile.
 * Returns the workspace root path, or null if none found within `maxDepth` levels.
 */
export async function findWorkspaceRoot(
  dir: string,
  maxDepth = 8
): Promise<string | null> {
  let current = dir;
  for (let i = 0; i < maxDepth; i++) {
    for (const filename of LOCKFILES) {
      try {
        await access(join(current, filename));
        return current;
      } catch {
        // not here
      }
    }
    const parent = dirname(current);
    if (parent === current) break; // reached filesystem root
    current = parent;
  }
  return null;
}

/**
 * Returns the workspace member names defined in the root package.json
 * `workspaces` field (supports both array and {packages:[]} object forms).
 * Returns an empty array if the root has no workspaces field or on any error.
 */
export async function readWorkspacePatterns(rootDir: string): Promise<string[]> {
  try {
    const raw = await readFile(join(rootDir, "package.json"), "utf-8");
    const pkg = JSON.parse(raw) as {
      workspaces?: string[] | { packages?: string[] };
    };
    const ws = pkg.workspaces;
    if (!ws) return [];
    if (Array.isArray(ws)) return ws;
    return ws.packages ?? [];
  } catch {
    return [];
  }
}

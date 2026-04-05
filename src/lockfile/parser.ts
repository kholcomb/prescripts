import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { PackageRef } from "../types.js";
import { findWorkspaceRoot } from "./workspace.js";

interface LockfileV1Dep {
  version: string;
  resolved?: string;
  integrity?: string;
  dependencies?: Record<string, LockfileV1Dep>;
}

interface LockfileV2Package {
  version: string;
  resolved?: string;
  integrity?: string;
  link?: boolean;
}

interface Lockfile {
  lockfileVersion: number;
  dependencies?: Record<string, LockfileV1Dep>;
  packages?: Record<string, LockfileV2Package>;
}

function collectV1(
  deps: Record<string, LockfileV1Dep>,
  seen: Map<string, PackageRef>
): void {
  for (const [name, dep] of Object.entries(deps)) {
    const key = `${name}@${dep.version}`;
    if (!seen.has(key)) {
      seen.set(key, {
        name,
        version: dep.version,
        resolved: dep.resolved ?? "",
        integrity: dep.integrity ?? null,
      });
    }
    if (dep.dependencies) {
      collectV1(dep.dependencies, seen);
    }
  }
}

function nameFromPackagePath(pkgPath: string): string {
  // "node_modules/foo" → "foo"
  // "node_modules/@scope/foo" → "@scope/foo"
  // "node_modules/foo/node_modules/bar" → "bar"
  const parts = pkgPath.split("node_modules/");
  const last = parts[parts.length - 1];
  return last ?? pkgPath;
}

export interface ParseResult {
  refs: PackageRef[];
  /** The directory where the lockfile was actually found (may differ from `dir` in a workspace). */
  lockfileDir: string;
}

export async function parseLockfile(dir: string): Promise<ParseResult> {
  // npm-shrinkwrap.json takes precedence over package-lock.json when both exist
  // (mirrors npm's own resolution order)
  let raw: string | undefined;
  let lockfileDir = dir;

  for (const filename of ["npm-shrinkwrap.json", "package-lock.json"]) {
    try {
      raw = await readFile(join(dir, filename), "utf-8");
      break;
    } catch {
      // try next
    }
  }

  // Not found in `dir` — walk up to find a workspace root
  if (!raw) {
    const wsRoot = await findWorkspaceRoot(dir);
    if (wsRoot && wsRoot !== dir) {
      for (const filename of ["npm-shrinkwrap.json", "package-lock.json"]) {
        try {
          raw = await readFile(join(wsRoot, filename), "utf-8");
          lockfileDir = wsRoot;
          break;
        } catch {
          // try next
        }
      }
    }
  }

  if (!raw) {
    throw new Error(
      `No package-lock.json or npm-shrinkwrap.json found in ${dir}. ` +
        `npm-prescripts requires an npm lockfile. ` +
        `For Yarn or pnpm projects, lockfile support is not yet implemented.`
    );
  }

  const lockfile = JSON.parse(raw) as Lockfile;
  const seen = new Map<string, PackageRef>();

  if (lockfile.lockfileVersion >= 2 && lockfile.packages) {
    // v2/v3: use `packages` object; skip the root entry (empty string key)
    for (const [pkgPath, pkg] of Object.entries(lockfile.packages)) {
      if (pkgPath === "") continue;
      if (pkg.link === true) continue; // symlinks to workspace packages

      const name = nameFromPackagePath(pkgPath);
      const key = `${name}@${pkg.version}`;
      if (!seen.has(key)) {
        seen.set(key, {
          name,
          version: pkg.version,
          resolved: pkg.resolved ?? "",
          integrity: pkg.integrity ?? null,
        });
      }
    }
  } else if (lockfile.dependencies) {
    // v1: recurse `dependencies` tree
    collectV1(lockfile.dependencies, seen);
  }

  return { refs: Array.from(seen.values()), lockfileDir };
}

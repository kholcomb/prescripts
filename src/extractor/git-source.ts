import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { join, extname } from "node:path";
import { tmpdir } from "node:os";
import { simpleGit } from "simple-git";
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
    if (entry.name === ".git") continue;
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

function parseGitUrl(resolved: string): { url: string; ref: string | null } {
  // Handles:
  //   git+https://github.com/owner/repo.git#abc123
  //   github:owner/repo#abc123
  //   gitlab:owner/repo#abc123
  let url = resolved;
  let ref: string | null = null;

  const hashIdx = url.lastIndexOf("#");
  if (hashIdx !== -1) {
    ref = url.slice(hashIdx + 1);
    url = url.slice(0, hashIdx);
  }

  if (url.startsWith("git+")) url = url.slice(4);
  if (url.startsWith("github:")) {
    url = `https://github.com/${url.slice(7)}.git`;
  } else if (url.startsWith("gitlab:")) {
    url = `https://gitlab.com/${url.slice(7)}.git`;
  } else if (url.startsWith("bitbucket:")) {
    url = `https://bitbucket.org/${url.slice(10)}.git`;
  }

  return { url, ref };
}

export async function extractGitSource(
  resolved: string,
  expectedCommit: string | null
): Promise<{ extracted: ExtractedPackage; integrityVerified: boolean }> {
  const { url, ref } = parseGitUrl(resolved);

  const cloneDir = await mkdtemp(join(tmpdir(), "prescripts-git-"));
  const git = simpleGit();

  await git.clone(url, cloneDir, ["--depth", "1", ...(ref ? ["--branch", ref] : [])]);

  let integrityVerified = false;
  if (expectedCommit) {
    const clonedGit = simpleGit(cloneDir);
    const log = await clonedGit.log(["-1", "--format=%H"]);
    const actualCommit = log.latest?.hash ?? "";
    integrityVerified = actualCommit.startsWith(expectedCommit);
  }

  const pkgJsonPath = join(cloneDir, "package.json");
  const pkgJsonRaw = await readFile(pkgJsonPath, "utf-8");
  const packageJson = JSON.parse(pkgJsonRaw) as Record<string, unknown>;

  const fileMap = new Map<string, string>();
  await collectFiles(cloneDir, "", fileMap);

  return { extracted: { packageJson, fileMap }, integrityVerified };
}

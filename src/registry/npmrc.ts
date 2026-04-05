import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";

/**
 * Parses an .npmrc file into a flat key→value map.
 * Lines starting with # or ; are comments. Keys and values are trimmed.
 * Handles `=` and ` = ` separators.
 */
function parseNpmrc(content: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const eqIdx = line.indexOf("=");
    if (eqIdx === -1) continue;
    const key = line.slice(0, eqIdx).trim();
    const value = line.slice(eqIdx + 1).trim();
    map.set(key, value);
  }
  return map;
}

async function tryReadNpmrc(filePath: string): Promise<Map<string, string>> {
  try {
    const content = await readFile(filePath, "utf-8");
    return parseNpmrc(content);
  } catch {
    return new Map();
  }
}

/**
 * Merges project-level and user-level .npmrc entries.
 * Project-level takes precedence (overlapping keys overwrite user-level).
 */
async function loadNpmrcEntries(projectDir: string): Promise<Map<string, string>> {
  const [userEntries, projectEntries] = await Promise.all([
    tryReadNpmrc(join(homedir(), ".npmrc")),
    tryReadNpmrc(join(projectDir, ".npmrc")),
  ]);
  // Merge: project overrides user
  const merged = new Map(userEntries);
  for (const [k, v] of projectEntries) merged.set(k, v);
  return merged;
}

/**
 * Resolves the auth token for a given registry URL by searching .npmrc entries
 * using npm's longest-prefix matching on `//host/path/:_authToken` keys.
 *
 * For example, URL `https://private.example.com/api/npm/@scope/pkg/-/pkg-1.0.0.tgz`
 * will match the key `//private.example.com/api/npm/:_authToken`.
 */
export async function resolveAuthToken(
  url: string,
  projectDir: string
): Promise<string | null> {
  const entries = await loadNpmrcEntries(projectDir);

  // Strip protocol to get the host+path portion npm uses as key prefix
  const withoutProtocol = url.replace(/^https?:/, "");

  // Walk path segments from most-specific to least-specific,
  // looking for //host/path/:_authToken
  const segments = withoutProtocol.split("/");
  for (let i = segments.length; i >= 2; i--) {
    const prefix = segments.slice(0, i).join("/");
    const key = `${prefix}/:_authToken`;
    const token = entries.get(key);
    if (token) return token;
  }

  return null;
}

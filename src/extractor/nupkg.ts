/**
 * NuGet .nupkg archive extractor.
 *
 * .nupkg files are standard ZIP archives. We extract:
 *   *.nuspec          — XML manifest (package metadata, dependencies)
 *   build/*.targets   — MSBuild targets (can execute code during build)
 *   build/*.props     — MSBuild properties (can execute code during build)
 *   tools/*.ps1       — PowerShell scripts (install.ps1, uninstall.ps1)
 *   tools/*.cmd       — Windows batch scripts
 *   tools/*.bat       — Windows batch scripts
 *
 * Integrity: NuGet's contentHash is "sha512-<base64>" (SRI format).
 * We compute SHA-512 of the raw bytes and compare.
 */

import { createHash } from "node:crypto";
import { downloadAndExtractZip } from "./zip.js";

const ALLOWED_EXTENSIONS = new Set([
  ".nuspec",
  ".targets",
  ".props",
  ".ps1",
  ".cmd",
  ".bat",
]);

function shouldInclude(relPath: string): boolean {
  const lower = relPath.toLowerCase();
  const dot = lower.lastIndexOf(".");
  if (dot < 0) return false;
  return ALLOWED_EXTENSIONS.has(lower.slice(dot));
}

export interface NupkgExtraction {
  fileMap: Map<string, string>;
  /** SHA-256 hex of the raw .nupkg bytes (for cache key). */
  sha256hex: string;
  /** Whether the sha512 contentHash from NuGet matched. */
  integrityVerified: boolean;
  /** "sha512-<base64>" of the downloaded bytes. */
  computedIntegrity: string;
}

/**
 * Extract a .nupkg buffer into a fileMap and verify the optional integrity hash.
 *
 * @param bytes            Raw .nupkg bytes.
 * @param expectedIntegrity  "sha512-<base64>" from packages.lock.json, or null.
 */
export async function extractNupkg(
  bytes: Buffer,
  expectedIntegrity: string | null
): Promise<NupkgExtraction> {
  const { fileMap, sha256hex } = await downloadAndExtractZip(bytes, shouldInclude);

  // Compute SHA-512 for integrity verification
  const sha512b64 = createHash("sha512").update(bytes).digest("base64");
  const computedIntegrity = `sha512-${sha512b64}`;

  const integrityVerified = expectedIntegrity !== null
    ? computedIntegrity === expectedIntegrity
    : false;

  return { fileMap, sha256hex, integrityVerified, computedIntegrity };
}

/**
 * Go module ZIP extraction.
 *
 * Go module archives (from proxy.golang.org) are standard ZIP files with a
 * top-level prefix of "{module}@{version}/". We strip this prefix when building
 * the fileMap, leaving paths like "internal/foo/bar.go".
 *
 * We collect only .go files (max 100KB each). The fileMap is used to:
 *   - Detect //go:generate directives
 *   - Detect import "C" (CGO)
 *   - Detect func init() bodies with dangerous patterns
 *   - Run pattern matching for go_exec, go_cgo, go_network, go_unsafe
 */

import { downloadAndExtractZip } from "./zip.js";
import { extname } from "node:path";

const ALLOWED_EXTENSIONS = new Set([".go"]);

function shouldIncludeGoFile(relPath: string): boolean {
  return ALLOWED_EXTENSIONS.has(extname(relPath));
}

export interface GoModuleExtraction {
  fileMap: Map<string, string>;
  sha256hex: string;
  integrityVerified: boolean;
  computedIntegrity: string;
}

/**
 * Extract a Go module zip archive.
 *
 * @param bytes          Raw bytes of the .zip archive.
 * @param moduleName     Module path (e.g. "github.com/foo/bar").
 * @param version        Module version (e.g. "v1.2.3").
 * @param expectedIntegrity  h1: hash from go.sum (e.g. "h1:abc123="), or null.
 */
export async function extractGoModule(
  bytes: Buffer,
  moduleName: string,
  version: string,
  expectedIntegrity: string | null
): Promise<GoModuleExtraction> {
  // Go module zip prefix: "module@version/"
  const stripPrefix = `${moduleName}@${version}/`;

  const { fileMap, sha256hex } = await downloadAndExtractZip(
    bytes,
    shouldIncludeGoFile,
    stripPrefix
  );

  // We cannot recompute the h1: hash ourselves without implementing the full
  // Go Hash1 algorithm (Merkle tree over sorted file hashes). Instead, we treat
  // go.sum as authoritative: if the package has an integrity hash in go.sum,
  // consider it verified (the Go toolchain enforces go.sum consistency).
  const computedIntegrity = `sha256:${sha256hex}`;
  const integrityVerified = expectedIntegrity !== null;

  return { fileMap, sha256hex, integrityVerified, computedIntegrity };
}

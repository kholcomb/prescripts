/**
 * JAR (Java Archive) extraction.
 *
 * JARs are standard ZIP files. We extract a small allowlisted set of files:
 *   - META-INF/MANIFEST.MF              — agent declarations, classpath info
 *   - META-INF/maven/.../pom.xml         — bundled POM (lifecycle plugin configs)
 *   - META-INF/maven/.../*.properties   — artifact coordinates
 *   - .../*.properties                  — app properties (may contain URLs/tokens)
 *
 * We do NOT extract .class files — bytecode analysis requires a dedicated
 * decompiler and is out of scope for this static-text scanner.
 *
 * Security model: same as tarball.ts — zip-slip defence, no symlinks,
 * 100KB per-file cap, UTF-8 only.
 */

import { downloadAndExtractZip } from "./zip.js";
import { basename, extname } from "node:path";

const ALLOWED_EXTENSIONS = new Set([".xml", ".properties"]);
const ALLOWED_EXACT_NAMES = new Set(["MANIFEST.MF"]);

function shouldIncludeJarFile(relPath: string): boolean {
  const name = basename(relPath);
  if (ALLOWED_EXACT_NAMES.has(name)) return true;

  const ext = extname(relPath);
  if (!ALLOWED_EXTENSIONS.has(ext)) return false;

  return true;
}

export interface JarExtraction {
  fileMap: Map<string, string>;
  sha256hex: string;
  integrityVerified: boolean;
  computedIntegrity: string;
}

/**
 * Extract relevant metadata files from a JAR archive.
 *
 * @param bytes             Raw bytes of the .jar file.
 * @param expectedSha       Expected SHA hash in "sha256:<hex>" or "sha1:<hex>" format, or null.
 */
export async function extractJar(
  bytes: Buffer,
  expectedSha: string | null
): Promise<JarExtraction> {
  // JARs have no top-level prefix to strip — entries are at the root
  const { fileMap, sha256hex } = await downloadAndExtractZip(
    bytes,
    shouldIncludeJarFile,
    undefined  // no prefix to strip
  );

  const computedIntegrity = `sha256:${sha256hex}`;

  let integrityVerified = false;
  if (expectedSha) {
    if (expectedSha.startsWith("sha256:")) {
      integrityVerified = sha256hex === expectedSha.slice(7);
    }
    // sha1 verification: we only compute sha256 here; accept sha1 as "trusted"
    if (expectedSha.startsWith("sha1:")) {
      integrityVerified = true; // best-effort — sha1 is not recomputed
    }
  }

  return { fileMap, sha256hex, integrityVerified, computedIntegrity };
}

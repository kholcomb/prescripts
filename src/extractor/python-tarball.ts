/**
 * Extracts Python packages (sdist .tar.gz and .whl wheels) for security analysis.
 *
 * PyPI sdist tarballs are structured as <name>-<version>/<files>, so strip:1
 * removes the top-level prefix (same as npm tarballs).
 *
 * .whl wheels are ZIP files; extraction is handled separately via Node's
 * built-in zlib + a minimal ZIP reader.
 *
 * Allowed file types for scanning: .py, .pth, .cfg, .toml
 * Max file size: 100KB (same as npm extractor)
 */

import { createHash } from "node:crypto";
import { mkdtemp, writeFile, readFile, readdir, mkdir } from "node:fs/promises";
import { join, extname } from "node:path";
import { tmpdir } from "node:os";
import { stat } from "node:fs/promises";
import * as tar from "tar";
import type { ExtractedPackage } from "../types.js";

const PYTHON_ALLOWED_EXTENSIONS = new Set([".py", ".pth", ".cfg", ".toml"]);
const MAX_FILE_SIZE = 100 * 1024;

function isSafeEntry(entryPath: string): boolean {
  return !entryPath.includes("..") && !entryPath.startsWith("/");
}

async function collectPythonFiles(
  dir: string,
  base: string,
  fileMap: Map<string, string>
): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    const relPath = base ? `${base}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      await collectPythonFiles(fullPath, relPath, fileMap);
    } else if (entry.isFile()) {
      if (!PYTHON_ALLOWED_EXTENSIONS.has(extname(entry.name))) continue;
      try {
        const info = await stat(fullPath);
        if (info.size > MAX_FILE_SIZE) continue;
        const content = await readFile(fullPath, "utf-8");
        fileMap.set(relPath, content);
      } catch {
        // skip unreadable files
      }
    }
  }
}

/**
 * Parse pyproject.toml into a Record for use as the `packageJson` equivalent.
 * We do a very simple TOML → object conversion for the fields we care about.
 */
function parsePyprojectToml(content: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  // Extract [project] section — PEP 517/518 standard
  const projectMatch = content.match(/\[project\]([\s\S]*?)(?=\n\[|$)/);
  if (projectMatch) {
    result["project"] = { _raw: projectMatch[1] };
  }

  // Extract [build-system] section
  const buildMatch = content.match(/\[build-system\]([\s\S]*?)(?=\n\[|$)/);
  if (buildMatch) {
    result["build-system"] = { _raw: buildMatch[1] };
  }

  // Extract [tool.*] sections for build hook configuration
  const toolMatches = [...content.matchAll(/\[tool\.([^\]]+)\]([\s\S]*?)(?=\n\[|$)/g)];
  if (toolMatches.length > 0) {
    const tools: Record<string, unknown> = {};
    for (const m of toolMatches) {
      tools[m[1]!] = { _raw: m[2] };
    }
    result["tool"] = tools;
  }

  return result;
}

export interface PythonExtractResult {
  extracted: ExtractedPackage;
  integrityVerified: boolean;
  /** sha256 of the tarball bytes in "sha256:<hex>" format. */
  computedIntegrity: string;
  /** Whether this was a wheel (.whl) rather than a sdist (.tar.gz). */
  isWheel: boolean;
}

/**
 * Downloads bytes from a URL, respecting HTTPS_PROXY/HTTP_PROXY env vars.
 * PyPI tarball downloads must go through the same proxy as metadata requests.
 */
async function downloadBytes(url: string, timeout: number): Promise<Buffer> {
  const { fetchWithProxyRaw } = await import("../registry/pypi-client.js");
  return fetchWithProxyRaw(url, timeout);
}

export async function extractPythonPackage(
  tarballUrl: string,
  expectedIntegrity: string | null,
  timeout = 30_000
): Promise<PythonExtractResult> {
  const bytes = await downloadBytes(tarballUrl, timeout);

  // Compute sha256 for integrity verification (PyPI uses sha256, not sha512)
  const sha256hex = createHash("sha256").update(bytes).digest("hex");
  const computedIntegrity = `sha256:${sha256hex}`;

  let integrityVerified = false;
  if (expectedIntegrity) {
    // Support both "sha256:<hex>" (poetry.lock) and bare hex
    const expected = expectedIntegrity.startsWith("sha256:")
      ? expectedIntegrity.slice(7)
      : expectedIntegrity;
    integrityVerified = sha256hex === expected;
  }

  const isWheel = tarballUrl.endsWith(".whl");
  const tempDir = await mkdtemp(join(tmpdir(), "npm-prescripts-py-"));
  const extractDir = join(tempDir, "extracted");
  await mkdir(extractDir, { recursive: true });

  const fileMap = new Map<string, string>();
  let packageJson: Record<string, unknown> = {};

  if (isWheel) {
    // Wheels are ZIP files — extract using a minimal ZIP reader
    await extractWheel(bytes, extractDir);
  } else {
    // sdist is .tar.gz
    const tgzPath = join(tempDir, "pkg.tar.gz");
    await writeFile(tgzPath, bytes);
    await tar.extract({
      file: tgzPath,
      cwd: extractDir,
      strip: 1,
      filter: (path: string) => isSafeEntry(path),
    });
  }

  await collectPythonFiles(extractDir, "", fileMap);

  // Parse pyproject.toml if present
  const pyprojectContent = fileMap.get("pyproject.toml");
  if (pyprojectContent) {
    packageJson = parsePyprojectToml(pyprojectContent);
  }

  return { extracted: { packageJson, fileMap }, integrityVerified, computedIntegrity, isWheel };
}

/**
 * Minimal ZIP extractor for .whl files.
 *
 * ZIP format overview:
 *   Local file headers at the start, followed by file data, followed by the
 *   central directory at the end. We walk local file headers sequentially.
 *
 * We only extract text files matching PYTHON_ALLOWED_EXTENSIONS.
 */
async function extractWheel(bytes: Buffer, destDir: string): Promise<void> {
  let offset = 0;

  while (offset < bytes.length - 4) {
    // Local file header signature: 0x04034b50
    if (bytes.readUInt32LE(offset) !== 0x04034b50) break;

    const compressionMethod = bytes.readUInt16LE(offset + 8);
    const compressedSize = bytes.readUInt32LE(offset + 18);
    const uncompressedSize = bytes.readUInt32LE(offset + 22);
    const filenameLength = bytes.readUInt16LE(offset + 26);
    const extraLength = bytes.readUInt16LE(offset + 28);

    const filename = bytes.subarray(offset + 30, offset + 30 + filenameLength).toString("utf-8");
    const dataOffset = offset + 30 + filenameLength + extraLength;

    const ext = extname(filename);
    const isSafe = isSafeEntry(filename) && !filename.endsWith("/");
    const isAllowed = PYTHON_ALLOWED_EXTENSIONS.has(ext);

    if (isAllowed && isSafe && uncompressedSize < MAX_FILE_SIZE) {
      const compressedData = bytes.subarray(dataOffset, dataOffset + compressedSize);
      let fileBytes: Buffer;

      if (compressionMethod === 0) {
        // Stored (no compression)
        fileBytes = compressedData;
      } else if (compressionMethod === 8) {
        // Deflate
        const { inflateRawSync } = await import("node:zlib");
        fileBytes = inflateRawSync(compressedData);
      } else {
        // Unsupported compression method — skip
        offset = dataOffset + compressedSize;
        continue;
      }

      // Write to dest directory
      const destPath = join(destDir, filename);
      const dirPath = destPath.substring(0, destPath.lastIndexOf("/"));
      if (dirPath && dirPath !== destDir) {
        await mkdir(dirPath, { recursive: true });
      }
      await writeFile(destPath, fileBytes);
    }

    offset = dataOffset + compressedSize;
  }
}

/**
 * ZIP archive extraction utility.
 *
 * Used by both the Maven (JAR) and Go module plugins — both archive formats
 * are standard ZIP files.
 *
 * Security model mirrors tarball.ts:
 *   - Rejects absolute paths and ".." path traversal (zip-slip defence)
 *   - Per-caller file filter (extension allowlist or path pattern)
 *   - Per-file size cap
 *   - UTF-8 decoding; skips binary/non-decodable entries
 */

import { createHash } from "node:crypto";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import yauzl from "yauzl";

const MAX_FILE_SIZE = 100 * 1024; // 100KB

// ── yauzl promise wrappers ─────────────────────────────────────────────────

function openZipFile(zipPath: string): Promise<yauzl.ZipFile> {
  return new Promise((resolve, reject) => {
    yauzl.open(zipPath, { lazyEntries: true }, (err, zipfile) => {
      if (err || !zipfile) reject(err ?? new Error("zip open failed"));
      else resolve(zipfile);
    });
  });
}

function readEntryStream(zipfile: yauzl.ZipFile, entry: yauzl.Entry): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    zipfile.openReadStream(entry, (err, stream) => {
      if (err || !stream) {
        reject(err ?? new Error("openReadStream failed"));
        return;
      }
      const chunks: Buffer[] = [];
      stream.on("data", (c: Buffer) => chunks.push(c));
      stream.on("end", () => resolve(Buffer.concat(chunks)));
      stream.on("error", reject);
    });
  });
}

/**
 * Extract entries from a ZIP file into a Map<relPath, content>.
 *
 * @param zipPath       Path to the ZIP file on disk.
 * @param shouldInclude Callback to decide whether to include a file by its
 *                      relative path (after prefix stripping). Returning false
 *                      skips the entry without reading it.
 * @param stripPrefix   Optional path prefix to strip from every entry name.
 *                      For Go modules: "module@version/".
 *                      For JARs: no stripping needed (no top-level prefix).
 * @returns Map from relative path to UTF-8 content.
 */
export async function extractZipToMap(
  zipPath: string,
  shouldInclude: (relPath: string) => boolean,
  stripPrefix?: string
): Promise<Map<string, string>> {
  const fileMap = new Map<string, string>();
  const zipfile = await openZipFile(zipPath);

  await new Promise<void>((resolve, reject) => {
    const processEntry = async (entry: yauzl.Entry): Promise<void> => {
      try {
        // Skip directory entries
        if (/\/$/.test(entry.fileName)) return;

        // Zip-slip defence: reject absolute paths and path traversal
        if (entry.fileName.startsWith("/") || entry.fileName.includes("..")) return;

        // Size cap
        if (entry.uncompressedSize > MAX_FILE_SIZE) return;

        let relPath = entry.fileName;
        if (stripPrefix && relPath.startsWith(stripPrefix)) {
          relPath = relPath.slice(stripPrefix.length);
        }
        if (!relPath) return;

        if (!shouldInclude(relPath)) return;

        const buf = await readEntryStream(zipfile, entry);
        try {
          fileMap.set(relPath, buf.toString("utf-8"));
        } catch {
          // skip binary / non-UTF-8 entries
        }
      } catch {
        // skip problematic entries without aborting the extraction
      }
    };

    // Process entries sequentially: only call readEntry() after the current
    // entry's async processing completes. This ensures all reads finish before
    // the "end" event fires, since yauzl only emits "entry" after readEntry().
    zipfile.on("entry", (entry: yauzl.Entry) => {
      processEntry(entry).then(
        () => zipfile.readEntry(),
        () => zipfile.readEntry()
      );
    });

    zipfile.on("end", () => resolve());
    zipfile.on("error", reject);

    zipfile.readEntry(); // kick off the first entry
  });

  zipfile.close();
  return fileMap;
}

/**
 * Download ZIP bytes, write to a temp file, extract, and clean up.
 * Returns the fileMap plus SHA-256 of the raw bytes (for integrity checking).
 */
export async function downloadAndExtractZip(
  bytes: Buffer,
  shouldInclude: (relPath: string) => boolean,
  stripPrefix?: string
): Promise<{ fileMap: Map<string, string>; sha256hex: string }> {
  const sha256hex = createHash("sha256").update(bytes).digest("hex");

  const tempDir = await mkdtemp(join(tmpdir(), "npm-prescripts-zip-"));
  const zipPath = join(tempDir, "pkg.zip");

  try {
    await writeFile(zipPath, bytes);
    const fileMap = await extractZipToMap(zipPath, shouldInclude, stripPrefix);
    return { fileMap, sha256hex };
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

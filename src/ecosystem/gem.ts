/**
 * Ruby/RubyGems ecosystem plugin.
 *
 * Implements EcosystemPlugin for gems published to rubygems.org.
 * Supports Gemfile.lock (Bundler) lockfiles.
 *
 * Security focus — three install-time attack vectors:
 *
 * 1. C extensions (.gemspec extensions: field)
 *    Causes compilation of native code at `gem install` time.
 *    extconf.rb / mkrf_conf.rb run arbitrary Ruby during compilation.
 *
 * 2. rubygems_plugin.rb
 *    Loaded by the `gem` command on every invocation after install.
 *    A persistence mechanism — runs indefinitely after the gem is removed.
 *    Attack example: used in the rest-client compromise (2019).
 *
 * 3. Malicious code in lib/**\/*.rb
 *    Does not run at install time but executes when the gem is `require`d.
 *    Most common Ruby supply chain attack vector — compromise of main library file.
 *    Examples: rest-client (2019), strong_password (2019), bootstrap-sass (2019).
 *
 * .gem file format:
 *   Outer TAR containing:
 *     data.tar.gz  — actual gem files
 *     metadata.gz  — gemspec (gzip-compressed YAML)
 *     checksums.yaml.gz
 */

import { createHash } from "node:crypto";
import { mkdtemp, writeFile, readFile, readdir, mkdir } from "node:fs/promises";
import { join, extname } from "node:path";
import { tmpdir } from "node:os";
import { stat } from "node:fs/promises";
import * as tar from "tar";
import type {
  PackageRef,
  ProvenanceFetchResult,
  ProvenanceInfo,
  Finding,
  AdvisoryMatch,
  ScanOptions,
} from "../types.js";
import type { DiskCache } from "../cache/disk-cache.js";
import type { EcosystemPlugin, ExtractionResult } from "./types.js";
import { hasGemfileLock, parseGemfileLock, parseGemfileLockContent } from "../lockfile/gemfile-parser.js";
import { fetchOsvAdvisories } from "../registry/osv-client.js";
import {
  fetchGemsMeta,
  fetchGemBytes,
  fetchGemsOwners,
  resolveGemLatestVersion,
} from "../registry/rubygems-client.js";

const GEM_ALLOWED_EXTENSIONS = new Set([".rb", ".gemspec"]);
const MAX_FILE_SIZE = 100 * 1024;

export class GemPlugin implements EcosystemPlugin {
  readonly packageManager = "gem" as const;

  init(_opts: ScanOptions): void {
    // No global state to configure for RubyGems
  }

  async detectLockfile(dir: string): Promise<boolean> {
    return hasGemfileLock(dir);
  }

  async getLockfilePaths(dir: string): Promise<string[]> {
    return (await hasGemfileLock(dir)) ? ["Gemfile.lock"] : [];
  }

  parseLockfileContent(content: string, _filename: string): PackageRef[] {
    return parseGemfileLockContent(content);
  }

  async parseLockfile(dir: string): Promise<{ refs: PackageRef[]; lockfileDir: string } | null> {
    const result = await parseGemfileLock(dir);
    if (!result) return null;
    return { refs: result.refs, lockfileDir: dir };
  }

  async resolveCheckSpec(spec: string, _opts: ScanOptions): Promise<PackageRef[] | null> {
    const atIdx = spec.lastIndexOf("@");
    let name: string;
    let version: string;
    if (atIdx > 0) {
      name = spec.slice(0, atIdx);
      version = spec.slice(atIdx + 1);
    } else {
      name = spec;
      version = "latest";
    }

    if (version === "latest") {
      const resolved = await resolveGemLatestVersion(name);
      if (!resolved) return null;
      version = resolved;
    }

    return [{ name, version, resolved: "", integrity: null }];
  }

  async fetchPackage(
    ref: PackageRef,
    opts: ScanOptions,
    cache: DiskCache,
    _projectDir: string
  ): Promise<ExtractionResult> {
    // Resolve download URL from RubyGems if not already set
    let downloadUrl = ref.resolved;
    let expectedSha: string | null = ref.integrity;

    if (!downloadUrl) {
      const meta = await fetchGemsMeta(ref.name, ref.version);
      if (!meta) {
        throw new Error(`RubyGems: no metadata for ${ref.name}@${ref.version}`);
      }
      downloadUrl = meta.downloadUrl;
      expectedSha = expectedSha ?? meta.sha256;
    }

    const cacheKey = expectedSha ?? ref.version;

    if (!opts.noCache) {
      const cached = await cache.read(ref.name, cacheKey, ref.version);
      if (cached) {
        return {
          packageJson: cached.extracted.packageJson,
          fileMap: cached.extracted.fileMap,
          sourceType: "registry",
          integrityVerified: expectedSha !== null,
          computedIntegrity: expectedSha,
          binaryDownload: null,
        };
      }
    }

    const bytes = await fetchGemBytes(downloadUrl, opts.timeout);

    const sha256hex = createHash("sha256").update(bytes).digest("hex");
    const computedIntegrity = `sha256:${sha256hex}`;

    let integrityVerified = false;
    if (expectedSha) {
      const expected = expectedSha.startsWith("sha256:")
        ? expectedSha.slice(7)
        : expectedSha;
      integrityVerified = sha256hex === expected;
    }

    const tempDir = await mkdtemp(join(tmpdir(), "prescripts-gem-"));
    const fileMap = new Map<string, string>();

    await extractGem(bytes, tempDir, fileMap);

    const packageJson = parseGemspec(fileMap);
    const extracted = { packageJson, fileMap };

    if (!opts.noCache) {
      await cache.write(ref.name, ref.version, cacheKey, "registry", extracted);
    }

    return {
      packageJson,
      fileMap,
      sourceType: "registry",
      integrityVerified,
      computedIntegrity,
      binaryDownload: null,
    };
  }

  extractHooks(result: ExtractionResult): Record<string, string> {
    const hooks: Record<string, string> = {};

    // Scan all .rb and .gemspec files — malicious code can appear anywhere in the gem
    for (const [path, content] of result.fileMap.entries()) {
      const ext = extname(path);
      if (ext === ".rb" || ext === ".gemspec") {
        hooks[path] = content;
      }
    }

    return hooks;
  }

  hasHooks(hooks: Record<string, string>): boolean {
    // Always true for gems that have any Ruby or gemspec files
    return Object.keys(hooks).length > 0;
  }

  async fetchProvenance(ref: PackageRef, _opts: ScanOptions): Promise<ProvenanceFetchResult> {
    const [meta, owners] = await Promise.all([
      fetchGemsMeta(ref.name, ref.version),
      fetchGemsOwners(ref.name),
    ]);

    if (!meta) {
      return {
        provenance: emptyProvenance("RubyGems metadata unavailable"),
        registryManifestScripts: null,
        registryIntegrity: null,
        registrySignatures: null,
      };
    }

    const provenance: ProvenanceInfo = {
      publishedAt: meta.uploadTime,
      weeklyDownloads: null,          // RubyGems API has total downloads, not weekly
      maintainerCount: owners.length > 0 ? owners.length : null,
      installScriptIsNew: null,
      totalVersions: meta.totalVersions,
      unavailableReason: null,
      attestation: null,              // RubyGems does not have Sigstore attestations
      deprecated: meta.yanked ? "Yanked from RubyGems" : null,
      publisher: meta.authors ?? null,
      publisherInMaintainers: null,   // no per-version published_by in RubyGems API
      hasRegistrySignature: null,     // RubyGems does not sign .gem files with ECDSA
      attestationRegressed: null,
      firstPublishedAt: meta.firstUploadTime,
      publisherIsNewToPackage: null,  // no per-version published_by in RubyGems API
      binaryHostChanged: null,        // RubyGems does not use node-pre-gyp binary.host
      previousBinaryHost: null,
    };

    return {
      provenance,
      registryManifestScripts: null,
      registryIntegrity: meta.sha256,
      registrySignatures: null,
    };
  }

  async extraFindings(
    ref: PackageRef,
    _opts: ScanOptions,
    result: ExtractionResult,
    prov: ProvenanceFetchResult,
    _hooks: Record<string, string>
  ): Promise<Finding[]> {
    const findings: Finding[] = [];
    const { registryIntegrity } = prov;

    if (ref.integrity && registryIntegrity && ref.integrity !== registryIntegrity) {
      findings.push({
        scriptHook: null,
        source: "Gemfile.lock vs. RubyGems integrity",
        category: "lockfile_poisoning",
        severity: "critical",
        confidence: "high",
        pattern: "Gemfile.lock sha256 does not match RubyGems release sha256",
        excerpt: {
          _warning: "UNTRUSTED THIRD-PARTY CONTENT",
          lines: `Gemfile.lock: ${ref.integrity}\nRubyGems:     ${registryIntegrity}`,
        },
      });
    }

    if (ref.integrity && !result.integrityVerified) {
      findings.push({
        scriptHook: null,
        source: "tarball integrity check",
        category: "integrity_mismatch",
        severity: "critical",
        confidence: "medium",
        pattern: "sha256 hash mismatch",
        excerpt: {
          _warning: "UNTRUSTED THIRD-PARTY CONTENT",
          lines: `Expected: ${ref.integrity}\nActual hash did not match.`,
        },
      });
    }

    return findings;
  }

  async fetchAdvisories(
    refs: PackageRef[],
    _opts: ScanOptions
  ): Promise<Map<string, AdvisoryMatch[]>> {
    return fetchOsvAdvisories(refs, "RubyGems");
  }
}

// ── .gem extraction (TAR-in-TAR) ─────────────────────────────────────────────

/**
 * Extract a .gem file.
 *
 * .gem = outer TAR containing:
 *   data.tar.gz   — gem source files (strip:1 for <gem>-<version>/ prefix)
 *   metadata.gz   — gemspec as gzipped YAML
 */
async function extractGem(
  bytes: Buffer,
  tempDir: string,
  fileMap: Map<string, string>
): Promise<void> {
  const gemPath = join(tempDir, "pkg.gem");
  const outerDir = join(tempDir, "outer");
  await mkdir(outerDir, { recursive: true });
  await writeFile(gemPath, bytes);

  // Extract outer TAR (no strip — top-level contains data.tar.gz etc.)
  await tar.extract({
    file: gemPath,
    cwd: outerDir,
    filter: (path: string) => !path.includes("..") && !path.startsWith("/"),
  });

  // Find data.tar.gz in the extracted outer directory
  const dataTarGz = join(outerDir, "data.tar.gz");
  let dataTarBytes: Buffer;
  try {
    dataTarBytes = await readFile(dataTarGz);
  } catch {
    // Older format may use data.tar — try without .gz
    try {
      dataTarBytes = await readFile(join(outerDir, "data.tar"));
    } catch {
      return; // Can't find data archive
    }
  }

  const innerDir = join(tempDir, "extracted");
  await mkdir(innerDir, { recursive: true });
  const innerTarPath = join(tempDir, "data.tar.gz");
  await writeFile(innerTarPath, dataTarBytes);

  // Extract inner tar.gz (strip:1 removes <name>-<version>/ prefix)
  await tar.extract({
    file: innerTarPath,
    cwd: innerDir,
    strip: 1,
    filter: (path: string) => !path.includes("..") && !path.startsWith("/"),
  });

  await collectGemFiles(innerDir, "", fileMap);
}

async function collectGemFiles(
  dir: string,
  base: string,
  fileMap: Map<string, string>
): Promise<void> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    const relPath = base ? `${base}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      await collectGemFiles(fullPath, relPath, fileMap);
    } else if (entry.isFile()) {
      if (!GEM_ALLOWED_EXTENSIONS.has(extname(entry.name))) continue;
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
 * Build a minimal packageJson-equivalent from the first .gemspec found in fileMap.
 */
function parseGemspec(fileMap: Map<string, string>): Record<string, unknown> {
  for (const [path, content] of fileMap.entries()) {
    if (path.endsWith(".gemspec")) {
      return { gemspec: { _raw: content } };
    }
  }
  return {};
}

function emptyProvenance(reason: string): ProvenanceInfo {
  return {
    publishedAt: null,
    weeklyDownloads: null,
    maintainerCount: null,
    installScriptIsNew: null,
    totalVersions: null,
    unavailableReason: reason,
    attestation: null,
    deprecated: null,
    publisher: null,
    publisherInMaintainers: null,
    hasRegistrySignature: null,
    attestationRegressed: null,
    firstPublishedAt: null,
    publisherIsNewToPackage: null,
    binaryHostChanged: null,
    previousBinaryHost: null,
  };
}

export const gemPlugin = new GemPlugin();

/**
 * Rust/Cargo ecosystem plugin.
 *
 * Implements EcosystemPlugin for crates published to crates.io.
 * Supports Cargo.lock lockfiles (v2 and v3).
 *
 * Security focus — build.rs:
 *   Cargo build scripts (build.rs) are arbitrary Rust code executed at compile
 *   time before crate compilation. They can:
 *   - Execute system commands (std::process::Command)
 *   - Make network requests (std::net::TcpStream, reqwest, ureq)
 *   - Link native libraries (cargo:rustc-link-lib=)
 *   - Write to the filesystem
 *
 *   This plugin detects build.rs presence and scans its contents for dangerous
 *   patterns. Crates without build.rs are skipped (return null from scanAny).
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
import { hasCargoLockfile, parseCargoLockfile, parseCargoLockfileContent } from "../lockfile/cargo-parser.js";
import { fetchOsvAdvisories } from "../registry/osv-client.js";
import {
  fetchCratesMeta,
  fetchCrateBytes,
  fetchCratesOwners,
  resolveCratesLatestVersion,
} from "../registry/cratesio-client.js";

const CARGO_ALLOWED_EXTENSIONS = new Set([".rs", ".toml"]);
const MAX_FILE_SIZE = 100 * 1024;

export class CargoPlugin implements EcosystemPlugin {
  readonly packageManager = "cargo" as const;

  init(_opts: ScanOptions): void {
    // crates.io timeout is set via setCratesTimeout; for now uses default 30s
  }

  async detectLockfile(dir: string): Promise<boolean> {
    return hasCargoLockfile(dir);
  }

  async getLockfilePaths(dir: string): Promise<string[]> {
    return (await hasCargoLockfile(dir)) ? ["Cargo.lock"] : [];
  }

  parseLockfileContent(content: string, _filename: string): PackageRef[] {
    return parseCargoLockfileContent(content);
  }

  async parseLockfile(dir: string): Promise<{ refs: PackageRef[]; lockfileDir: string } | null> {
    const result = await parseCargoLockfile(dir);
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
      const resolved = await resolveCratesLatestVersion(name);
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
    // Resolve download URL from crates.io if not already set
    let downloadUrl = ref.resolved;
    let expectedIntegrity = ref.integrity;

    if (!downloadUrl) {
      const meta = await fetchCratesMeta(ref.name, ref.version);
      if (!meta) {
        throw new Error(`crates.io: no metadata for ${ref.name}@${ref.version}`);
      }
      downloadUrl = meta.downloadUrl;
      expectedIntegrity = expectedIntegrity ?? meta.sha256;
    }

    const cacheKey = expectedIntegrity ?? ref.version;

    if (!opts.noCache) {
      const cached = await cache.read(ref.name, cacheKey, ref.version);
      if (cached) {
        return {
          packageJson: cached.extracted.packageJson,
          fileMap: cached.extracted.fileMap,
          sourceType: "registry",
          integrityVerified: expectedIntegrity !== null,
          computedIntegrity: expectedIntegrity,
          binaryDownload: null,
        };
      }
    }

    const bytes = await fetchCrateBytes(downloadUrl, opts.timeout);

    const sha256hex = createHash("sha256").update(bytes).digest("hex");
    const computedIntegrity = `sha256:${sha256hex}`;

    let integrityVerified = false;
    if (expectedIntegrity) {
      const expected = expectedIntegrity.startsWith("sha256:")
        ? expectedIntegrity.slice(7)
        : expectedIntegrity;
      integrityVerified = sha256hex === expected;
    }

    const tempDir = await mkdtemp(join(tmpdir(), "npm-prescripts-rs-"));
    const extractDir = join(tempDir, "extracted");
    await mkdir(extractDir, { recursive: true });

    const cratePath = join(tempDir, "pkg.crate");
    await writeFile(cratePath, bytes);

    // .crate files are .tar.gz with <name>-<version>/ top-level prefix
    await tar.extract({
      file: cratePath,
      cwd: extractDir,
      strip: 1,
      filter: (path: string) => !path.includes("..") && !path.startsWith("/"),
    });

    const fileMap = new Map<string, string>();
    await collectCargoFiles(extractDir, "", fileMap);

    // Use Cargo.toml as the "packageJson" equivalent
    const packageJson = parseCargoToml(fileMap.get("Cargo.toml") ?? "");

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
    // build.rs is the primary install-time execution hook for Cargo
    const buildRs = result.fileMap.get("build.rs");
    if (buildRs) {
      hooks["build.rs"] = buildRs;
    }
    return hooks;
  }

  hasHooks(hooks: Record<string, string>): boolean {
    return Object.keys(hooks).length > 0;
  }

  async fetchProvenance(ref: PackageRef, _opts: ScanOptions): Promise<ProvenanceFetchResult> {
    const [meta, owners] = await Promise.all([
      fetchCratesMeta(ref.name, ref.version),
      fetchCratesOwners(ref.name),
    ]);

    if (!meta) {
      return {
        provenance: emptyProvenance("crates.io metadata unavailable"),
        registryManifestScripts: null,
        registryIntegrity: null,
        registrySignatures: null,
      };
    }

    const publisher = meta.publisher;

    // Is the publisher currently an owner of this crate?
    const publisherInMaintainers =
      publisher !== null && owners.length > 0
        ? owners.includes(publisher)
        : null;

    // Has this publisher ever published this crate before?
    const publisherIsNewToPackage =
      publisher !== null
        ? !meta.previousPublishers.includes(publisher)
        : null;

    const provenance: ProvenanceInfo = {
      publishedAt: meta.uploadTime,
      weeklyDownloads: null,       // crates.io has total downloads, not weekly
      maintainerCount: owners.length > 0 ? owners.length : null,
      installScriptIsNew: null,
      totalVersions: meta.totalVersions,
      unavailableReason: null,
      attestation: null,           // crates.io does not have Sigstore attestations
      deprecated: meta.yanked ? "Yanked from crates.io" : null,
      publisher,
      publisherInMaintainers,
      hasRegistrySignature: null,  // crates.io does not sign packages
      attestationRegressed: null,
      firstPublishedAt: meta.firstUploadTime,
      publisherIsNewToPackage,
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

    // Lockfile integrity mismatch (Cargo.lock checksum vs computed)
    if (ref.integrity && registryIntegrity && ref.integrity !== registryIntegrity) {
      findings.push({
        scriptHook: null,
        source: "Cargo.lock vs. crates.io integrity",
        category: "lockfile_poisoning",
        severity: "critical",
        confidence: "high",
        pattern: "Cargo.lock checksum does not match crates.io release checksum",
        excerpt: {
          _warning: "UNTRUSTED THIRD-PARTY CONTENT",
          lines: `Cargo.lock: ${ref.integrity}\ncrates.io:  ${registryIntegrity}`,
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
    return fetchOsvAdvisories(refs, "crates.io");
  }
}

// ── File collection helpers ───────────────────────────────────────────────────

async function collectCargoFiles(
  dir: string,
  base: string,
  fileMap: Map<string, string>
): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    const relPath = base ? `${base}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      await collectCargoFiles(fullPath, relPath, fileMap);
    } else if (entry.isFile()) {
      if (!CARGO_ALLOWED_EXTENSIONS.has(extname(entry.name))) continue;
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
 * Minimal Cargo.toml parser — extracts just enough for the packageJson field.
 */
function parseCargoToml(content: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  const packageMatch = content.match(/\[package\]([\s\S]*?)(?=\n\[|$)/);
  if (packageMatch) {
    result["package"] = { _raw: packageMatch[1] };
  }

  const depsMatch = content.match(/\[dependencies\]([\s\S]*?)(?=\n\[|$)/);
  if (depsMatch) {
    result["dependencies"] = { _raw: depsMatch[1] };
  }

  const buildDepsMatch = content.match(/\[build-dependencies\]([\s\S]*?)(?=\n\[|$)/);
  if (buildDepsMatch) {
    result["build-dependencies"] = { _raw: buildDepsMatch[1] };
  }

  return result;
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
  };
}

export const cargoPlugin = new CargoPlugin();

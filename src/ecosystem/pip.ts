/**
 * Python/pip ecosystem plugin.
 *
 * Implements EcosystemPlugin for packages published to PyPI.
 * Supports requirements.txt and poetry.lock lockfiles.
 * Respects PIP_INDEX_URL for corporate mirrors and HTTPS_PROXY for proxies.
 */

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
import { parsePipLockfile, hasPipLockfile, parsePipLockfileContent, findRequirementsFiles } from "../lockfile/pip-parser.js";
import { extractPythonPackage } from "../extractor/python-tarball.js";
import { fetchPyPIMeta, fetchPyPIProvenance, findPyPIFileByHash, resolvePyPILatestVersion } from "../registry/pypi-client.js";
import { parsePyPIAttestation } from "../registry/pypi-attestation.js";
import { extractPythonHooks, hasPythonHooks } from "../analyzer/python-hooks.js";
import { fetchOsvAdvisories } from "../registry/osv-client.js";

/**
 * Checks whether a previous PyPI release had a PEP 740 attestation that the
 * current release is missing. This is a lightweight presence check — we only
 * verify that the provenance endpoint returns attestation_bundles, not the
 * full Sigstore chain (the current version's bundle is already verified).
 *
 * Returns:
 *   false  — current version has attestation (no regression possible), or
 *            previous version also lacks attestation
 *   true   — previous version had attestation, current version does not
 *   null   — no previous version to compare, or comparison unavailable
 */
async function resolveAttestationRegressed(
  currentAttestation: import("../types.js").AttestationInfo | null,
  previousVersion: string | null,
  packageName: string
): Promise<boolean | null> {
  // Current version has attestation — no regression possible
  if (currentAttestation !== null) return false;

  // No previous version to compare against
  if (!previousVersion) return null;

  try {
    const prevMeta = await fetchPyPIMeta(packageName, previousVersion);
    if (!prevMeta) return null;

    const prevFilename = prevMeta.tarballUrl.split("/").pop() ?? "";
    if (!prevFilename) return null;

    const raw = await fetchPyPIProvenance(packageName, previousVersion, prevFilename);
    if (!raw || typeof raw !== "object") return false;

    const bundles = (raw as Record<string, unknown>)["attestation_bundles"];
    return Array.isArray(bundles) && bundles.length > 0;
  } catch {
    return null;
  }
}

export class PipPlugin implements EcosystemPlugin {
  readonly packageManager = "pip" as const;

  init(_opts: ScanOptions): void {
    // No global state to configure for pip — PIP_INDEX_URL and HTTPS_PROXY
    // are read from the environment directly in pypi-client.ts.
  }

  async detectLockfile(dir: string): Promise<boolean> {
    return hasPipLockfile(dir);
  }

  async getLockfilePaths(dir: string): Promise<string[]> {
    const { access } = await import("node:fs/promises");
    const { join, relative } = await import("node:path");
    for (const name of ["uv.lock", "poetry.lock"]) {
      try {
        await access(join(dir, name));
        return [name];
      } catch {
        // not found
      }
    }
    // Recursively discover requirements*.txt files and return paths relative to dir
    const absPaths = await findRequirementsFiles(dir);
    return absPaths.map((p) => relative(dir, p));
  }

  parseLockfileContent(content: string, filename: string): PackageRef[] {
    return parsePipLockfileContent(content, filename);
  }

  async parseLockfile(dir: string): Promise<{ refs: PackageRef[]; lockfileDir: string } | null> {
    const result = await parsePipLockfile(dir);
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
      const resolved = await resolvePyPILatestVersion(name);
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
    // Resolve tarball URL from PyPI if not already in the ref
    let tarballUrl = ref.resolved;
    let expectedIntegrity = ref.integrity;

    if (!tarballUrl) {
      // When the lockfile provides a hash, find the exact file on PyPI that
      // matches it. This ensures we download the correct wheel variant (e.g.
      // win32 vs amd64) so hash verification doesn't fail spuriously.
      if (expectedIntegrity) {
        const byHash = await findPyPIFileByHash(ref.name, ref.version, expectedIntegrity);
        if (byHash) {
          tarballUrl = byHash.url;
        }
      }

      if (!tarballUrl) {
        const meta = await fetchPyPIMeta(ref.name, ref.version);
        if (!meta) {
          throw new Error(`PyPI: no metadata for ${ref.name}@${ref.version}`);
        }
        tarballUrl = meta.tarballUrl;
        expectedIntegrity = expectedIntegrity ?? meta.sha256;
      }
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

    const result = await extractPythonPackage(tarballUrl, expectedIntegrity, opts.timeout);

    if (!opts.noCache) {
      await cache.write(ref.name, ref.version, cacheKey, "registry", result.extracted);
    }

    return {
      packageJson: result.extracted.packageJson,
      fileMap: result.extracted.fileMap,
      sourceType: "registry",
      integrityVerified: result.integrityVerified,
      computedIntegrity: result.computedIntegrity,
      binaryDownload: null,
    };
  }

  extractHooks(result: ExtractionResult): Record<string, string> {
    return extractPythonHooks(result.fileMap);
  }

  hasHooks(hooks: Record<string, string>): boolean {
    return hasPythonHooks(hooks);
  }

  async fetchProvenance(ref: PackageRef, opts: ScanOptions): Promise<ProvenanceFetchResult> {
    const meta = await fetchPyPIMeta(ref.name, ref.version);

    if (!meta) {
      return {
        provenance: emptyProvenance("PyPI metadata unavailable"),
        registryManifestScripts: null,
        registryIntegrity: null,
        registrySignatures: null,
      };
    }

    // Fetch PEP 740 attestation from the PyPI integrity API.
    // The attestation endpoint is always on pypi.org regardless of which index
    // the package was installed from — a 404 simply means no attestation exists.
    // Skip when pypiAttestations: false is set (air-gapped environments).
    const filename = meta.tarballUrl.split("/").pop() ?? "";
    const attestation =
      filename && opts.pypiAttestations !== false
        ? await parsePyPIAttestation(
            await fetchPyPIProvenance(ref.name, ref.version, filename)
          )
        : null;

    // Regression check: only needed when the current version lacks attestation.
    // If it has one, regression is impossible. If there's no previous version to
    // compare against, we can't determine regression (null = unknown).
    const attestationRegressed = await resolveAttestationRegressed(
      attestation,
      meta.previousVersion,
      ref.name
    );

    const provenance: ProvenanceInfo = {
      publishedAt: meta.uploadTime,
      weeklyDownloads: null,           // requires pypistats.org — not fetched
      maintainerCount: null,           // PyPI has author/maintainer as strings, not arrays
      installScriptIsNew: null,        // would require comparing with previous version
      totalVersions: meta.totalVersions,
      unavailableReason: null,
      attestation,
      deprecated: meta.yanked ? (meta.yankedReason ?? "Yanked from PyPI") : null,
      // Prefer OIDC-verified source repo from attestation over free-text package metadata
      publisher: attestation?.sourceRepo ?? meta.maintainer ?? meta.author ?? null,
      publisherInMaintainers: null,    // no maintainer list in PyPI API
      hasRegistrySignature: null,      // PyPI does not sign packages with ECDSA
      attestationRegressed,
      firstPublishedAt: meta.firstUploadTime,
      publisherIsNewToPackage: null,
      binaryHostChanged: null,         // PyPI packages don't use node-pre-gyp binary.host
      previousBinaryHost: null,
    };

    return {
      provenance,
      registryManifestScripts: null,
      registryIntegrity: meta.sha256,
      registryIntegrityAll: meta.allSha256.length > 0 ? meta.allSha256 : null,
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
    const { registryIntegrity, registryIntegrityAll } = prov;

    // Lockfile poisoning — lockfile sha256 not found among any PyPI artifact for this version.
    // Use the full set of hashes (all wheel variants, sdist) when available so that
    // platform-specific wheels don't produce false positives.
    const validHashes = new Set<string>(
      registryIntegrityAll ?? (registryIntegrity ? [registryIntegrity] : [])
    );
    if (ref.integrity && validHashes.size > 0 && !validHashes.has(ref.integrity)) {
      findings.push({
        scriptHook: null,
        source: "lockfile vs. PyPI integrity",
        category: "lockfile_poisoning",
        severity: "critical",
        confidence: "high",
        pattern: "lockfile sha256 does not match any PyPI release artifact",
        excerpt: {
          _warning: "UNTRUSTED THIRD-PARTY CONTENT",
          lines: `lockfile: ${ref.integrity}\nPyPI:     ${registryIntegrity ?? "(unavailable)"}`,
        },
      });
    }

    // Tarball integrity mismatch
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
    return fetchOsvAdvisories(refs, "PyPI");
  }
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

export const pipPlugin = new PipPlugin();

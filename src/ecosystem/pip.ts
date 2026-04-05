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
import { parsePipLockfile, hasPipLockfile } from "../lockfile/pip-parser.js";
import { extractPythonPackage } from "../extractor/python-tarball.js";
import { fetchPyPIMeta, fetchPyPIProvenance, resolvePyPILatestVersion } from "../registry/pypi-client.js";
import { parsePyPIAttestation } from "../registry/pypi-attestation.js";
import { extractPythonHooks, hasPythonHooks } from "../analyzer/python-hooks.js";
import { fetchOsvAdvisories } from "../registry/osv-client.js";

export class PipPlugin implements EcosystemPlugin {
  readonly packageManager = "pip" as const;

  init(_opts: ScanOptions): void {
    // No global state to configure for pip — PIP_INDEX_URL and HTTPS_PROXY
    // are read from the environment directly in pypi-client.ts.
  }

  async detectLockfile(dir: string): Promise<boolean> {
    return hasPipLockfile(dir);
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
      const meta = await fetchPyPIMeta(ref.name, ref.version);
      if (!meta) {
        throw new Error(`PyPI: no metadata for ${ref.name}@${ref.version}`);
      }
      tarballUrl = meta.tarballUrl;
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

  async fetchProvenance(ref: PackageRef, _opts: ScanOptions): Promise<ProvenanceFetchResult> {
    const meta = await fetchPyPIMeta(ref.name, ref.version);

    if (!meta) {
      return {
        provenance: emptyProvenance("PyPI metadata unavailable"),
        registryManifestScripts: null,
        registryIntegrity: null,
        registrySignatures: null,
      };
    }

    // Fetch PEP 740 attestation using the filename from the selected tarball/wheel URL.
    // fetchPyPIProvenance short-circuits to null on private indexes — safe to always call.
    const filename = meta.tarballUrl.split("/").pop() ?? "";
    const attestation = filename
      ? await parsePyPIAttestation(
          await fetchPyPIProvenance(ref.name, ref.version, filename)
        )
      : null;

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
      attestationRegressed: null,      // populated in segment 4
      firstPublishedAt: meta.firstUploadTime,
      publisherIsNewToPackage: null,
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

    // Lockfile poisoning — poetry.lock sha256 ≠ PyPI sha256
    if (ref.integrity && registryIntegrity && ref.integrity !== registryIntegrity) {
      findings.push({
        scriptHook: null,
        source: "lockfile vs. PyPI integrity",
        category: "lockfile_poisoning",
        severity: "critical",
        confidence: "high",
        pattern: "lockfile sha256 does not match PyPI release sha256",
        excerpt: {
          _warning: "UNTRUSTED THIRD-PARTY CONTENT",
          lines: `lockfile: ${ref.integrity}\nPyPI:     ${registryIntegrity}`,
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
  };
}

export const pipPlugin = new PipPlugin();

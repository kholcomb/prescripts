/**
 * Go modules ecosystem plugin.
 *
 * Implements EcosystemPlugin for Go modules published via proxy.golang.org.
 * Supports go.mod + go.sum lockfiles.
 *
 * Threat model — Go has no install-time lifecycle hooks, but three mechanisms
 * are relevant for supply-chain analysis:
 *
 *   1. //go:generate directives — shell commands embedded in source files,
 *      run by `go generate`. Automated CI tooling often runs this without
 *      inspecting the commands.
 *
 *   2. CGO (import "C") — C code in CGO preambles compiles and links into the
 *      binary. The C code runs at init time.
 *
 *   3. func init() — runs automatically when the package is imported. An
 *      init() that exfiltrates env vars or makes network requests is a
 *      supply-chain attack vector.
 *
 * Integrity: go.sum h1: hashes are trusted as authoritative (the Go toolchain
 * enforces go.sum consistency). We do not recompute h1: hashes ourselves as
 * that requires the full Go Hash1 algorithm.
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
import {
  hasGoLockfile,
  parseGoLockfile,
  parseGoSumContent,
} from "../lockfile/go-parser.js";
import {
  fetchGoVersionInfo,
  fetchGoModuleBytes,
  resolveGoLatestVersion,
  goModuleDownloadUrl,
  setGoTimeout,
} from "../registry/gomodule-client.js";
import { extractGoModule } from "../extractor/gomodule.js";
import { extractGoHooks } from "../analyzer/go-hooks.js";
import { fetchOsvAdvisories } from "../registry/osv-client.js";

export class GoPlugin implements EcosystemPlugin {
  readonly packageManager = "go" as const;

  init(opts: ScanOptions): void {
    if (opts.timeout) setGoTimeout(opts.timeout);
  }

  async detectLockfile(dir: string): Promise<boolean> {
    return hasGoLockfile(dir);
  }

  async getLockfilePaths(dir: string): Promise<string[]> {
    return (await hasGoLockfile(dir)) ? ["go.mod", "go.sum"] : [];
  }

  parseLockfileContent(content: string, filename: string): PackageRef[] {
    if (filename === "go.sum") {
      return parseGoSumContent(content);
    }
    // go.mod alone can't produce integrity-verified refs; return empty
    return [];
  }

  async parseLockfile(dir: string): Promise<{ refs: PackageRef[]; lockfileDir: string } | null> {
    return parseGoLockfile(dir);
  }

  async resolveCheckSpec(spec: string, _opts: ScanOptions): Promise<PackageRef[] | null> {
    // Go module paths use the full module path, not a short name.
    // Spec format: "github.com/foo/bar@v1.2.3" or "github.com/foo/bar"
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
      const resolved = await resolveGoLatestVersion(name);
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
    const cacheKey = ref.integrity ?? ref.version;

    if (!opts.noCache) {
      const cached = await cache.read(ref.name, cacheKey, ref.version);
      if (cached) {
        return {
          packageJson: cached.extracted.packageJson,
          fileMap: cached.extracted.fileMap,
          sourceType: "registry",
          integrityVerified: ref.integrity !== null,
          computedIntegrity: ref.integrity,
          binaryDownload: null,
        };
      }
    }

    const bytes = await fetchGoModuleBytes(ref.name, ref.version);
    if (!bytes) {
      throw new Error(`go module proxy: failed to download ${ref.name}@${ref.version}`);
    }

    const { fileMap, sha256hex, integrityVerified, computedIntegrity } =
      await extractGoModule(bytes, ref.name, ref.version, ref.integrity);

    // Use a minimal "packageJson" equivalent derived from the module path
    const packageJson: Record<string, unknown> = {
      name: ref.name,
      version: ref.version,
      _goModule: true,
    };

    const extracted = { packageJson, fileMap };
    if (!opts.noCache) {
      await cache.write(ref.name, ref.version, cacheKey, "registry", extracted);
    }

    void sha256hex; // used for integrity; stored in computedIntegrity

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
    return extractGoHooks(result.fileMap);
  }

  hasHooks(hooks: Record<string, string>): boolean {
    return Object.keys(hooks).length > 0;
  }

  async fetchProvenance(ref: PackageRef, _opts: ScanOptions): Promise<ProvenanceFetchResult> {
    const meta = await fetchGoVersionInfo(ref.name, ref.version);

    if (!meta) {
      return {
        provenance: emptyProvenance("go module proxy metadata unavailable"),
        registryManifestScripts: null,
        registryIntegrity: null,
        registrySignatures: null,
      };
    }

    const provenance: ProvenanceInfo = {
      publishedAt: meta.publishedAt,
      weeklyDownloads: null,        // Go proxy does not expose download stats
      maintainerCount: null,        // no maintainer concept in Go module proxy
      installScriptIsNew: null,     // Go has no lifecycle scripts
      totalVersions: meta.totalVersions,
      unavailableReason: null,
      attestation: null,            // no standard Sigstore attestation for Go modules
      deprecated: null,             // go.mod retract is handled at parse time
      publisher: null,              // proxy does not expose publisher identity
      publisherInMaintainers: null,
      hasRegistrySignature: null,   // Go module proxy does not sign packages
      attestationRegressed: null,
      firstPublishedAt: meta.firstPublishedAt,
      publisherIsNewToPackage: null,
      binaryHostChanged: null,
      previousBinaryHost: null,
    };

    return {
      provenance,
      registryManifestScripts: null,
      registryIntegrity: null,     // Go uses h1: hashes (go.sum), not SRI format
      registrySignatures: null,
    };
  }

  async extraFindings(
    ref: PackageRef,
    _opts: ScanOptions,
    result: ExtractionResult,
    _prov: ProvenanceFetchResult,
    _hooks: Record<string, string>
  ): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Integrity: go.sum is authoritative; if the download failed integrity check,
    // flag it (though integrityVerified is always true when go.sum has a hash)
    if (ref.integrity && !result.integrityVerified) {
      findings.push({
        scriptHook: null,
        source: "go.sum integrity check",
        category: "integrity_mismatch",
        severity: "critical",
        confidence: "medium",
        pattern: "go.sum hash could not be verified",
        excerpt: {
          _warning: "UNTRUSTED THIRD-PARTY CONTENT",
          lines: `go.sum: ${ref.integrity}`,
        },
      });
    }

    // Flag the download URL for reference (helps triage)
    const downloadUrl = goModuleDownloadUrl(ref.name, ref.version);
    void downloadUrl; // logged implicitly via resolved field in PackageRef

    return findings;
  }

  async fetchAdvisories(
    refs: PackageRef[],
    _opts: ScanOptions
  ): Promise<Map<string, AdvisoryMatch[]>> {
    return fetchOsvAdvisories(refs, "Go");
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

export const goPlugin = new GoPlugin();

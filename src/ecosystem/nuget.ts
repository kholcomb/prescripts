/**
 * NuGet ecosystem plugin.
 *
 * Implements EcosystemPlugin for .NET packages published to NuGet.org.
 * Supports:
 *   - packages.lock.json (primary, with SHA-512 integrity hashes)
 *   - *.csproj / *.fsproj / *.vbproj (SDK-style project files)
 *   - packages.config (legacy)
 *   - Directory.Packages.props (Central Package Management)
 *
 * Threat model — NuGet packages don't have install-time lifecycle scripts
 * in the npm sense, but:
 *
 *   1. MSBuild .targets / .props files in a package execute during
 *      `dotnet build` or `msbuild`. <Exec Command="..."> runs arbitrary
 *      shell commands in the consumer's build environment.
 *
 *   2. PowerShell scripts (install.ps1, uninstall.ps1, init.ps1) in the
 *      tools/ directory auto-execute with older nuget.exe workflows.
 *      init.ps1 runs on every Visual Studio project open.
 *
 *   3. Roslyn source generators and analyzers run inside the compiler
 *      process and can emit arbitrary code or exfiltrate source.
 *
 * Integrity: packages.lock.json provides SHA-512 content hashes matching
 * the "sha512-<base64>" SRI format. We verify the downloaded .nupkg against
 * this hash when available.
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
  hasNugetFiles,
  getNugetLockfilePaths,
  parseNugetLockfileContent,
  parseNugetLockfile,
} from "../lockfile/nuget-parser.js";
import {
  fetchNugetMeta,
  fetchNupkgBytes,
  resolveNugetLatestVersion,
  setNugetTimeout,
} from "../registry/nuget-client.js";
import { extractNupkg } from "../extractor/nupkg.js";
import { extractNugetHooksFromFileMap } from "../analyzer/nuget-hooks.js";
import { fetchOsvAdvisories } from "../registry/osv-client.js";

export class NuGetPlugin implements EcosystemPlugin {
  readonly packageManager = "nuget" as const;

  init(opts: ScanOptions): void {
    if (opts.timeout) setNugetTimeout(opts.timeout);
  }

  async detectLockfile(dir: string): Promise<boolean> {
    return hasNugetFiles(dir);
  }

  async getLockfilePaths(dir: string): Promise<string[]> {
    return getNugetLockfilePaths(dir);
  }

  parseLockfileContent(content: string, filename: string): PackageRef[] {
    return parseNugetLockfileContent(content, filename).refs;
  }

  async parseLockfile(
    dir: string
  ): Promise<{ refs: PackageRef[]; lockfileDir: string; warnings?: string[] } | null> {
    return parseNugetLockfile(dir);
  }

  async resolveCheckSpec(spec: string, _opts: ScanOptions): Promise<PackageRef[] | null> {
    // NuGet spec: "PackageName@version" or "PackageName" (latest)
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

    // Heuristic: NuGet package IDs contain dots or are PascalCase.
    // Reject specs that look like Go module paths (contain //).
    if (name.includes("//")) return null;

    if (version === "latest") {
      const resolved = await resolveNugetLatestVersion(name);
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
    const meta = await fetchNugetMeta(ref.name, ref.version);
    if (!meta) {
      throw new Error(`NuGet: no metadata for ${ref.name}@${ref.version}`);
    }

    // packages.lock.json integrity is in ref.integrity (sha512-<base64>)
    const expectedIntegrity = ref.integrity;
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

    const bytes = await fetchNupkgBytes(meta.nupkgUrl);
    if (!bytes) {
      throw new Error(`NuGet: failed to download .nupkg for ${ref.name}@${ref.version}`);
    }

    const { fileMap, integrityVerified, computedIntegrity } =
      await extractNupkg(bytes, expectedIntegrity);

    // Build a minimal packageJson from the nuspec if available
    const nuspecContent = findNuspec(fileMap);
    const packageJson: Record<string, unknown> = {
      name: ref.name,
      version: ref.version,
      _nugetArtifact: true,
    };
    if (nuspecContent) {
      packageJson["_nuspec"] = nuspecContent;
    }

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
    return extractNugetHooksFromFileMap(result.fileMap);
  }

  hasHooks(hooks: Record<string, string>): boolean {
    return Object.keys(hooks).length > 0;
  }

  async fetchProvenance(ref: PackageRef, _opts: ScanOptions): Promise<ProvenanceFetchResult> {
    const meta = await fetchNugetMeta(ref.name, ref.version);

    if (!meta) {
      return {
        provenance: emptyProvenance("NuGet metadata unavailable"),
        registryManifestScripts: null,
        registryIntegrity: null,
        registrySignatures: null,
      };
    }

    const provenance: ProvenanceInfo = {
      publishedAt: meta.uploadTime,
      weeklyDownloads: meta.totalDownloads,   // NuGet exposes total, not weekly
      maintainerCount: null,                  // NuGet does not expose maintainer count
      installScriptIsNew: null,               // no npm-style install scripts
      totalVersions: meta.totalVersions,
      unavailableReason: null,
      attestation: null,                      // NuGet has no Sigstore attestations
      deprecated: meta.deprecated ? "Package is deprecated or unlisted" : null,
      publisher: null,                        // NuGet registration does not expose publisher identity
      publisherInMaintainers: null,
      hasRegistrySignature: null,             // NuGet signing is optional and not universally checked
      attestationRegressed: null,
      firstPublishedAt: meta.firstUploadTime,
      publisherIsNewToPackage: null,
      binaryHostChanged: null,
      previousBinaryHost: null,
    };

    return {
      provenance,
      registryManifestScripts: null,
      registryIntegrity: ref.integrity,       // sha512-<base64> from packages.lock.json
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

    // .nupkg integrity mismatch
    if (registryIntegrity && result.integrityVerified === false) {
      const computed = result.computedIntegrity ?? "unknown";
      findings.push({
        scriptHook: null,
        source: ".nupkg integrity check",
        category: "integrity_mismatch",
        severity: "critical",
        confidence: "high",
        pattern: "Downloaded .nupkg sha512 does not match packages.lock.json contentHash",
        excerpt: {
          _warning: "UNTRUSTED THIRD-PARTY CONTENT",
          lines: `Expected: ${registryIntegrity}\nActual:   ${computed}`,
        },
      });
    }

    return findings;
  }

  async fetchAdvisories(
    refs: PackageRef[],
    _opts: ScanOptions
  ): Promise<Map<string, AdvisoryMatch[]>> {
    return fetchOsvAdvisories(refs, "NuGet");
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function findNuspec(fileMap: Map<string, string>): string | null {
  for (const [path, content] of fileMap) {
    if (path.toLowerCase().endsWith(".nuspec")) return content;
  }
  return null;
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

export const nugetPlugin = new NuGetPlugin();

/**
 * Maven + Gradle ecosystem plugin.
 *
 * Implements EcosystemPlugin for Java artifacts published to Maven Central.
 * Supports:
 *   - pom.xml (Maven dependency manifest)
 *   - gradle.lockfile (Gradle dependency locking)
 *   - build.gradle / build.gradle.kts (best-effort extraction)
 *
 * Threat model — Maven dependencies don't run code at download time, but:
 *
 *   1. Maven plugins execute code during the build lifecycle. A dependency
 *      that is itself a Maven plugin (or declares dangerous plugins in its
 *      bundled pom.xml) can run arbitrary commands during `mvn compile`,
 *      `mvn test`, etc.
 *
 *   2. Java agents (MANIFEST.MF Premain-Class / Agent-Class) instrument the
 *      JVM and can intercept any method call.
 *
 *   3. Java reflection (Class.forName, URLClassLoader) enables loading
 *      arbitrary code at runtime — common in deserialization gadget chains.
 *
 *   4. Native code via JNI (System.loadLibrary) executes outside the JVM
 *      security model.
 *
 * Integrity: Maven Central provides SHA-256 and SHA-1 checksums for each
 * artifact. We verify the downloaded JAR against the registry checksum.
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
  hasMavenOrGradleFiles,
  getMavenLockfilePaths,
  parseMavenLockfileContent,
  parseMavenLockfile,
} from "../lockfile/maven-parser.js";
import {
  fetchMavenMeta,
  fetchJarBytes,
  resolveMavenLatestVersion,
  setMavenTimeout,
} from "../registry/mavencentral-client.js";
import { extractJar } from "../extractor/jar.js";
import { extractMavenHooksFromFileMap } from "../analyzer/maven-hooks.js";
import { fetchOsvAdvisories } from "../registry/osv-client.js";

export class MavenPlugin implements EcosystemPlugin {
  readonly packageManager = "maven" as const;

  init(opts: ScanOptions): void {
    if (opts.timeout) setMavenTimeout(opts.timeout);
  }

  async detectLockfile(dir: string): Promise<boolean> {
    return hasMavenOrGradleFiles(dir);
  }

  async getLockfilePaths(dir: string): Promise<string[]> {
    return getMavenLockfilePaths(dir);
  }

  parseLockfileContent(content: string, filename: string): PackageRef[] {
    return parseMavenLockfileContent(content, filename).refs;
  }

  async parseLockfile(dir: string): Promise<{ refs: PackageRef[]; lockfileDir: string } | null> {
    return parseMavenLockfile(dir);
  }

  async resolveCheckSpec(spec: string, _opts: ScanOptions): Promise<PackageRef[] | null> {
    // Maven spec: "groupId:artifactId@version" or "groupId:artifactId"
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

    if (!name.includes(":")) {
      // Not a Maven coordinate — can't resolve
      return null;
    }

    if (version === "latest") {
      const resolved = await resolveMavenLatestVersion(name);
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
    const meta = await fetchMavenMeta(ref.name, ref.version);
    if (!meta) {
      throw new Error(`Maven Central: no metadata for ${ref.name}@${ref.version}`);
    }

    const cacheKey = meta.sha256 ?? ref.version;

    if (!opts.noCache) {
      const cached = await cache.read(ref.name, cacheKey, ref.version);
      if (cached) {
        return {
          packageJson: cached.extracted.packageJson,
          fileMap: cached.extracted.fileMap,
          sourceType: "registry",
          integrityVerified: meta.sha256 !== null,
          computedIntegrity: meta.sha256,
          binaryDownload: null,
        };
      }
    }

    const bytes = await fetchJarBytes(meta.jarUrl);
    if (!bytes) {
      throw new Error(`Maven Central: failed to download JAR for ${ref.name}@${ref.version}`);
    }

    const { fileMap, sha256hex, integrityVerified, computedIntegrity } =
      await extractJar(bytes, meta.sha256);

    // Verify sha256 directly when we have a sha256 hash
    let verified = integrityVerified;
    if (meta.sha256?.startsWith("sha256:")) {
      verified = sha256hex === meta.sha256.slice(7);
    }

    // Build a minimal "packageJson" from the Maven coordinate
    const [groupId = "", artifactId = ""] = ref.name.split(":");
    const packageJson: Record<string, unknown> = {
      name: ref.name,
      version: ref.version,
      groupId,
      artifactId,
      _mavenArtifact: true,
    };

    // Extract bundled POM from the JAR for additional metadata
    const bundledPom = findBundledPom(fileMap);
    if (bundledPom) {
      packageJson["_bundledPom"] = bundledPom;
    }

    const extracted = { packageJson, fileMap };
    if (!opts.noCache) {
      await cache.write(ref.name, ref.version, cacheKey, "registry", extracted);
    }

    return {
      packageJson,
      fileMap,
      sourceType: "registry",
      integrityVerified: verified,
      computedIntegrity,
      binaryDownload: null,
    };
  }

  extractHooks(result: ExtractionResult): Record<string, string> {
    return extractMavenHooksFromFileMap(result.fileMap);
  }

  hasHooks(hooks: Record<string, string>): boolean {
    return Object.keys(hooks).length > 0;
  }

  async fetchProvenance(ref: PackageRef, _opts: ScanOptions): Promise<ProvenanceFetchResult> {
    const meta = await fetchMavenMeta(ref.name, ref.version);

    if (!meta) {
      return {
        provenance: emptyProvenance("Maven Central metadata unavailable"),
        registryManifestScripts: null,
        registryIntegrity: null,
        registrySignatures: null,
      };
    }

    const provenance: ProvenanceInfo = {
      publishedAt: meta.uploadTime,
      weeklyDownloads: null,        // Maven Central does not expose download stats
      maintainerCount: null,        // no maintainer concept in Maven Central
      installScriptIsNew: null,     // Maven has no lifecycle scripts in the npm sense
      totalVersions: meta.totalVersions,
      unavailableReason: null,
      attestation: null,            // Maven Central has no Sigstore attestations
      deprecated: null,
      publisher: null,              // Maven Central does not expose publisher identity
      publisherInMaintainers: null,
      hasRegistrySignature: null,   // Maven Central does not sign packages
      attestationRegressed: null,
      firstPublishedAt: meta.firstUploadTime,
      publisherIsNewToPackage: null,
      binaryHostChanged: null,
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

    // Tarball integrity mismatch
    if (registryIntegrity && result.integrityVerified === false) {
      const computed = result.computedIntegrity ?? "unknown";
      findings.push({
        scriptHook: null,
        source: "JAR integrity check",
        category: "integrity_mismatch",
        severity: "critical",
        confidence: "high",
        pattern: "Downloaded JAR sha256 does not match Maven Central checksum",
        excerpt: {
          _warning: "UNTRUSTED THIRD-PARTY CONTENT",
          lines: `Expected: ${registryIntegrity}\nActual:   sha256:${computedSha256(computed)}`,
        },
      });
    }

    return findings;
  }

  async fetchAdvisories(
    refs: PackageRef[],
    _opts: ScanOptions
  ): Promise<Map<string, AdvisoryMatch[]>> {
    return fetchOsvAdvisories(refs, "Maven");
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Find the first bundled pom.xml in a JAR's file map.
 * Bundled POMs are at META-INF/maven/{groupId}/{artifactId}/pom.xml
 */
function findBundledPom(fileMap: Map<string, string>): string | null {
  for (const [path, content] of fileMap) {
    if (path.startsWith("META-INF/maven/") && path.endsWith("pom.xml")) {
      return content;
    }
  }
  return null;
}

function computedSha256(integrity: string): string {
  if (integrity.startsWith("sha256:")) return integrity.slice(7);
  return integrity;
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

export const mavenPlugin = new MavenPlugin();

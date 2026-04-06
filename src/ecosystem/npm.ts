/**
 * npm/Node.js ecosystem plugin.
 *
 * Implements EcosystemPlugin for packages published to the npm registry.
 * Supports package-lock.json (v1/v2/v3) and npm-shrinkwrap.json lockfiles.
 */

import { join } from "node:path";
import { access } from "node:fs/promises";
import type {
  PackageRef,
  ProvenanceFetchResult,
  Finding,
  AdvisoryMatch,
  ScanOptions,
  LifecycleScripts,
} from "../types.js";
import type { DiskCache } from "../cache/disk-cache.js";
import type { EcosystemPlugin, ExtractionResult } from "./types.js";
import { parseLockfile, parseLockfileContent } from "../lockfile/parser.js";
import { readWorkspacePatterns } from "../lockfile/workspace.js";
import { fetchAndExtract } from "../extractor/index.js";
import { fetchProvenance } from "../registry/metadata.js";
import { fetchAdvisories } from "../registry/advisory.js";
import { verifyRegistrySignature } from "../registry/signature-verify.js";
import { resolveTree } from "../resolver/package-tree.js";
import { extractLifecycleScripts, hasLifecycleScripts, extractBinaryField } from "../analyzer/lifecycle.js";
import {
  setRegistry,
  setTimeout_ as setRequestTimeout,
} from "../registry/client.js";
import { setRegistryConcurrency } from "../registry/rate-limiter.js";

export class NpmPlugin implements EcosystemPlugin {
  readonly packageManager = "npm" as const;

  init(opts: ScanOptions): void {
    setRegistry(opts.registry);
    setRequestTimeout(opts.timeout);
    setRegistryConcurrency(opts.concurrency);
  }

  async detectLockfile(dir: string): Promise<boolean> {
    for (const name of ["package-lock.json", "npm-shrinkwrap.json"]) {
      try {
        await access(join(dir, name));
        return true;
      } catch {
        // not found
      }
    }
    return false;
  }

  async getLockfilePaths(dir: string): Promise<string[]> {
    for (const name of ["npm-shrinkwrap.json", "package-lock.json"]) {
      try {
        await access(join(dir, name));
        return [name];
      } catch {
        // not found
      }
    }
    return [];
  }

  parseLockfileContent(content: string, _filename: string): PackageRef[] {
    return parseLockfileContent(content);
  }

  async parseLockfile(dir: string): Promise<{ refs: PackageRef[]; lockfileDir: string } | null> {
    try {
      const result = await parseLockfile(dir);
      const lockfileDir = result.lockfileDir;
      if (lockfileDir !== dir) {
        const wsPatterns = await readWorkspacePatterns(lockfileDir);
        const wsNote = wsPatterns.length > 0
          ? ` (workspace: ${wsPatterns.join(", ")})`
          : "";
        process.stderr.write(`Using workspace root lockfile: ${lockfileDir}${wsNote}\n`);
      }
      return result;
    } catch {
      return null;
    }
  }

  async resolveCheckSpec(spec: string, opts: ScanOptions): Promise<PackageRef[] | null> {
    const [rawName, rawVersion = "latest"] = spec.split("@").filter(Boolean) as [string, string?];
    const name = spec.startsWith("@")
      ? `@${spec.slice(1).split("@")[0]}`
      : (rawName ?? spec);
    const version = spec.startsWith("@")
      ? (spec.slice(1).split("@")[1] ?? "latest")
      : rawVersion;

    try {
      return await resolveTree(name, version, opts.depth);
    } catch {
      return null;
    }
  }

  async fetchPackage(
    ref: PackageRef,
    opts: ScanOptions,
    cache: DiskCache,
    projectDir: string
  ): Promise<ExtractionResult> {
    if (!opts.noCache) {
      const cached = await cache.read(ref.name, ref.integrity, ref.version);
      if (cached) {
        const packageJson = cached.extracted.packageJson;
        const binaryDownload = extractBinaryField(packageJson);
        return {
          packageJson,
          fileMap: cached.extracted.fileMap,
          sourceType: cached.meta.sourceType,
          integrityVerified: ref.integrity !== null,
          computedIntegrity: ref.integrity ?? null,
          binaryDownload,
        };
      }
    }

    const result = await fetchAndExtract(ref, projectDir, opts.registry);
    if (!opts.noCache) {
      await cache.write(ref.name, ref.version, ref.integrity, result.sourceType, result.extracted);
    }

    const binaryDownload = extractBinaryField(result.extracted.packageJson);
    return {
      packageJson: result.extracted.packageJson,
      fileMap: result.extracted.fileMap,
      sourceType: result.sourceType,
      integrityVerified: result.integrityVerified,
      computedIntegrity: result.computedIntegrity,
      binaryDownload,
    };
  }

  extractHooks(result: ExtractionResult): Record<string, string> {
    return extractLifecycleScripts(result.packageJson);
  }

  hasHooks(hooks: Record<string, string>): boolean {
    return hasLifecycleScripts(hooks as LifecycleScripts);
  }

  async fetchProvenance(ref: PackageRef, opts: ScanOptions): Promise<ProvenanceFetchResult> {
    return fetchProvenance(ref.name, ref.version, opts.registry);
  }

  async extraFindings(
    ref: PackageRef,
    opts: ScanOptions,
    result: ExtractionResult,
    prov: ProvenanceFetchResult,
    hooks: Record<string, string>
  ): Promise<Finding[]> {
    const findings: Finding[] = [];
    const { provenance, registryManifestScripts, registryIntegrity, registrySignatures } = prov;

    // Attestation chain failure (most severe — prepend first so it ends up at the top)
    if (provenance.attestation?.sigstoreVerified === false) {
      const errorSummary = (provenance.attestation.sigstoreErrors ?? []).join("; ");
      findings.push({
        scriptHook: null,
        source: "Sigstore bundle verification",
        category: "attestation_invalid",
        severity: "critical",
        confidence: "high",
        pattern: "Sigstore chain verification failed",
        excerpt: {
          _warning: "UNTRUSTED THIRD-PARTY CONTENT",
          lines: errorSummary || "One or more verification checks failed.",
        },
      });
    }

    // Attestation subject mismatch — substitution attack
    if (
      provenance.attestation?.subjectIntegrity &&
      result.computedIntegrity &&
      provenance.attestation.subjectIntegrity !== result.computedIntegrity
    ) {
      findings.push({
        scriptHook: null,
        source: "Sigstore attestation subject",
        category: "attestation_subject_mismatch",
        severity: "critical",
        confidence: "high",
        pattern: "attested tarball hash does not match downloaded tarball",
        excerpt: {
          _warning: "UNTRUSTED THIRD-PARTY CONTENT",
          lines:
            `attested:   ${provenance.attestation.subjectIntegrity}\n` +
            `downloaded: ${result.computedIntegrity}`,
        },
      });
    }

    // npm ECDSA registry signature verification
    if (registryIntegrity && registrySignatures && result.sourceType === "registry") {
      const sigValid = await verifyRegistrySignature(
        ref.name,
        ref.version,
        registryIntegrity,
        registrySignatures,
        opts.registry
      );
      if (sigValid === false) {
        findings.push({
          scriptHook: null,
          source: "npm registry ECDSA signature",
          category: "signature_invalid",
          severity: "critical",
          confidence: "high",
          pattern: "registry signature verification failed",
          excerpt: {
            _warning: "UNTRUSTED THIRD-PARTY CONTENT",
            lines:
              "The npm registry ECDSA signature for this package did not verify.\n" +
              "This may indicate a tampered package or MITM between client and registry.",
          },
        });
      }
    }

    // Lockfile poisoning — lockfile hash ≠ registry hash
    if (ref.integrity && registryIntegrity && ref.integrity !== registryIntegrity) {
      findings.push({
        scriptHook: null,
        source: "lockfile vs. registry integrity",
        category: "lockfile_poisoning",
        severity: "critical",
        confidence: "high",
        pattern: "lockfile integrity hash does not match registry dist.integrity",
        excerpt: {
          _warning: "UNTRUSTED THIRD-PARTY CONTENT",
          lines: `lockfile:  ${ref.integrity}\nregistry:  ${registryIntegrity}`,
        },
      });
    }

    // Tarball integrity mismatch vs lockfile
    if (ref.integrity && !result.integrityVerified) {
      findings.push({
        scriptHook: null,
        source: "tarball integrity check",
        category: "integrity_mismatch",
        severity: "critical",
        confidence: "medium",
        pattern: "hash mismatch",
        excerpt: {
          _warning: "UNTRUSTED THIRD-PARTY CONTENT",
          lines: `Expected: ${ref.integrity}\nActual hash did not match.`,
        },
      });
    }

    // Manifest confusion — tarball scripts differ from registry manifest scripts
    if (registryManifestScripts !== null || hasLifecycleScripts(hooks as LifecycleScripts)) {
      for (const hook of Object.keys(hooks)) {
        const tarballValue = hooks[hook];
        const registryValue = (registryManifestScripts as Record<string, string> | null)?.[hook];
        if (tarballValue !== registryValue) {
          findings.push({
            scriptHook: hook,
            source: "manifest confusion: tarball vs. registry manifest",
            category: "manifest_confusion",
            severity: "critical",
            confidence: "medium",
            pattern: registryValue === undefined
              ? "script present in tarball but absent from registry manifest"
              : "script value differs between tarball and registry manifest",
            excerpt: {
              _warning: "UNTRUSTED THIRD-PARTY CONTENT",
              lines: `registry: ${registryValue ?? "(not present)"}\ntarball:  ${tarballValue}`,
            },
          });
        }
      }
    }

    // Binary host change — download host differs from previous version
    if (provenance.binaryHostChanged === true) {
      findings.push({
        scriptHook: null,
        source: "binary download host",
        category: "binary_host_changed",
        severity: "high",
        confidence: "medium",
        pattern: "binary download host changed from previous version",
        excerpt: {
          _warning: "UNTRUSTED THIRD-PARTY CONTENT",
          lines:
            `previous: ${provenance.previousBinaryHost ?? "(none)"}\n` +
            `current:  ${result.binaryDownload?.host ?? "(none)"}`,
        },
      });
    }

    // Provenance regression — attestation absent when previous version had one
    if (provenance.attestationRegressed === true) {
      findings.push({
        scriptHook: null,
        source: "provenance attestation",
        category: "provenance_regression",
        severity: "high",
        confidence: "medium",
        pattern: "attestation absent (present in previous version)",
        excerpt: {
          _warning: "UNTRUSTED THIRD-PARTY CONTENT",
          lines:
            "Previous version had Sigstore provenance attestation.\n" +
            "This version does not — consistent with the Axios supply chain attack pattern (2026).",
        },
      });
    }

    return findings;
  }

  async fetchAdvisories(
    refs: PackageRef[],
    opts: ScanOptions
  ): Promise<Map<string, AdvisoryMatch[]>> {
    return fetchAdvisories(refs, opts.registry);
  }
}

export const npmPlugin = new NpmPlugin();

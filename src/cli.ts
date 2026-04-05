import { Command } from "commander";
import pLimit from "p-limit";
import { parseLockfile } from "./lockfile/parser.js";
import { parsePipLockfile, hasPipLockfile } from "./lockfile/pip-parser.js";
import { readWorkspacePatterns } from "./lockfile/workspace.js";
import { fetchAndExtract } from "./extractor/index.js";
import { extractPythonPackage } from "./extractor/python-tarball.js";
import { fetchProvenance } from "./registry/metadata.js";
import { fetchPyPIMeta, resolvePyPILatestVersion } from "./registry/pypi-client.js";
import { extractLifecycleScripts, hasLifecycleScripts, extractBinaryField } from "./analyzer/lifecycle.js";
import { extractPythonHooks, hasPythonHooks } from "./analyzer/python-hooks.js";
import { scanPackage } from "./analyzer/scanner.js";
import { DiskCache } from "./cache/disk-cache.js";
import { resolveTree } from "./resolver/package-tree.js";
import { buildProjectReport, toJson } from "./report/json-report.js";
import { renderReport, renderProgress, clearProgress } from "./report/human.js";
import { toSarif } from "./report/sarif.js";
import {
  setRegistry,
  setTimeout_ as setRequestTimeout,
} from "./registry/client.js";
import { setRegistryConcurrency } from "./registry/rate-limiter.js";
import { fetchAdvisories } from "./registry/advisory.js";
import { scoreFindings, applyBinaryDownloaderCluster, computeRisk } from "./analyzer/confidence.js";
import { verifyRegistrySignature } from "./registry/signature-verify.js";
import { loadConfig } from "./config.js";
import type { PackageReport, PackageRef, ProvenanceInfo, ScanOptions, Severity, Finding, AdvisoryMatch, LifecycleScripts, RiskLevel } from "./types.js";
import { writeFile, readFile, mkdir, access } from "node:fs/promises";
import { resolve, join } from "node:path";
import { spawn } from "node:child_process";

async function scanRef(
  ref: PackageRef,
  opts: ScanOptions,
  cache: DiskCache,
  projectDir: string,
  advisoryMap: Map<string, AdvisoryMatch[]> = new Map()
): Promise<PackageReport | null> {
  // Check hosted API first if configured
  if (opts.apiUrl) {
    try {
      const url = `${opts.apiUrl.replace(/\/$/, "")}/v1/package/${encodeURIComponent(ref.name)}/${encodeURIComponent(ref.version)}`;
      const res = await fetch(url, { signal: AbortSignal.timeout(opts.timeout) });
      if (res.ok) {
        return (await res.json()) as PackageReport;
      }
    } catch {
      // fall through to local analysis
    }
  }

  let packageJson: Record<string, unknown>;
  let fileMap: Map<string, string>;
  let sourceType;
  let integrityVerified = false;
  let computedIntegrity: string | null = null;

  if (!opts.noCache) {
    const cached = await cache.read(ref.name, ref.integrity, ref.version);
    if (cached) {
      packageJson = cached.extracted.packageJson;
      fileMap = cached.extracted.fileMap;
      sourceType = cached.meta.sourceType;
      integrityVerified = ref.integrity !== null;
      // When served from cache, the integrity was already verified on first download
      computedIntegrity = ref.integrity ?? null;
    } else {
      const result = await fetchAndExtract(ref, projectDir, opts.registry);
      packageJson = result.extracted.packageJson;
      fileMap = result.extracted.fileMap;
      sourceType = result.sourceType;
      integrityVerified = result.integrityVerified;
      computedIntegrity = result.computedIntegrity;
      await cache.write(ref.name, ref.version, ref.integrity, sourceType, result.extracted);
    }
  } else {
    const result = await fetchAndExtract(ref, projectDir, opts.registry);
    packageJson = result.extracted.packageJson;
    fileMap = result.extracted.fileMap;
    sourceType = result.sourceType;
    integrityVerified = result.integrityVerified;
    computedIntegrity = result.computedIntegrity;
  }

  const lifecycleScripts = extractLifecycleScripts(packageJson);
  const binaryDownload = extractBinaryField(packageJson);
  // Prefer SHA-keyed lookup (content-pinned) over version-keyed (range-matched)
  const advisories =
    (ref.integrity ? advisoryMap.get(`${ref.name}@${ref.integrity}`) : undefined) ??
    advisoryMap.get(`${ref.name}@${ref.version}`) ??
    [];

  if (!hasLifecycleScripts(lifecycleScripts) && !binaryDownload && advisories.length === 0) {
    return null; // nothing to report
  }

  const {
    provenance,
    registryManifestScripts,
    registryIntegrity,
    registrySignatures,
  } = await fetchProvenance(ref.name, ref.version, opts.registry);
  const { findings: patternFindings } = scanPackage(lifecycleScripts, fileMap, opts.severity);

  const findings: Finding[] = [...patternFindings];

  // --- Manifest confusion: tarball scripts vs. registry manifest scripts ---
  if (registryManifestScripts !== null || hasLifecycleScripts(lifecycleScripts)) {
    for (const hook of Object.keys(lifecycleScripts) as (keyof LifecycleScripts)[]) {
      const tarballValue = lifecycleScripts[hook];
      const registryValue = (registryManifestScripts as Record<string, string> | null)?.[hook];
      if (tarballValue !== registryValue) {
        findings.unshift({
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

  // --- Provenance regression ---
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

  // --- Integrity mismatch ---
  if (ref.integrity && !integrityVerified) {
    findings.unshift({
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

  // --- Lockfile poisoning: lockfile integrity ≠ registry dist.integrity ---
  // Detects: attacker modifies lockfile hash to match a tampered tarball.
  // The registry still holds the original hash — they diverge.
  if (ref.integrity && registryIntegrity && ref.integrity !== registryIntegrity) {
    findings.unshift({
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

  // --- npm ECDSA registry signature verification ---
  // Detects: tampered tarball or MITM — attacker cannot re-sign with npm's private key.
  if (registryIntegrity && registrySignatures && sourceType === "registry") {
    const sigValid = await verifyRegistrySignature(
      ref.name,
      ref.version,
      registryIntegrity,
      registrySignatures,
      opts.registry
    );
    if (sigValid === false) {
      findings.unshift({
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

  // --- Attestation subject verification ---
  // Detects: attestation substitution — using package A's attestation for package B's tarball.
  if (
    provenance.attestation?.subjectIntegrity &&
    computedIntegrity &&
    provenance.attestation.subjectIntegrity !== computedIntegrity
  ) {
    findings.unshift({
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
          `downloaded: ${computedIntegrity}`,
      },
    });
  }

  // --- Sigstore chain verification failure ---
  // Detects: fabricated attestation bundle (self-signed cert, forged Rekor SET,
  //          invalid Merkle proof). sigstoreVerified === false means crypto
  //          definitively failed; null means could not verify (not a finding).
  if (provenance.attestation?.sigstoreVerified === false) {
    const errorSummary = (provenance.attestation.sigstoreErrors ?? []).join("; ");
    findings.unshift({
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

  // Post-process findings: cluster detection → confidence scoring → risk
  const clustered = applyBinaryDownloaderCluster(findings, binaryDownload);
  const scored = scoreFindings(clustered, provenance, opts.trust);
  const risk = computeRisk(scored, advisories, provenance);

  return {
    name: ref.name,
    version: ref.version,
    source: {
      type: sourceType,
      resolved: ref.resolved,
      integrity: ref.integrity,
      integrityVerified,
    },
    provenance,
    lifecycleScripts,
    binaryDownload,
    advisories,
    findings: scored,
    risk,
  };
}

// ── Python (pip/PyPI) scan path ───────────────────────────────────────────────

/**
 * Builds a ProvenanceInfo from PyPI metadata.
 * Maps PyPI fields to the generic ProvenanceInfo shape; npm-specific fields are null.
 */
async function fetchPyPIProvenance(name: string, version: string): Promise<{
  provenance: ProvenanceInfo;
  registryIntegrity: string | null;
}> {
  const meta = await fetchPyPIMeta(name, version);

  if (!meta) {
    return {
      provenance: {
        publishedAt: null,
        weeklyDownloads: null,
        maintainerCount: null,
        installScriptIsNew: null,
        totalVersions: null,
        unavailableReason: "PyPI metadata unavailable",
        attestation: null,
        deprecated: null,
        publisher: null,
        publisherInMaintainers: null,
        hasRegistrySignature: null,
        attestationRegressed: null,
        firstPublishedAt: null,
        publisherIsNewToPackage: null,
      },
      registryIntegrity: null,
    };
  }

  const provenance: ProvenanceInfo = {
    publishedAt: meta.uploadTime,
    weeklyDownloads: null,           // requires pypistats.org — skip for now
    maintainerCount: null,           // PyPI has author/maintainer as strings, not arrays
    installScriptIsNew: null,        // would require comparing with prev version
    totalVersions: meta.totalVersions,
    unavailableReason: null,
    attestation: null,               // PyPI doesn't have Sigstore attestations yet
    deprecated: meta.yanked ? (meta.yankedReason ?? "Yanked from PyPI") : null,
    publisher: meta.maintainer ?? meta.author ?? null,
    publisherInMaintainers: null,    // no maintainer list in PyPI API
    hasRegistrySignature: null,      // PyPI doesn't sign packages with ECDSA
    attestationRegressed: null,      // no attestations on PyPI
    firstPublishedAt: meta.firstUploadTime,
    publisherIsNewToPackage: null,
  };

  return { provenance, registryIntegrity: meta.sha256 };
}

async function scanPipRef(
  ref: PackageRef,
  opts: ScanOptions,
  cache: DiskCache
): Promise<PackageReport | null> {
  let fileMap: Map<string, string>;
  let packageJson: Record<string, unknown>;
  let integrityVerified = false;
  let computedIntegrity: string | null = null;

  // Resolve tarball URL from PyPI if not already in the ref
  let tarballUrl = ref.resolved;
  let expectedIntegrity = ref.integrity;

  if (!tarballUrl) {
    const meta = await fetchPyPIMeta(ref.name, ref.version);
    if (!meta) {
      if (opts.verbose) {
        process.stderr.write(`\nPyPI: no metadata for ${ref.name}@${ref.version}\n`);
      }
      return null;
    }
    tarballUrl = meta.tarballUrl;
    expectedIntegrity = expectedIntegrity ?? meta.sha256;
  }

  // Check cache (keyed by integrity hash if available, else by name@version)
  const cacheKey = expectedIntegrity ?? ref.version;
  if (!opts.noCache) {
    const cached = await cache.read(ref.name, cacheKey, ref.version);
    if (cached) {
      packageJson = cached.extracted.packageJson;
      fileMap = cached.extracted.fileMap;
      integrityVerified = expectedIntegrity !== null;
      computedIntegrity = expectedIntegrity;
    } else {
      const result = await extractPythonPackage(tarballUrl, expectedIntegrity, opts.timeout);
      packageJson = result.extracted.packageJson;
      fileMap = result.extracted.fileMap;
      integrityVerified = result.integrityVerified;
      computedIntegrity = result.computedIntegrity;
      await cache.write(ref.name, ref.version, cacheKey, "registry", result.extracted);
    }
  } else {
    const result = await extractPythonPackage(tarballUrl, expectedIntegrity, opts.timeout);
    packageJson = result.extracted.packageJson;
    fileMap = result.extracted.fileMap;
    integrityVerified = result.integrityVerified;
    computedIntegrity = result.computedIntegrity;
  }

  const pythonHooks = extractPythonHooks(fileMap);

  // For Python, skip packages with no install hooks and no advisories
  if (!hasPythonHooks(pythonHooks)) {
    return null;
  }

  const { provenance, registryIntegrity } = await fetchPyPIProvenance(ref.name, ref.version);
  const { findings: patternFindings } = scanPackage(pythonHooks, fileMap, opts.severity);
  const findings: Finding[] = [...patternFindings];

  // --- Integrity mismatch (PyPI sha256 vs. computed sha256) ---
  if (ref.integrity && !integrityVerified) {
    findings.unshift({
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

  // --- Lockfile poisoning: poetry.lock sha256 ≠ PyPI sha256 ---
  if (ref.integrity && registryIntegrity && ref.integrity !== registryIntegrity) {
    findings.unshift({
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

  const scored = scoreFindings(findings, provenance, opts.trust);
  const risk = computeRisk(scored, [], provenance);

  return {
    name: ref.name,
    version: ref.version,
    packageManager: "pip",
    source: {
      type: "registry",
      resolved: tarballUrl,
      integrity: ref.integrity,
      integrityVerified,
    },
    provenance,
    lifecycleScripts: pythonHooks,
    binaryDownload: null,
    advisories: [],
    findings: scored,
    risk,
  };
}

export async function runPipCheck(packageSpec: string, opts: ScanOptions): Promise<number> {
  // Parse "requests@2.28.0" or "requests" (latest)
  const atIdx = packageSpec.lastIndexOf("@");
  let name: string;
  let version: string;
  if (atIdx > 0) {
    name = packageSpec.slice(0, atIdx);
    version = packageSpec.slice(atIdx + 1);
  } else {
    name = packageSpec;
    version = "latest";
  }

  if (version === "latest") {
    const resolved = await resolvePyPILatestVersion(name);
    if (!resolved) {
      process.stderr.write(`pip: package "${name}" not found on PyPI\n`);
      return 2;
    }
    version = resolved;
  }

  const cache = new DiskCache(opts.cacheDir);
  const ref: PackageRef = { name, version, resolved: "", integrity: null };
  const report = await scanPipRef(ref, opts, cache);
  if (!report) {
    const project = buildProjectReport([], "check", false, opts.minRisk);
    await writeOutput(project, opts);
    return 0;
  }

  const project = buildProjectReport([report], "check", opts.onlyFlagged, opts.minRisk);
  await writeOutput(project, opts);
  return project.flaggedPackages > 0 ? 1 : 0;
}

export async function runPipScan(dir: string, opts: ScanOptions): Promise<number> {
  const projectDir = resolve(dir);

  const parsed = await parsePipLockfile(projectDir);
  if (!parsed) {
    process.stderr.write("No pip lockfile found (requirements.txt or poetry.lock)\n");
    return 2;
  }

  const { refs } = parsed;
  const cache = new DiskCache(opts.cacheDir);
  const limit = pLimit(opts.concurrency);
  let completed = 0;
  const total = refs.length;
  const reports: PackageReport[] = [];

  await Promise.all(
    refs.map((ref) =>
      limit(async () => {
        try {
          const report = await scanPipRef(ref, opts, cache);
          if (report) reports.push(report);
        } catch (err) {
          if (opts.verbose) {
            process.stderr.write(`\nError scanning ${ref.name}@${ref.version}: ${String(err)}\n`);
          }
        } finally {
          completed++;
          renderProgress(completed, total, `${ref.name}@${ref.version} (pip)`);
        }
      })
    )
  );

  clearProgress();
  const project = buildProjectReport(reports, "scan", opts.onlyFlagged, opts.minRisk);
  await writeOutput(project, opts);
  return project.flaggedPackages > 0 ? 1 : 0;
}

export async function scanSinglePackage(
  name: string,
  version: string,
  opts: ScanOptions
): Promise<import("./types.js").PackageReport | null> {
  setRegistry(opts.registry);
  setRequestTimeout(opts.timeout);
  setRegistryConcurrency(opts.concurrency);
  const cache = new DiskCache(opts.cacheDir);
  const ref: PackageRef = { name, version, resolved: "", integrity: null };
  // Resolve the tarball URL from registry
  const { fetchVersionMeta } = await import("./registry/client.js");
  const meta = await fetchVersionMeta(name, version);
  ref.resolved = meta.tarballUrl;
  ref.integrity = meta.integrity;
  const advisoryMap = await fetchAdvisories([ref], opts.registry);
  return scanRef(ref, opts, cache, process.cwd(), advisoryMap);
}

export async function runScan(dir: string, opts: ScanOptions): Promise<number> {
  const projectDir = resolve(dir);
  setRegistry(opts.registry);
  setRequestTimeout(opts.timeout);
  setRegistryConcurrency(opts.concurrency);

  const fileConfig = await loadConfig(projectDir);
  const mergedOpts: ScanOptions = {
    ...opts,
    trust: opts.trust ?? fileConfig.trust,
    minRisk: opts.minRisk ?? fileConfig.minRisk,
  };

  // Auto-detect pip lockfiles and run Python scan alongside npm scan
  const pipFound = await hasPipLockfile(projectDir);
  if (pipFound) {
    process.stderr.write("Detected pip lockfile (requirements.txt / poetry.lock) — running Python scan\n");
    const pipExit = await runPipScan(projectDir, mergedOpts);
    // If only pip lockfile (no npm lockfile), return pip exit code
    try {
      await import("node:fs/promises").then((m) => m.access(join(projectDir, "package-lock.json")));
    } catch {
      try {
        await import("node:fs/promises").then((m) => m.access(join(projectDir, "npm-shrinkwrap.json")));
      } catch {
        return pipExit;
      }
    }
  }

  const cache = new DiskCache(mergedOpts.cacheDir);
  const { refs, lockfileDir } = await parseLockfile(projectDir);

  // Notify when the lockfile was found in a parent workspace root
  if (lockfileDir !== projectDir) {
    const wsPatterns = await readWorkspacePatterns(lockfileDir);
    const wsNote = wsPatterns.length > 0
      ? ` (workspace: ${wsPatterns.join(", ")})`
      : "";
    process.stderr.write(`Using workspace root lockfile: ${lockfileDir}${wsNote}\n`);
  }

  // Batch advisory lookup — one request for all packages before the scan loop
  const advisoryMap = await fetchAdvisories(refs, mergedOpts.registry);

  const limit = pLimit(opts.concurrency);
  let completed = 0;
  const total = refs.length;

  const reports: PackageReport[] = [];

  await Promise.all(
    refs.map((ref) =>
      limit(async () => {
        try {
          const report = await scanRef(ref, mergedOpts, cache, lockfileDir, advisoryMap);
          if (report) reports.push(report);
        } catch (err) {
          if (mergedOpts.verbose) {
            process.stderr.write(`\nError scanning ${ref.name}@${ref.version}: ${String(err)}\n`);
          }
        } finally {
          completed++;
          renderProgress(completed, total, `${ref.name}@${ref.version}`);
        }
      })
    )
  );

  clearProgress();

  const project = buildProjectReport(reports, "scan", mergedOpts.onlyFlagged, mergedOpts.minRisk);
  await writeOutput(project, mergedOpts);

  return project.flaggedPackages > 0 ? 1 : 0;
}

export async function runCheck(
  packageSpec: string,
  opts: ScanOptions
): Promise<number> {
  setRegistry(opts.registry);
  setRequestTimeout(opts.timeout);
  setRegistryConcurrency(opts.concurrency);

  const [name, version = "latest"] = packageSpec.split("@").filter(Boolean) as [string, string?];
  const resolvedName = packageSpec.startsWith("@")
    ? `@${packageSpec.slice(1).split("@")[0]}`
    : name ?? packageSpec;
  const resolvedVersion = packageSpec.startsWith("@")
    ? (packageSpec.slice(1).split("@")[1] ?? "latest")
    : version;

  const fileConfig = await loadConfig(process.cwd());
  const mergedOpts: ScanOptions = {
    ...opts,
    trust: opts.trust ?? fileConfig.trust,
    minRisk: opts.minRisk ?? fileConfig.minRisk,
  };

  const cache = new DiskCache(mergedOpts.cacheDir);
  const refs = await resolveTree(resolvedName, resolvedVersion, mergedOpts.depth);

  const advisoryMap = await fetchAdvisories(refs, mergedOpts.registry);

  const limit = pLimit(opts.concurrency);
  let completed = 0;
  const total = refs.length;
  const reports: PackageReport[] = [];

  await Promise.all(
    refs.map((ref) =>
      limit(async () => {
        try {
          const report = await scanRef(ref, mergedOpts, cache, process.cwd(), advisoryMap);
          if (report) reports.push(report);
        } catch (err) {
          if (mergedOpts.verbose) {
            process.stderr.write(`\nError scanning ${ref.name}@${ref.version}: ${String(err)}\n`);
          }
        } finally {
          completed++;
          renderProgress(completed, total, `${ref.name}@${ref.version}`);
        }
      })
    )
  );

  clearProgress();

  const project = buildProjectReport(reports, "check", mergedOpts.onlyFlagged, mergedOpts.minRisk);
  await writeOutput(project, mergedOpts);

  return project.flaggedPackages > 0 ? 1 : 0;
}

async function writeOutput(
  report: ReturnType<typeof buildProjectReport>,
  opts: ScanOptions
): Promise<void> {
  // --output <dir>: write report.json + results.sarif to directory,
  // and still render human output to stdout.
  if (opts.outputDir) {
    await mkdir(opts.outputDir, { recursive: true });
    const jsonPath = join(opts.outputDir, "report.json");
    const sarifPath = join(opts.outputDir, "results.sarif");
    await Promise.all([
      writeFile(jsonPath, toJson(report), "utf-8"),
      writeFile(sarifPath, toSarif(report), "utf-8"),
    ]);
    process.stderr.write(`Reports written to ${opts.outputDir}/\n`);
  }

  // stdout format: --sarif > --json > human (mutually exclusive stdout modes)
  if (opts.sarif) {
    process.stdout.write(toSarif(report) + "\n");
  } else if (opts.json) {
    process.stdout.write(toJson(report) + "\n");
  } else {
    renderReport(report, opts.onlyFlagged);
  }
}

function buildWorkflow(minRisk: string, noFail: boolean): string {
  const scanLine = noFail
    ? `npm-prescripts scan --output-dir . --min-risk ${minRisk} || true`
    : `npm-prescripts scan --output-dir . --min-risk ${minRisk}`;

  return `# Generated by npm-prescripts init-ci
# Scans the npm lockfile for malicious lifecycle scripts and known vulnerabilities.
# Results appear in the GitHub Security tab (pull_request summary + Code Scanning alerts).
#
# To adjust the failure threshold: change --min-risk below.
# Valid values: low | medium | high | critical
# To never fail the workflow, add --no-fail to init-ci or set || true on the scan step.

name: npm-prescripts

on:
  pull_request:
  push:
    branches:
      - main

permissions:
  contents: read
  security-events: write   # required for SARIF upload

jobs:
  scan:
    name: Scan dependencies
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install npm-prescripts
        run: npm install -g npm-prescripts

      - name: Scan lockfile
        run: ${scanLine}

      - name: Upload SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()   # upload even when the scan step fails
        with:
          sarif_file: results.sarif
`;
}

export async function runInitCi(
  dir: string,
  minRisk: string,
  noFail: boolean,
  force: boolean
): Promise<number> {
  const projectDir = resolve(dir);
  const workflowDir = join(projectDir, ".github", "workflows");
  const workflowPath = join(workflowDir, "npm-prescripts.yml");

  const NO_COLOR = process.env["NO_COLOR"] !== undefined || !process.stdout.isTTY;
  const RESET = "\x1b[0m";
  const BOLD = "\x1b[1m";
  const GREEN = "\x1b[32m";
  const YELLOW = "\x1b[33m";
  const DIM = "\x1b[2m";
  const cc = (col: string, t: string) => NO_COLOR ? t : `${col}${t}${RESET}`;

  // Check if file already exists
  if (!force) {
    try {
      await access(workflowPath);
      process.stderr.write(
        `${cc(YELLOW, "File already exists:")} ${workflowPath}\n` +
        `Use --force to overwrite.\n`
      );
      return 1;
    } catch {
      // doesn't exist — proceed
    }
  }

  await mkdir(workflowDir, { recursive: true });
  await writeFile(workflowPath, buildWorkflow(minRisk, noFail), "utf-8");

  process.stdout.write(
    `${cc(GREEN, "✓")} ${cc(BOLD, workflowPath)}\n\n` +
    `  Triggers on: pull_request, push to main\n` +
    `  Fails workflow when risk ≥ ${cc(BOLD, minRisk)}\n` +
    `  Uploads SARIF to GitHub Security tab\n\n` +
    `  ${cc(DIM, "Commit and push to activate:")}\n` +
    `  git add ${workflowPath}\n` +
    `  git commit -m "Add npm-prescripts CI workflow"\n`
  );

  return 0;
}

interface CliScanOptions {
  severity: Severity;
  minRisk: RiskLevel;
  onlyFlagged: boolean;
  concurrency: string;
  registry: string;
  noCache: boolean;
  cacheDir?: string;
  depth: string;
  timeout: string;
  verbose: boolean;
  json: boolean;
  sarif: boolean;
  outputDir?: string;
  apiUrl?: string;
}

function parseOpts(raw: CliScanOptions): ScanOptions {
  return {
    severity: raw.severity,
    minRisk: raw.minRisk ?? "low",
    onlyFlagged: raw.onlyFlagged,
    concurrency: parseInt(raw.concurrency, 10),
    registry: raw.registry,
    noCache: raw.noCache,
    cacheDir: raw.cacheDir ?? null,
    depth: parseInt(raw.depth, 10),
    timeout: parseInt(raw.timeout, 10),
    verbose: raw.verbose,
    json: raw.json,
    sarif: raw.sarif,
    outputDir: raw.outputDir ?? null,
    apiUrl: raw.apiUrl ?? null,
    trust: { signed: true, attested: true, minWeeklyDownloads: 10_000, minVersions: 10 },
  };
}

interface FixCandidate {
  name: string;
  currentVersion: string;
  patchedVersions: string;
  cves: string[];
  advisoryTitle: string;
  isDirect: boolean;
}

async function readDirectDeps(projectDir: string): Promise<Set<string>> {
  try {
    const raw = await readFile(join(projectDir, "package.json"), "utf-8");
    const pkg = JSON.parse(raw) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
    };
    const names = new Set<string>();
    for (const key of ["dependencies", "devDependencies", "optionalDependencies"] as const) {
      for (const name of Object.keys(pkg[key] ?? {})) names.add(name);
    }
    return names;
  } catch {
    return new Set();
  }
}

function spawnNpmInstall(args: string[], cwd: string): Promise<number> {
  return new Promise((resolve) => {
    const child = spawn("npm", ["install", ...args], {
      cwd,
      stdio: "inherit",
      shell: process.platform === "win32",
    });
    child.on("close", (code) => resolve(code ?? 1));
  });
}

export async function runFix(dir: string, opts: ScanOptions, apply: boolean): Promise<number> {
  const projectDir = resolve(dir);
  setRegistry(opts.registry);
  setRequestTimeout(opts.timeout);
  setRegistryConcurrency(opts.concurrency);

  const fileConfig = await loadConfig(projectDir);
  const mergedOpts: ScanOptions = {
    ...opts,
    trust: opts.trust ?? fileConfig.trust,
    minRisk: opts.minRisk ?? fileConfig.minRisk,
  };

  const cache = new DiskCache(mergedOpts.cacheDir);
  const { refs, lockfileDir } = await parseLockfile(projectDir);
  const directDeps = await readDirectDeps(lockfileDir);
  const advisoryMap = await fetchAdvisories(refs, mergedOpts.registry);

  const limit = pLimit(opts.concurrency);
  let completed = 0;
  const total = refs.length;
  const reports: PackageReport[] = [];

  await Promise.all(
    refs.map((ref) =>
      limit(async () => {
        try {
          const report = await scanRef(ref, mergedOpts, cache, projectDir, advisoryMap);
          if (report) reports.push(report);
        } catch {
          // best-effort
        } finally {
          completed++;
          renderProgress(completed, total, `${ref.name}@${ref.version}`);
        }
      })
    )
  );

  clearProgress();

  // Collect one fix candidate per package (highest severity advisory with a patch)
  const candidateMap = new Map<string, FixCandidate>();
  for (const report of reports) {
    for (const advisory of report.advisories) {
      if (!advisory.patchedVersions) continue;
      const existing = candidateMap.get(report.name);
      const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
      if (existing && (severityOrder[existing.cves[0] ?? ""] ?? 0) >= (severityOrder[advisory.severity] ?? 0)) continue;
      candidateMap.set(report.name, {
        name: report.name,
        currentVersion: report.version,
        patchedVersions: advisory.patchedVersions,
        cves: advisory.cves,
        advisoryTitle: advisory.title,
        isDirect: directDeps.has(report.name),
      });
    }
  }

  const candidates = Array.from(candidateMap.values()).sort((a, b) =>
    Number(b.isDirect) - Number(a.isDirect) || a.name.localeCompare(b.name)
  );

  if (candidates.length === 0) {
    process.stdout.write("No advisory findings with available patches.\n");
    return 0;
  }

  const RESET = "\x1b[0m";
  const BOLD = "\x1b[1m";
  const RED = "\x1b[31m";
  const GREEN = "\x1b[32m";
  const YELLOW = "\x1b[33m";
  const DIM = "\x1b[2m";
  const NO_COLOR = process.env["NO_COLOR"] !== undefined || !process.stdout.isTTY;
  const cc = (col: string, t: string) => NO_COLOR ? t : `${col}${t}${RESET}`;

  process.stdout.write(`\n${cc(BOLD, "Advisory fixes available:")}\n\n`);

  for (const c of candidates) {
    const tag = c.isDirect ? cc(YELLOW, "[direct]") : cc(DIM, "[transitive]");
    const cveStr = c.cves.length > 0 ? cc(DIM, `  ${c.cves.join(", ")}`) : "";
    process.stdout.write(
      `  ${tag} ${cc(BOLD, c.name)}  ${cc(DIM, c.currentVersion)} → ${cc(GREEN, c.patchedVersions)}\n` +
      `         ${cc(DIM, c.advisoryTitle)}${cveStr}\n`
    );
  }

  if (!apply) {
    process.stdout.write(
      `\n${cc(DIM, `Run with --apply to install fixes (${candidates.length} package${candidates.length === 1 ? "" : "s"})`)}\n`
    );
    return candidates.length > 0 ? 1 : 0;
  }

  // Build install args: name@"patchedVersions" for each candidate
  const installArgs = candidates.map((c) => `${c.name}@${c.patchedVersions}`);
  process.stdout.write(`\n${cc(BOLD, "Running:")} npm install ${installArgs.join(" ")}\n\n`);

  const code = await spawnNpmInstall(installArgs, lockfileDir);
  if (code !== 0) {
    process.stderr.write(`npm install exited with code ${code}\n`);
    return 2;
  }

  process.stdout.write(`\n${cc(GREEN, `✓ Applied ${candidates.length} fix${candidates.length === 1 ? "" : "es"}`)}\n`);
  return 0;
}

function buildHookScript(minRisk: string): string {
  return `#!/bin/sh
# npm-prescripts pre-commit hook
# Scans the lockfile when package-lock.json or npm-shrinkwrap.json is staged.
# Generated by: npm-prescripts init-hooks
#
# To bypass in an emergency: git commit --no-verify
# To reconfigure: npm-prescripts init-hooks --min-risk <level> --force

STAGED=$(git diff --cached --name-only 2>/dev/null | grep -E '(^|/)package-lock\\.json$|(^|/)npm-shrinkwrap\\.json$')

if [ -z "$STAGED" ]; then
  exit 0
fi

echo "npm-prescripts: lockfile changed — scanning dependencies..."

# Resolve npm-prescripts binary — never use npx (downloads from registry without scanning)
if command -v npm-prescripts >/dev/null 2>&1; then
  PRESCRIPTS_CMD="npm-prescripts"
elif [ -x "./node_modules/.bin/npm-prescripts" ]; then
  PRESCRIPTS_CMD="./node_modules/.bin/npm-prescripts"
else
  echo ""
  echo "npm-prescripts: binary not found. Cannot scan dependencies before committing."
  echo "  Install globally:     npm install -g npm-prescripts"
  echo "  Or as devDependency:  npm install --save-dev npm-prescripts"
  echo "  Do not use npx — it downloads from the registry without scanning."
  echo "  To bypass this check: git commit --no-verify"
  exit 1
fi

$PRESCRIPTS_CMD scan --min-risk ${minRisk} --only-flagged
STATUS=$?

if [ $STATUS -ne 0 ]; then
  echo ""
  echo "npm-prescripts: findings at risk >= ${minRisk} detected in staged lockfile."
  echo "  Review the findings above before committing."
  echo "  To bypass: git commit --no-verify"
  exit 1
fi

exit 0
`;
}

export async function runInitHooks(
  dir: string,
  minRisk: string,
  force: boolean
): Promise<number> {
  const projectDir = resolve(dir);
  const gitDir = join(projectDir, ".git");
  const hooksDir = join(gitDir, "hooks");
  const hookPath = join(hooksDir, "pre-commit");

  const NO_COLOR = process.env["NO_COLOR"] !== undefined || !process.stdout.isTTY;
  const RESET = "\x1b[0m";
  const BOLD = "\x1b[1m";
  const GREEN = "\x1b[32m";
  const YELLOW = "\x1b[33m";
  const DIM = "\x1b[2m";
  const cc = (col: string, t: string) => NO_COLOR ? t : `${col}${t}${RESET}`;

  // Verify this is a git repo
  try {
    await access(gitDir);
  } catch {
    process.stderr.write(`No .git directory found at ${projectDir}. Run from a git repository root.\n`);
    return 1;
  }

  // Check if hook already exists
  if (!force) {
    try {
      await access(hookPath);
      process.stderr.write(
        `${cc(YELLOW, "Hook already exists:")} ${hookPath}\n` +
        `Use --force to overwrite.\n`
      );
      return 1;
    } catch {
      // doesn't exist — proceed
    }
  }

  await mkdir(hooksDir, { recursive: true });
  const script = buildHookScript(minRisk);
  await writeFile(hookPath, script, { encoding: "utf-8", mode: 0o755 });

  process.stdout.write(
    `${cc(GREEN, "✓")} ${cc(BOLD, hookPath)}\n\n` +
    `  Triggers on: git commit (when lockfile is staged)\n` +
    `  Blocks commit when risk ≥ ${cc(BOLD, minRisk)}\n` +
    `  Bypass: ${cc(DIM, "git commit --no-verify")}\n\n` +
    `  ${cc(DIM, "This hook runs before npm install executes any lifecycle scripts.")}\n` +
    `  ${cc(DIM, "Pair with init-ci for full enforcement (local + CI).")}\n`
  );

  return 0;
}

export function buildProgram(): Command {
  const program = new Command();

  program
    .name("npm-prescripts")
    .description(
      "Static lifecycle script scanner for npm dependencies.\n" +
      "Surfaces inbound threats in package install scripts — triage tool for humans and LLM agents."
    )
    .version("0.1.0");

  const sharedOptions = (cmd: Command): Command =>
    cmd
      .option("-j, --json", "Output JSON report to stdout", false)
      .option("--sarif", "Output SARIF 2.1.0 report (for GitHub Actions upload-sarif)", false)
      .option("-o, --output-dir <dir>", "Write report.json + results.sarif to directory (human output still goes to stdout)")
      .option(
        "--min-risk <level>",
        "Minimum risk level to surface: verified|low|medium|high|critical",
        "low"
      )
      .option(
        "--severity <level>",
        "Minimum severity: low|medium|high|critical",
        "medium"
      )
      .option("--only-flagged", "Suppress packages with no findings", false)
      .option("--no-cache", "Skip cache reads")
      .option("--cache-dir <path>", "Override cache directory")
      .option("--concurrency <n>", "Max simultaneous registry requests", "5")
      .option(
        "--registry <url>",
        "npm registry URL",
        "https://registry.npmjs.org"
      )
      .option("--timeout <ms>", "Per-request timeout in milliseconds", "30000")
      .option("--api-url <url>", "Hosted npm-prescripts-api URL (optional)")
      .option("-v, --verbose", "Debug output to stderr", false);

  sharedOptions(
    program
      .command("scan [dir]")
      .description("Scan all packages in a project lockfile (default: cwd)")
  ).action(async (dir: string | undefined, opts: CliScanOptions) => {
    try {
      const code = await runScan(dir ?? ".", parseOpts(opts));
      process.exit(code);
    } catch (err) {
      process.stderr.write(`Error: ${String(err)}\n`);
      process.exit(2);
    }
  });

  sharedOptions(
    program
      .command("check <package>")
      .description(
        "Scan a package before installing (e.g. check express@4.18.2)\n" +
        "Use --pm pip to scan a PyPI package (e.g. check requests@2.28.0 --pm pip)"
      )
      .option("--depth <n>", "Max dependency resolution depth", "5")
      .option("--pm <manager>", "Package manager: npm|pip (default: npm)", "npm")
  ).action(async (pkg: string, opts: CliScanOptions & { pm: string }) => {
    try {
      if (opts.pm === "pip") {
        const code = await runPipCheck(pkg, parseOpts(opts));
        process.exit(code);
      } else {
        const code = await runCheck(pkg, parseOpts(opts));
        process.exit(code);
      }
    } catch (err) {
      process.stderr.write(`Error: ${String(err)}\n`);
      process.exit(2);
    }
  });

  program
    .command("fix [dir]")
    .description(
      "Show advisory-driven upgrades for a project lockfile (default: cwd).\n" +
      "Use --apply to run npm install with the patched versions."
    )
    .option("--apply", "Apply fixes by running npm install", false)
    .option("--no-cache", "Skip cache reads")
    .option("--cache-dir <path>", "Override cache directory")
    .option("--concurrency <n>", "Max simultaneous registry requests", "5")
    .option("--registry <url>", "npm registry URL", "https://registry.npmjs.org")
    .option("--timeout <ms>", "Per-request timeout in milliseconds", "30000")
    .action(async (dir: string | undefined, opts: { apply: boolean } & Pick<CliScanOptions, "concurrency" | "registry" | "noCache" | "cacheDir" | "timeout">) => {
      try {
        const scanOpts = parseOpts({
          severity: "low",
          minRisk: "low",
          onlyFlagged: false,
          json: false,
          sarif: false,
          verbose: false,
          depth: "5",
          ...opts,
        });
        const code = await runFix(dir ?? ".", scanOpts, opts.apply);
        process.exit(code);
      } catch (err) {
        process.stderr.write(`Error: ${String(err)}\n`);
        process.exit(2);
      }
    });

  program
    .command("init-ci [dir]")
    .description(
      "Write a GitHub Actions workflow that scans the lockfile on every PR.\n" +
      "Outputs SARIF to the GitHub Security tab. Default: cwd."
    )
    .option(
      "--min-risk <level>",
      "Minimum risk level that fails the workflow: low|medium|high|critical",
      "medium"
    )
    .option("--no-fail", "Never fail the workflow — always upload SARIF but exit 0", false)
    .option("--force", "Overwrite existing workflow file", false)
    .action(async (
      dir: string | undefined,
      opts: { minRisk: string; noFail: boolean; force: boolean }
    ) => {
      try {
        const code = await runInitCi(dir ?? ".", opts.minRisk, opts.noFail, opts.force);
        process.exit(code);
      } catch (err) {
        process.stderr.write(`Error: ${String(err)}\n`);
        process.exit(2);
      }
    });

  program
    .command("init-hooks [dir]")
    .description(
      "Install a git pre-commit hook that scans when the lockfile changes.\n" +
      "Blocks the commit if findings meet or exceed --min-risk. Default: cwd."
    )
    .option(
      "--min-risk <level>",
      "Risk level that blocks the commit: low|medium|high|critical",
      "medium"
    )
    .option("--force", "Overwrite existing pre-commit hook", false)
    .action(async (
      dir: string | undefined,
      opts: { minRisk: string; force: boolean }
    ) => {
      try {
        const code = await runInitHooks(dir ?? ".", opts.minRisk, opts.force);
        process.exit(code);
      } catch (err) {
        process.stderr.write(`Error: ${String(err)}\n`);
        process.exit(2);
      }
    });

  return program;
}

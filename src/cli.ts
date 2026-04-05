import { Command } from "commander";
import pLimit from "p-limit";
import { parseLockfile } from "./lockfile/parser.js";
import { fetchAndExtract } from "./extractor/index.js";
import { fetchProvenance } from "./registry/metadata.js";
import { extractLifecycleScripts, hasLifecycleScripts, extractBinaryField } from "./analyzer/lifecycle.js";
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
import type { PackageReport, PackageRef, ScanOptions, Severity, Finding, AdvisoryMatch, LifecycleScripts } from "./types.js";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";

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

  if (!opts.noCache) {
    const cached = await cache.read(ref.name, ref.integrity, ref.version);
    if (cached) {
      packageJson = cached.extracted.packageJson;
      fileMap = cached.extracted.fileMap;
      sourceType = cached.meta.sourceType;
      integrityVerified = ref.integrity !== null;
    } else {
      const result = await fetchAndExtract(ref, projectDir, opts.registry);
      packageJson = result.extracted.packageJson;
      fileMap = result.extracted.fileMap;
      sourceType = result.sourceType;
      integrityVerified = result.integrityVerified;
      await cache.write(ref.name, ref.version, ref.integrity, sourceType, result.extracted);
    }
  } else {
    const result = await fetchAndExtract(ref, projectDir, opts.registry);
    packageJson = result.extracted.packageJson;
    fileMap = result.extracted.fileMap;
    sourceType = result.sourceType;
    integrityVerified = result.integrityVerified;
  }

  const lifecycleScripts = extractLifecycleScripts(packageJson);
  const binaryDownload = extractBinaryField(packageJson);
  const advisories = advisoryMap.get(ref.name) ?? [];

  if (!hasLifecycleScripts(lifecycleScripts) && !binaryDownload && advisories.length === 0) {
    return null; // nothing to report
  }

  const { provenance, registryManifestScripts } = await fetchProvenance(
    ref.name,
    ref.version,
    opts.registry
  );
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
      pattern: "hash mismatch",
      excerpt: {
        _warning: "UNTRUSTED THIRD-PARTY CONTENT",
        lines: `Expected: ${ref.integrity}\nActual hash did not match.`,
      },
    });
  }

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
    findings,
  };
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

  const cache = new DiskCache(opts.cacheDir);
  const refs = await parseLockfile(projectDir);

  // Batch advisory lookup — one request for all packages before the scan loop
  const advisoryMap = await fetchAdvisories(refs, opts.registry);

  const limit = pLimit(opts.concurrency);
  let completed = 0;
  const total = refs.length;

  const reports: PackageReport[] = [];

  await Promise.all(
    refs.map((ref) =>
      limit(async () => {
        try {
          const report = await scanRef(ref, opts, cache, projectDir, advisoryMap);
          if (report) reports.push(report);
        } catch (err) {
          if (opts.verbose) {
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

  const project = buildProjectReport(reports, "scan", opts.onlyFlagged);
  await writeOutput(project, opts);

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

  const cache = new DiskCache(opts.cacheDir);
  const refs = await resolveTree(resolvedName, resolvedVersion, opts.depth);

  const advisoryMap = await fetchAdvisories(refs, opts.registry);

  const limit = pLimit(opts.concurrency);
  let completed = 0;
  const total = refs.length;
  const reports: PackageReport[] = [];

  await Promise.all(
    refs.map((ref) =>
      limit(async () => {
        try {
          const report = await scanRef(ref, opts, cache, process.cwd(), advisoryMap);
          if (report) reports.push(report);
        } catch (err) {
          if (opts.verbose) {
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

  const project = buildProjectReport(reports, "check", opts.onlyFlagged);
  await writeOutput(project, opts);

  return project.flaggedPackages > 0 ? 1 : 0;
}

async function writeOutput(
  report: ReturnType<typeof buildProjectReport>,
  opts: ScanOptions
): Promise<void> {
  const json = toJson(report);

  if (opts.onlyFlagged && report.flaggedPackages === 0) {
    if (!opts.onlyFlagged) {
      process.stdout.write("No findings.\n");
    }
    return;
  }

  const sarifOutput = opts.sarif ? toSarif(report) : null;
  const content = sarifOutput ?? json;

  if (opts.output) {
    await writeFile(opts.output, content, "utf-8");
    process.stderr.write(`Report written to ${opts.output}\n`);
  } else if (opts.sarif) {
    process.stdout.write(content + "\n");
  } else if (opts.json) {
    process.stdout.write(json + "\n");
  } else {
    renderReport(report, opts.onlyFlagged);
  }
}

interface CliScanOptions {
  severity: Severity;
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
  output?: string;
  apiUrl?: string;
}

function parseOpts(raw: CliScanOptions): ScanOptions {
  return {
    severity: raw.severity,
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
    output: raw.output ?? null,
    apiUrl: raw.apiUrl ?? null,
  };
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
      .option("-o, --output <file>", "Write report to file (format determined by --json/--sarif)")
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
      .description("Scan a package before installing (e.g. check express@4.18.2)")
      .option("--depth <n>", "Max dependency resolution depth", "5")
  ).action(async (pkg: string, opts: CliScanOptions) => {
    try {
      const code = await runCheck(pkg, parseOpts(opts));
      process.exit(code);
    } catch (err) {
      process.stderr.write(`Error: ${String(err)}\n`);
      process.exit(2);
    }
  });

  return program;
}

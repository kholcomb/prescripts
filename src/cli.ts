import { Command } from "commander";
import pLimit from "p-limit";
import { parseLockfile } from "./lockfile/parser.js";
import { readWorkspacePatterns } from "./lockfile/workspace.js";
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
import { scoreFindings, applyBinaryDownloaderCluster, computeRisk } from "./analyzer/confidence.js";
import { loadConfig } from "./config.js";
import type { PackageReport, PackageRef, ScanOptions, Severity, Finding, AdvisoryMatch, LifecycleScripts, RiskLevel } from "./types.js";
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
  const advisories = advisoryMap.get(`${ref.name}@${ref.version}`) ?? [];

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

function buildWorkflow(minRisk: string, noFail: boolean): string {
  const scanLine = noFail
    ? `npm-prescripts scan --sarif -o results.sarif --min-risk ${minRisk} || true`
    : `npm-prescripts scan --sarif -o results.sarif --min-risk ${minRisk}`;

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
  output?: string;
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
    output: raw.output ?? null,
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

  return program;
}

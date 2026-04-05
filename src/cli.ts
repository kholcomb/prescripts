import { Command } from "commander";
import pLimit from "p-limit";
import { loadConfig } from "./config.js";
import { DiskCache } from "./cache/disk-cache.js";
import { buildProjectReport, toJson } from "./report/json-report.js";
import { renderReport, renderProgress, clearProgress } from "./report/human.js";
import { toSarif } from "./report/sarif.js";
import { parseLockfile } from "./lockfile/parser.js";
import { detectEcosystems, scanAny, npmPlugin, getPluginByName } from "./ecosystem/index.js";
import { runLocalScanners } from "./scanner/local.js";
import type { EcosystemPlugin } from "./ecosystem/types.js";
import type {
  PackageReport,
  PackageRef,
  ScanOptions,
  Severity,
  AdvisoryMatch,
  RiskLevel,
} from "./types.js";
import { writeFile, readFile, mkdir, access } from "node:fs/promises";
import { resolve, join } from "node:path";
import { spawn } from "node:child_process";

// ── Generic scan helpers ──────────────────────────────────────────────────────

/**
 * Runs the scan loop for a single ecosystem plugin against a set of refs.
 * Handles concurrency, progress output, and error reporting.
 */
async function runEcosystemRefs(
  plugin: EcosystemPlugin,
  refs: PackageRef[],
  opts: ScanOptions,
  cache: DiskCache,
  projectDir: string,
  advisoryMap: Map<string, AdvisoryMatch[]>
): Promise<PackageReport[]> {
  const limit = pLimit(opts.concurrency);
  let completed = 0;
  const total = refs.length;
  const reports: PackageReport[] = [];
  const pmLabel = plugin.packageManager !== "npm" ? ` [${plugin.packageManager}]` : "";

  await Promise.all(
    refs.map((ref) =>
      limit(async () => {
        try {
          const report = await scanAny(ref, plugin, opts, cache, projectDir, advisoryMap);
          if (report) reports.push(report);
        } catch (err) {
          if (opts.verbose) {
            process.stderr.write(
              `\nError scanning ${ref.name}@${ref.version}: ${String(err)}\n`
            );
          }
        } finally {
          completed++;
          renderProgress(completed, total, `${ref.name}@${ref.version}${pmLabel}`);
        }
      })
    )
  );

  clearProgress();
  return reports;
}

// ── Primary scan / check entrypoints ─────────────────────────────────────────

export async function runScan(dir: string, opts: ScanOptions): Promise<number> {
  const projectDir = resolve(dir);

  const fileConfig = await loadConfig(projectDir);
  const mergedOpts: ScanOptions = {
    ...opts,
    trust: opts.trust ?? fileConfig.trust,
    minRisk: opts.minRisk ?? fileConfig.minRisk,
  };

  const plugins = await detectEcosystems(projectDir);
  if (plugins.length === 0) {
    process.stderr.write(
      "No supported lockfile found.\n" +
      "Supported: package-lock.json, uv.lock, poetry.lock, requirements*.txt, Cargo.lock, Gemfile.lock\n"
    );
    return 2;
  }

  const allReports: PackageReport[] = [];

  for (const plugin of plugins) {
    plugin.init(mergedOpts);

    if (plugins.length > 1) {
      process.stderr.write(`Scanning ${plugin.packageManager} packages...\n`);
    }

    const parsed = await plugin.parseLockfile(projectDir);
    if (!parsed) continue;

    const { refs, lockfileDir } = parsed;
    const cache = new DiskCache(mergedOpts.cacheDir);
    const advisoryMap = await plugin.fetchAdvisories(refs, mergedOpts);
    const reports = await runEcosystemRefs(plugin, refs, mergedOpts, cache, lockfileDir, advisoryMap);
    allReports.push(...reports);
  }

  // Local file scanners (GitHub Actions, git submodules) — no registry, no packages
  const localReports = await runLocalScanners(projectDir, mergedOpts);
  allReports.push(...localReports);

  const project = buildProjectReport(allReports, "scan", mergedOpts.onlyFlagged, mergedOpts.minRisk);
  await writeOutput(project, mergedOpts);
  return project.flaggedPackages > 0 ? 1 : 0;
}

/**
 * Scans a package spec before installing.
 *
 * @param pm - "npm" (default) or "pip"; selects the ecosystem plugin.
 *             The mcp.ts server calls this without `pm`, defaulting to npm.
 */
export async function runCheck(
  packageSpec: string,
  opts: ScanOptions,
  pm?: string
): Promise<number> {
  const plugin = (pm ? getPluginByName(pm) : null) ?? npmPlugin;
  plugin.init(opts);

  const fileConfig = await loadConfig(process.cwd());
  const mergedOpts: ScanOptions = {
    ...opts,
    trust: opts.trust ?? fileConfig.trust,
    minRisk: opts.minRisk ?? fileConfig.minRisk,
  };

  const refs = await plugin.resolveCheckSpec(packageSpec, mergedOpts);
  if (!refs || refs.length === 0) {
    process.stderr.write(`${plugin.packageManager}: package "${packageSpec}" not found\n`);
    return 2;
  }

  const cache = new DiskCache(mergedOpts.cacheDir);
  const advisoryMap = await plugin.fetchAdvisories(refs, mergedOpts);
  const reports = await runEcosystemRefs(plugin, refs, mergedOpts, cache, process.cwd(), advisoryMap);

  const project = buildProjectReport(reports, "check", mergedOpts.onlyFlagged, mergedOpts.minRisk);
  await writeOutput(project, mergedOpts);
  return project.flaggedPackages > 0 ? 1 : 0;
}

/**
 * Scans a single npm package by name+version.
 * Used by the MCP compare_versions tool.
 */
export async function scanSinglePackage(
  name: string,
  version: string,
  opts: ScanOptions
): Promise<PackageReport | null> {
  npmPlugin.init(opts);
  const cache = new DiskCache(opts.cacheDir);
  const ref: PackageRef = { name, version, resolved: "", integrity: null };
  // Resolve the tarball URL and integrity from the registry
  const { fetchVersionMeta } = await import("./registry/client.js");
  const meta = await fetchVersionMeta(name, version);
  ref.resolved = meta.tarballUrl;
  ref.integrity = meta.integrity;
  const advisoryMap = await npmPlugin.fetchAdvisories([ref], opts);
  return scanAny(ref, npmPlugin, opts, cache, process.cwd(), advisoryMap);
}

// ── npm-only commands (fix, init-ci, init-hooks) ──────────────────────────────

export async function runFix(dir: string, opts: ScanOptions, apply: boolean): Promise<number> {
  const projectDir = resolve(dir);
  npmPlugin.init(opts);

  const fileConfig = await loadConfig(projectDir);
  const mergedOpts: ScanOptions = {
    ...opts,
    trust: opts.trust ?? fileConfig.trust,
    minRisk: opts.minRisk ?? fileConfig.minRisk,
  };

  const cache = new DiskCache(mergedOpts.cacheDir);
  const { refs, lockfileDir } = await parseLockfile(projectDir);
  const directDeps = await readDirectDeps(lockfileDir);
  const advisoryMap = await npmPlugin.fetchAdvisories(refs, mergedOpts);
  const reports = await runEcosystemRefs(npmPlugin, refs, mergedOpts, cache, projectDir, advisoryMap);

  // Collect one fix candidate per package (highest severity advisory with a patch)
  const candidateMap = new Map<string, FixCandidate>();
  for (const report of reports) {
    for (const advisory of report.advisories) {
      if (!advisory.patchedVersions) continue;
      const existing = candidateMap.get(report.name);
      const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
      if (
        existing &&
        (severityOrder[existing.cves[0] ?? ""] ?? 0) >= (severityOrder[advisory.severity] ?? 0)
      )
        continue;
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

  const candidates = Array.from(candidateMap.values()).sort(
    (a, b) => Number(b.isDirect) - Number(a.isDirect) || a.name.localeCompare(b.name)
  );

  if (candidates.length === 0) {
    process.stdout.write("No advisory findings with available patches.\n");
    return 0;
  }

  const RESET = "\x1b[0m";
  const BOLD = "\x1b[1m";
  const GREEN = "\x1b[32m";
  const YELLOW = "\x1b[33m";
  const DIM = "\x1b[2m";
  const NO_COLOR = process.env["NO_COLOR"] !== undefined || !process.stdout.isTTY;
  const cc = (col: string, t: string) => (NO_COLOR ? t : `${col}${t}${RESET}`);

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

  const installArgs = candidates.map((c) => `${c.name}@${c.patchedVersions}`);
  process.stdout.write(`\n${cc(BOLD, "Running:")} npm install ${installArgs.join(" ")}\n\n`);

  const code = await spawnNpmInstall(installArgs, lockfileDir);
  if (code !== 0) {
    process.stderr.write(`npm install exited with code ${code}\n`);
    return 2;
  }

  process.stdout.write(
    `\n${cc(GREEN, `✓ Applied ${candidates.length} fix${candidates.length === 1 ? "" : "es"}`)}\n`
  );
  return 0;
}

// ── Output helpers ────────────────────────────────────────────────────────────

async function writeOutput(
  report: ReturnType<typeof buildProjectReport>,
  opts: ScanOptions
): Promise<void> {
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

  if (opts.sarif) {
    process.stdout.write(toSarif(report) + "\n");
  } else if (opts.json) {
    process.stdout.write(toJson(report) + "\n");
  } else {
    renderReport(report, opts.onlyFlagged);
  }
}

// ── init-ci / init-hooks ──────────────────────────────────────────────────────

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
  const cc = (col: string, t: string) => (NO_COLOR ? t : `${col}${t}${RESET}`);

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
  const cc = (col: string, t: string) => (NO_COLOR ? t : `${col}${t}${RESET}`);

  try {
    await access(gitDir);
  } catch {
    process.stderr.write(
      `No .git directory found at ${projectDir}. Run from a git repository root.\n`
    );
    return 1;
  }

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

// ── Internal helpers ──────────────────────────────────────────────────────────

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

// ── CLI option types + parser ─────────────────────────────────────────────────

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

// ── Commander program ─────────────────────────────────────────────────────────

export function buildProgram(): Command {
  const program = new Command();

  program
    .name("npm-prescripts")
    .description(
      "Static lifecycle script scanner for npm and PyPI dependencies.\n" +
        "Surfaces inbound threats in package install scripts — triage tool for humans and LLM agents."
    )
    .version("0.1.0");

  const sharedOptions = (cmd: Command): Command =>
    cmd
      .option("-j, --json", "Output JSON report to stdout", false)
      .option(
        "--sarif",
        "Output SARIF 2.1.0 report (for GitHub Actions upload-sarif)",
        false
      )
      .option(
        "-o, --output-dir <dir>",
        "Write report.json + results.sarif to directory (human output still goes to stdout)"
      )
      .option(
        "--min-risk <level>",
        "Minimum risk level to surface: verified|low|medium|high|critical",
        "low"
      )
      .option("--severity <level>", "Minimum severity: low|medium|high|critical", "medium")
      .option("--only-flagged", "Suppress packages with no findings", false)
      .option("--no-cache", "Skip cache reads")
      .option("--cache-dir <path>", "Override cache directory")
      .option("--concurrency <n>", "Max simultaneous registry requests", "5")
      .option("--registry <url>", "npm registry URL", "https://registry.npmjs.org")
      .option("--timeout <ms>", "Per-request timeout in milliseconds", "30000")
      .option("--api-url <url>", "Hosted npm-prescripts-api URL (optional)")
      .option("-v, --verbose", "Debug output to stderr", false);

  sharedOptions(
    program
      .command("scan [dir]")
      .description(
        "Scan all packages in a project lockfile (default: cwd).\n" +
          "Auto-detects npm (package-lock.json) and pip (requirements.txt / poetry.lock)."
      )
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
      .option("--depth <n>", "Max dependency resolution depth (npm only)", "5")
      .option("--pm <manager>", "Package manager: npm|pip|cargo|gem (default: npm)", "npm")
  ).action(async (pkg: string, opts: CliScanOptions & { pm: string }) => {
    try {
      const code = await runCheck(pkg, parseOpts(opts), opts.pm);
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
    .action(
      async (
        dir: string | undefined,
        opts: { apply: boolean } & Pick<
          CliScanOptions,
          "concurrency" | "registry" | "noCache" | "cacheDir" | "timeout"
        >
      ) => {
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
      }
    );

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
    .action(
      async (
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
      }
    );

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
    .action(
      async (dir: string | undefined, opts: { minRisk: string; force: boolean }) => {
        try {
          const code = await runInitHooks(dir ?? ".", opts.minRisk, opts.force);
          process.exit(code);
        } catch (err) {
          process.stderr.write(`Error: ${String(err)}\n`);
          process.exit(2);
        }
      }
    );

  return program;
}

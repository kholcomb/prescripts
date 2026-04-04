import type { PackageReport, ProjectReport, Finding, AdvisoryMatch, Severity } from "../types.js";

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const DIM = "\x1b[2m";
const GREEN = "\x1b[32m";

const NO_COLOR = process.env["NO_COLOR"] !== undefined || !process.stdout.isTTY;

function c(color: string, text: string): string {
  if (NO_COLOR) return text;
  return `${color}${text}${RESET}`;
}

function severityColor(sev: Severity): string {
  if (NO_COLOR) return "";
  switch (sev) {
    case "critical": return RED + BOLD;
    case "high":     return RED;
    case "medium":   return YELLOW;
    case "low":      return DIM;
  }
}

function renderFinding(finding: Finding): string {
  const lines: string[] = [];
  const sevLabel = c(severityColor(finding.severity), `[${finding.category}/${finding.severity}]`);
  lines.push(`  ${sevLabel} in ${c(CYAN, finding.source)}`);
  lines.push(`  Pattern: ${c(BOLD, finding.pattern)}`);

  const boxWidth = 62;
  const border = "─".repeat(boxWidth);
  lines.push(`  ┌─ ${c(BOLD + RED, "UNTRUSTED PACKAGE CONTENT")} ${"─".repeat(boxWidth - 27)}┐`);
  for (const line of finding.excerpt.lines.split("\n")) {
    const padded = line.padEnd(boxWidth);
    lines.push(`  │ ${padded} │`);
  }
  lines.push(`  └${border}┘`);

  return lines.join("\n");
}

function renderAdvisory(advisory: AdvisoryMatch): string {
  const lines: string[] = [];
  const sevLabel = c(severityColor(advisory.severity), `[advisory/${advisory.severity}]`);
  const cveList = advisory.cves.length > 0 ? `  ${c(DIM, advisory.cves.join(", "))}` : "";
  const cvss = advisory.cvssScore !== null ? c(DIM, ` CVSS ${advisory.cvssScore.toFixed(1)}`) : "";
  lines.push(`  ${sevLabel} ${c(BOLD, advisory.title)}${cvss}`);
  lines.push(`  Affects: ${c(DIM, advisory.vulnerableVersions)}${cveList}`);
  lines.push(`  ${c(CYAN, advisory.url)}`);
  return lines.join("\n");
}

function renderPackage(pkg: PackageReport): string {
  const lines: string[] = [];

  const srcBadge = pkg.source.type !== "registry"
    ? c(YELLOW, `[${pkg.source.type.toUpperCase()}]`) + " "
    : "";

  const integrityBadge = pkg.source.integrity && !pkg.source.integrityVerified
    ? c(RED + BOLD, "[INTEGRITY MISMATCH]") + " "
    : "";

  const provenance = pkg.provenance;
  const newScript = provenance.installScriptIsNew
    ? c(RED + BOLD, "[NEW INSTALL SCRIPT]") + " "
    : "";
  const maintainers = provenance.maintainerCount !== null
    ? c(DIM, `[${provenance.maintainerCount} maintainer${provenance.maintainerCount === 1 ? "" : "s"}]`) + " "
    : "";
  const downloads = provenance.weeklyDownloads !== null
    ? c(DIM, `[${provenance.weeklyDownloads.toLocaleString()} dl/wk]`) + " "
    : "";
  const noProvenance = provenance.unavailableReason
    ? c(DIM, `[no provenance: ${provenance.unavailableReason}]`) + " "
    : "";

  lines.push(
    `\n${c(BOLD, `${pkg.name}@${pkg.version}`)}  ` +
    srcBadge + integrityBadge + newScript + maintainers + downloads + noProvenance
  );

  for (const [hook, script] of Object.entries(pkg.lifecycleScripts)) {
    lines.push(`  ${c(CYAN, hook)}: ${c(DIM, JSON.stringify(script))}`);
  }

  if (pkg.binaryDownload) {
    const host = pkg.binaryDownload.host ?? "unknown host";
    lines.push(
      `  ${c(YELLOW, "[binary download]")} host: ${c(BOLD, host)}` +
      (pkg.binaryDownload.remote_path ? ` path: ${c(DIM, pkg.binaryDownload.remote_path)}` : "")
    );
  }

  for (const advisory of pkg.advisories) {
    lines.push(renderAdvisory(advisory));
  }

  if (pkg.findings.length === 0 && pkg.advisories.length === 0) {
    lines.push(c(GREEN, "  ✓ No findings"));
  } else {
    for (const finding of pkg.findings) {
      lines.push(renderFinding(finding));
    }
  }

  return lines.join("\n");
}

export function renderReport(report: ProjectReport, onlyFlagged: boolean): void {
  const out = process.stdout;

  for (const pkg of report.packages) {
    if (onlyFlagged && pkg.findings.length === 0 && pkg.advisories.length === 0) continue;
    out.write(renderPackage(pkg) + "\n");
  }

  const summary = [
    `\n${c(BOLD, "Summary:")}`,
    `  Packages scanned:  ${report.totalPackages}`,
    `  Packages flagged:  ${report.flaggedPackages > 0 ? c(RED, String(report.flaggedPackages)) : c(GREEN, "0")}`,
  ].join("\n");

  out.write(summary + "\n");
}

export function renderProgress(current: number, total: number, name: string): void {
  if (NO_COLOR) return;
  process.stderr.write(`\r${c(DIM, `[${current}/${total}]`)} ${name}`.padEnd(80));
}

export function clearProgress(): void {
  if (NO_COLOR) return;
  process.stderr.write("\r" + " ".repeat(80) + "\r");
}

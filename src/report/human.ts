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
  const confSuffix = finding.confidence !== "high"
    ? c(DIM, `/${finding.confidence}-confidence`)
    : "";
  const sevLabel = c(severityColor(finding.severity), `[${finding.category}/${finding.severity}${confSuffix}]`);
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
  lines.push(`  Vulnerable: ${c(DIM, advisory.vulnerableVersions)}${cveList}`);
  if (advisory.patchedVersions) {
    lines.push(`  ${c(GREEN, `Fix: upgrade to ${advisory.patchedVersions}`)}`);
  } else {
    lines.push(`  ${c(YELLOW, "Fix: no patched version available")}`);
  }
  lines.push(`  ${c(CYAN, advisory.url)}`);
  return lines.join("\n");
}

function riskColor(risk: import("../types.js").RiskLevel): string {
  if (NO_COLOR) return "";
  switch (risk) {
    case "critical": return RED + BOLD;
    case "high":     return RED;
    case "medium":   return YELLOW;
    case "low":      return DIM;
    case "verified": return GREEN;
  }
}

function renderPackage(pkg: PackageReport): string {
  const lines: string[] = [];
  const riskBadge = c(riskColor(pkg.risk), `[risk:${pkg.risk}]`);

  const srcBadge = pkg.source.type !== "registry"
    ? c(YELLOW, `[${pkg.source.type.toUpperCase()}]`) + " "
    : "";

  const pmBadge = pkg.packageManager === "pip"
    ? c(DIM, "[pip]") + " "
    : pkg.packageManager === "cargo"
    ? c(DIM, "[cargo]") + " "
    : pkg.packageManager === "gem"
    ? c(DIM, "[gem]") + " "
    : pkg.packageManager === "actions"
    ? c(DIM, "[actions]") + " "
    : pkg.packageManager === "gitmodules"
    ? c(DIM, "[gitmodules]") + " "
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

  const attestationBadge = (() => {
    if (!provenance.attestation) {
      return provenance.unavailableReason ? "" : c(DIM, "[no provenance attestation]") + " ";
    }
    const { sigstoreVerified, signingIdentity, sourceRepo } = provenance.attestation;
    const label = signingIdentity ?? sourceRepo ?? "attested";
    if (sigstoreVerified === true) {
      return c(GREEN, `[chain-verified: ${label}]`) + " ";
    }
    if (sigstoreVerified === false) {
      return c(RED + BOLD, `[ATTESTATION INVALID: ${label}]`) + " ";
    }
    // null = parsed but not cryptographically verified
    return c(GREEN, `[provenance: ${label}]`) + " ";
  })();

  const deprecatedBadge = provenance.deprecated
    ? c(RED + BOLD, `[DEPRECATED: ${provenance.deprecated}]`) + " "
    : "";

  const sigBadge =
    provenance.hasRegistrySignature === false
      ? c(YELLOW, "[unsigned]") + " "
      : provenance.hasRegistrySignature === true
      ? c(DIM, "[signed]") + " "
      : "";

  const publisherBadge =
    provenance.publisher && provenance.publisherInMaintainers === false
      ? c(YELLOW, `[publisher not in maintainers: ${provenance.publisher}]`) + " "
      : provenance.publisher
      ? c(DIM, `[publisher: ${provenance.publisher}]`) + " "
      : "";

  const newPublisherBadge =
    provenance.publisherIsNewToPackage === true
      ? c(YELLOW, "[new publisher for this package]") + " "
      : "";

  const velocityBadge = (() => {
    const { firstPublishedAt, publishedAt, totalVersions } = provenance;
    if (!firstPublishedAt || !publishedAt || (totalVersions ?? 0) < 5) return "";
    const ageDays =
      (new Date(publishedAt).getTime() - new Date(firstPublishedAt).getTime()) /
      (1000 * 60 * 60 * 24);
    const velocity = (totalVersions ?? 1) / Math.max(1, ageDays);
    if (velocity > 10) return c(YELLOW, `[${(velocity).toFixed(0)} versions/day]`) + " ";
    if (velocity > 3) return c(DIM, `[${(velocity).toFixed(1)} versions/day]`) + " ";
    return "";
  })();

  lines.push(
    `\n${c(BOLD, `${pkg.name}@${pkg.version}`)}  ${riskBadge}  ` +
    pmBadge + srcBadge + integrityBadge + deprecatedBadge + newScript +
    maintainers + downloads + sigBadge + publisherBadge + newPublisherBadge +
    velocityBadge + noProvenance + attestationBadge
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

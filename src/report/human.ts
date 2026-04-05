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

function findingLines(finding: Finding): string[] {
  const confSuffix = finding.confidence !== "high"
    ? c(DIM, ` (${finding.confidence} confidence)`)
    : "";
  const sevLabel = c(severityColor(finding.severity), finding.severity);
  const out = [
    `${c(BOLD, finding.category)}  ${sevLabel}${confSuffix}`,
    `${c(DIM, finding.source)}  ${finding.pattern}`,
  ];
  for (const line of finding.excerpt.lines.split("\n").filter(l => l.trim())) {
    out.push(c(DIM, line));
  }
  return out;
}

function advisoryLines(advisory: AdvisoryMatch): string[] {
  const sevLabel = c(severityColor(advisory.severity), `[advisory/${advisory.severity}]`);
  const cveList = advisory.cves.length > 0 ? `  ${c(DIM, advisory.cves.join(", "))}` : "";
  const cvss = advisory.cvssScore !== null ? c(DIM, ` CVSS ${advisory.cvssScore.toFixed(1)}`) : "";
  const fix = advisory.patchedVersions
    ? c(GREEN, `fix: upgrade to ${advisory.patchedVersions}`)
    : c(YELLOW, "fix: no patched version available");
  return [
    `${sevLabel} ${c(BOLD, advisory.title)}${cvss}`,
    `vulnerable: ${c(DIM, advisory.vulnerableVersions)}${cveList}`,
    fix,
    c(CYAN, advisory.url),
  ];
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

// Render a labeled section. First content line follows the label; subsequent
// lines are indented to the same column.
function section(label: string, items: string[]): string {
  if (items.length === 0) return "";
  const col = 11; // "  " + label padded to 9
  const pad = " ".repeat(col);
  const labelStr = `  ${label.padEnd(col - 2)}`;
  return labelStr + items.join("\n" + pad);
}

function renderPackage(pkg: PackageReport): string {
  const lines: string[] = [];
  const provenance = pkg.provenance;

  // ── Header: name + risk + critical alerts ──────────────────────────────────
  const riskBadge = c(riskColor(pkg.risk), `[risk:${pkg.risk}]`);
  const alerts: string[] = [];
  if (pkg.source.integrity && !pkg.source.integrityVerified)
    alerts.push(c(RED + BOLD, "[INTEGRITY MISMATCH]"));
  if (provenance.installScriptIsNew)
    alerts.push(c(RED + BOLD, "[NEW INSTALL SCRIPT]"));
  if (provenance.deprecated)
    alerts.push(c(RED + BOLD, `[DEPRECATED: ${provenance.deprecated}]`));
  const alertStr = alerts.length > 0 ? "  " + alerts.join("  ") : "";
  lines.push(`\n${c(BOLD, `${pkg.name}@${pkg.version}`)}  ${riskBadge}${alertStr}`);

  // ── Signals: registry + provenance metadata ────────────────────────────────
  const signals: string[] = [];
  if (pkg.packageManager !== "npm")
    signals.push(c(DIM, `[${pkg.packageManager}]`));
  if (pkg.source.type !== "registry")
    signals.push(c(YELLOW, `[${pkg.source.type.toUpperCase()}]`));
  if (provenance.maintainerCount !== null)
    signals.push(c(DIM, `[${provenance.maintainerCount} maintainer${provenance.maintainerCount === 1 ? "" : "s"}]`));
  if (provenance.weeklyDownloads !== null)
    signals.push(c(DIM, `[${provenance.weeklyDownloads.toLocaleString()} dl/wk]`));
  const { firstPublishedAt, publishedAt, totalVersions } = provenance;
  if (firstPublishedAt && publishedAt && (totalVersions ?? 0) >= 5) {
    const ageDays = (new Date(publishedAt).getTime() - new Date(firstPublishedAt).getTime()) / (1000 * 60 * 60 * 24);
    const vel = (totalVersions ?? 1) / Math.max(1, ageDays);
    if (vel > 10) signals.push(c(YELLOW, `[${vel.toFixed(0)} versions/day]`));
    else if (vel > 3) signals.push(c(DIM, `[${vel.toFixed(1)} versions/day]`));
  }
  if (provenance.hasRegistrySignature === false)
    signals.push(c(YELLOW, "[unsigned]"));
  else if (provenance.hasRegistrySignature === true)
    signals.push(c(DIM, "[signed]"));
  if (provenance.publisher && provenance.publisherInMaintainers === false)
    signals.push(c(YELLOW, `[publisher not in maintainers: ${provenance.publisher}]`));
  else if (provenance.publisher)
    signals.push(c(DIM, `[publisher: ${provenance.publisher}]`));
  if (provenance.publisherIsNewToPackage === true)
    signals.push(c(YELLOW, "[new publisher for this package]"));
  if (provenance.unavailableReason) {
    signals.push(c(DIM, `[no provenance: ${provenance.unavailableReason}]`));
  } else if (provenance.attestation) {
    const { sigstoreVerified, signingIdentity, sourceRepo } = provenance.attestation;
    const label = (signingIdentity ?? sourceRepo ?? "attested").replace(/^https?:\/\//, "");
    if (sigstoreVerified === true)       signals.push(c(GREEN, `[chain-verified: ${label}]`));
    else if (sigstoreVerified === false) signals.push(c(RED + BOLD, `[ATTESTATION INVALID: ${label}]`));
    else                                 signals.push(c(GREEN, `[provenance: ${label}]`));
  } else {
    signals.push(c(DIM, "[no provenance attestation]"));
  }
  const signalsLine = section("signals", [signals.join("  ")]);
  if (signalsLine) lines.push(signalsLine);

  // ── Scripts: lifecycle hooks ───────────────────────────────────────────────
  const scriptItems = Object.entries(pkg.lifecycleScripts).map(
    ([hook, script]) => `${c(CYAN, hook)}: ${c(DIM, JSON.stringify(script))}`
  );
  const scriptsSection = section("scripts", scriptItems);
  if (scriptsSection) lines.push(scriptsSection);

  // ── Findings: pattern findings + advisories + binary download ──────────────
  const findingItems: string[] = [];
  if (pkg.binaryDownload) {
    const host = pkg.binaryDownload.host ?? "unknown host";
    const path = pkg.binaryDownload.remote_path ? `  path: ${c(DIM, pkg.binaryDownload.remote_path)}` : "";
    findingItems.push(`binary download  host: ${c(BOLD, host)}${path}`);
  }
  for (const advisory of pkg.advisories) findingItems.push(...advisoryLines(advisory));
  for (const finding of pkg.findings)    findingItems.push(...findingLines(finding));

  if (findingItems.length > 0) {
    lines.push(section("findings", findingItems));
  } else {
    lines.push(c(GREEN, "  no findings"));
  }

  return lines.join("\n");
}

export function renderReport(report: ProjectReport, onlyFlagged: boolean): void {
  const out = process.stdout;

  for (const pkg of report.packages) {
    if (onlyFlagged && pkg.findings.length === 0 && pkg.advisories.length === 0) continue;
    out.write(renderPackage(pkg) + "\n");
  }

  const col = 20;
  const row = (label: string, value: string) =>
    `  ${label.padEnd(col)}${value}`;

  const actionable = report.actionablePackages;
  const monitor = report.monitorPackages;

  const summary = [
    `\n${c(BOLD, "Summary:")}`,
    row("Packages scanned:", String(report.totalPackages)),
    row("Requires action:", actionable > 0 ? c(RED, String(actionable)) : c(GREEN, "0")),
    row("Monitor only:", monitor > 0 ? c(YELLOW, `${monitor}  ${c(DIM, "(unpatched advisories — no upstream fix)")}`) : c(GREEN, "0")),
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

import type { PackageReport, ProjectReport, RiskLevel } from "../types.js";

const RISK_ORDER: Record<RiskLevel, number> = {
  critical: 5, high: 4, medium: 3, low: 2, verified: 1,
};

export function buildProjectReport(
  packages: PackageReport[],
  mode: "scan" | "check",
  onlyFlagged: boolean,
  minRisk: RiskLevel = "low"
): ProjectReport {
  const isFlagged = (p: PackageReport) =>
    p.findings.length > 0 || p.advisories.length > 0;
  const meetsThreshold = (p: PackageReport) =>
    RISK_ORDER[p.risk] >= RISK_ORDER[minRisk];

  const output = onlyFlagged
    ? packages.filter((p) => isFlagged(p) && meetsThreshold(p))
    : packages.filter(meetsThreshold);

  return {
    scannedAt: new Date().toISOString(),
    mode,
    totalPackages: packages.length,
    // flaggedPackages = packages with findings that meet the risk threshold —
    // used for exit code and summary. Matches what's shown in output.
    flaggedPackages: packages.filter((p) => isFlagged(p) && meetsThreshold(p)).length,
    packages: output,
  };
}

export function toJson(report: ProjectReport): string {
  return JSON.stringify(report, null, 2);
}

import type { PackageReport, ProjectReport } from "../types.js";

export function buildProjectReport(
  packages: PackageReport[],
  mode: "scan" | "check",
  onlyFlagged: boolean
): ProjectReport {
  const flagged = packages.filter((p) => p.findings.length > 0);
  const output = onlyFlagged ? flagged : packages;

  return {
    scannedAt: new Date().toISOString(),
    mode,
    totalPackages: packages.length,
    flaggedPackages: flagged.length,
    packages: output,
  };
}

export function toJson(report: ProjectReport): string {
  return JSON.stringify(report, null, 2);
}

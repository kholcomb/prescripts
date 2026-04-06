import type { PackageReport, ProjectReport, RiskLevel } from "../types.js";

const RISK_ORDER: Record<RiskLevel, number> = {
  critical: 5, high: 4, medium: 3, low: 2, verified: 1,
};

/**
 * A package is actionable when the user has something concrete to do:
 *   - Install-time threats: pattern findings, integrity mismatch, new install
 *     script, publisher anomaly, attestation regression
 *   - Runtime advisories where a patched version is available
 *
 * Packages with only unpatched advisories are monitor-only — real risk, but
 * no upstream fix exists and the user cannot resolve them right now.
 */
export function isActionable(pkg: PackageReport): boolean {
  if (pkg.findings.length > 0) return true;
  if (pkg.source.integrity && !pkg.source.integrityVerified) return true;
  if (pkg.provenance?.installScriptIsNew === true) return true;
  if (pkg.provenance?.publisherInMaintainers === false) return true;
  if (pkg.provenance?.attestationRegressed === true) return true;
  if (pkg.advisories.some((a) => a.patchedVersions !== null)) return true;
  return false;
}

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

  const flagged = packages.filter((p) => isFlagged(p) && meetsThreshold(p));
  const output = onlyFlagged
    ? flagged
    : packages.filter(meetsThreshold);

  return {
    scannedAt: new Date().toISOString(),
    mode,
    totalPackages: packages.length,
    flaggedPackages: flagged.length,
    actionablePackages: flagged.filter(isActionable).length,
    monitorPackages: flagged.filter((p) => !isActionable(p)).length,
    packages: output,
  };
}

export function toJson(report: ProjectReport): string {
  return JSON.stringify(report, (key, value) => key === "_warning" ? undefined : value, 2);
}

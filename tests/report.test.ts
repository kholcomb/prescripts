import { describe, it, expect } from "vitest";
import { buildProjectReport } from "../src/report/json-report.js";
import type { PackageReport } from "../src/types.js";

function makeReport(name: string, hasFindings: boolean): PackageReport {
  return {
    name,
    version: "1.0.0",
    source: {
      type: "registry",
      resolved: `https://registry.npmjs.org/${name}/-/${name}-1.0.0.tgz`,
      integrity: "sha512-test==",
      integrityVerified: true,
    },
    provenance: {
      publishedAt: "2022-01-01T00:00:00.000Z",
      weeklyDownloads: 1000,
      maintainerCount: 2,
      installScriptIsNew: false,
      totalVersions: 10,
      unavailableReason: null,
    },
    lifecycleScripts: { postinstall: "node setup.js" },
    binaryDownload: null,
    findings: hasFindings
      ? [
          {
            scriptHook: "postinstall",
            source: "postinstall script",
            category: "network",
            severity: "high",
            pattern: "curl",
            excerpt: {
              _warning: "UNTRUSTED THIRD-PARTY CONTENT",
              lines: "1: curl https://example.com",
            },
          },
        ]
      : [],
  };
}

describe("buildProjectReport", () => {
  it("counts total and flagged packages correctly", () => {
    const packages = [
      makeReport("clean-pkg", false),
      makeReport("flagged-pkg", true),
      makeReport("another-clean", false),
    ];
    const report = buildProjectReport(packages, "scan", false);
    expect(report.totalPackages).toBe(3);
    expect(report.flaggedPackages).toBe(1);
    expect(report.mode).toBe("scan");
  });

  it("filters to only flagged packages when onlyFlagged is true", () => {
    const packages = [
      makeReport("clean-pkg", false),
      makeReport("flagged-pkg", true),
    ];
    const report = buildProjectReport(packages, "scan", true);
    expect(report.packages).toHaveLength(1);
    expect(report.packages[0]?.name).toBe("flagged-pkg");
    expect(report.totalPackages).toBe(2); // total is still all packages
    expect(report.flaggedPackages).toBe(1);
  });

  it("includes scannedAt ISO timestamp", () => {
    const report = buildProjectReport([], "check", false);
    expect(report.scannedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("all excerpts in output have _warning field", () => {
    const packages = [makeReport("flagged-pkg", true)];
    const report = buildProjectReport(packages, "scan", false);
    for (const pkg of report.packages) {
      for (const finding of pkg.findings) {
        expect(finding.excerpt._warning).toBe("UNTRUSTED THIRD-PARTY CONTENT");
      }
    }
  });
});

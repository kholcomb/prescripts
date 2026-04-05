import { describe, it, expect } from "vitest";
import { toSarif } from "../src/report/sarif.js";
import type { ProjectReport, PackageReport } from "../src/types.js";

function makePackage(overrides: Partial<PackageReport> = {}): PackageReport {
  return {
    name: "test-pkg",
    version: "1.0.0",
    source: {
      type: "registry",
      resolved: "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz",
      integrity: "sha512-abc==",
      integrityVerified: true,
    },
    provenance: {
      publishedAt: "2024-01-01T00:00:00.000Z",
      weeklyDownloads: 1000,
      maintainerCount: 2,
      installScriptIsNew: false,
      totalVersions: 5,
      unavailableReason: null,
      attestation: null,
    },
    lifecycleScripts: { postinstall: "node setup.js" },
    binaryDownload: null,
    advisories: [],
    findings: [],
    ...overrides,
  };
}

function makeReport(packages: PackageReport[]): ProjectReport {
  const flagged = packages.filter(
    (p) => p.findings.length > 0 || p.advisories.length > 0
  );
  return {
    scannedAt: "2024-01-01T00:00:00.000Z",
    mode: "scan",
    totalPackages: packages.length,
    flaggedPackages: flagged.length,
    packages,
  };
}

describe("toSarif", () => {
  it("produces valid SARIF 2.1.0 schema version", () => {
    const sarif = JSON.parse(toSarif(makeReport([])));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif-schema-2.1.0");
  });

  it("includes tool driver with name and rules", () => {
    const sarif = JSON.parse(toSarif(makeReport([])));
    const driver = sarif.runs[0].tool.driver;
    expect(driver.name).toBe("npm-prescripts");
    expect(Array.isArray(driver.rules)).toBe(true);
    expect(driver.rules.length).toBeGreaterThan(0);
  });

  it("maps critical/high findings to SARIF error level", () => {
    const pkg = makePackage({
      findings: [
        {
          scriptHook: "postinstall",
          source: "postinstall script",
          category: "network",
          severity: "high",
          pattern: "curl",
          excerpt: { _warning: "UNTRUSTED THIRD-PARTY CONTENT", lines: "1: curl https://x.com" },
        },
      ],
    });
    const sarif = JSON.parse(toSarif(makeReport([pkg])));
    const result = sarif.runs[0].results[0];
    expect(result.level).toBe("error");
    expect(result.ruleId).toBe("network");
  });

  it("maps medium findings to SARIF warning level", () => {
    const pkg = makePackage({
      findings: [
        {
          scriptHook: "postinstall",
          source: "postinstall script",
          category: "dns_exfil",
          severity: "medium",
          pattern: "dns.lookup(",
          excerpt: { _warning: "UNTRUSTED THIRD-PARTY CONTENT", lines: "1: dns.lookup(host, cb)" },
        },
      ],
    });
    const sarif = JSON.parse(toSarif(makeReport([pkg])));
    expect(sarif.runs[0].results[0].level).toBe("warning");
  });

  it("maps low findings to SARIF note level", () => {
    const pkg = makePackage({
      findings: [
        {
          scriptHook: "postinstall",
          source: "postinstall script",
          category: "env_check",
          severity: "low",
          pattern: "process.env",
          excerpt: { _warning: "UNTRUSTED THIRD-PARTY CONTENT", lines: "1: process.env.FOO" },
        },
      ],
    });
    const sarif = JSON.parse(toSarif(makeReport([pkg])));
    expect(sarif.runs[0].results[0].level).toBe("note");
  });

  it("includes advisory matches as SARIF results with advisory_match ruleId", () => {
    const pkg = makePackage({
      advisories: [
        {
          id: 1523,
          title: "Prototype Pollution",
          severity: "high",
          url: "https://npmjs.com/advisories/1523",
          vulnerableVersions: "<4.17.19",
          patchedVersions: ">=4.17.19",
          cves: ["CVE-2020-8203"],
          cvssScore: 7.4,
        },
      ],
    });
    const sarif = JSON.parse(toSarif(makeReport([pkg])));
    const result = sarif.runs[0].results[0];
    expect(result.ruleId).toBe("advisory_match");
    expect(result.level).toBe("error");
    expect(result.message.text).toContain("CVE-2020-8203");
    expect(result.properties.advisory_id).toBe(1523);
  });

  it("sets artifact URI based on source type", () => {
    const pkg = makePackage({
      findings: [
        {
          scriptHook: "postinstall",
          source: "referenced file: scripts/setup.js",
          category: "network",
          severity: "high",
          pattern: "fetch(",
          excerpt: { _warning: "UNTRUSTED THIRD-PARTY CONTENT", lines: "5: fetch(url)" },
        },
      ],
    });
    const sarif = JSON.parse(toSarif(makeReport([pkg])));
    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    expect(loc.artifactLocation.uri).toContain("scripts/setup.js");
    expect(loc.region.startLine).toBe(5);
  });

  it("includes all rules for all PATTERN_REGISTRY categories", () => {
    const sarif = JSON.parse(toSarif(makeReport([])));
    const ruleIds: string[] = sarif.runs[0].tool.driver.rules.map(
      (r: { id: string }) => r.id
    );
    expect(ruleIds).toContain("network");
    expect(ruleIds).toContain("obfuscation");
    expect(ruleIds).toContain("cryptomining");
    expect(ruleIds).toContain("advisory_match");
  });
});

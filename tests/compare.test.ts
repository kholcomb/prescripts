import { describe, it, expect } from "vitest";
import { compareReports } from "../src/analyzer/compare.js";
import type { PackageReport, Finding } from "../src/types.js";

function makeReport(overrides: Partial<PackageReport> = {}): PackageReport {
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
      weeklyDownloads: 50000,
      maintainerCount: 2,
      installScriptIsNew: false,
      totalVersions: 20,
      unavailableReason: null,
      attestation: null,
      deprecated: null,
      publisher: "alice",
      publisherInMaintainers: true,
      hasRegistrySignature: true,
      attestationRegressed: false,
      firstPublishedAt: "2023-01-01T00:00:00.000Z",
      publisherIsNewToPackage: false,
    },
    lifecycleScripts: {},
    binaryDownload: null,
    advisories: [],
    findings: [],
    risk: "verified",
    ...overrides,
  };
}

function makeFinding(category: string, pattern: string, source = "postinstall script"): Finding {
  return {
    scriptHook: "postinstall",
    source,
    category,
    severity: "high",
    confidence: "medium",
    pattern,
    excerpt: { _warning: "UNTRUSTED THIRD-PARTY CONTENT", lines: `1: ${pattern}` },
  };
}

describe("compareReports — lifecycle scripts", () => {
  it("detects an added lifecycle hook", () => {
    const from = makeReport({ lifecycleScripts: {} });
    const to = makeReport({ lifecycleScripts: { postinstall: "node setup.js" } });
    const result = compareReports(from, to);
    expect(result.addedScripts).toHaveLength(1);
    expect(result.addedScripts[0]?.hook).toBe("postinstall");
    expect(result.addedScripts[0]?.before).toBeNull();
    expect(result.addedScripts[0]?.after).toBe("node setup.js");
    expect(result.removedScripts).toHaveLength(0);
    expect(result.changedScripts).toHaveLength(0);
  });

  it("detects a removed lifecycle hook", () => {
    const from = makeReport({ lifecycleScripts: { postinstall: "node setup.js" } });
    const to = makeReport({ lifecycleScripts: {} });
    const result = compareReports(from, to);
    expect(result.removedScripts).toHaveLength(1);
    expect(result.removedScripts[0]?.hook).toBe("postinstall");
    expect(result.removedScripts[0]?.before).toBe("node setup.js");
    expect(result.removedScripts[0]?.after).toBeNull();
  });

  it("detects a changed lifecycle hook value", () => {
    const from = makeReport({ lifecycleScripts: { postinstall: "node setup.js" } });
    const to = makeReport({ lifecycleScripts: { postinstall: "node setup.js --new-flag" } });
    const result = compareReports(from, to);
    expect(result.changedScripts).toHaveLength(1);
    expect(result.changedScripts[0]?.before).toBe("node setup.js");
    expect(result.changedScripts[0]?.after).toBe("node setup.js --new-flag");
  });

  it("reports no changes when scripts are identical", () => {
    const scripts = { postinstall: "node setup.js" };
    const result = compareReports(
      makeReport({ lifecycleScripts: scripts }),
      makeReport({ lifecycleScripts: scripts })
    );
    expect(result.addedScripts).toHaveLength(0);
    expect(result.removedScripts).toHaveLength(0);
    expect(result.changedScripts).toHaveLength(0);
  });
});

describe("compareReports — findings diff", () => {
  it("surfaces findings present in toVersion but not fromVersion as newFindings", () => {
    const from = makeReport({ findings: [] });
    const to = makeReport({ findings: [makeFinding("network", "curl")] });
    const result = compareReports(from, to);
    expect(result.newFindings).toHaveLength(1);
    expect(result.newFindings[0]?.category).toBe("network");
    expect(result.resolvedFindings).toHaveLength(0);
  });

  it("surfaces findings in fromVersion but not toVersion as resolvedFindings", () => {
    const from = makeReport({ findings: [makeFinding("network", "curl")] });
    const to = makeReport({ findings: [] });
    const result = compareReports(from, to);
    expect(result.resolvedFindings).toHaveLength(1);
    expect(result.resolvedFindings[0]?.category).toBe("network");
    expect(result.newFindings).toHaveLength(0);
  });

  it("findings present in both versions appear in neither list", () => {
    const finding = makeFinding("network", "curl");
    const result = compareReports(
      makeReport({ findings: [finding] }),
      makeReport({ findings: [finding] })
    );
    expect(result.newFindings).toHaveLength(0);
    expect(result.resolvedFindings).toHaveLength(0);
  });

  it("distinguishes findings by category + source + pattern", () => {
    const curl = makeFinding("network", "curl");
    const wget = makeFinding("network", "wget");
    const result = compareReports(
      makeReport({ findings: [curl] }),
      makeReport({ findings: [wget] })
    );
    expect(result.newFindings).toHaveLength(1);
    expect(result.newFindings[0]?.pattern).toBe("wget");
    expect(result.resolvedFindings).toHaveLength(1);
    expect(result.resolvedFindings[0]?.pattern).toBe("curl");
  });
});

describe("compareReports — binary download host", () => {
  it("detects binary host change", () => {
    const from = makeReport({ binaryDownload: { host: "cdn.old.com", remote_path: null, module_name: null } });
    const to = makeReport({ binaryDownload: { host: "cdn.new.com", remote_path: null, module_name: null } });
    const result = compareReports(from, to);
    expect(result.binaryHostChanged).toBe(true);
    expect(result.fromBinaryHost).toBe("cdn.old.com");
    expect(result.toBinaryHost).toBe("cdn.new.com");
  });

  it("no change when binary host is identical", () => {
    const bd = { host: "cdn.example.com", remote_path: null, module_name: null };
    const result = compareReports(
      makeReport({ binaryDownload: bd }),
      makeReport({ binaryDownload: bd })
    );
    expect(result.binaryHostChanged).toBe(false);
  });

  it("detects binary download added", () => {
    const from = makeReport({ binaryDownload: null });
    const to = makeReport({ binaryDownload: { host: "cdn.example.com", remote_path: null, module_name: null } });
    const result = compareReports(from, to);
    expect(result.binaryHostChanged).toBe(true);
    expect(result.fromBinaryHost).toBeNull();
    expect(result.toBinaryHost).toBe("cdn.example.com");
  });
});

describe("compareReports — metadata", () => {
  it("preserves name and version fields", () => {
    const from = makeReport({ name: "my-pkg", version: "1.0.0" });
    const to = makeReport({ name: "my-pkg", version: "2.0.0" });
    const result = compareReports(from, to);
    expect(result.name).toBe("my-pkg");
    expect(result.fromVersion).toBe("1.0.0");
    expect(result.toVersion).toBe("2.0.0");
  });
});

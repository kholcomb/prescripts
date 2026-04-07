/**
 * SARIF 2.1.0 output formatter.
 *
 * GitHub Actions natively ingests SARIF via actions/upload-sarif, displaying
 * findings in the repository Security tab with zero additional configuration.
 *
 * Usage in CI:
 *   prescripts scan --sarif -o results.sarif
 *   # then upload-sarif action points at results.sarif
 */

import { PATTERN_REGISTRY } from "../analyzer/patterns.js";
import type { ProjectReport, PackageReport, Finding, Severity } from "../types.js";

const SARIF_SCHEMA =
  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

// SARIF level mapping — critical and high both map to "error"
function sarifLevel(sev: Severity): "error" | "warning" | "note" {
  if (sev === "critical" || sev === "high") return "error";
  if (sev === "medium") return "warning";
  return "note";
}

// Parse the first line number out of an excerpt ("12: const cmd = ...")
function excerptStartLine(lines: string): number {
  const m = /^(\d+):/.exec(lines.trim());
  return m ? parseInt(m[1]!, 10) : 1;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: "error" | "warning" | "note" };
  helpUri: string;
  properties: { tags: string[] };
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string; uriBaseId: string };
    region: { startLine: number };
  };
  logicalLocations: Array<{ name: string; kind: string }>;
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: SarifLocation[];
  properties?: Record<string, unknown>;
}

function buildRules(): SarifRule[] {
  const rules: SarifRule[] = PATTERN_REGISTRY.map((def) => ({
    id: def.category,
    name: def.category
      .split("_")
      .map((w) => w[0]!.toUpperCase() + w.slice(1))
      .join(""),
    shortDescription: { text: def.description },
    defaultConfiguration: { level: sarifLevel(def.severity) },
    helpUri: "https://github.com/kholcomb/prescripts",
    properties: { tags: ["security", "supply-chain"] },
  }));

  // Advisory rule (not in PATTERN_REGISTRY — emitted from advisory API)
  rules.push({
    id: "advisory_match",
    name: "AdvisoryMatch",
    shortDescription: { text: "Known vulnerability in npm security advisory database" },
    defaultConfiguration: { level: "error" },
    helpUri: "https://www.npmjs.com/advisories",
    properties: { tags: ["security", "vulnerability", "supply-chain"] },
  });

  return rules;
}

function findingToResult(
  finding: Finding,
  pkg: PackageReport,
  ruleIndex: number
): SarifResult {
  const artifactUri = finding.source.startsWith("referenced file:")
    ? `node_modules/${pkg.name}/${finding.source.replace("referenced file: ", "")}`
    : `node_modules/${pkg.name}/package.json`;

  return {
    ruleId: finding.category,
    ruleIndex,
    level: sarifLevel(finding.severity),
    message: {
      text:
        `${pkg.name}@${pkg.version}: ${finding.category} pattern ` +
        `'${finding.pattern}' found in ${finding.source}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: artifactUri, uriBaseId: "%SRCROOT%" },
          region: { startLine: excerptStartLine(finding.excerpt.lines) },
        },
        logicalLocations: [{ name: `${pkg.name}@${pkg.version}`, kind: "module" }],
      },
    ],
  };
}

export function toSarif(report: ProjectReport): string {
  const rules = buildRules();
  const ruleIndexMap = new Map(rules.map((r, i) => [r.id, i]));

  const results: SarifResult[] = [];

  for (const pkg of report.packages) {
    // Behavioral findings
    for (const finding of pkg.findings) {
      const ruleIndex = ruleIndexMap.get(finding.category) ?? 0;
      results.push(findingToResult(finding, pkg, ruleIndex));
    }

    // Advisory findings — separate field, map to SARIF results
    for (const advisory of pkg.advisories) {
      const ruleIndex = ruleIndexMap.get("advisory_match") ?? rules.length - 1;
      const cveStr = advisory.cves.length > 0 ? ` (${advisory.cves.join(", ")})` : "";
      const cvssStr = advisory.cvssScore !== null ? ` CVSS ${advisory.cvssScore.toFixed(1)}` : "";
      results.push({
        ruleId: "advisory_match",
        ruleIndex,
        level: sarifLevel(advisory.severity),
        message: {
          text: `${pkg.name}@${pkg.version}: ${advisory.title}${cveStr}${cvssStr}. See ${advisory.url}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: `node_modules/${pkg.name}/package.json`,
                uriBaseId: "%SRCROOT%",
              },
              region: { startLine: 1 },
            },
            logicalLocations: [{ name: `${pkg.name}@${pkg.version}`, kind: "module" }],
          },
        ],
        properties: {
          advisory_id: advisory.id,
          cves: advisory.cves,
          vulnerable_versions: advisory.vulnerableVersions,
          patched_versions: advisory.patchedVersions,
          cvss_score: advisory.cvssScore,
          advisory_url: advisory.url,
        },
      });
    }
  }

  const sarif = {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "prescripts",
            version: "0.1.0",
            informationUri: "https://github.com/kholcomb/prescripts",
            rules,
          },
        },
        results,
        properties: {
          scannedAt: report.scannedAt,
          totalPackages: report.totalPackages,
          flaggedPackages: report.flaggedPackages,
        },
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

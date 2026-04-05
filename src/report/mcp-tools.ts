import type { PackageReport, ProjectReport } from "../types.js";

export const MCP_TOOL_DESCRIPTIONS: Record<string, string> = {
  scan_package:
    "Scan an npm package for lifecycle scripts before installing it. " +
    "Returns lifecycle script content, registry provenance signals, and pattern match findings.",

  scan_project:
    "Scan all packages in a project's package-lock.json for lifecycle scripts. " +
    "Returns a report of all packages with lifecycle scripts and any pattern findings.",

  compare_versions:
    "Compare lifecycle scripts and security findings between two versions of an npm package. " +
    "Returns added/removed/changed scripts, new findings introduced in toVersion, " +
    "findings resolved since fromVersion, and whether the binary download host changed. " +
    "Use this before upgrading a dependency to understand what changed in install-time behavior.",
};

function mcpReplacer(key: string, value: unknown): unknown {
  if (key === "excerpt" || key === "_warning") return undefined;
  return value;
}

export function packageReportToMcpContent(report: PackageReport): string {
  return JSON.stringify(report, mcpReplacer, 2);
}

export function projectReportToMcpContent(report: ProjectReport): string {
  return JSON.stringify(report, mcpReplacer, 2);
}

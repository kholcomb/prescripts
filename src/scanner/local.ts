/**
 * Orchestrates local file scanners (GitHub Actions, git submodules).
 *
 * These scanners produce PackageReport objects for non-registry artifacts
 * (CI workflows, embedded repos) that feed into the standard report pipeline.
 */

import type { PackageReport, ScanOptions } from "../types.js";
import { scanGithubActions } from "./github-actions.js";
import { scanGitSubmodules } from "./git-submodules.js";

export async function runLocalScanners(
  projectDir: string,
  opts: ScanOptions
): Promise<PackageReport[]> {
  const [actionReports, submodulesReport] = await Promise.all([
    scanGithubActions(projectDir, opts),
    scanGitSubmodules(projectDir, opts),
  ]);

  const reports: PackageReport[] = [...actionReports];
  if (submodulesReport) reports.push(submodulesReport);
  return reports;
}

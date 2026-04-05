/**
 * Git submodules scanner.
 *
 * Parses .gitmodules (INI format) and emits findings for:
 *   - file:// URLs (local filesystem embedding — critical)
 *   - Credentials in URL (https://user:pass@host — critical)
 *   - http:// URLs (unencrypted — high)
 *   - Mutable branch tracking (branch = main/master/HEAD — medium)
 *   - Unrecognized hosting domains (medium)
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { PackageReport, Finding, ScanOptions } from "../types.js";
import { scoreFindings, computeRisk } from "../analyzer/confidence.js";
import { emptyProvenance } from "./empty-provenance.js";

interface Submodule {
  name: string;
  path: string | null;
  url: string | null;
  branch: string | null;
}

const KNOWN_HOSTS = new Set([
  "github.com",
  "gitlab.com",
  "bitbucket.org",
  "codeberg.org",
  "sr.ht",
  "git.sr.ht",
  "salsa.debian.org",
  "framagit.org",
]);

function parseGitmodules(raw: string): Submodule[] {
  const submodules: Submodule[] = [];
  let current: Submodule | null = null;

  for (const rawLine of raw.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    // [submodule "name"] header
    const headerMatch = line.match(/^\[submodule\s+"([^"]+)"\]/i);
    if (headerMatch) {
      if (current) submodules.push(current);
      current = { name: headerMatch[1]!, path: null, url: null, branch: null };
      continue;
    }

    if (!current) continue;

    const kvMatch = line.match(/^(\w+)\s*=\s*(.+)$/);
    if (!kvMatch) continue;

    const key = kvMatch[1]!.toLowerCase();
    const val = kvMatch[2]!.trim();

    if (key === "path") current.path = val;
    else if (key === "url") current.url = val;
    else if (key === "branch") current.branch = val;
  }

  if (current) submodules.push(current);
  return submodules;
}

function findingsForSubmodule(sub: Submodule): Finding[] {
  const findings: Finding[] = [];
  const source = `.gitmodules[${sub.path ?? sub.name}]`;
  const url = sub.url ?? "";

  const make = (
    category: string,
    severity: Finding["severity"],
    pattern: string,
    lines: string
  ): Finding => ({
    scriptHook: null,
    source,
    category,
    severity,
    confidence: "medium", // will be rescored
    pattern,
    excerpt: { _warning: "UNTRUSTED THIRD-PARTY CONTENT", lines },
  });

  // file:// — local path embedding; no integrity, arbitrary local code
  if (/^file:\/\//i.test(url)) {
    findings.push(make(
      "submodule_local_url",
      "critical",
      "file:// URL in submodule",
      `url = ${url}`
    ));
  }
  // Credentials in URL: https://user:pass@host or https://:token@host
  else if (/^https?:\/\/[^@/]+:[^@/]*@/i.test(url)) {
    findings.push(make(
      "submodule_credential_url",
      "critical",
      "credentials embedded in submodule URL",
      `url = ${url.replace(/(:\/\/[^@]*@)/, "://***@")}`
    ));
  }
  // Plain http:// — unencrypted, MITM-able
  else if (/^http:\/\//i.test(url)) {
    findings.push(make(
      "submodule_insecure_url",
      "high",
      "unencrypted http:// submodule URL",
      `url = ${url}`
    ));
  }
  // Unrecognized hosting domain (only for non-file, non-credential URLs)
  else if (url) {
    try {
      const parsed = new URL(url.endsWith(".git") ? url : url);
      const host = parsed.hostname.toLowerCase();
      if (!KNOWN_HOSTS.has(host)) {
        findings.push(make(
          "submodule_unrecognized_host",
          "medium",
          `submodule hosted on unrecognized domain: ${host}`,
          `url = ${url}`
        ));
      }
    } catch {
      // unparseable URL — could be SSH shorthand like git@github.com:org/repo
      // SSH shorthand: git@<host>:<path> — extract host
      const sshMatch = url.match(/^git@([^:]+):/);
      if (sshMatch) {
        const host = sshMatch[1]!.toLowerCase();
        if (!KNOWN_HOSTS.has(host)) {
          findings.push(make(
            "submodule_unrecognized_host",
            "medium",
            `submodule hosted on unrecognized domain: ${host}`,
            `url = ${url}`
          ));
        }
      }
    }
  }

  // Mutable branch tracking (branch = main/master/HEAD or any branch)
  if (sub.branch !== null) {
    findings.push(make(
      "submodule_unpinned",
      "medium",
      `submodule tracks mutable branch: ${sub.branch}`,
      `url = ${url}\nbranch = ${sub.branch}`
    ));
  }

  return findings;
}

export async function scanGitSubmodules(
  projectDir: string,
  opts: ScanOptions
): Promise<PackageReport | null> {
  let raw: string;
  try {
    raw = await readFile(join(projectDir, ".gitmodules"), "utf-8");
  } catch {
    return null;
  }

  const submodules = parseGitmodules(raw);
  if (submodules.length === 0) return null;

  const allFindings: Finding[] = [];
  for (const sub of submodules) {
    allFindings.push(...findingsForSubmodule(sub));
  }

  if (allFindings.length === 0) return null;

  const prov = emptyProvenance();
  const scored = scoreFindings(allFindings, prov, opts.trust);
  const risk = computeRisk(scored, [], prov);

  return {
    name: ".gitmodules",
    version: "local",
    packageManager: "gitmodules",
    source: {
      type: "local",
      resolved: join(projectDir, ".gitmodules"),
      integrity: null,
      integrityVerified: false,
    },
    provenance: prov,
    lifecycleScripts: {},
    binaryDownload: null,
    advisories: [],
    findings: scored,
    risk,
  };
}

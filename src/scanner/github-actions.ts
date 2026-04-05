/**
 * GitHub Actions workflow scanner.
 *
 * Scans .github/workflows/*.yml and .github/workflows/*.yaml for:
 *   - Malicious patterns in run: blocks (reuses pattern engine)
 *   - Unpinned action references (uses: action@tag vs @sha)
 *   - Dangerous trigger: pull_request_target
 *
 * No YAML library needed — uses a line-oriented state machine.
 */

import { readFile, readdir } from "node:fs/promises";
import { join, relative } from "node:path";
import type { PackageReport, Finding, ScanOptions } from "../types.js";
import { scanPackage } from "../analyzer/scanner.js";
import { scoreFindings, computeRisk } from "../analyzer/confidence.js";
import { emptyProvenance } from "./empty-provenance.js";

interface WorkflowStep {
  jobId: string;
  stepIndex: number;
  runScript?: string;
  usesAction?: string;
}

interface WorkflowInfo {
  steps: WorkflowStep[];
  hasPullRequestTarget: boolean;
  filePath: string;
}

// ── YAML extraction ────────────────────────────────────────────────────────

/**
 * Minimal line-oriented state machine to extract `run:` blocks and `uses:` lines
 * from a GitHub Actions workflow YAML file.
 *
 * Handles:
 *   run: single-line value
 *   run: |
 *     multi
 *     line
 *   uses: actions/checkout@v4
 */
function extractWorkflowInfo(raw: string, filePath: string): WorkflowInfo {
  const lines = raw.split("\n");
  const steps: WorkflowStep[] = [];
  let hasPullRequestTarget = false;

  let currentJob = "unknown";
  let stepIndex = 0;
  let inRunBlock = false;
  let runIndent = 0;
  let runLines: string[] = [];
  let inStepBlock = false;
  let stepIndent = 0;

  function flushRun() {
    if (runLines.length > 0) {
      steps.push({
        jobId: currentJob,
        stepIndex,
        runScript: runLines.join("\n"),
      });
      runLines = [];
    }
    inRunBlock = false;
    runIndent = 0;
  }

  for (const rawLine of lines) {
    const line = rawLine.replace(/\t/g, "  "); // normalize tabs
    const trimmed = line.trimStart();
    const indent = line.length - trimmed.length;

    // Strip inline YAML comment
    const withoutComment = trimmed.replace(/\s+#.*$/, "").trimEnd();

    // Detect pull_request_target trigger (top-level)
    if (/pull_request_target/.test(withoutComment)) {
      hasPullRequestTarget = true;
    }

    // Detect job ID (e.g. "  build:" at indent 2)
    // Jobs are under "jobs:" section — look for identifier keys at indent 2
    const jobMatch = withoutComment.match(/^([a-zA-Z_][\w-]*):\s*$/);
    if (jobMatch && indent === 2) {
      if (inRunBlock) flushRun();
      currentJob = jobMatch[1]!;
      stepIndex = 0;
      inStepBlock = false;
      continue;
    }

    // Detect step start: "- name:" or "- run:" or "- uses:" at any indent
    const stepStart = trimmed.startsWith("- ");
    if (stepStart) {
      if (inRunBlock) flushRun();
      if (indent >= stepIndent || !inStepBlock) {
        stepIndex++;
        inStepBlock = true;
        stepIndent = indent;
      }
    }

    // If we're in a multi-line run block, collect lines
    if (inRunBlock) {
      if (indent > runIndent || (trimmed === "" && runLines.length > 0)) {
        // Continuation of the run block
        runLines.push(rawLine.slice(runIndent + 2)); // strip leading indent
        continue;
      } else {
        // Block ended
        flushRun();
      }
    }

    // Detect "run:" key
    const runInlineMatch = withoutComment.match(/^[-\s]*run:\s+(.+)$/);
    const runBlockMatch = withoutComment.match(/^[-\s]*run:\s*[|>-]*\s*$/);

    if (runInlineMatch) {
      steps.push({
        jobId: currentJob,
        stepIndex,
        runScript: runInlineMatch[1]!,
      });
    } else if (runBlockMatch) {
      inRunBlock = true;
      runIndent = indent + (stepStart ? 2 : 0);
      runLines = [];
    }

    // Detect "uses:" key
    const usesMatch = withoutComment.match(/^[-\s]*uses:\s+(.+)$/);
    if (usesMatch) {
      if (inRunBlock) flushRun();
      steps.push({
        jobId: currentJob,
        stepIndex,
        usesAction: usesMatch[1]!.trim(),
      });
    }
  }

  if (inRunBlock) flushRun();

  return { steps, hasPullRequestTarget, filePath };
}

// ── Findings from uses: references ────────────────────────────────────────

const SHA_PIN_RE = /^[a-fA-F0-9]{40}$/;
const SEMVER_TAG_RE = /^v?\d+(\.\d+)*$/;
const MUTABLE_REF_RE = /^(main|master|HEAD|develop|dev|latest|next|canary)$/i;

/** Trusted first-party action namespaces — not flagged for tag pinning. */
const FIRST_PARTY = new Set(["actions", "github"]);

function findingsForUsesRef(
  action: string,
  source: string
): Finding | null {
  // Docker image: docker://image:tag (without digest)
  if (action.startsWith("docker://")) {
    const hasDigest = action.includes("@sha256:");
    if (!hasDigest) {
      return {
        scriptHook: "github-actions",
        source,
        category: "unpinned_action",
        severity: "medium",
        confidence: "medium",
        pattern: "Docker image without sha256 digest",
        excerpt: { _warning: "UNTRUSTED THIRD-PARTY CONTENT", lines: `uses: ${action}` },
      };
    }
    return null;
  }

  // action/ref format: owner/repo@ref or owner/repo/path@ref
  const atIdx = action.lastIndexOf("@");
  if (atIdx === -1) return null;

  const ownerRepo = action.slice(0, atIdx);
  const ref = action.slice(atIdx + 1);
  const owner = ownerRepo.split("/")[0]!.toLowerCase();

  // SHA-pinned — safest
  if (SHA_PIN_RE.test(ref)) return null;

  // Mutable branch ref — highest risk
  if (MUTABLE_REF_RE.test(ref)) {
    return {
      scriptHook: "github-actions",
      source,
      category: "unpinned_action",
      severity: "high",
      confidence: "high",
      pattern: `action pinned to mutable ref: ${ref}`,
      excerpt: { _warning: "UNTRUSTED THIRD-PARTY CONTENT", lines: `uses: ${action}` },
    };
  }

  // Semver tag — can be force-pushed, but lower risk than branch
  if (SEMVER_TAG_RE.test(ref)) {
    // First-party actions: lower severity (GitHub controls the namespace)
    if (FIRST_PARTY.has(owner)) {
      return {
        scriptHook: "github-actions",
        source,
        category: "unpinned_action",
        severity: "low",
        confidence: "medium",
        pattern: `first-party action pinned to semver tag (not SHA): ${ref}`,
        excerpt: { _warning: "UNTRUSTED THIRD-PARTY CONTENT", lines: `uses: ${action}` },
      };
    }
    return {
      scriptHook: "github-actions",
      source,
      category: "unpinned_action",
      severity: "medium",
      confidence: "medium",
      pattern: `third-party action pinned to semver tag (not SHA): ${ref}`,
      excerpt: { _warning: "UNTRUSTED THIRD-PARTY CONTENT", lines: `uses: ${action}` },
    };
  }

  // Unknown ref format — flag as medium
  return {
    scriptHook: "github-actions",
    source,
    category: "unpinned_action",
    severity: "medium",
    confidence: "medium",
    pattern: `action pinned to unrecognized ref: ${ref}`,
    excerpt: { _warning: "UNTRUSTED THIRD-PARTY CONTENT", lines: `uses: ${action}` },
  };
}

// ── Per-workflow scan ──────────────────────────────────────────────────────

async function scanWorkflowFile(
  filePath: string,
  projectDir: string,
  opts: ScanOptions
): Promise<PackageReport | null> {
  let raw: string;
  try {
    raw = await readFile(filePath, "utf-8");
  } catch {
    return null;
  }

  const relPath = relative(projectDir, filePath);
  const info = extractWorkflowInfo(raw, filePath);
  const findings: Finding[] = [];

  for (const step of info.steps) {
    const source = `workflow: ${relPath}[${step.jobId}/step ${step.stepIndex}]`;

    if (step.runScript !== undefined) {
      // Scan the run block content with the pattern engine
      // Pass as a "preinstall" hook so all shell patterns fire
      const hooks = { "run": step.runScript };
      const { findings: patternFindings } = scanPackage(hooks, new Map(), opts.severity);
      // Relabel source to include workflow location
      for (const f of patternFindings) {
        findings.push({ ...f, scriptHook: "github-actions", source });
      }
    }

    if (step.usesAction !== undefined) {
      const f = findingsForUsesRef(step.usesAction, source);
      if (f) findings.push(f);
    }
  }

  // pull_request_target trigger finding
  if (info.hasPullRequestTarget) {
    findings.push({
      scriptHook: "github-actions",
      source: `workflow: ${relPath}`,
      category: "actions_prt",
      severity: "medium",
      confidence: "high",
      pattern: "pull_request_target trigger grants write permissions to untrusted forks",
      excerpt: {
        _warning: "UNTRUSTED THIRD-PARTY CONTENT",
        lines: "on: pull_request_target\n# This trigger runs in the context of the base repo with write access,\n# even when triggered by a fork PR.",
      },
    });
  }

  if (findings.length === 0) return null;

  const prov = emptyProvenance();
  const scored = scoreFindings(findings, prov, opts.trust);
  const risk = computeRisk(scored, [], prov);

  return {
    name: relPath,
    version: "local",
    packageManager: "actions",
    source: {
      type: "local",
      resolved: filePath,
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

// ── Public API ─────────────────────────────────────────────────────────────

export async function scanGithubActions(
  projectDir: string,
  opts: ScanOptions
): Promise<PackageReport[]> {
  const workflowDir = join(projectDir, ".github", "workflows");
  let files: string[];

  try {
    const entries = await readdir(workflowDir);
    files = entries
      .filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"))
      .map((f) => join(workflowDir, f));
  } catch {
    return [];
  }

  if (files.length === 0) return [];

  const results = await Promise.all(
    files.map((f) => scanWorkflowFile(f, projectDir, opts))
  );

  return results.filter((r): r is PackageReport => r !== null);
}

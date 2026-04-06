/**
 * Markdown renderer for diff output.
 *
 * Produces a PR-comment-friendly markdown document from a DiffResult.
 * Intended to be written to diff.md and posted via `gh pr comment --body-file`.
 */

import type { DiffResult } from "../diff.js";
import type { CompareResult } from "../analyzer/compare.js";
import type { Finding } from "../types.js";

// ── Severity emoji indicators ─────────────────────────────────────────────────

function severityBadge(severity: Finding["severity"]): string {
  switch (severity) {
    case "critical": return "🔴 critical";
    case "high":     return "🟠 high";
    case "medium":   return "🟡 medium";
    case "low":      return "🔵 low";
  }
}

// ── Summary table ─────────────────────────────────────────────────────────────

function summaryRow(c: CompareResult): string {
  const change = `${c.fromVersion} → ${c.toVersion}`;

  const scriptChanges = [
    ...c.addedScripts.map((s) => `\`${s.hook}\` added`),
    ...c.removedScripts.map((s) => `\`${s.hook}\` removed`),
    ...c.changedScripts.map((s) => `\`${s.hook}\` changed`),
  ];
  const scriptsCell = scriptChanges.length > 0 ? scriptChanges.join(", ") : "—";

  const findingsCell =
    c.newFindings.length > 0
      ? c.newFindings.map((f) => severityBadge(f.severity)).join(", ")
      : c.resolvedFindings.length > 0
      ? "✅ findings resolved"
      : "—";

  const binaryCell = c.binaryHostChanged ? "⚠️ host changed" : "—";

  return `| \`${c.name}\` | ${change} | ${scriptsCell} | ${findingsCell} | ${binaryCell} |`;
}

// ── Per-package detail ────────────────────────────────────────────────────────

function scriptDiffBlock(label: string, before: string | null, after: string | null): string {
  const lines: string[] = [`**${label}**`];
  if (before !== null) {
    lines.push(`<details><summary>before</summary>\n\n\`\`\`sh\n${before}\n\`\`\`\n</details>`);
  }
  if (after !== null) {
    lines.push(`<details><summary>after</summary>\n\n\`\`\`sh\n${after}\n\`\`\`\n</details>`);
  }
  return lines.join("\n");
}

function findingBlock(f: Finding, label: string): string {
  const badge = severityBadge(f.severity);
  const conf = f.confidence !== "high" ? ` _(${f.confidence} confidence)_` : "";
  const excerpt = f.excerpt.lines.trim()
    ? `\n\`\`\`\n${f.excerpt.lines}\n\`\`\``
    : "";
  return `- **${f.category}** ${badge}${conf}  \n  \`${f.pattern}\` in \`${f.source}\`${excerpt}`;
}

function packageDetail(c: CompareResult): string {
  const sections: string[] = [
    `### \`${c.name}\` — ${c.fromVersion} → ${c.toVersion}`,
  ];

  for (const s of c.addedScripts) {
    sections.push(scriptDiffBlock(`\`${s.hook}\` added`, null, s.after));
  }
  for (const s of c.removedScripts) {
    sections.push(scriptDiffBlock(`\`${s.hook}\` removed`, s.before, null));
  }
  for (const s of c.changedScripts) {
    sections.push(scriptDiffBlock(`\`${s.hook}\` changed`, s.before, s.after));
  }

  if (c.binaryHostChanged) {
    sections.push(
      `> ⚠️ **Binary download host changed**  \n` +
      `> before: \`${c.fromBinaryHost ?? "none"}\`  \n` +
      `> after: \`${c.toBinaryHost ?? "none"}\``
    );
  }

  if (c.newFindings.length > 0) {
    sections.push(
      `**New findings introduced in ${c.toVersion}:**\n` +
      c.newFindings.map((f) => findingBlock(f, "new")).join("\n")
    );
  }

  if (c.resolvedFindings.length > 0) {
    sections.push(
      `**Findings resolved since ${c.fromVersion}:**\n` +
      c.resolvedFindings.map((f) => `- ~~${f.category}~~ (was ${severityBadge(f.severity)})`).join("\n")
    );
  }

  return sections.join("\n\n");
}

// ── Public API ────────────────────────────────────────────────────────────────

export function renderDiffMarkdown(result: DiffResult): string {
  const { comparisons, baseRef } = result;

  if (comparisons.length === 0) {
    return `## npm-prescripts: no package version changes detected\n\n_Compared against \`${baseRef}\`._\n`;
  }

  const hasNewFindings = comparisons.some((c) => c.newFindings.length > 0);
  const hasBinaryHostChange = comparisons.some((c) => c.binaryHostChanged);
  const hasScriptChanges = comparisons.some(
    (c) => c.addedScripts.length + c.removedScripts.length + c.changedScripts.length > 0
  );

  const headline =
    hasNewFindings
      ? `## ⚠️ npm-prescripts: ${comparisons.length} package${comparisons.length === 1 ? "" : "s"} changed — new findings`
      : hasBinaryHostChange
      ? `## ⚠️ npm-prescripts: ${comparisons.length} package${comparisons.length === 1 ? "" : "s"} changed — binary host changed`
      : hasScriptChanges
      ? `## 🔍 npm-prescripts: ${comparisons.length} package${comparisons.length === 1 ? "" : "s"} changed — install scripts modified`
      : `## ✅ npm-prescripts: ${comparisons.length} package${comparisons.length === 1 ? "" : "s"} changed — no install-time changes`;

  const lines: string[] = [
    headline,
    "",
    `_Compared against \`${baseRef}\`. Ecosystems: ${result.ecosystems.join(", ")}._`,
    "",
    "| Package | Version change | Install scripts | New findings | Binary host |",
    "|---------|---------------|-----------------|--------------|-------------|",
    ...comparisons.map(summaryRow),
  ];

  // Detail blocks only for packages with something interesting to show
  const interesting = comparisons.filter(
    (c) =>
      c.addedScripts.length > 0 ||
      c.removedScripts.length > 0 ||
      c.changedScripts.length > 0 ||
      c.newFindings.length > 0 ||
      c.resolvedFindings.length > 0 ||
      c.binaryHostChanged
  );

  if (interesting.length > 0) {
    lines.push("", "---", "");
    for (const c of interesting) {
      lines.push(packageDetail(c), "");
    }
  }

  return lines.join("\n");
}

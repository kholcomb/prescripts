import type {
  Finding,
  Excerpt,
  Severity,
} from "../types.js";
import { PATTERN_REGISTRY } from "./patterns.js";

const CONTEXT_LINES = 3;

function makeExcerpt(text: string, matchIndex: number): Excerpt {
  const lines = text.split("\n");
  let charCount = 0;
  let matchLine = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (charCount + line.length >= matchIndex) {
      matchLine = i;
      break;
    }
    charCount += line.length + 1;
  }

  const start = Math.max(0, matchLine - CONTEXT_LINES);
  const end = Math.min(lines.length - 1, matchLine + CONTEXT_LINES);
  const excerptLines = lines
    .slice(start, end + 1)
    .map((l, i) => `${start + i + 1}: ${l}`)
    .join("\n");

  return {
    _warning: "UNTRUSTED THIRD-PARTY CONTENT",
    lines: excerptLines,
  };
}

function scanText(
  text: string,
  source: string,
  hook: string | null,
  minSeverity: Severity
): Finding[] {
  const findings: Finding[] = [];
  const severityOrder: Record<Severity, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
  };

  for (const patternDef of PATTERN_REGISTRY) {
    if (patternDef.patterns.length === 0) continue;
    if (severityOrder[patternDef.severity] < severityOrder[minSeverity]) {
      continue;
    }
    // sourceMatch: only apply to matching sources (e.g. pth_persistence → .pth files only)
    if (patternDef.sourceMatch && !patternDef.sourceMatch.test(source)) {
      continue;
    }
    // sourceExclude: skip for matching sources (e.g. JS patterns skip .py files)
    if (patternDef.sourceExclude && patternDef.sourceExclude.test(source)) {
      continue;
    }

    for (const regex of patternDef.patterns) {
      const match = regex.exec(text);
      if (match) {
        findings.push({
          scriptHook: hook,
          source,
          category: patternDef.category,
          severity: patternDef.severity,
          confidence: "medium", // placeholder — scored against provenance in cli.ts
          pattern: match[0],
          excerpt: makeExcerpt(text, match.index),
        });
        break; // one finding per category per source
      }
    }
  }

  return findings;
}

// Extracts filenames referenced by node/bash/sh/python in a script string
const SCRIPT_REF_PATTERN =
  /(?:node|bash|sh|python\d*)\s+([\w./\-]+\.(?:js|ts|mjs|cjs|sh|py))/g;

function extractReferencedFiles(scriptValue: string): string[] {
  const refs: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = SCRIPT_REF_PATTERN.exec(scriptValue)) !== null) {
    const ref = match[1];
    if (ref) refs.push(ref);
  }
  return refs;
}

export interface ScanResult {
  findings: Finding[];
}

export function scanPackage(
  scripts: Record<string, string>,
  fileMap: Map<string, string>,
  minSeverity: Severity
): ScanResult {
  const findings: Finding[] = [];

  for (const [hook, scriptValue] of Object.entries(scripts)) {
    // Scan the script string itself
    const scriptFindings = scanText(
      scriptValue,
      `${hook} script`,
      hook,
      minSeverity
    );
    findings.push(...scriptFindings);

    // Find and scan referenced files
    const referencedFiles = extractReferencedFiles(scriptValue);
    for (const ref of referencedFiles) {
      // Try exact match and common path variations
      const candidates = [ref, ref.replace(/^\.\//, "")];
      for (const candidate of candidates) {
        const content = fileMap.get(candidate);
        if (content) {
          const fileFindings = scanText(
            content,
            `referenced file: ${candidate}`,
            hook,
            minSeverity
          );
          findings.push(...fileFindings);
          break;
        }
      }
    }
  }

  // Deduplicate: same category + source combination
  const seen = new Set<string>();
  const deduped = findings.filter((f) => {
    const key = `${f.category}::${f.source}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Co-occurrence elevation: env_probe + network in the same hook → synthesize critical finding
  const hooks = new Set(deduped.map((f) => f.scriptHook));
  for (const hook of hooks) {
    const forHook = deduped.filter((f) => f.scriptHook === hook);
    const hasEnvProbe = forHook.some((f) => f.category === "env_probe");
    const hasNetwork = forHook.some(
      (f) => f.category === "network" || f.category === "dns_exfil"
    );
    if (hasEnvProbe && hasNetwork) {
      const networkFinding = forHook.find(
        (f) => f.category === "network" || f.category === "dns_exfil"
      )!;
      deduped.push({
        scriptHook: hook,
        source: networkFinding.source,
        category: "env_exfil",
        severity: "critical",
        confidence: "medium",
        pattern: "(env_probe + network co-occurrence)",
        excerpt: networkFinding.excerpt,
      });
    }
  }

  return { findings: deduped };
}

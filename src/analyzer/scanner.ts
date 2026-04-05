import type {
  Finding,
  Excerpt,
  Severity,
} from "../types.js";
import { PATTERN_REGISTRY, SEVERITY_ORDER } from "./patterns.js";
import type { PatternDef } from "./patterns.js";

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

// ── Source type classification ────────────────────────────────────────────────

// Representative source strings for each distinct pattern-guard bucket.
// Each is chosen so that running it through the sourceMatch/sourceExclude
// guards in PATTERN_REGISTRY produces the correct applicable set.
// Order in classifySource() matters: more specific checks come first.
const SOURCE_TYPE_KEYS = [
  "postinstall script",  // JS/npm lifecycle scripts and .js files (default)
  "setup.py",            // Python source files (.py, setup.*, pyproject, .cfg)
  "file.pth",            // Python .pth persistence files (site-packages hook)
  "build.rs",            // Rust build scripts — superset of .rs, includes cargo_unsafe
  "file.rs",             // Other Rust source files
  "file.gemspec",        // Ruby gemspec files
  "file.rb",             // Ruby source files
  "rubygems_plugin.rb",  // Ruby plugin hook (executes on every gem command)
] as const;

type SourceTypeKey = typeof SOURCE_TYPE_KEYS[number];

/**
 * Maps a source string (lifecycle hook name or referenced file path) to the
 * canonical bucket key used for pattern pre-grouping.
 */
function classifySource(source: string): SourceTypeKey {
  if (/\.pth\b/.test(source))             return "file.pth";
  if (/rubygems_plugin\.rb/.test(source)) return "rubygems_plugin.rb";
  if (/build\.rs\b/.test(source))         return "build.rs";
  if (/\.py\b|setup\.(?:py|cfg)\b|pyproject|\.cfg\b/.test(source)) return "setup.py";
  if (/\.rs\b/.test(source))              return "file.rs";
  if (/\.gemspec\b/.test(source))         return "file.gemspec";
  if (/\.rb\b/.test(source))             return "file.rb";
  return "postinstall script";
}

/**
 * Pre-computed pattern subsets, built once at module load.
 * Indexed as PATTERN_LOOKUP[minSeverity][sourceTypeKey].
 *
 * Eliminates the per-pattern sourceMatch / sourceExclude guard checks
 * from the scan hot path — each scanText() call resolves its source
 * to a bucket and iterates only the applicable subset.
 */
const PATTERN_LOOKUP = (() => {
  const lookup = new Map<Severity, Map<SourceTypeKey, readonly PatternDef[]>>();
  for (const severity of ["critical", "high", "medium", "low"] as Severity[]) {
    const bySource = new Map<SourceTypeKey, readonly PatternDef[]>();
    for (const sourceKey of SOURCE_TYPE_KEYS) {
      bySource.set(
        sourceKey,
        PATTERN_REGISTRY.filter((def) => {
          if (def.patterns.length === 0) return false;
          if (SEVERITY_ORDER[def.severity] < SEVERITY_ORDER[severity]) return false;
          if (def.sourceMatch && !def.sourceMatch.test(sourceKey)) return false;
          if (def.sourceExclude && def.sourceExclude.test(sourceKey)) return false;
          return true;
        })
      );
    }
    lookup.set(severity, bySource);
  }
  return lookup;
})();

// ── Scanner ───────────────────────────────────────────────────────────────────

function scanText(
  text: string,
  source: string,
  hook: string | null,
  minSeverity: Severity
): Finding[] {
  const findings: Finding[] = [];
  const sourceKey = classifySource(source);
  const applicablePatterns = PATTERN_LOOKUP.get(minSeverity)!.get(sourceKey)!;

  for (const patternDef of applicablePatterns) {
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

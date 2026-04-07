/**
 * Go module hook extraction.
 *
 * Go has no install-time hooks in the npm sense, but three mechanisms can
 * execute code in ways a developer consuming the package may not expect:
 *
 * 1. //go:generate directives — `go generate ./...` runs them explicitly, but
 *    automated tooling and CI often does this without inspecting the commands.
 *
 * 2. import "C" (CGO) — enables C interop; C code in the CGO preamble compiles
 *    and links into the binary. C preamble runs at init time.
 *
 * 3. func init() — runs automatically when a package is imported. init()
 *    functions that perform network requests, spawn processes, or write files
 *    are a supply-chain attack vector (e.g. malicious init() exfiltrating
 *    environment variables).
 *
 * This extractor returns a hooks map keyed by a descriptive label and valued
 * by the relevant code snippet, so the pattern scanner can run against them.
 */

/**
 * Extract security-relevant hooks from Go source files.
 *
 * @param fileMap  Map of relPath → content from the module extraction.
 * @returns hooks  Record<hookLabel, codeSnippet> for pattern scanning.
 */
export function extractGoHooks(fileMap: Map<string, string>): Record<string, string> {
  const hooks: Record<string, string> = {};

  for (const [filePath, content] of fileMap) {
    if (!filePath.endsWith(".go")) continue;

    extractGenerateDirectives(filePath, content, hooks);
    extractCgoBlocks(filePath, content, hooks);
    extractInitFunctions(filePath, content, hooks);
  }

  return hooks;
}

// ── //go:generate extraction ─────────────────────────────────────────────────

function extractGenerateDirectives(
  filePath: string,
  content: string,
  hooks: Record<string, string>
): void {
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    const m = line.match(/^\/\/go:generate\s+(.+)$/);
    if (m?.[1]) {
      // Key: "go:generate:<path>:<linenum>" — unique even if a file has multiple directives
      const key = `go:generate:${filePath}:${i + 1}`;
      hooks[key] = m[1].trim();
    }
  }
}

// ── CGO preamble extraction ───────────────────────────────────────────────────

function extractCgoBlocks(
  filePath: string,
  content: string,
  hooks: Record<string, string>
): void {
  // CGO: preamble comment block immediately before `import "C"`
  // Pattern: lines starting with "// " or "/*" immediately before import "C"
  const importCRe = /^import\s+"C"\s*$/m;
  const match = importCRe.exec(content);
  if (!match) return;

  // Collect the comment block that precedes import "C"
  const before = content.slice(0, match.index);
  const lines = before.split("\n");

  const preambleLines: string[] = [];
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i] ?? "";
    if (line.startsWith("//") || line.startsWith("/*") || line.startsWith(" *") || line.trim() === "") {
      preambleLines.unshift(line);
    } else {
      break;
    }
  }

  // Include the import "C" line itself so pattern matcher sees it
  const snippet = [...preambleLines, `import "C"`].join("\n").trim();
  if (snippet) {
    hooks[`cgo:${filePath}`] = snippet;
  }
}

// ── init() body extraction ────────────────────────────────────────────────────

// Patterns that make an init() body interesting from a security standpoint
const INIT_DANGEROUS_PATTERNS = [
  /\bexec\.Command\b/,
  /\bexec\.CommandContext\b/,
  /\bos\.StartProcess\b/,
  /\bsyscall\.Exec\b/,
  /\bnet\.Dial\b/,
  /\bhttp\.Get\b/,
  /\bhttp\.Post\b/,
  /\bhttp\.NewRequest\b/,
  /\bos\.WriteFile\b/,
  /\bioutil\.WriteFile\b/,
  /\bos\.OpenFile\b/,
  /\bos\.Getenv\b/,
  /\bos\.Environ\b/,
];

function extractInitFunctions(
  filePath: string,
  content: string,
  hooks: Record<string, string>
): void {
  // Find all `func init()` declarations and extract their bodies.
  // This is a best-effort brace-counting approach — not a full parser.
  const funcInitRe = /\bfunc\s+init\s*\(\s*\)/g;
  let match: RegExpExecArray | null;

  let initIdx = 0;
  while ((match = funcInitRe.exec(content)) !== null) {
    const bodyStart = content.indexOf("{", match.index);
    if (bodyStart === -1) continue;

    const body = extractBraceBlock(content, bodyStart);
    if (!body) continue;

    // Only flag if the init body contains dangerous patterns
    const isDangerous = INIT_DANGEROUS_PATTERNS.some((re) => re.test(body));
    if (!isDangerous) continue;

    initIdx++;
    hooks[`init:${filePath}:${initIdx}`] = body;
  }
}

/**
 * Extract a brace-delimited block starting at `openBraceIndex`.
 * Returns the full block including the braces, or null on unbalanced input.
 */
function extractBraceBlock(content: string, openBraceIndex: number): string | null {
  let depth = 0;
  let inString = false;
  let inRune = false;
  let inLineComment = false;
  let inBlockComment = false;
  let i = openBraceIndex;

  while (i < content.length) {
    const ch = content[i]!;
    const next = content[i + 1];

    if (inLineComment) {
      if (ch === "\n") inLineComment = false;
      i++;
      continue;
    }
    if (inBlockComment) {
      if (ch === "*" && next === "/") { inBlockComment = false; i += 2; continue; }
      i++;
      continue;
    }
    if (inString) {
      if (ch === "\\") { i += 2; continue; }
      if (ch === '"') inString = false;
      i++;
      continue;
    }
    if (inRune) {
      if (ch === "\\") { i += 2; continue; }
      if (ch === "'") inRune = false;
      i++;
      continue;
    }

    if (ch === "/" && next === "/") { inLineComment = true; i += 2; continue; }
    if (ch === "/" && next === "*") { inBlockComment = true; i += 2; continue; }
    if (ch === '"') { inString = true; i++; continue; }
    if (ch === "'") { inRune = true; i++; continue; }
    if (ch === "`") {
      // raw string literal — scan to closing backtick
      i++;
      while (i < content.length && content[i] !== "`") i++;
      i++;
      continue;
    }

    if (ch === "{") { depth++; i++; continue; }
    if (ch === "}") {
      depth--;
      i++;
      if (depth === 0) {
        return content.slice(openBraceIndex, i);
      }
      continue;
    }

    i++;
  }

  return null; // unbalanced braces
}

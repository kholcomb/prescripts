/**
 * Maven plugin configuration hook extraction.
 *
 * Maven's threat model differs from npm: dependencies don't run code at
 * download time, but Maven plugins execute arbitrary code during the build
 * lifecycle. This extractor scans pom.xml content for dangerous plugin
 * configurations.
 *
 * Dangerous plugins:
 *   - exec-maven-plugin (org.codehaus.mojo) — runs arbitrary executables
 *   - maven-antrun-plugin — runs Ant build scripts (can exec shell commands)
 *   - groovy-maven-plugin / gmaven-plugin — executes Groovy code
 *   - Any <plugin> with <executable> or <commandlineArgs> configurations
 *
 * Returns a hooks map keyed by "plugin:<artifactId>:<phase>" with the
 * relevant XML configuration block as the value, for pattern scanning.
 *
 * Also scans the bundled POM from inside a JAR (META-INF/maven/.../pom.xml)
 * to detect plugins declared by the dependency itself.
 */

const DANGEROUS_PLUGINS = new Set([
  "exec-maven-plugin",
  "maven-antrun-plugin",
  "groovy-maven-plugin",
  "gmaven-plugin",
]);

const DANGEROUS_CONFIG_PATTERNS = [
  /<executable>/,
  /<commandlineArgs>/,
];

/**
 * Extract dangerous plugin configurations from pom.xml content.
 * Works on both project pom.xml and dependency-bundled pom.xml files.
 *
 * @param content  Raw XML content of a pom.xml file.
 * @param source   Label for the hook key (e.g. "pom.xml" or "META-INF/maven/g/a/pom.xml").
 * @returns hooks  Record<hookLabel, xmlSnippet> for pattern scanning.
 */
export function extractMavenHooks(
  content: string,
  source: string = "pom.xml"
): Record<string, string> {
  const hooks: Record<string, string> = {};

  // Extract all <plugin> blocks from <build><plugins> section
  const pluginBlockRe = /<plugin>([\s\S]*?)<\/plugin>/g;
  let match: RegExpExecArray | null;
  let pluginIdx = 0;

  while ((match = pluginBlockRe.exec(content)) !== null) {
    const block = match[1] ?? "";

    const artifactId = extractXmlTag(block, "artifactId");
    if (!artifactId) continue;

    const isDangerous = DANGEROUS_PLUGINS.has(artifactId.toLowerCase()) ||
      DANGEROUS_CONFIG_PATTERNS.some((re) => re.test(block));

    if (!isDangerous) continue;

    const phase = extractPhase(block) ?? "default";
    pluginIdx++;
    const key = `plugin:${artifactId}:${phase}:${pluginIdx}:${source}`;
    // Store the full plugin block as the hook value for pattern scanning
    hooks[key] = `<plugin>${block}</plugin>`;
  }

  return hooks;
}

/**
 * Extract maven hooks from a file map (e.g. from a JAR's extracted contents).
 * Processes META-INF/maven/**\/pom.xml files.
 */
export function extractMavenHooksFromFileMap(
  fileMap: Map<string, string>
): Record<string, string> {
  const hooks: Record<string, string> = {};

  for (const [path, content] of fileMap) {
    if (!path.endsWith("pom.xml")) continue;
    const fileHooks = extractMavenHooks(content, path);
    Object.assign(hooks, fileHooks);
  }

  return hooks;
}

// ── XML helpers ───────────────────────────────────────────────────────────────

function extractXmlTag(block: string, tag: string): string | null {
  const re = new RegExp(`<${tag}[^>]*>([^<]+)</${tag}>`);
  const m = re.exec(block);
  return m?.[1]?.trim() ?? null;
}

/**
 * Extract the lifecycle phase from an <execution> block within a plugin config.
 */
function extractPhase(block: string): string | null {
  const m = block.match(/<phase>([^<]+)<\/phase>/);
  return m?.[1]?.trim() ?? null;
}

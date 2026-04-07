/**
 * NuGet MSBuild hook extractor.
 *
 * NuGet packages can include MSBuild files that execute during `dotnet build`:
 *   build/{packageId}.targets  — target definitions
 *   build/{packageId}.props    — property/import definitions
 *   buildMultiTargeting/       — multi-targeting variants
 *
 * The primary risk vector is <Exec Command="..." /> in a <Target> block.
 * This is equivalent to npm's postinstall — it runs arbitrary shell commands
 * during the consumer's build, not at package install time.
 *
 * Also included: tools/*.ps1 / *.cmd / *.bat — PowerShell and batch scripts
 * that can be invoked during package install in older nuget.exe workflows.
 *
 * Return format: { "<filepath>:<TargetName>": "<Exec element xml>" }
 * For PowerShell/batch: { "<filepath>": "<full script content>" }
 */

/**
 * Extract build-time hooks from a .nupkg fileMap.
 * Called by NuGetPlugin.extractHooks().
 */
export function extractNugetHooksFromFileMap(fileMap: Map<string, string>): Record<string, string> {
  const hooks: Record<string, string> = {};

  for (const [path, content] of fileMap) {
    const lower = path.toLowerCase();

    if (lower.endsWith(".targets") || lower.endsWith(".props")) {
      extractMsbuildExec(path, content, hooks);
    }

    if (lower.endsWith(".ps1") || lower.endsWith(".cmd") || lower.endsWith(".bat")) {
      if (content.trim()) {
        hooks[path] = content;
      }
    }
  }

  return hooks;
}

/**
 * Extract <Exec Command="..."> elements from a .targets or .props file.
 * Exported for unit testing.
 */
export function extractMsbuildExec(
  filePath: string,
  xml: string,
  hooks: Record<string, string> = {}
): Record<string, string> {
  // Find all <Exec ...> elements — self-closing or with children
  const execRe = /<Exec\b[^>]*>/gi;
  let m: RegExpExecArray | null;

  while ((m = execRe.exec(xml)) !== null) {
    const execElement = m[0];
    const targetName = findEnclosingTargetName(xml, m.index);
    const key = targetName ? `${filePath}:${targetName}` : filePath;

    // Avoid duplicate keys by appending an index suffix
    let finalKey = key;
    let i = 1;
    while (finalKey in hooks) {
      finalKey = `${key}[${i++}]`;
    }

    hooks[finalKey] = execElement;
  }

  return hooks;
}

/**
 * Walk backwards from `offset` in `xml` to find the Name attribute of the
 * nearest enclosing <Target> element.
 */
function findEnclosingTargetName(xml: string, offset: number): string | null {
  // Find the last <Target ...> before offset
  const before = xml.slice(0, offset);
  const lastTargetIdx = before.lastIndexOf("<Target");
  if (lastTargetIdx < 0) return null;

  // Check it wasn't closed before our position
  const between = before.slice(lastTargetIdx);
  if (between.includes("</Target>")) return null;

  const nameM = xml.slice(lastTargetIdx).match(/\bName="([^"]+)"/i);
  return nameM?.[1] ?? null;
}

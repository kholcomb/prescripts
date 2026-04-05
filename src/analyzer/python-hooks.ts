/**
 * Extracts Python install hooks from an extracted package for security scanning.
 *
 * Python "lifecycle" equivalents:
 *
 *   setup.py         — Executed with `python setup.py install` on older packages.
 *                      Arbitrary Python, runs at install time. The primary attack surface.
 *
 *   pyproject.toml   — Build system configuration. Custom build hooks (hatch, flit,
 *                      setuptools cmdclass, etc.) can run arbitrary Python.
 *
 *   *.pth files      — Python path configuration files placed in site-packages.
 *                      Processed at EVERY Python startup after install, not just at
 *                      install time. Lines starting with "import" are executed as code.
 *                      This was the attack vector in the ctx/Python-utils campaign (2022).
 *
 * Returns a Record<string, string> matching the LifecycleScripts shape:
 *   key   = hook name (displayed in terminal output)
 *   value = short command/description string (scanner follows file refs via fileMap)
 *
 * The actual file content is in the fileMap and gets scanned when the scanner
 * resolves "python setup.py" → looks up "setup.py" in fileMap.
 */

/**
 * Extracts Python install hooks from the extracted package.
 *
 * @param fileMap  - Map of relative file paths to content from the extracted package.
 * @returns Record mapping hook name → command/description string for display + scanning.
 */
export function extractPythonHooks(
  fileMap: Map<string, string>
): Record<string, string> {
  const hooks: Record<string, string> = {};

  // setup.py — runs at install time (pip install .)
  if (fileMap.has("setup.py")) {
    hooks["setup.py"] = "python setup.py install";
  }

  // pyproject.toml build hooks — scan for dynamic hook configurations
  const pyproject = fileMap.get("pyproject.toml");
  if (pyproject) {
    const buildHookContent = extractBuildHookSection(pyproject);
    if (buildHookContent) {
      hooks["pyproject.toml [build-hooks]"] = buildHookContent;
    }
  }

  // .pth files — each one runs at Python startup after install
  // These are persistence mechanisms. Legitimate .pth files contain only filesystem paths.
  // Malicious ones contain "import" statements or exec() calls.
  for (const [path, content] of fileMap) {
    if (!path.endsWith(".pth")) continue;
    const filename = path.split("/").pop() ?? path;
    // Show first non-empty line as the "command" for display
    const firstLine = content.split("\n").find((l) => l.trim()) ?? "(empty)";
    hooks[`${filename} [.pth persistence]`] = content;
    void firstLine; // used above for display, content is the actual scan target
  }

  // setup.cfg — may contain [options.entry_points] or [distutils.commands]
  if (fileMap.has("setup.cfg")) {
    const cfg = fileMap.get("setup.cfg")!;
    const scriptSection = extractSetupCfgScripts(cfg);
    if (scriptSection) {
      hooks["setup.cfg [entry-points/scripts]"] = scriptSection;
    }
  }

  return hooks;
}

/**
 * Extracts the build hook configuration section from pyproject.toml content.
 * Returns the relevant section text, or null if no custom build hooks are present.
 *
 * Focuses on sections that indicate custom code execution at build time:
 * - [tool.hatch.build.hooks.*]
 * - [tool.setuptools.cmdclass] or [build-system] with setuptools
 * - [tool.flit....]
 * - [tool.meson-python.args] (runs meson, which can run custom code)
 */
function extractBuildHookSection(pyproject: string): string | null {
  const lines = pyproject.split("\n");
  const hookSections: string[] = [];
  let inHookSection = false;
  let sectionContent: string[] = [];

  const hookSectionPatterns = [
    /^\[tool\.hatch\.build\.hooks/,
    /^\[tool\.setuptools\.cmdclass/,
    /^\[tool\.pdm\.build/,
    /^\[tool\.poetry\.scripts/,  // scripts that run on install
    /^\[build-system\]/,
  ];

  for (const line of lines) {
    if (line.startsWith("[")) {
      if (inHookSection && sectionContent.length > 0) {
        hookSections.push(sectionContent.join("\n"));
      }
      inHookSection = hookSectionPatterns.some((p) => p.test(line));
      sectionContent = inHookSection ? [line] : [];
    } else if (inHookSection) {
      sectionContent.push(line);
    }
  }

  if (inHookSection && sectionContent.length > 0) {
    hookSections.push(sectionContent.join("\n"));
  }

  return hookSections.length > 0 ? hookSections.join("\n\n") : null;
}

/**
 * Extracts potentially interesting sections from setup.cfg:
 * [options.entry_points] — scripts that run when the package is invoked
 * [distutils.commands] — custom build commands
 */
function extractSetupCfgScripts(cfg: string): string | null {
  const lines = cfg.split("\n");
  const interesting: string[] = [];
  let inSection = false;
  let sectionContent: string[] = [];

  const interestingSections = [
    /^\[options\.entry_points\]/,
    /^\[distutils\.commands\]/,
    /^\[options\.scripts\]/,
  ];

  for (const line of lines) {
    if (line.startsWith("[")) {
      if (inSection && sectionContent.length > 1) {
        interesting.push(sectionContent.join("\n"));
      }
      inSection = interestingSections.some((p) => p.test(line));
      sectionContent = inSection ? [line] : [];
    } else if (inSection) {
      sectionContent.push(line);
    }
  }

  if (inSection && sectionContent.length > 1) {
    interesting.push(sectionContent.join("\n"));
  }

  return interesting.length > 0 ? interesting.join("\n\n") : null;
}

/**
 * Returns true if the package has any Python install hooks.
 */
export function hasPythonHooks(hooks: Record<string, string>): boolean {
  return Object.keys(hooks).length > 0;
}

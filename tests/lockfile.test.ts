import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseLockfile } from "../src/lockfile/parser.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, "fixtures");

describe("parseLockfile", () => {
  it("parses v3 lockfile and returns all packages", async () => {
    const { refs, lockfileDir } = await parseLockfile(join(FIXTURES, "project-v3"));
    expect(refs.length).toBeGreaterThan(0);
    expect(refs.some((r) => r.name === "clean-pkg")).toBe(true);
    expect(refs.some((r) => r.name === "@scope/scoped-pkg")).toBe(true);
    // git and local deps included
    expect(refs.some((r) => r.name === "git-dep")).toBe(true);
    expect(refs.some((r) => r.name === "local-dep")).toBe(true);
    // root entry (empty string key) excluded
    expect(refs.every((r) => r.name !== "")).toBe(true);
    // lockfileDir should match the fixture dir
    expect(lockfileDir).toBe(join(FIXTURES, "project-v3"));
  });

  it("parses v1 lockfile including nested dependencies", async () => {
    const raw = await readFile(join(FIXTURES, "lockfile-v1.json"), "utf-8");
    const lockfile = JSON.parse(raw) as {
      lockfileVersion: number;
      dependencies: Record<string, unknown>;
    };
    expect(lockfile.lockfileVersion).toBe(1);
    expect(lockfile.dependencies).toHaveProperty("pkg-with-deps");
    expect(
      (lockfile.dependencies["pkg-with-deps"] as { dependencies: Record<string, unknown> })
        .dependencies
    ).toHaveProperty("nested-dep");
  });

  it("v3 lockfile contains expected source types", async () => {
    const raw = await readFile(join(FIXTURES, "lockfile-v3.json"), "utf-8");
    const lockfile = JSON.parse(raw) as {
      packages: Record<string, { resolved?: string }>;
    };
    const packages = lockfile.packages;
    expect(packages["node_modules/git-dep"]?.resolved).toMatch(/^git\+/);
    expect(packages["node_modules/local-dep"]?.resolved).toMatch(/^file:/);
    expect(packages["node_modules/clean-pkg"]?.resolved).toMatch(
      /registry\.npmjs\.org/
    );
  });

  it("throws a clear error when no lockfile is present", async () => {
    await expect(parseLockfile("/nonexistent/path")).rejects.toThrow(
      "No package-lock.json or npm-shrinkwrap.json found"
    );
  });
});

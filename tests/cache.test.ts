import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DiskCache } from "../src/cache/disk-cache.js";

describe("DiskCache", () => {
  let tmpDir: string;
  let cache: DiskCache;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), "npm-prescripts-test-"));
    cache = new DiskCache(tmpDir);
  });

  it("returns false for isCached on empty cache", async () => {
    const result = await cache.isCached("lodash", "sha512-abc123", "4.17.21");
    expect(result).toBe(false);
  });

  it("round-trips a package through write/read", async () => {
    const extracted = {
      packageJson: { name: "test-pkg", version: "1.0.0", scripts: { postinstall: "echo hi" } },
      fileMap: new Map([["index.js", "// hello\n"]]),
    };

    await cache.write("test-pkg", "1.0.0", "sha512-testHash==", "registry", extracted);

    const isCached = await cache.isCached("test-pkg", "sha512-testHash==", "1.0.0");
    expect(isCached).toBe(true);

    const result = await cache.read("test-pkg", "sha512-testHash==", "1.0.0");
    expect(result).not.toBeNull();
    expect(result?.meta.name).toBe("test-pkg");
    expect(result?.meta.version).toBe("1.0.0");
    expect(result?.meta.sourceType).toBe("registry");
    expect(result?.extracted.packageJson["name"]).toBe("test-pkg");
    expect(result?.extracted.fileMap.get("index.js")).toBe("// hello\n");
  });

  it("returns null for read on cache miss", async () => {
    const result = await cache.read("missing", "sha512-nope", "0.0.0");
    expect(result).toBeNull();
  });

  it("uses fallback key when integrity is null", async () => {
    const extracted = {
      packageJson: { name: "no-integrity", version: "1.0.0" },
      fileMap: new Map<string, string>(),
    };
    await cache.write("no-integrity", "1.0.0", null, "git", extracted);
    const isCached = await cache.isCached("no-integrity", null, "1.0.0");
    expect(isCached).toBe(true);
  });
});

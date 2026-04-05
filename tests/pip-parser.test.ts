import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { parsePipLockfile, hasPipLockfile } from "../src/lockfile/pip-parser.js";

async function withTmpDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "prescripts-pip-"));
  try {
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

describe("parseRequirementsTxt", () => {
  it("parses simple pinned packages", async () => {
    await withTmpDir(async (dir) => {
      await writeFile(join(dir, "requirements.txt"), [
        "requests==2.28.0",
        "flask==2.3.1",
      ].join("\n"));
      const result = await parsePipLockfile(dir);
      expect(result).not.toBeNull();
      expect(result!.refs.some((r) => r.name === "requests" && r.version === "2.28.0")).toBe(true);
      expect(result!.refs.some((r) => r.name === "flask" && r.version === "2.3.1")).toBe(true);
    });
  });

  it("extracts --hash=sha256: as integrity", async () => {
    await withTmpDir(async (dir) => {
      await writeFile(join(dir, "requirements.txt"),
        "requests==2.28.0 --hash=sha256:0f90c7b1" + "a".repeat(56) + "\n"
      );
      const result = await parsePipLockfile(dir);
      expect(result).not.toBeNull();
      const req = result!.refs.find((r) => r.name === "requests");
      expect(req).toBeDefined();
      expect(req!.integrity).toMatch(/^sha256:[a-f0-9]{64}$/);
    });
  });

  it("handles backslash line continuations with hashes", async () => {
    await withTmpDir(async (dir) => {
      const hash = "a".repeat(64);
      await writeFile(join(dir, "requirements.txt"),
        `requests==2.28.0 \\\n    --hash=sha256:${hash}\n`
      );
      const result = await parsePipLockfile(dir);
      expect(result).not.toBeNull();
      const req = result!.refs.find((r) => r.name === "requests");
      expect(req).toBeDefined();
      expect(req!.integrity).toBe(`sha256:${hash}`);
    });
  });

  it("skips -r includes, URLs, and VCS entries", async () => {
    await withTmpDir(async (dir) => {
      await writeFile(join(dir, "requirements.txt"), [
        "-r base.txt",
        "https://example.com/package.whl",
        "git+https://github.com/org/repo.git@main#egg=mypkg",
        "./local/path",
        "requests==2.28.0",
      ].join("\n"));
      const result = await parsePipLockfile(dir);
      expect(result).not.toBeNull();
      expect(result!.refs).toHaveLength(1);
      expect(result!.refs[0]!.name).toBe("requests");
    });
  });

  it("strips environment markers", async () => {
    await withTmpDir(async (dir) => {
      await writeFile(join(dir, "requirements.txt"),
        'requests==2.28.0 ; python_version >= "3.8"\n'
      );
      const result = await parsePipLockfile(dir);
      expect(result).not.toBeNull();
      expect(result!.refs[0]!.version).toBe("2.28.0");
    });
  });

  it("normalizes underscores to hyphens in package names", async () => {
    await withTmpDir(async (dir) => {
      await writeFile(join(dir, "requirements.txt"), "my_package==1.0.0\n");
      const result = await parsePipLockfile(dir);
      expect(result!.refs[0]!.name).toBe("my-package");
    });
  });
});

describe("findRequirementsFiles — project-wide discovery", () => {
  it("discovers requirements files in subdirectories", async () => {
    await withTmpDir(async (dir) => {
      await mkdir(join(dir, "requirements"));
      await mkdir(join(dir, "backend"));
      await writeFile(join(dir, "requirements.txt"), "requests==2.28.0\n");
      await writeFile(join(dir, "requirements", "dev.txt"), "pytest==7.4.0\n");
      await writeFile(join(dir, "requirements", "prod.txt"), "gunicorn==21.2.0\n");
      await writeFile(join(dir, "backend", "requirements.txt"), "django==4.2.0\n");

      const result = await parsePipLockfile(dir);
      expect(result).not.toBeNull();
      const names = result!.refs.map((r) => r.name);
      expect(names).toContain("requests");
      expect(names).toContain("pytest");
      expect(names).toContain("gunicorn");
      expect(names).toContain("django");
    });
  });

  it("deduplicates packages that appear in multiple files", async () => {
    await withTmpDir(async (dir) => {
      await mkdir(join(dir, "requirements"));
      await writeFile(join(dir, "requirements.txt"), "requests==2.28.0\n");
      await writeFile(join(dir, "requirements", "prod.txt"), "requests==2.28.0\nflask==2.3.1\n");

      const result = await parsePipLockfile(dir);
      expect(result).not.toBeNull();
      const requestsEntries = result!.refs.filter((r) => r.name === "requests");
      expect(requestsEntries).toHaveLength(1);
    });
  });

  it("skips node_modules and .venv directories", async () => {
    await withTmpDir(async (dir) => {
      await mkdir(join(dir, "node_modules", "some-pkg"), { recursive: true });
      await mkdir(join(dir, ".venv", "lib"), { recursive: true });
      await writeFile(join(dir, "node_modules", "some-pkg", "requirements.txt"), "requests==1.0.0\n");
      await writeFile(join(dir, ".venv", "lib", "requirements.txt"), "pip==23.0.0\n");
      await writeFile(join(dir, "requirements.txt"), "flask==2.3.1\n");

      const result = await parsePipLockfile(dir);
      expect(result).not.toBeNull();
      expect(result!.refs).toHaveLength(1);
      expect(result!.refs[0]!.name).toBe("flask");
    });
  });

  it("hasPipLockfile returns true when requirements.txt exists anywhere", async () => {
    await withTmpDir(async (dir) => {
      await mkdir(join(dir, "services", "api"), { recursive: true });
      await writeFile(join(dir, "services", "api", "requirements.txt"), "flask==2.3.1\n");
      expect(await hasPipLockfile(dir)).toBe(true);
    });
  });
});

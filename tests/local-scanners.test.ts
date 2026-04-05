import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile, mkdir, rm } from "node:fs/promises";
import { join, tmpdir } from "node:path";
import { tmpdir as osTmpdir } from "node:os";
import { scanGitSubmodules } from "../src/scanner/git-submodules.js";
import { scanGithubActions } from "../src/scanner/github-actions.js";
import { DEFAULT_TRUST } from "../src/analyzer/confidence.js";
import type { ScanOptions } from "../src/types.js";

const BASE_OPTS: ScanOptions = {
  severity: "low",
  minRisk: "low",
  onlyFlagged: false,
  concurrency: 4,
  registry: "https://registry.npmjs.org",
  noCache: true,
  cacheDir: null,
  depth: 0,
  timeout: 10000,
  verbose: false,
  json: false,
  sarif: false,
  outputDir: null,
  apiUrl: null,
  trust: DEFAULT_TRUST,
};

async function withTmpDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(osTmpdir(), "prescripts-test-"));
  try {
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

// ── Git submodules ────────────────────────────────────────────────────────────

describe("scanGitSubmodules", () => {
  it("returns null when no .gitmodules exists", async () => {
    await withTmpDir(async (dir) => {
      const result = await scanGitSubmodules(dir, BASE_OPTS);
      expect(result).toBeNull();
    });
  });

  it("returns null when .gitmodules has no findings", async () => {
    await withTmpDir(async (dir) => {
      await writeFile(join(dir, ".gitmodules"), `
[submodule "vendor/lib"]
    path = vendor/lib
    url = https://github.com/user/repo.git
`);
      const result = await scanGitSubmodules(dir, BASE_OPTS);
      expect(result).toBeNull();
    });
  });

  it("detects file:// URL as critical", async () => {
    await withTmpDir(async (dir) => {
      await writeFile(join(dir, ".gitmodules"), `
[submodule "local-lib"]
    path = local-lib
    url = file:///tmp/myrepo
`);
      const result = await scanGitSubmodules(dir, BASE_OPTS);
      expect(result).not.toBeNull();
      expect(result!.findings.some((f) => f.category === "submodule_local_url")).toBe(true);
      const f = result!.findings.find((f) => f.category === "submodule_local_url")!;
      expect(f.severity).toBe("critical");
    });
  });

  it("detects credentials in URL as critical", async () => {
    await withTmpDir(async (dir) => {
      await writeFile(join(dir, ".gitmodules"), `
[submodule "private"]
    path = private
    url = https://user:s3cr3t@github.com/org/repo.git
`);
      const result = await scanGitSubmodules(dir, BASE_OPTS);
      expect(result).not.toBeNull();
      expect(result!.findings.some((f) => f.category === "submodule_credential_url")).toBe(true);
      // Credentials should be redacted in excerpt
      const f = result!.findings.find((f) => f.category === "submodule_credential_url")!;
      expect(f.excerpt.lines).not.toContain("s3cr3t");
    });
  });

  it("detects http:// as high severity", async () => {
    await withTmpDir(async (dir) => {
      await writeFile(join(dir, ".gitmodules"), `
[submodule "legacy"]
    path = legacy
    url = http://github.com/org/repo.git
`);
      const result = await scanGitSubmodules(dir, BASE_OPTS);
      expect(result).not.toBeNull();
      expect(result!.findings.some((f) => f.category === "submodule_insecure_url")).toBe(true);
      const f = result!.findings.find((f) => f.category === "submodule_insecure_url")!;
      expect(f.severity).toBe("high");
    });
  });

  it("detects mutable branch tracking as medium", async () => {
    await withTmpDir(async (dir) => {
      await writeFile(join(dir, ".gitmodules"), `
[submodule "tracked"]
    path = tracked
    url = https://github.com/org/repo.git
    branch = main
`);
      const result = await scanGitSubmodules(dir, BASE_OPTS);
      expect(result).not.toBeNull();
      expect(result!.findings.some((f) => f.category === "submodule_unpinned")).toBe(true);
      const f = result!.findings.find((f) => f.category === "submodule_unpinned")!;
      expect(f.severity).toBe("medium");
    });
  });

  it("detects unrecognized hosting domain", async () => {
    await withTmpDir(async (dir) => {
      await writeFile(join(dir, ".gitmodules"), `
[submodule "custom"]
    path = custom
    url = https://mygitserver.internal/org/repo.git
`);
      const result = await scanGitSubmodules(dir, BASE_OPTS);
      expect(result).not.toBeNull();
      expect(result!.findings.some((f) => f.category === "submodule_unrecognized_host")).toBe(true);
    });
  });

  it("packageManager is 'gitmodules'", async () => {
    await withTmpDir(async (dir) => {
      await writeFile(join(dir, ".gitmodules"), `
[submodule "test"]
    path = test
    url = http://github.com/org/repo.git
`);
      const result = await scanGitSubmodules(dir, BASE_OPTS);
      expect(result!.packageManager).toBe("gitmodules");
    });
  });
});

// ── GitHub Actions ────────────────────────────────────────────────────────────

describe("scanGithubActions", () => {
  it("returns empty array when no .github/workflows exists", async () => {
    await withTmpDir(async (dir) => {
      const results = await scanGithubActions(dir, BASE_OPTS);
      expect(results).toHaveLength(0);
    });
  });

  it("returns empty array when workflows have no findings", async () => {
    await withTmpDir(async (dir) => {
      const wfDir = join(dir, ".github", "workflows");
      await mkdir(wfDir, { recursive: true });
      await writeFile(join(wfDir, "ci.yml"), `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675
      - run: echo "hello"
`);
      const results = await scanGithubActions(dir, BASE_OPTS);
      expect(results).toHaveLength(0);
    });
  });

  it("detects pipe_exec pattern in run block", async () => {
    await withTmpDir(async (dir) => {
      const wfDir = join(dir, ".github", "workflows");
      await mkdir(wfDir, { recursive: true });
      await writeFile(join(wfDir, "deploy.yml"), `
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: curl https://example.com/install.sh | bash
`);
      const results = await scanGithubActions(dir, BASE_OPTS);
      expect(results.length).toBeGreaterThan(0);
      const allFindings = results.flatMap((r) => r.findings);
      expect(allFindings.some((f) => f.category === "pipe_exec")).toBe(true);
    });
  });

  it("detects unpinned action with mutable branch ref as high", async () => {
    await withTmpDir(async (dir) => {
      const wfDir = join(dir, ".github", "workflows");
      await mkdir(wfDir, { recursive: true });
      await writeFile(join(wfDir, "build.yml"), `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action@main
`);
      const results = await scanGithubActions(dir, BASE_OPTS);
      expect(results.length).toBeGreaterThan(0);
      const f = results.flatMap((r) => r.findings).find((f) => f.category === "unpinned_action");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("high");
    });
  });

  it("does not flag SHA-pinned actions", async () => {
    await withTmpDir(async (dir) => {
      const wfDir = join(dir, ".github", "workflows");
      await mkdir(wfDir, { recursive: true });
      await writeFile(join(wfDir, "build.yml"), `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675
      - uses: some-org/some-action@b94d27b9938d30b26b9947b8c5c33b9bf06dd4e5
`);
      const results = await scanGithubActions(dir, BASE_OPTS);
      expect(results).toHaveLength(0);
    });
  });

  it("detects pull_request_target trigger", async () => {
    await withTmpDir(async (dir) => {
      const wfDir = join(dir, ".github", "workflows");
      await mkdir(wfDir, { recursive: true });
      await writeFile(join(wfDir, "pr.yml"), `
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675
`);
      const results = await scanGithubActions(dir, BASE_OPTS);
      expect(results.length).toBeGreaterThan(0);
      const f = results.flatMap((r) => r.findings).find((f) => f.category === "actions_prt");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("medium");
    });
  });

  it("flags semver-pinned third-party actions as medium", async () => {
    await withTmpDir(async (dir) => {
      const wfDir = join(dir, ".github", "workflows");
      await mkdir(wfDir, { recursive: true });
      await writeFile(join(wfDir, "build.yml"), `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: third-party/action@v2.3.1
`);
      const results = await scanGithubActions(dir, BASE_OPTS);
      const f = results.flatMap((r) => r.findings).find((f) => f.category === "unpinned_action");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("medium");
    });
  });

  it("packageManager is 'actions'", async () => {
    await withTmpDir(async (dir) => {
      const wfDir = join(dir, ".github", "workflows");
      await mkdir(wfDir, { recursive: true });
      await writeFile(join(wfDir, "ci.yml"), `
on: push
jobs:
  ci:
    runs-on: ubuntu-latest
    steps:
      - uses: my-org/my-action@main
`);
      const results = await scanGithubActions(dir, BASE_OPTS);
      expect(results.length).toBeGreaterThan(0);
      expect(results[0]!.packageManager).toBe("actions");
    });
  });
});

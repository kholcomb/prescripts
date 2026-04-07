import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fetchOsvAdvisories } from "../src/registry/osv-client.js";
import type { PackageRef } from "../src/types.js";

function makeRef(name: string, version: string, integrity: string | null = null): PackageRef {
  return { name, version, resolved: "", integrity };
}

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULNS_BASE = "https://api.osv.dev/v1/vulns";

/**
 * Simulates the two-phase OSV API:
 *   - POST to batch URL → returns stubs (id only)
 *   - GET to /v1/vulns/{id} → returns full vuln object
 *
 * Accepts the same full-vuln structure that tests already define.
 */
function mockFetch(batchBody: { results: Array<{ vulns?: Array<{ id: string; [k: string]: unknown }> }> }): void {
  const vulnById = new Map<string, unknown>();
  for (const entry of batchBody.results) {
    for (const vuln of entry.vulns ?? []) {
      vulnById.set(vuln.id, vuln);
    }
  }
  const stubResults = batchBody.results.map((r) => ({
    vulns: (r.vulns ?? []).map((v) => ({ id: v.id })),
  }));

  vi.stubGlobal("fetch", vi.fn().mockImplementation(async (url: string) => {
    if (url.startsWith(OSV_VULNS_BASE + "/")) {
      const id = url.slice(OSV_VULNS_BASE.length + 1);
      const vuln = vulnById.get(id);
      return { ok: !!vuln, json: async () => vuln };
    }
    // Batch endpoint
    return { ok: true, json: async () => ({ results: stubResults }) };
  }));
}

beforeEach(() => vi.stubGlobal("fetch", vi.fn()));
afterEach(() => vi.unstubAllGlobals());

// Minimal OSV vuln with a SEMVER range: >=2.0.0 <2.28.2
const SEMVER_VULN = {
  id: "PYSEC-2023-74",
  aliases: ["CVE-2023-32681"],
  summary: "Requests forwards proxy-authorization to destination servers",
  affected: [{
    ranges: [{
      type: "SEMVER",
      events: [{ introduced: "2.0.0" }, { fixed: "2.28.2" }],
    }],
  }],
  database_specific: { severity: "MODERATE" },
};

// Go-style vuln: versions use v-prefix, OSV events use bare semver (no v)
const GO_VULN = {
  id: "GO-2024-1234",
  summary: "Vulnerability in golang.org/x/net",
  affected: [{
    ranges: [{
      type: "SEMVER",
      events: [{ introduced: "0" }, { fixed: "0.38.0" }],
    }],
  }],
  database_specific: { severity: "HIGH" },
};

// Vuln matched only by exact versions list
const EXACT_VERSION_VULN = {
  id: "GHSA-abcd-1234-efgh",
  summary: "Exact version match",
  affected: [{ versions: ["1.0.0", "1.0.1"] }],
  database_specific: { severity: "HIGH" },
};

describe("fetchOsvAdvisories — Go v-prefix version matching", () => {
  it("matches a v-prefixed version within the vulnerable range", async () => {
    mockFetch({ results: [{ vulns: [GO_VULN] }] });
    const result = await fetchOsvAdvisories([makeRef("golang.org/x/net", "v0.37.0")], "Go");
    expect(result.has("golang.org/x/net@v0.37.0")).toBe(true);
  });

  it("excludes a v-prefixed version at or after the fixed point", async () => {
    mockFetch({ results: [{ vulns: [GO_VULN] }] });
    const result = await fetchOsvAdvisories([makeRef("golang.org/x/net", "v0.38.0")], "Go");
    expect(result.has("golang.org/x/net@v0.38.0")).toBe(false);
  });

  it("matches a v-prefixed version against introduced: 0 (from the beginning)", async () => {
    mockFetch({ results: [{ vulns: [GO_VULN] }] });
    const result = await fetchOsvAdvisories([makeRef("golang.org/x/net", "v0.1.0")], "Go");
    expect(result.has("golang.org/x/net@v0.1.0")).toBe(true);
  });
});

describe("fetchOsvAdvisories — SEMVER range matching", () => {
  it("matches a version within the vulnerable range", async () => {
    mockFetch({ results: [{ vulns: [SEMVER_VULN] }] });
    const result = await fetchOsvAdvisories([makeRef("requests", "2.27.1")], "PyPI");
    expect(result.has("requests@2.27.1")).toBe(true);
  });

  it("excludes a version at or after the fixed point", async () => {
    mockFetch({ results: [{ vulns: [SEMVER_VULN] }] });
    const result = await fetchOsvAdvisories([makeRef("requests", "2.28.2")], "PyPI");
    expect(result.has("requests@2.28.2")).toBe(false);
  });

  it("excludes a version before the introduced point", async () => {
    mockFetch({ results: [{ vulns: [SEMVER_VULN] }] });
    const result = await fetchOsvAdvisories([makeRef("requests", "1.9.0")], "PyPI");
    expect(result.has("requests@1.9.0")).toBe(false);
  });
});

describe("fetchOsvAdvisories — exact version list matching", () => {
  it("matches a version in the exact list", async () => {
    mockFetch({ results: [{ vulns: [EXACT_VERSION_VULN] }] });
    const result = await fetchOsvAdvisories([makeRef("mypkg", "1.0.0")], "PyPI");
    expect(result.has("mypkg@1.0.0")).toBe(true);
  });

  it("excludes a version not in the exact list", async () => {
    mockFetch({ results: [{ vulns: [EXACT_VERSION_VULN] }] });
    const result = await fetchOsvAdvisories([makeRef("mypkg", "1.0.2")], "PyPI");
    expect(result.has("mypkg@1.0.2")).toBe(false);
  });
});

describe("fetchOsvAdvisories — field mapping", () => {
  it("maps advisory fields to AdvisoryMatch correctly", async () => {
    mockFetch({ results: [{ vulns: [SEMVER_VULN] }] });
    const result = await fetchOsvAdvisories([makeRef("requests", "2.27.1")], "PyPI");
    const advisory = result.get("requests@2.27.1")?.[0];
    expect(advisory).toBeDefined();
    expect(advisory!.id).toBe("PYSEC-2023-74");
    expect(advisory!.severity).toBe("medium"); // MODERATE → medium
    expect(advisory!.cves).toEqual(["CVE-2023-32681"]);
    expect(advisory!.vulnerableVersions).toBe(">=2.0.0 <2.28.2");
    expect(advisory!.patchedVersions).toBe(">=2.28.2");
    expect(advisory!.url).toBe("https://osv.dev/vulnerability/PYSEC-2023-74");
  });

  it("maps HIGH database_specific severity", async () => {
    mockFetch({ results: [{ vulns: [EXACT_VERSION_VULN] }] });
    const result = await fetchOsvAdvisories([makeRef("mypkg", "1.0.0")], "PyPI");
    expect(result.get("mypkg@1.0.0")?.[0]?.severity).toBe("high");
  });
});

describe("fetchOsvAdvisories — integrity key", () => {
  it("adds integrity secondary key when ref has integrity hash", async () => {
    mockFetch({ results: [{ vulns: [SEMVER_VULN] }] });
    const ref = makeRef("requests", "2.27.1", "sha256-abc123==");
    const result = await fetchOsvAdvisories([ref], "PyPI");
    expect(result.has("requests@2.27.1")).toBe(true);
    expect(result.has("requests@sha256-abc123==")).toBe(true);
  });
});

describe("fetchOsvAdvisories — resilience", () => {
  it("returns empty map on network failure without throwing", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network error")));
    const result = await fetchOsvAdvisories([makeRef("requests", "2.27.1")], "PyPI");
    expect(result.size).toBe(0);
  });

  it("returns empty map on non-ok HTTP response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false }));
    const result = await fetchOsvAdvisories([makeRef("requests", "2.27.1")], "PyPI");
    expect(result.size).toBe(0);
  });

  it("returns empty map when vulns array is empty", async () => {
    mockFetch({ results: [{ vulns: [] }] });
    const result = await fetchOsvAdvisories([makeRef("requests", "2.27.1")], "PyPI");
    expect(result.size).toBe(0);
  });

  it("sends queries in parallel array matching refs order", async () => {
    mockFetch({ results: [{ vulns: [] }, { vulns: [SEMVER_VULN] }] });
    const refs = [makeRef("safe-pkg", "1.0.0"), makeRef("requests", "2.27.1")];
    const result = await fetchOsvAdvisories(refs, "PyPI");
    expect(result.has("safe-pkg@1.0.0")).toBe(false);
    expect(result.has("requests@2.27.1")).toBe(true);
  });
});

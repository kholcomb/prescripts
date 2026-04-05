/**
 * Tests for advisory version matching and SHA-keyed secondary lookup.
 *
 * Key invariant: an advisory covering <=0.24.2 must appear on the vulnerable
 * version but NOT on a patched version in the same lockfile, even when both
 * are queried in the same bulk API request.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fetchAdvisories } from "../src/registry/advisory.js";
import type { PackageRef } from "../src/types.js";

// Minimal advisory response from the npm bulk API
const MOCK_ADVISORY = {
  id: 1102341,
  url: "https://github.com/advisories/GHSA-67mh-4wv8-2f99",
  title: "Dev server CORS bypass",
  severity: "moderate" as const,
  vulnerable_versions: "<=0.24.2",
  patched_versions: ">=0.24.3",
  cves: ["CVE-2024-12345"],
  cvss: { score: 5.3 },
};

const PUBLIC_REGISTRY = "https://registry.npmjs.org";

function makeRef(name: string, version: string, integrity: string | null = null): PackageRef {
  return { name, version, resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`, integrity };
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function mockFetch(responseBody: unknown): void {
  (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
    ok: true,
    json: async () => responseBody,
  });
}

describe("fetchAdvisories — version matching", () => {
  it("applies advisory only to the vulnerable version, not the patched one", async () => {
    mockFetch({ mypkg: [MOCK_ADVISORY] });

    const refs = [
      makeRef("mypkg", "0.21.5"), // vulnerable: <=0.24.2
      makeRef("mypkg", "0.27.7"), // patched: >0.24.2
    ];

    const result = await fetchAdvisories(refs, PUBLIC_REGISTRY);

    expect(result.has("mypkg@0.21.5")).toBe(true);
    expect(result.has("mypkg@0.27.7")).toBe(false);
  });

  it("advisory on the exact boundary version (0.24.2) is included", async () => {
    mockFetch({ mypkg: [MOCK_ADVISORY] });

    const refs = [makeRef("mypkg", "0.24.2")];
    const result = await fetchAdvisories(refs, PUBLIC_REGISTRY);

    expect(result.has("mypkg@0.24.2")).toBe(true);
  });

  it("advisory on the first patched version (0.24.3) is excluded", async () => {
    mockFetch({ mypkg: [MOCK_ADVISORY] });

    const refs = [makeRef("mypkg", "0.24.3")];
    const result = await fetchAdvisories(refs, PUBLIC_REGISTRY);

    expect(result.has("mypkg@0.24.3")).toBe(false);
  });

  it("maps advisory fields correctly", async () => {
    mockFetch({ mypkg: [MOCK_ADVISORY] });

    const refs = [makeRef("mypkg", "0.21.5")];
    const result = await fetchAdvisories(refs, PUBLIC_REGISTRY);

    const advisory = result.get("mypkg@0.21.5")?.[0];
    expect(advisory).toBeDefined();
    expect(advisory!.id).toBe("1102341");
    expect(advisory!.severity).toBe("medium"); // "moderate" mapped to "medium"
    expect(advisory!.vulnerableVersions).toBe("<=0.24.2");
    expect(advisory!.patchedVersions).toBe(">=0.24.3");
    expect(advisory!.cves).toEqual(["CVE-2024-12345"]);
    expect(advisory!.cvssScore).toBe(5.3);
  });

  it("returns empty map for non-public registries", async () => {
    const refs = [makeRef("mypkg", "0.21.5")];
    const result = await fetchAdvisories(refs, "https://private.registry.example.com");

    expect(result.size).toBe(0);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("returns empty map on network failure without throwing", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("network error"));

    const refs = [makeRef("mypkg", "0.21.5")];
    const result = await fetchAdvisories(refs, PUBLIC_REGISTRY);

    expect(result.size).toBe(0);
  });
});

describe("fetchAdvisories — SHA secondary key", () => {
  it("also keys result by name@integrity when ref has an integrity hash", async () => {
    mockFetch({ mypkg: [MOCK_ADVISORY] });

    const integrity = "sha512-abc123==";
    const refs = [makeRef("mypkg", "0.21.5", integrity)];
    const result = await fetchAdvisories(refs, PUBLIC_REGISTRY);

    // Both version key and SHA key should be present
    expect(result.has("mypkg@0.21.5")).toBe(true);
    expect(result.has(`mypkg@${integrity}`)).toBe(true);

    // Both point to the same advisory
    expect(result.get("mypkg@0.21.5")).toEqual(result.get(`mypkg@${integrity}`));
  });

  it("does not add SHA key when ref has no integrity hash", async () => {
    mockFetch({ mypkg: [MOCK_ADVISORY] });

    const refs = [makeRef("mypkg", "0.21.5", null)];
    const result = await fetchAdvisories(refs, PUBLIC_REGISTRY);

    expect(result.has("mypkg@0.21.5")).toBe(true);
    // Only the version key — no null/undefined SHA key added
    expect(result.size).toBe(1);
  });

  it("SHA key is absent for the patched version even if it has an integrity hash", async () => {
    mockFetch({ mypkg: [MOCK_ADVISORY] });

    const refs = [makeRef("mypkg", "0.27.7", "sha512-patched==")];
    const result = await fetchAdvisories(refs, PUBLIC_REGISTRY);

    expect(result.has("mypkg@0.27.7")).toBe(false);
    expect(result.has("mypkg@sha512-patched==")).toBe(false);
    expect(result.size).toBe(0);
  });
});

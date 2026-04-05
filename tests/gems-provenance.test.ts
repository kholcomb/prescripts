/**
 * Smoke tests for RubyGems provenance signals — maintainerCount.
 *
 * RubyGems does not expose a per-version published_by field, so
 * publisherIsNewToPackage and publisherInMaintainers remain null.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { gemPlugin } from "../src/ecosystem/gem.js";
import type { PackageRef, ScanOptions } from "../src/types.js";

vi.mock("../src/registry/rubygems-client.js", () => ({
  fetchGemsMeta: vi.fn(),
  fetchGemsOwners: vi.fn(),
  fetchGemBytes: vi.fn(),
  resolveGemLatestVersion: vi.fn(),
  setGemsTimeout: vi.fn(),
}));

import { fetchGemsMeta, fetchGemsOwners } from "../src/registry/rubygems-client.js";

const BASE_META = {
  downloadUrl: "https://rubygems.org/gems/rails-7.1.0.gem",
  sha256: "sha256:abc123",
  uploadTime: "2023-10-05T00:00:00Z",
  yanked: false,
  totalVersions: 200,
  firstUploadTime: "2005-12-13T00:00:00Z",
  authors: "David Heinemeier Hansson",
};

const REF: PackageRef = { name: "rails", version: "7.1.0", resolved: "", integrity: null };
const OPTS = {} as ScanOptions;

beforeEach(() => {
  vi.mocked(fetchGemsMeta).mockResolvedValue(BASE_META);
  vi.mocked(fetchGemsOwners).mockResolvedValue(["dhh", "tenderlove", "rafaelfranca"]);
});

afterEach(() => vi.resetAllMocks());

describe("gem fetchProvenance — maintainerCount", () => {
  it("sets maintainerCount from owners array length", async () => {
    const result = await gemPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.maintainerCount).toBe(3);
  });

  it("sets maintainerCount: null when owners fetch returns empty", async () => {
    vi.mocked(fetchGemsOwners).mockResolvedValue([]);
    const result = await gemPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.maintainerCount).toBeNull();
  });

  it("fetches meta and owners in parallel (both are called)", async () => {
    await gemPlugin.fetchProvenance(REF, OPTS);
    expect(fetchGemsMeta).toHaveBeenCalledWith("rails", "7.1.0");
    expect(fetchGemsOwners).toHaveBeenCalledWith("rails");
  });

  it("returns empty provenance when meta is unavailable", async () => {
    vi.mocked(fetchGemsMeta).mockResolvedValue(null);
    const result = await gemPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.unavailableReason).toBe("RubyGems metadata unavailable");
    expect(result.provenance.maintainerCount).toBeNull();
  });
});

describe("gem fetchProvenance — signals not available without per-version publisher", () => {
  it("sets publisherIsNewToPackage: null (no per-version published_by in RubyGems API)", async () => {
    const result = await gemPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.publisherIsNewToPackage).toBeNull();
  });

  it("sets publisherInMaintainers: null (no per-version published_by in RubyGems API)", async () => {
    const result = await gemPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.publisherInMaintainers).toBeNull();
  });

  it("sets publisher from gem authors field", async () => {
    const result = await gemPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.publisher).toBe("David Heinemeier Hansson");
  });
});

/**
 * Smoke tests for crates.io provenance signals — publisher, maintainerCount,
 * publisherInMaintainers, and publisherIsNewToPackage.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { cargoPlugin } from "../src/ecosystem/cargo.js";
import type { PackageRef, ScanOptions } from "../src/types.js";

vi.mock("../src/registry/cratesio-client.js", () => ({
  fetchCratesMeta: vi.fn(),
  fetchCratesOwners: vi.fn(),
  fetchCrateBytes: vi.fn(),
  resolveCratesLatestVersion: vi.fn(),
  setCratesTimeout: vi.fn(),
}));

import { fetchCratesMeta, fetchCratesOwners } from "../src/registry/cratesio-client.js";

const BASE_META = {
  downloadUrl: "https://static.crates.io/crates/serde/serde-1.0.195.crate",
  sha256: "sha256:abc123",
  uploadTime: "2024-01-15T12:00:00Z",
  yanked: false,
  totalVersions: 150,
  firstUploadTime: "2015-01-01T00:00:00Z",
  publisher: "dtolnay",
  previousPublishers: ["dtolnay"],
};

const REF: PackageRef = { name: "serde", version: "1.0.195", resolved: "", integrity: null };
const OPTS = {} as ScanOptions;

beforeEach(() => {
  vi.mocked(fetchCratesMeta).mockResolvedValue(BASE_META);
  vi.mocked(fetchCratesOwners).mockResolvedValue(["dtolnay", "erickt"]);
});

afterEach(() => vi.resetAllMocks());

describe("cargo fetchProvenance — publisher", () => {
  it("sets publisher from meta.publisher", async () => {
    const result = await cargoPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.publisher).toBe("dtolnay");
  });

  it("sets publisher: null when meta.publisher is null", async () => {
    vi.mocked(fetchCratesMeta).mockResolvedValue({ ...BASE_META, publisher: null });
    const result = await cargoPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.publisher).toBeNull();
  });

  it("returns empty provenance when meta is unavailable", async () => {
    vi.mocked(fetchCratesMeta).mockResolvedValue(null);
    const result = await cargoPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.unavailableReason).toBe("crates.io metadata unavailable");
    expect(result.provenance.publisher).toBeNull();
  });
});

describe("cargo fetchProvenance — maintainerCount", () => {
  it("sets maintainerCount from owners array length", async () => {
    const result = await cargoPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.maintainerCount).toBe(2);
  });

  it("sets maintainerCount: null when owners fetch returns empty", async () => {
    vi.mocked(fetchCratesOwners).mockResolvedValue([]);
    const result = await cargoPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.maintainerCount).toBeNull();
  });
});

describe("cargo fetchProvenance — publisherInMaintainers", () => {
  it("sets publisherInMaintainers: true when publisher is a current owner", async () => {
    const result = await cargoPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.publisherInMaintainers).toBe(true);
  });

  it("sets publisherInMaintainers: false when publisher is not a current owner", async () => {
    vi.mocked(fetchCratesOwners).mockResolvedValue(["erickt", "someone-else"]);
    const result = await cargoPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.publisherInMaintainers).toBe(false);
  });

  it("sets publisherInMaintainers: null when publisher is unknown", async () => {
    vi.mocked(fetchCratesMeta).mockResolvedValue({ ...BASE_META, publisher: null });
    const result = await cargoPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.publisherInMaintainers).toBeNull();
  });

  it("sets publisherInMaintainers: null when owners fetch returns empty", async () => {
    vi.mocked(fetchCratesOwners).mockResolvedValue([]);
    const result = await cargoPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.publisherInMaintainers).toBeNull();
  });
});

describe("cargo fetchProvenance — publisherIsNewToPackage", () => {
  it("sets publisherIsNewToPackage: false when publisher has published before", async () => {
    // BASE_META.previousPublishers includes "dtolnay"
    const result = await cargoPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.publisherIsNewToPackage).toBe(false);
  });

  it("sets publisherIsNewToPackage: true when publisher has never published this crate", async () => {
    vi.mocked(fetchCratesMeta).mockResolvedValue({
      ...BASE_META,
      publisher: "new-contributor",
      previousPublishers: ["dtolnay", "erickt"],
    });
    const result = await cargoPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.publisherIsNewToPackage).toBe(true);
  });

  it("sets publisherIsNewToPackage: true when previousPublishers is empty (first ever publish)", async () => {
    vi.mocked(fetchCratesMeta).mockResolvedValue({
      ...BASE_META,
      publisher: "dtolnay",
      previousPublishers: [],
    });
    const result = await cargoPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.publisherIsNewToPackage).toBe(true);
  });

  it("sets publisherIsNewToPackage: null when publisher is unknown", async () => {
    vi.mocked(fetchCratesMeta).mockResolvedValue({ ...BASE_META, publisher: null });
    const result = await cargoPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.publisherIsNewToPackage).toBeNull();
  });
});

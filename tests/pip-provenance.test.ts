/**
 * Smoke tests for pip plugin fetchProvenance — attestation wiring (segment 3).
 *
 * We test the integration between fetchPyPIMeta, fetchPyPIProvenance, and
 * parsePyPIAttestation as wired in pip.ts. Full parser correctness is covered
 * in pypi-attestation.test.ts; full OSV coverage in osv-advisory.test.ts.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { pipPlugin } from "../src/ecosystem/pip.js";
import type { PackageRef, ScanOptions } from "../src/types.js";

// Mock registry clients — no real network calls
vi.mock("../src/registry/pypi-client.js", () => ({
  fetchPyPIMeta: vi.fn(),
  fetchPyPIProvenance: vi.fn(),
  resolvePyPILatestVersion: vi.fn(),
  fetchWithProxyRaw: vi.fn(),
  setPyPITimeout: vi.fn(),
}));

vi.mock("../src/registry/pypi-attestation.js", () => ({
  parsePyPIAttestation: vi.fn(),
}));

import { fetchPyPIMeta, fetchPyPIProvenance } from "../src/registry/pypi-client.js";
import { parsePyPIAttestation } from "../src/registry/pypi-attestation.js";

const BASE_META = {
  tarballUrl: "https://files.pythonhosted.org/packages/requests-2.31.0.tar.gz",
  sha256: "sha256:abc123",
  uploadTime: "2023-05-22T15:00:00Z",
  yanked: false,
  yankedReason: null,
  totalVersions: 80,
  firstUploadTime: "2011-02-14T00:00:00Z",
  maintainer: "Kenneth Reitz",
  author: "Kenneth Reitz",
  previousVersion: "2.30.0",
};

const ATTESTATION_INFO = {
  sourceRepo: "psf/requests",
  buildWorkflow: ".github/workflows/publish.yml",
  predicateType: "https://slsa.dev/provenance/v1",
  subjectIntegrity: "sha256-abc==",
  sigstoreVerified: true,
  signingIdentity: "https://github.com/psf/requests/.github/workflows/publish.yml@refs/tags/v2.31.0",
  sigstoreErrors: null,
};

const REF: PackageRef = { name: "requests", version: "2.31.0", resolved: "", integrity: null };
const OPTS = {} as ScanOptions;

beforeEach(() => {
  vi.mocked(fetchPyPIMeta).mockResolvedValue(BASE_META);
  vi.mocked(fetchPyPIProvenance).mockResolvedValue({ version: 1, attestation_bundles: [] });
  vi.mocked(parsePyPIAttestation).mockResolvedValue(null);
});

afterEach(() => vi.resetAllMocks());

describe("pip fetchProvenance — attestationRegressed", () => {
  it("sets attestationRegressed: false when current version has attestation", async () => {
    vi.mocked(parsePyPIAttestation).mockResolvedValue(ATTESTATION_INFO);
    const result = await pipPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.attestationRegressed).toBe(false);
    // Should not fetch previous version — regression impossible when current has attestation
    expect(fetchPyPIProvenance).toHaveBeenCalledTimes(1); // only current version
  });

  it("sets attestationRegressed: null when no previous version exists", async () => {
    vi.mocked(parsePyPIAttestation).mockResolvedValue(null);
    vi.mocked(fetchPyPIMeta).mockResolvedValue({ ...BASE_META, previousVersion: null });
    const result = await pipPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.attestationRegressed).toBeNull();
  });

  it("sets attestationRegressed: true when previous version had attestation", async () => {
    vi.mocked(parsePyPIAttestation).mockResolvedValue(null);
    vi.mocked(fetchPyPIMeta)
      .mockResolvedValueOnce({ ...BASE_META, previousVersion: "2.30.0" }) // current
      .mockResolvedValueOnce({ ...BASE_META, tarballUrl: "https://files.pythonhosted.org/packages/requests-2.30.0.tar.gz" }); // previous
    vi.mocked(fetchPyPIProvenance)
      .mockResolvedValueOnce(null)                                       // current: no attestation
      .mockResolvedValueOnce({ version: 1, attestation_bundles: [{}] }); // previous: had attestation
    const result = await pipPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.attestationRegressed).toBe(true);
  });

  it("sets attestationRegressed: false when previous version also lacks attestation", async () => {
    vi.mocked(parsePyPIAttestation).mockResolvedValue(null);
    vi.mocked(fetchPyPIMeta)
      .mockResolvedValueOnce({ ...BASE_META, previousVersion: "2.30.0" })
      .mockResolvedValueOnce({ ...BASE_META, tarballUrl: "https://files.pythonhosted.org/packages/requests-2.30.0.tar.gz" });
    vi.mocked(fetchPyPIProvenance)
      .mockResolvedValueOnce(null)   // current: no attestation
      .mockResolvedValueOnce(null);  // previous: also no attestation
    const result = await pipPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.attestationRegressed).toBe(false);
  });

  it("sets attestationRegressed: null when previous version metadata is unavailable", async () => {
    vi.mocked(parsePyPIAttestation).mockResolvedValue(null);
    vi.mocked(fetchPyPIMeta)
      .mockResolvedValueOnce({ ...BASE_META, previousVersion: "2.30.0" })
      .mockResolvedValueOnce(null); // previous version fetch fails
    const result = await pipPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.attestationRegressed).toBeNull();
  });
});

describe("pip fetchProvenance — attestation wiring", () => {
  it("calls fetchPyPIProvenance with the filename extracted from tarballUrl", async () => {
    await pipPlugin.fetchProvenance(REF, OPTS);
    expect(fetchPyPIProvenance).toHaveBeenCalledWith(
      "requests",
      "2.31.0",
      "requests-2.31.0.tar.gz"
    );
  });

  it("passes fetchPyPIProvenance result to parsePyPIAttestation", async () => {
    const raw = { version: 1, attestation_bundles: [{ publisher: {}, attestations: [] }] };
    vi.mocked(fetchPyPIProvenance).mockResolvedValue(raw);
    await pipPlugin.fetchProvenance(REF, OPTS);
    expect(parsePyPIAttestation).toHaveBeenCalledWith(raw);
  });

  it("sets attestation: null in provenance when no attestation exists", async () => {
    vi.mocked(parsePyPIAttestation).mockResolvedValue(null);
    const result = await pipPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.attestation).toBeNull();
  });

  it("sets attestation in provenance when parser returns AttestationInfo", async () => {
    vi.mocked(parsePyPIAttestation).mockResolvedValue(ATTESTATION_INFO);
    const result = await pipPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.attestation).toEqual(ATTESTATION_INFO);
  });

  it("uses attestation sourceRepo as publisher when attestation is present", async () => {
    vi.mocked(parsePyPIAttestation).mockResolvedValue(ATTESTATION_INFO);
    const result = await pipPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.publisher).toBe("psf/requests");
  });

  it("falls back to meta maintainer as publisher when attestation is absent", async () => {
    vi.mocked(parsePyPIAttestation).mockResolvedValue(null);
    const result = await pipPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.publisher).toBe("Kenneth Reitz");
  });

  it("returns empty provenance when fetchPyPIMeta fails", async () => {
    vi.mocked(fetchPyPIMeta).mockResolvedValue(null);
    const result = await pipPlugin.fetchProvenance(REF, OPTS);
    expect(result.provenance.unavailableReason).toBe("PyPI metadata unavailable");
    expect(fetchPyPIProvenance).not.toHaveBeenCalled();
  });
});

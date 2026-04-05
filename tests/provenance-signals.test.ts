/**
 * Tests for the five npm security/provenance signals:
 * 1. Manifest confusion (tarball scripts ≠ registry manifest scripts)
 * 2. Provenance regression (attestation dropped from previous version)
 * 3. Deprecated version flag
 * 4. Publisher not in maintainers
 * 5. Registry signature presence
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { fetchProvenance } from "../src/registry/metadata.js";
import * as client from "../src/registry/client.js";
import * as attestationMod from "../src/registry/attestation.js";

// Minimal FullPackageMeta factory
function makeMeta(overrides: Record<string, unknown> = {}) {
  return {
    versions: {
      "1.0.0": {
        scripts: { postinstall: "node setup.js" },
        deprecated: undefined as string | undefined,
        _npmUser: { name: "alice" },
        dist: {
          tarball: "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
          integrity: "sha512-abc==",
          signatures: [{ keyid: "SHA256:...", sig: "abc123" }],
          attestations: { url: "https://registry.npmjs.org/-/npm/v1/attestations/pkg@1.0.0" },
        },
      },
      "1.0.1": {
        scripts: { postinstall: "node setup.js" },
        deprecated: undefined as string | undefined,
        _npmUser: { name: "alice" },
        dist: {
          tarball: "https://registry.npmjs.org/pkg/-/pkg-1.0.1.tgz",
          integrity: "sha512-def==",
          signatures: [{ keyid: "SHA256:...", sig: "def456" }],
          attestations: { url: "https://registry.npmjs.org/-/npm/v1/attestations/pkg@1.0.1" },
        },
      },
    },
    time: { "1.0.0": "2024-01-01T00:00:00.000Z", "1.0.1": "2024-01-02T00:00:00.000Z" },
    maintainers: [{ name: "alice" }, { name: "bob" }],
    ...overrides,
  };
}

const PUBLIC_REGISTRY = "https://registry.npmjs.org";

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(client, "fetchDownloads").mockResolvedValue(1000);
  vi.spyOn(attestationMod, "fetchAttestation").mockResolvedValue({
    sourceRepo: "github.com/owner/pkg",
    buildWorkflow: ".github/workflows/release.yml",
    predicateType: "https://slsa.dev/provenance/v1",
  });
});

describe("manifest confusion detection", () => {
  it("returns registryManifestScripts from version entry scripts", async () => {
    vi.spyOn(client, "fetchFullMeta").mockResolvedValue(makeMeta() as never);
    const { registryManifestScripts } = await fetchProvenance("pkg", "1.0.1", PUBLIC_REGISTRY);
    expect(registryManifestScripts).toEqual({ postinstall: "node setup.js" });
  });

  it("returns null registryManifestScripts when version has no scripts", async () => {
    const meta = makeMeta();
    (meta.versions["1.0.1"] as Record<string, unknown>).scripts = {};
    vi.spyOn(client, "fetchFullMeta").mockResolvedValue(meta as never);
    const { registryManifestScripts } = await fetchProvenance("pkg", "1.0.1", PUBLIC_REGISTRY);
    expect(registryManifestScripts).toBeNull();
  });
});

describe("provenance regression detection", () => {
  it("attestationRegressed is false when current version has attestation", async () => {
    vi.spyOn(client, "fetchFullMeta").mockResolvedValue(makeMeta() as never);
    const { provenance } = await fetchProvenance("pkg", "1.0.1", PUBLIC_REGISTRY);
    expect(provenance.attestationRegressed).toBe(false);
  });

  it("attestationRegressed is true when prev had attestation, current does not", async () => {
    // fetchAttestation returns null for this test (no attestation on 1.0.1)
    vi.spyOn(attestationMod, "fetchAttestation").mockResolvedValue(null);
    const meta = makeMeta();
    // 1.0.1 has no attestations url
    (meta.versions["1.0.1"].dist as Record<string, unknown>).attestations = undefined;
    vi.spyOn(client, "fetchFullMeta").mockResolvedValue(meta as never);
    const { provenance } = await fetchProvenance("pkg", "1.0.1", PUBLIC_REGISTRY);
    expect(provenance.attestationRegressed).toBe(true);
    expect(provenance.attestation).toBeNull();
  });

  it("attestationRegressed is null for first version (no prev to compare)", async () => {
    vi.spyOn(attestationMod, "fetchAttestation").mockResolvedValue(null);
    const meta = makeMeta();
    (meta.versions["1.0.0"].dist as Record<string, unknown>).attestations = undefined;
    vi.spyOn(client, "fetchFullMeta").mockResolvedValue(meta as never);
    const { provenance } = await fetchProvenance("pkg", "1.0.0", PUBLIC_REGISTRY);
    expect(provenance.attestationRegressed).toBeNull();
  });
});

describe("deprecated flag", () => {
  it("deprecated is null for non-deprecated versions", async () => {
    vi.spyOn(client, "fetchFullMeta").mockResolvedValue(makeMeta() as never);
    const { provenance } = await fetchProvenance("pkg", "1.0.1", PUBLIC_REGISTRY);
    expect(provenance.deprecated).toBeNull();
  });

  it("deprecated contains the deprecation message when set", async () => {
    const meta = makeMeta();
    meta.versions["1.0.1"].deprecated = "Use pkg@2.x instead";
    vi.spyOn(client, "fetchFullMeta").mockResolvedValue(meta as never);
    const { provenance } = await fetchProvenance("pkg", "1.0.1", PUBLIC_REGISTRY);
    expect(provenance.deprecated).toBe("Use pkg@2.x instead");
  });
});

describe("publisher identity", () => {
  it("publisherInMaintainers is true when publisher is a current maintainer", async () => {
    vi.spyOn(client, "fetchFullMeta").mockResolvedValue(makeMeta() as never);
    const { provenance } = await fetchProvenance("pkg", "1.0.1", PUBLIC_REGISTRY);
    expect(provenance.publisher).toBe("alice");
    expect(provenance.publisherInMaintainers).toBe(true);
  });

  it("publisherInMaintainers is false when publisher is not in current maintainers", async () => {
    const meta = makeMeta();
    meta.versions["1.0.1"]._npmUser = { name: "mallory" }; // not in maintainers
    vi.spyOn(client, "fetchFullMeta").mockResolvedValue(meta as never);
    const { provenance } = await fetchProvenance("pkg", "1.0.1", PUBLIC_REGISTRY);
    expect(provenance.publisher).toBe("mallory");
    expect(provenance.publisherInMaintainers).toBe(false);
  });

  it("publisherInMaintainers is null when _npmUser is absent", async () => {
    const meta = makeMeta();
    (meta.versions["1.0.1"] as Record<string, unknown>)._npmUser = undefined;
    vi.spyOn(client, "fetchFullMeta").mockResolvedValue(meta as never);
    const { provenance } = await fetchProvenance("pkg", "1.0.1", PUBLIC_REGISTRY);
    expect(provenance.publisher).toBeNull();
    expect(provenance.publisherInMaintainers).toBeNull();
  });
});

describe("registry signature presence", () => {
  it("hasRegistrySignature is true when dist.signatures is populated", async () => {
    vi.spyOn(client, "fetchFullMeta").mockResolvedValue(makeMeta() as never);
    const { provenance } = await fetchProvenance("pkg", "1.0.1", PUBLIC_REGISTRY);
    expect(provenance.hasRegistrySignature).toBe(true);
  });

  it("hasRegistrySignature is false when dist.signatures is empty array", async () => {
    const meta = makeMeta();
    (meta.versions["1.0.1"].dist as Record<string, unknown>).signatures = [];
    vi.spyOn(client, "fetchFullMeta").mockResolvedValue(meta as never);
    const { provenance } = await fetchProvenance("pkg", "1.0.1", PUBLIC_REGISTRY);
    expect(provenance.hasRegistrySignature).toBe(false);
  });

  it("hasRegistrySignature is null when dist.signatures is absent", async () => {
    const meta = makeMeta();
    (meta.versions["1.0.1"].dist as Record<string, unknown>).signatures = undefined;
    vi.spyOn(client, "fetchFullMeta").mockResolvedValue(meta as never);
    const { provenance } = await fetchProvenance("pkg", "1.0.1", PUBLIC_REGISTRY);
    expect(provenance.hasRegistrySignature).toBeNull();
  });
});

describe("private registry short-circuit", () => {
  it("returns all null fields for private registry without calling the API", async () => {
    const spy = vi.spyOn(client, "fetchFullMeta");
    const { provenance } = await fetchProvenance(
      "pkg",
      "1.0.0",
      "https://npm.pkg.github.com"
    );
    expect(spy).not.toHaveBeenCalled();
    expect(provenance.unavailableReason).toContain("Private registry");
    expect(provenance.deprecated).toBeNull();
    expect(provenance.publisher).toBeNull();
    expect(provenance.attestationRegressed).toBeNull();
  });
});

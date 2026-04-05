import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { parsePyPIAttestation } from "../src/registry/pypi-attestation.js";
import { verifySigstoreBundle } from "../src/registry/sigstore-verify.js";

// verifySigstoreBundle makes network calls — auto-mock and set implementation per test
vi.mock("../src/registry/sigstore-verify.js");

const DEFAULT_VERIFY_RESULT = {
  verified: true as boolean | null,
  errors: [] as string[],
  signingIdentity:
    "https://github.com/psf/requests/.github/workflows/publish.yml@refs/tags/v2.31.0",
};

// ── Fixtures ──────────────────────────────────────────────────────────────────

// sha256 hex digest → base64
const SHA256_HEX = "a".repeat(64); // 32 bytes of 0xaa
const SHA256_B64 = Buffer.from(SHA256_HEX, "hex").toString("base64");

const DSSE_PAYLOAD = Buffer.from(
  JSON.stringify({
    predicateType: "https://slsa.dev/provenance/v1",
    subject: [{ name: "requests-2.31.0.tar.gz", digest: { sha256: SHA256_HEX } }],
  })
).toString("base64");

const INNER_BUNDLE = {
  dsseEnvelope: {
    payload: DSSE_PAYLOAD,
    payloadType: "application/vnd.in-toto+json",
    signatures: [{ sig: "fakesig" }],
  },
  verificationMaterial: {
    certificate: { rawBytes: "fakecert" },
    tlogEntries: [],
  },
};

function makeResponse(overrides: Record<string, unknown> = {}): unknown {
  return {
    version: 1,
    attestation_bundles: [
      {
        publisher: {
          kind: "github-actions",
          claims: {
            repository: "psf/requests",
            workflow: ".github/workflows/publish.yml",
            environment: "pypi",
          },
        },
        attestations: [INNER_BUNDLE],
      },
    ],
    ...overrides,
  };
}

beforeEach(() => {
  vi.mocked(verifySigstoreBundle).mockResolvedValue(DEFAULT_VERIFY_RESULT);
});

afterEach(() => {
  vi.resetAllMocks();
});

// ── Null / malformed input ────────────────────────────────────────────────────

describe("parsePyPIAttestation — null / malformed input", () => {
  it("returns null for null input", async () => {
    expect(await parsePyPIAttestation(null)).toBeNull();
  });

  it("returns null for non-object input", async () => {
    expect(await parsePyPIAttestation("string")).toBeNull();
    expect(await parsePyPIAttestation(42)).toBeNull();
  });

  it("returns null when attestation_bundles is missing", async () => {
    expect(await parsePyPIAttestation({ version: 1 })).toBeNull();
  });

  it("returns null when attestation_bundles is empty", async () => {
    expect(await parsePyPIAttestation({ version: 1, attestation_bundles: [] })).toBeNull();
  });
});

// ── Field extraction ──────────────────────────────────────────────────────────

describe("parsePyPIAttestation — field extraction", () => {
  it("extracts sourceRepo and buildWorkflow from github-actions claims", async () => {
    const result = await parsePyPIAttestation(makeResponse());
    expect(result).not.toBeNull();
    expect(result!.sourceRepo).toBe("psf/requests");
    expect(result!.buildWorkflow).toBe(".github/workflows/publish.yml");
  });

  it("extracts predicateType from DSSE payload", async () => {
    const result = await parsePyPIAttestation(makeResponse());
    expect(result!.predicateType).toBe("https://slsa.dev/provenance/v1");
  });

  it("extracts sha256 subject integrity in SRI format", async () => {
    const result = await parsePyPIAttestation(makeResponse());
    expect(result!.subjectIntegrity).toBe(`sha256-${SHA256_B64}`);
  });

  it("populates sigstoreVerified and signingIdentity from verify result", async () => {
    const result = await parsePyPIAttestation(makeResponse());
    expect(result!.sigstoreVerified).toBe(true);
    expect(result!.signingIdentity).toContain("psf/requests");
  });

  it("sets sigstoreErrors to null when verification has no errors", async () => {
    const result = await parsePyPIAttestation(makeResponse());
    expect(result!.sigstoreErrors).toBeNull();
  });
});

// ── Verification failure ──────────────────────────────────────────────────────

describe("parsePyPIAttestation — verification failure", () => {
  it("returns AttestationInfo with sigstoreVerified: false on failed verification", async () => {
    vi.mocked(verifySigstoreBundle).mockResolvedValueOnce({
      verified: false,
      errors: ["DSSE envelope signature did not verify"],
      signingIdentity: null,
    });

    const result = await parsePyPIAttestation(makeResponse());
    expect(result).not.toBeNull();
    expect(result!.sigstoreVerified).toBe(false);
    expect(result!.sigstoreErrors).toEqual(["DSSE envelope signature did not verify"]);
  });

  it("returns AttestationInfo with sigstoreVerified: null when verification is inconclusive", async () => {
    vi.mocked(verifySigstoreBundle).mockResolvedValueOnce({
      verified: null,
      errors: ["Sigstore trusted root unavailable"],
      signingIdentity: null,
    });

    const result = await parsePyPIAttestation(makeResponse());
    expect(result!.sigstoreVerified).toBeNull();
  });
});

// ── Edge cases ────────────────────────────────────────────────────────────────

describe("parsePyPIAttestation — edge cases", () => {
  it("returns partial result with sigstoreVerified: null when attestations array is empty", async () => {
    const response = {
      version: 1,
      attestation_bundles: [{
        publisher: {
          kind: "github-actions",
          claims: { repository: "psf/requests", workflow: ".github/workflows/publish.yml" },
        },
        attestations: [],
      }],
    };
    const result = await parsePyPIAttestation(response);
    expect(result).not.toBeNull();
    expect(result!.sourceRepo).toBe("psf/requests");
    expect(result!.sigstoreVerified).toBeNull();
    expect(result!.sigstoreErrors).toContain("No Sigstore bundle in attestation");
  });

  it("handles non-github-actions publisher kinds gracefully", async () => {
    const response = makeResponse() as Record<string, unknown>;
    (response["attestation_bundles"] as Record<string, unknown>[])[0]!["publisher"] = {
      kind: "gitlab",
      claims: { project_path: "psf/requests", ci_config_ref_uri: ".gitlab-ci.yml" },
    };
    const result = await parsePyPIAttestation(response);
    expect(result).not.toBeNull();
    expect(result!.sourceRepo).toBe("psf/requests");
    expect(result!.buildWorkflow).toBe(".gitlab-ci.yml");
  });

  it("returns null sourceRepo and buildWorkflow when claims are absent", async () => {
    const response = makeResponse() as Record<string, unknown>;
    (response["attestation_bundles"] as Record<string, unknown>[])[0]!["publisher"] = {
      kind: "unknown-publisher",
    };
    const result = await parsePyPIAttestation(response);
    expect(result!.sourceRepo).toBeNull();
    expect(result!.buildWorkflow).toBeNull();
  });

  it("returns null subjectIntegrity when no recognised digest algorithm is present", async () => {
    const payload = Buffer.from(
      JSON.stringify({
        predicateType: "https://slsa.dev/provenance/v1",
        subject: [{ name: "foo.tar.gz", digest: { sha1: "abc" } }],
      })
    ).toString("base64");

    const bundleWithUnknownDigest = {
      ...INNER_BUNDLE,
      dsseEnvelope: { ...INNER_BUNDLE.dsseEnvelope, payload },
    };

    const response = makeResponse() as Record<string, unknown>;
    (response["attestation_bundles"] as Record<string, unknown>[])[0]!["attestations"] =
      [bundleWithUnknownDigest];

    const result = await parsePyPIAttestation(response);
    expect(result!.subjectIntegrity).toBeNull();
  });

  it("uses the first bundle that has attestations when multiple bundles are present", async () => {
    const emptyBundle = { publisher: { kind: "github-actions", claims: {} }, attestations: [] };
    const fullBundle = (makeResponse() as Record<string, unknown>)
      ["attestation_bundles"] as unknown[];

    const response = { version: 1, attestation_bundles: [emptyBundle, ...fullBundle] };
    const result = await parsePyPIAttestation(response);
    expect(result!.sourceRepo).toBe("psf/requests");
  });
});

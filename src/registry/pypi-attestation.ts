/**
 * PEP 740 attestation parser for PyPI packages.
 *
 * Parses the raw response from the PyPI integrity API into AttestationInfo.
 * The response wraps a Sigstore bundle in a publisher-aware envelope:
 *
 *   {
 *     "version": 1,
 *     "attestation_bundles": [{
 *       "publisher": { "kind": "github-actions", "claims": { ... } },
 *       "attestations": [ <sigstore bundle> ]
 *     }]
 *   }
 *
 * Key difference from npm: sourceRepo and buildWorkflow are available directly
 * in publisher.claims — no need to decode the DSSE payload for them.
 * The inner Sigstore bundle uses the same format as npm, so verifySigstoreBundle
 * is reused as-is.
 */

import type { AttestationInfo } from "../types.js";
import { verifySigstoreBundle } from "./sigstore-verify.js";

// ── PEP 740 response shape ────────────────────────────────────────────────────

interface Pep740Publisher {
  kind: string;
  claims?: Record<string, unknown>;
}

interface Pep740Bundle {
  publisher?: Pep740Publisher;
  attestations?: unknown[];
}

interface Pep740Response {
  version?: number;
  attestation_bundles?: Pep740Bundle[];
}

// ── In-toto statement (subset we care about) ──────────────────────────────────

interface InTotoSubject {
  name?: string;
  digest?: Record<string, string>; // algorithm → hex digest
}

interface InTotoStatement {
  predicateType?: string;
  subject?: InTotoSubject[];
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Decode the DSSE payload from a Sigstore bundle and return the parsed
 * in-toto statement, or null if the payload is missing or malformed.
 */
function decodeDssePayload(bundle: Record<string, unknown>): InTotoStatement | null {
  try {
    const envelope = bundle["dsseEnvelope"] as Record<string, unknown> | undefined;
    const payloadB64 = envelope?.["payload"];
    if (typeof payloadB64 !== "string") return null;
    const raw = Buffer.from(payloadB64, "base64").toString("utf-8");
    return JSON.parse(raw) as InTotoStatement;
  } catch {
    return null;
  }
}

/**
 * Extract an SRI-format subject integrity string from an in-toto statement.
 * Prefers sha256 (PyPI standard); falls back to sha512 (npm standard).
 * Returns null if neither algorithm is present.
 */
function extractSubjectIntegrity(stmt: InTotoStatement): string | null {
  const digest = stmt.subject?.[0]?.digest;
  if (!digest) return null;

  if (digest["sha256"]) {
    try {
      const b64 = Buffer.from(digest["sha256"], "hex").toString("base64");
      return `sha256-${b64}`;
    } catch {
      return null;
    }
  }

  if (digest["sha512"]) {
    try {
      const b64 = Buffer.from(digest["sha512"], "hex").toString("base64");
      return `sha512-${b64}`;
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Extract sourceRepo and buildWorkflow from publisher claims.
 *
 * github-actions:  claims.repository, claims.workflow
 * gitlab:          claims.project_path, claims.ci_config_ref_uri (best-effort)
 * other/unknown:   extract what we can, leave the rest null
 */
function extractPublisherIdentity(
  publisher: Pep740Publisher
): { sourceRepo: string | null; buildWorkflow: string | null } {
  const claims = publisher.claims ?? {};

  const sourceRepo =
    typeof claims["repository"] === "string" ? claims["repository"] :
    typeof claims["project_path"] === "string" ? claims["project_path"] :
    null;

  const buildWorkflow =
    typeof claims["workflow"] === "string" ? claims["workflow"] :
    typeof claims["ci_config_ref_uri"] === "string" ? claims["ci_config_ref_uri"] :
    null;

  return { sourceRepo, buildWorkflow };
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Parse a raw PEP 740 provenance response into AttestationInfo.
 *
 * Returns null when:
 *   - attestation_bundles is absent or empty (package not published with attestation)
 *   - the response structure is unrecognisable
 *
 * Returns AttestationInfo with sigstoreVerified: false when the bundle is
 * present but verification fails — a failed verification is itself a signal.
 */
export async function parsePyPIAttestation(
  raw: unknown
): Promise<AttestationInfo | null> {
  // Validate top-level structure
  if (!raw || typeof raw !== "object") return null;

  const response = raw as Pep740Response;
  const bundles = response.attestation_bundles;
  if (!Array.isArray(bundles) || bundles.length === 0) return null;

  // Prefer the first bundle with attestations; fall back to first bundle overall
  const bundle =
    bundles.find((b) => Array.isArray(b.attestations) && b.attestations.length > 0)
    ?? bundles[0];

  if (!bundle) return null;

  // Extract publisher identity from the outer claims — no DSSE decode needed
  const { sourceRepo, buildWorkflow } = bundle.publisher
    ? extractPublisherIdentity(bundle.publisher)
    : { sourceRepo: null, buildWorkflow: null };

  // Get the inner Sigstore bundle for cryptographic verification
  const innerBundle = Array.isArray(bundle.attestations)
    ? (bundle.attestations[0] as Record<string, unknown> | undefined)
    : undefined;

  if (!innerBundle) {
    // Publisher claims present but no inner bundle — partial result
    return {
      sourceRepo,
      buildWorkflow,
      predicateType: null,
      subjectIntegrity: null,
      sigstoreVerified: null,
      signingIdentity: null,
      sigstoreErrors: ["No Sigstore bundle in attestation"],
    };
  }

  // Decode DSSE payload for predicateType and subject integrity
  const stmt = decodeDssePayload(innerBundle);
  const predicateType = stmt?.predicateType ?? null;
  const subjectIntegrity = stmt ? extractSubjectIntegrity(stmt) : null;

  // Full Sigstore chain verification (reuses npm implementation)
  const verifyResult = await verifySigstoreBundle(innerBundle);

  return {
    sourceRepo,
    buildWorkflow,
    predicateType,
    subjectIntegrity,
    sigstoreVerified: verifyResult.verified,
    signingIdentity: verifyResult.signingIdentity,
    sigstoreErrors: verifyResult.errors.length > 0 ? verifyResult.errors : null,
  };
}

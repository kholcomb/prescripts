/**
 * Fetches and decodes an npm Sigstore provenance attestation.
 *
 * We parse the bundle to extract the claimed source repo, build workflow,
 * and subject digest — the subject digest lets us verify that the attested
 * tarball matches the one we actually downloaded (attestation substitution check).
 *
 * Full cryptographic verification (Fulcio cert chain + Rekor log lookup) is
 * not yet implemented — the subject check and the separate ECDSA registry
 * signature verify the tarball content independently.
 */

import type { AttestationInfo } from "../types.js";
export type { AttestationInfo };
import { verifySigstoreBundle } from "./sigstore-verify.js";

interface AttestationsResponse {
  attestations?: Array<{
    predicateType?: string;
    /** Legacy format: base64-encoded JSON bundle */
    bundleBytes?: string;
    /** Current format (npm registry v2): bundle as a direct JSON object */
    bundle?: Record<string, unknown>;
  }>;
}

interface SigstoreBundle {
  dsseEnvelope?: { payload?: string };
}

interface InTotoStatement {
  predicateType?: string;
  subject?: Array<{
    name?: string;
    digest?: Record<string, string>; // algorithm → hex digest
  }>;
}

// SLSA v1
interface SLSAv1Statement extends InTotoStatement {
  predicate?: {
    buildDefinition?: {
      externalParameters?: {
        workflow?: { repository?: string; path?: string };
      };
    };
  };
}

// SLSA v0.2
interface SLSAv02Statement extends InTotoStatement {
  predicate?: {
    invocation?: {
      configSource?: { uri?: string; entryPoint?: string };
    };
  };
}

/** Convert the in-toto subject digest to SRI format (sha512-<base64>).
 *  The in-toto spec stores digests as hex; npm uses sha512. */
function extractSubjectIntegrity(stmt: InTotoStatement): string | null {
  const subject = stmt.subject?.[0];
  if (!subject?.digest) return null;
  const hexDigest = subject.digest["sha512"] ?? null;
  if (!hexDigest) return null;
  try {
    const b64 = Buffer.from(hexDigest, "hex").toString("base64");
    return `sha512-${b64}`;
  } catch {
    return null;
  }
}

export async function fetchAttestation(
  url: string
): Promise<AttestationInfo | null> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(15_000) });
    if (!res.ok) return null;

    const data = (await res.json()) as AttestationsResponse;
    const attestations = data.attestations;
    if (!Array.isArray(attestations) || attestations.length === 0) return null;

    // Prefer SLSA provenance; fall back to first attestation
    const entry =
      attestations.find((a) =>
        a.predicateType?.startsWith("https://slsa.dev/provenance/")
      ) ?? attestations[0];

    if (!entry) return null;

    // Support both current format (bundle object) and legacy (bundleBytes base64 string)
    const bundleInput = entry.bundle ?? (
      entry.bundleBytes
        ? JSON.parse(Buffer.from(entry.bundleBytes, "base64").toString("utf-8"))
        : null
    );
    if (!bundleInput) return null;

    // Full Sigstore chain verification (DSSE + cert chain + Rekor SET + Merkle proof)
    const verifyResult = await verifySigstoreBundle(bundleInput);

    const bundle = bundleInput as SigstoreBundle;

    const payloadB64 = bundle.dsseEnvelope?.payload;
    if (!payloadB64) return null;

    const raw = Buffer.from(payloadB64, "base64").toString("utf-8");
    const predicateType =
      (JSON.parse(raw) as { predicateType?: string }).predicateType ?? null;

    let sourceRepo: string | null = null;
    let buildWorkflow: string | null = null;
    let subjectIntegrity: string | null = null;

    if (predicateType === "https://slsa.dev/provenance/v1") {
      const stmt = JSON.parse(raw) as SLSAv1Statement;
      const wf = stmt.predicate?.buildDefinition?.externalParameters?.workflow;
      sourceRepo = wf?.repository ?? null;
      buildWorkflow = wf?.path ?? null;
      subjectIntegrity = extractSubjectIntegrity(stmt);
    } else if (predicateType === "https://slsa.dev/provenance/v0.2") {
      const stmt = JSON.parse(raw) as SLSAv02Statement;
      const src = stmt.predicate?.invocation?.configSource;
      // URI: "git+https://github.com/owner/repo@refs/tags/v1.0.0"
      const uri = src?.uri ?? null;
      if (uri) {
        sourceRepo = uri.replace(/^git\+/, "").split("@")[0] ?? null;
      }
      buildWorkflow = src?.entryPoint ?? null;
      subjectIntegrity = extractSubjectIntegrity(stmt);
    }

    // Normalize to display form: drop "https://" prefix
    if (sourceRepo?.startsWith("https://")) {
      sourceRepo = sourceRepo.slice("https://".length);
    }

    return {
      sourceRepo,
      buildWorkflow,
      predicateType,
      subjectIntegrity,
      sigstoreVerified: verifyResult.verified,
      signingIdentity: verifyResult.signingIdentity,
      sigstoreErrors: verifyResult.errors.length > 0 ? verifyResult.errors : null,
    };
  } catch {
    return null; // best-effort
  }
}

/**
 * Fetches and decodes an npm Sigstore provenance attestation.
 *
 * We parse the bundle to extract the claimed source repo and build workflow —
 * this gives a "built in CI from this repo" signal without requiring full
 * cryptographic verification (Fulcio cert chain + Rekor log lookup).
 *
 * Absence of an attestation is not flagged as a finding; it's surfaced as
 * context alongside other provenance signals so the consumer can weigh it.
 */

export interface AttestationInfo {
  sourceRepo: string | null;    // e.g. "github.com/expressjs/express"
  buildWorkflow: string | null; // e.g. ".github/workflows/release.yml"
  predicateType: string | null; // "https://slsa.dev/provenance/v1" etc.
}

interface AttestationsResponse {
  attestations?: Array<{
    predicateType?: string;
    bundleBytes?: string;
  }>;
}

interface SigstoreBundle {
  dsseEnvelope?: { payload?: string };
}

// SLSA v1
interface SLSAv1Statement {
  predicateType?: string;
  predicate?: {
    buildDefinition?: {
      externalParameters?: {
        workflow?: { repository?: string; path?: string };
      };
    };
  };
}

// SLSA v0.2
interface SLSAv02Statement {
  predicateType?: string;
  predicate?: {
    invocation?: {
      configSource?: { uri?: string; entryPoint?: string };
    };
  };
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

    if (!entry?.bundleBytes) return null;

    // Decode Sigstore bundle → DSSE envelope → in-toto payload
    const bundle = JSON.parse(
      Buffer.from(entry.bundleBytes, "base64").toString("utf-8")
    ) as SigstoreBundle;

    const payloadB64 = bundle.dsseEnvelope?.payload;
    if (!payloadB64) return null;

    const raw = Buffer.from(payloadB64, "base64").toString("utf-8");
    const predicateType =
      (JSON.parse(raw) as { predicateType?: string }).predicateType ?? null;

    let sourceRepo: string | null = null;
    let buildWorkflow: string | null = null;

    if (predicateType === "https://slsa.dev/provenance/v1") {
      const stmt = JSON.parse(raw) as SLSAv1Statement;
      const wf = stmt.predicate?.buildDefinition?.externalParameters?.workflow;
      sourceRepo = wf?.repository ?? null;
      buildWorkflow = wf?.path ?? null;
    } else if (predicateType === "https://slsa.dev/provenance/v0.2") {
      const stmt = JSON.parse(raw) as SLSAv02Statement;
      const src = stmt.predicate?.invocation?.configSource;
      // URI: "git+https://github.com/owner/repo@refs/tags/v1.0.0"
      const uri = src?.uri ?? null;
      if (uri) {
        sourceRepo = uri.replace(/^git\+/, "").split("@")[0] ?? null;
      }
      buildWorkflow = src?.entryPoint ?? null;
    }

    // Normalize to display form: drop "https://" prefix
    if (sourceRepo?.startsWith("https://")) {
      sourceRepo = sourceRepo.slice("https://".length);
    }

    return { sourceRepo, buildWorkflow, predicateType };
  } catch {
    return null; // best-effort
  }
}

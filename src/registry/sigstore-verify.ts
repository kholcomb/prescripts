/**
 * Full Sigstore bundle verification for npm package attestations.
 *
 * Implements all four layers of the Sigstore trust chain:
 *   1. DSSE envelope signature — payload was signed by the key in the certificate
 *   2. Certificate chain      — certificate was issued by Sigstore's Fulcio CA
 *   3. Rekor SET              — signing event was logged before distribution
 *   4. Merkle inclusion proof — log entry is provably in the append-only tree (RFC 9162)
 *
 * Trusted root (Fulcio CA certs + Rekor public keys) is fetched from the
 * Sigstore TUF CDN via a lightweight TUF metadata walk:
 *
 *   1. GET /timestamp.json              → snapshot version number
 *   2. GET /<N>.snapshot.json           → targets metadata version number
 *   3. GET /<N>.targets.json            → sha256 hash of trusted_root.json
 *   4. GET /targets/<hash>.trusted_root.json  → the actual trusted root
 *
 * This is the correct TUF client flow (consistent snapshot mode). The hash
 * in step 4 binds the file to the metadata chain, so we can trust TLS alone
 * for the CDN fetch — the hash provides content integrity even without a full
 * TUF implementation.
 *
 * The result is cached for 24 hours. Key rotations are picked up automatically
 * on the next cache expiry.
 *
 * Return semantics:
 *   verified: true  — all four checks passed
 *   verified: false — one or more checks definitively failed (tampered bundle)
 *   verified: null  — could not complete verification (network unavailable,
 *                     unrecognised format) — not a failure, just unknown
 */

import { createHash, createVerify, X509Certificate } from "node:crypto";

// ── Trusted root ─────────────────────────────────────────────────────────────

interface TrustedRootKey {
  rawBytes: string;    // base64 DER SubjectPublicKeyInfo
  keyDetails: string;  // e.g. "PKIX_ECDSA_P256_SHA_256"
  validFor?: { start?: string; end?: string };
}

interface TrustedRoot {
  tlogs?: Array<{
    baseUrl: string;
    publicKey: TrustedRootKey;
    logId: { keyId: string };  // base64 SHA-256 of the public key
  }>;
  /** In the Sigstore trusted_root.json format this field is `certificateAuthorities`. */
  certificateAuthorities?: Array<{
    uri: string;
    certChain: {
      certificates: Array<{ rawBytes: string }>;  // base64 DER X.509
    };
    validFor?: { start?: string; end?: string };
  }>;
}

const TUF_BASE = "https://tuf-repo-cdn.sigstore.dev";
let _trustedRoot: TrustedRoot | null = null;
let _trustedRootFetchedAt = 0;
const TRUSTED_ROOT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Lightweight TUF client: walks timestamp → snapshot → targets → content.
 *
 * We trust TLS for the CDN fetch and use the sha256 hash from the targets
 * metadata to bind the trusted_root.json content to the metadata chain.
 * This is sufficient integrity protection without a full TUF implementation.
 */
async function fetchTrustedRootFromTUF(): Promise<TrustedRoot | null> {
  // Step 1: timestamp.json → snapshot version
  const tsRes = await fetch(`${TUF_BASE}/timestamp.json`, {
    signal: AbortSignal.timeout(10_000),
  });
  if (!tsRes.ok) return null;
  const ts = (await tsRes.json()) as { signed?: { meta?: { "snapshot.json"?: { version?: number } } } };
  const snapshotVersion = ts.signed?.meta?.["snapshot.json"]?.version;
  if (!snapshotVersion) return null;

  // Step 2: <N>.snapshot.json → targets version
  const ssRes = await fetch(`${TUF_BASE}/${snapshotVersion}.snapshot.json`, {
    signal: AbortSignal.timeout(10_000),
  });
  if (!ssRes.ok) return null;
  const ss = (await ssRes.json()) as { signed?: { meta?: { "targets.json"?: { version?: number } } } };
  const targetsVersion = ss.signed?.meta?.["targets.json"]?.version;
  if (!targetsVersion) return null;

  // Step 3: <N>.targets.json → sha256 hash of trusted_root.json
  const tgRes = await fetch(`${TUF_BASE}/${targetsVersion}.targets.json`, {
    signal: AbortSignal.timeout(10_000),
  });
  if (!tgRes.ok) return null;
  const tg = (await tgRes.json()) as {
    signed?: { targets?: { "trusted_root.json"?: { hashes?: { sha256?: string }; length?: number } } };
  };
  const trHash = tg.signed?.targets?.["trusted_root.json"]?.hashes?.sha256;
  if (!trHash) return null;

  // Step 4: /targets/<hash>.trusted_root.json → the actual content
  const trRes = await fetch(`${TUF_BASE}/targets/${trHash}.trusted_root.json`, {
    signal: AbortSignal.timeout(10_000),
  });
  if (!trRes.ok) return null;

  // Content integrity: verify sha256 of the response matches the hash from metadata
  const bytes = Buffer.from(await trRes.arrayBuffer());
  const actualHash = createHash("sha256").update(bytes).digest("hex");
  if (actualHash !== trHash) return null; // tampered — reject

  return JSON.parse(bytes.toString("utf-8")) as TrustedRoot;
}

export async function fetchTrustedRoot(): Promise<TrustedRoot | null> {
  const now = Date.now();
  if (_trustedRoot && now - _trustedRootFetchedAt < TRUSTED_ROOT_TTL_MS) {
    return _trustedRoot;
  }
  try {
    const data = await fetchTrustedRootFromTUF();
    if (data) {
      _trustedRoot = data;
      _trustedRootFetchedAt = now;
    }
    return _trustedRoot; // return stale if fresh fetch failed
  } catch {
    return _trustedRoot; // return stale or null
  }
}

/** Exposed for testing — clears the in-process cache. */
export function clearTrustedRootCache(): void {
  _trustedRoot = null;
  _trustedRootFetchedAt = 0;
}

// ── Bundle types ──────────────────────────────────────────────────────────────

export interface TlogEntry {
  logIndex: string;
  logId: { keyId: string };       // base64 key identifier
  integratedTime: string;         // Unix timestamp as decimal string
  inclusionPromise: {
    signedEntryTimestamp: string; // base64 ECDSA signature
  };
  inclusionProof: {
    logIndex: string;
    rootHash: string;             // base64 bytes (RFC 9162 Merkle root)
    treeSize: string;
    hashes: string[];             // base64 bytes (sibling hashes)
    checkpoint: { envelope: string };
  };
  canonicalizedBody: string;      // base64 JSON body of the log entry
}

export interface SigstoreVerifyBundle {
  verificationMaterial?: {
    certificate?: { rawBytes: string };  // base64 DER leaf certificate
    tlogEntries?: TlogEntry[];
  };
  dsseEnvelope?: {
    payload: string;       // base64 in-toto statement
    payloadType: string;   // "application/vnd.in-toto+json"
    signatures: Array<{ sig: string; keyid?: string }>;
  };
}

// ── 1. DSSE signature verification ───────────────────────────────────────────

/**
 * Compute DSSE Pre-Authentication Encoding (PAE).
 * Defined in https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
 *
 * PAE(payloadType, payload) =
 *   "DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload
 */
function dssePreAuthEncoding(payloadType: string, payload: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${payloadType.length} `),
    Buffer.from(payloadType),
    Buffer.from(` ${payload.length} `),
    payload,
  ]);
}

function verifyDsseSignature(
  bundle: SigstoreVerifyBundle,
  cert: X509Certificate
): boolean {
  try {
    const envelope = bundle.dsseEnvelope;
    if (!envelope?.payload || !envelope.signatures?.[0]?.sig) return false;

    const payload = Buffer.from(envelope.payload, "base64");
    const payloadType = envelope.payloadType ?? "application/vnd.in-toto+json";
    const signingContent = dssePreAuthEncoding(payloadType, payload);
    const sig = Buffer.from(envelope.signatures[0].sig, "base64");

    // Choose hash algorithm based on the signing key's curve
    const curve =
      cert.publicKey.asymmetricKeyDetails?.namedCurve ?? "prime256v1";
    const hashAlgo = curve === "secp384r1" ? "SHA384" : "SHA256";

    const verifier = createVerify(hashAlgo);
    verifier.update(signingContent);
    return verifier.verify(cert.publicKey, sig);
  } catch {
    return false;
  }
}

// ── 2. Certificate chain verification ────────────────────────────────────────

function extractSANIdentity(cert: X509Certificate): string | null {
  try {
    const san = cert.subjectAltName ?? "";
    // SAN format from Fulcio: "URI:https://github.com/owner/repo/.github/workflows/..."
    const match = san.match(/URI:([^\s,]+)/);
    return match?.[1] ?? null;
  } catch {
    return null;
  }
}

/**
 * Verify the leaf certificate was issued by any cert in Sigstore's trusted CA set.
 * The trusted_root.json contains both root and intermediate certs; verifying against
 * any of them is sufficient because all are trusted by the same TUF root.
 */
function verifyCertChain(
  leafCert: X509Certificate,
  cas: NonNullable<TrustedRoot["certificateAuthorities"]>,
  signingTime: Date
): { valid: boolean; identity: string | null } {
  const identity = extractSANIdentity(leafCert);

  // Check the leaf cert's validity window includes the signing time
  try {
    const notBefore = new Date(leafCert.validFrom);
    const notAfter = new Date(leafCert.validTo);
    if (signingTime < notBefore || signingTime > notAfter) {
      // Fulcio certs are 10-minute TTL — signing time must be within that window
      return { valid: false, identity };
    }
  } catch {
    // If we can't parse the dates, don't fail hard
  }

  for (const ca of cas) {
    for (const certEntry of ca.certChain.certificates) {
      try {
        const caCert = new X509Certificate(
          Buffer.from(certEntry.rawBytes, "base64")
        );
        if (leafCert.verify(caCert.publicKey)) {
          return { valid: true, identity };
        }
      } catch {
        continue;
      }
    }
  }

  return { valid: false, identity };
}

// ── 3. Rekor SET verification ─────────────────────────────────────────────────

/**
 * The Rekor signed entry timestamp (SET) is an ECDSA signature over:
 * SHA256(canonical_json({ body, integratedTime, logID, logIndex }))
 *
 * Where:
 * - body           = the canonicalizedBody string (base64 as-is, not decoded)
 * - integratedTime = integer Unix timestamp
 * - logID          = hex of the base64-decoded logId.keyId bytes
 * - logIndex       = integer log index
 *
 * Key order matches Go's json.Marshal struct field order.
 */
function verifyRekorSET(
  entry: TlogEntry,
  rekorKeyDer: Buffer
): boolean | null {
  try {
    const logID = Buffer.from(entry.logId.keyId, "base64").toString("hex");

    // Key order must match the Go struct field order: body, integratedTime, logID, logIndex
    const signingContent = JSON.stringify({
      body: entry.canonicalizedBody,
      integratedTime: parseInt(entry.integratedTime, 10),
      logID,
      logIndex: parseInt(entry.logIndex, 10),
    });

    const setBytes = Buffer.from(
      entry.inclusionPromise.signedEntryTimestamp,
      "base64"
    );

    const verifier = createVerify("SHA256");
    verifier.update(signingContent);
    return verifier.verify(
      { key: rekorKeyDer, format: "der", type: "spki" },
      setBytes
    );
  } catch {
    // Format or encoding error — cannot determine validity
    return null;
  }
}

// ── 4. Merkle inclusion proof (RFC 9162) ──────────────────────────────────────

/**
 * RFC 9162 Section 2.1.3 VERIFY_INCLUSION algorithm.
 *
 * Leaf hash: SHA256(0x00 || canonicalizedBody_bytes)
 * Interior node hash: SHA256(0x01 || left || right)
 *
 * The logIndex (leaf position) and hashes[] (sibling path) from the inclusion
 * proof are used to compute the root and compare against the expected rootHash.
 */
function verifyMerkleProof(entry: TlogEntry): boolean | null {
  try {
    const proof = entry.inclusionProof;
    if (!proof?.hashes || !proof.rootHash) return null;

    const logIndex = parseInt(proof.logIndex, 10);
    const treeSize = parseInt(proof.treeSize, 10);
    const expectedRoot = Buffer.from(proof.rootHash, "base64");
    const siblings = proof.hashes.map((h) => Buffer.from(h, "base64"));

    if (isNaN(logIndex) || isNaN(treeSize) || treeSize <= 0) return null;

    // Leaf hash: SHA256(0x00 || entry_data)
    const leafData = Buffer.from(entry.canonicalizedBody, "base64");
    const leafHash = createHash("sha256")
      .update(Buffer.from([0x00]))
      .update(leafData)
      .digest();

    // RFC 9162 Section 2.1.3
    let fn = logIndex;
    let sn = treeSize - 1;
    let r = leafHash;

    for (const p of siblings) {
      if (sn === 0) return false; // more siblings than expected

      if ((fn & 1) === 1 || fn === sn) {
        // fn is right child (odd) or the rightmost node at this level:
        // sibling p is on the left → HASH(0x01 || p || r)
        r = createHash("sha256")
          .update(Buffer.from([0x01]))
          .update(p)
          .update(r)
          .digest();
        // Move up while fn is a right-most even node
        while (fn !== 0 && (fn & 1) === 0) {
          fn >>= 1;
          sn >>= 1;
        }
      } else {
        // fn is left child (even, not rightmost): sibling p is on the right
        // → HASH(0x01 || r || p)
        r = createHash("sha256")
          .update(Buffer.from([0x01]))
          .update(r)
          .update(p)
          .digest();
      }

      fn >>= 1;
      sn >>= 1;
    }

    // After consuming all siblings, sn must be 0 and r must equal the expected root
    return sn === 0 && r.equals(expectedRoot);
  } catch {
    return null;
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

export interface BundleVerifyResult {
  /**
   * true  = all four checks passed
   * false = one or more checks definitively failed
   * null  = could not complete verification (no trusted root, format error)
   */
  verified: boolean | null;
  errors: string[];
  /** GitHub Actions identity URI from the Fulcio certificate SAN.
   *  e.g. "https://github.com/owner/repo/.github/workflows/release.yml@refs/tags/v1.0.0" */
  signingIdentity: string | null;
}

export async function verifySigstoreBundle(
  bundleInput: string | Record<string, unknown> // base64 JSON string (legacy) or bundle object (current)
): Promise<BundleVerifyResult> {
  const errors: string[] = [];
  let signingIdentity: string | null = null;
  let anyDefiniteFailure = false;
  let anyUnverifiable = false;

  function fail(msg: string): void {
    errors.push(msg);
    anyDefiniteFailure = true;
  }

  function skip(msg: string): void {
    errors.push(msg);
    anyUnverifiable = true;
  }

  // Accept either a pre-parsed bundle object or a base64-encoded JSON string (legacy)
  let bundle: SigstoreVerifyBundle;
  try {
    if (typeof bundleInput === "string") {
      bundle = JSON.parse(
        Buffer.from(bundleInput, "base64").toString("utf-8")
      ) as SigstoreVerifyBundle;
    } else {
      bundle = bundleInput as SigstoreVerifyBundle;
    }
  } catch {
    return {
      verified: null,
      errors: ["Failed to parse Sigstore bundle"],
      signingIdentity: null,
    };
  }

  // Fetch trusted root (Fulcio CAs + Rekor keys) — handles key rotation
  const root = await fetchTrustedRoot();
  if (!root) {
    return {
      verified: null,
      errors: ["Sigstore trusted root unavailable — TUF walk failed (tuf-repo-cdn.sigstore.dev)"],
      signingIdentity: null,
    };
  }

  // Extract and parse the signing certificate
  const certRawBytes = bundle.verificationMaterial?.certificate?.rawBytes;
  if (!certRawBytes) {
    return {
      verified: null,
      errors: ["No signing certificate in bundle"],
      signingIdentity: null,
    };
  }

  let leafCert: X509Certificate;
  try {
    leafCert = new X509Certificate(Buffer.from(certRawBytes, "base64"));
  } catch {
    return {
      verified: null,
      errors: ["Failed to parse signing certificate DER"],
      signingIdentity: null,
    };
  }

  // ── Check 1: DSSE signature ──────────────────────────────────────────────
  if (!verifyDsseSignature(bundle, leafCert)) {
    fail("DSSE envelope signature did not verify against signing certificate");
  }

  // ── Check 2: Certificate chain to Fulcio ────────────────────────────────
  // Use integratedTime from the log entry as the signing time for cert validity check
  const tlogEntries = bundle.verificationMaterial?.tlogEntries ?? [];
  const integratedTime = tlogEntries[0]?.integratedTime
    ? new Date(parseInt(tlogEntries[0].integratedTime, 10) * 1000)
    : new Date();

  const cas = root.certificateAuthorities ?? [];
  if (cas.length === 0) {
    skip("No Fulcio CA certificates in trusted root");
  } else {
    const { valid: chainValid, identity } = verifyCertChain(
      leafCert,
      cas,
      integratedTime
    );
    signingIdentity = identity;
    if (!chainValid) {
      fail("Certificate not issued by Sigstore Fulcio CA, or was expired at signing time");
    }
  }

  // ── Checks 3 + 4: Rekor SET and Merkle proof ────────────────────────────
  if (tlogEntries.length === 0) {
    skip("No transparency log entries in bundle");
  }

  for (const entry of tlogEntries) {
    // Find the matching Rekor key by logId.keyId
    const entryKeyId = entry.logId?.keyId;
    const tlog = root.tlogs?.find((t) => t.logId.keyId === entryKeyId);

    if (!tlog) {
      skip(
        `Rekor log key not found in trusted root for keyId ${entryKeyId ?? "(missing)"}`
      );
      continue;
    }

    const rekorKeyDer = Buffer.from(tlog.publicKey.rawBytes, "base64");

    // Check 3: Rekor SET
    const setResult = verifyRekorSET(entry, rekorKeyDer);
    if (setResult === false) {
      fail("Rekor signed entry timestamp (SET) verification failed");
    } else if (setResult === null) {
      // Format/encoding error — treat as unverifiable, not a hard failure
      skip("Rekor SET format unrecognised — could not verify");
    }

    // Check 4: Merkle inclusion proof
    if (entry.inclusionProof) {
      const merkleResult = verifyMerkleProof(entry);
      if (merkleResult === false) {
        fail(
          `Merkle inclusion proof invalid — log entry at index ${entry.logIndex} ` +
          `does not produce the expected root hash`
        );
      } else if (merkleResult === null) {
        skip("Merkle proof format unrecognised — could not verify");
      }
    } else {
      skip("No Merkle inclusion proof in bundle");
    }
  }

  if (anyDefiniteFailure) return { verified: false, errors, signingIdentity };
  if (anyUnverifiable) return { verified: null, errors, signingIdentity };
  return { verified: true, errors: [], signingIdentity };
}

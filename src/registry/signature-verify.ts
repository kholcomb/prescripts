/**
 * Verifies npm registry ECDSA-P256 package signatures.
 *
 * The npm registry signs each package's integrity hash using ECDSA-P256.
 * The signed message is: "${name}@${version}:${integrity}"
 * where integrity is the SRI string from dist.integrity (e.g. sha512-abc...==).
 *
 * Public keys are fetched once from /-/npm/v1/keys and cached for the process
 * lifetime. Verification uses node:crypto — no external dependencies.
 *
 * Returns:
 *   true  — signature is cryptographically valid
 *   false — signature is definitively invalid (tampered tarball or registry)
 *   null  — cannot determine (no keys fetched, no matching keyid, or format error)
 *
 * We return null rather than false on any exception to avoid false positives
 * from format/encoding mismatches in edge cases.
 */

import { createVerify } from "node:crypto";

interface RegistryKey {
  keyid: string;
  keytype: string;
  scheme: string;
  key: string; // base64-encoded DER SubjectPublicKeyInfo
}

// Module-level cache: keyed by registry base URL
const keyCache = new Map<string, RegistryKey[]>();

async function fetchRegistryKeys(registryUrl: string): Promise<RegistryKey[]> {
  const baseUrl = registryUrl.replace(/\/$/, "");
  const cached = keyCache.get(baseUrl);
  if (cached) return cached;

  try {
    const url = `${baseUrl}/-/npm/v1/keys`;
    const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) return [];
    const data = (await res.json()) as { keys?: RegistryKey[] };
    const keys = data.keys ?? [];
    keyCache.set(baseUrl, keys);
    return keys;
  } catch {
    return [];
  }
}

export async function verifyRegistrySignature(
  name: string,
  version: string,
  integrity: string,
  signatures: Array<{ keyid: string; sig: string }>,
  registryUrl: string
): Promise<boolean | null> {
  if (!signatures.length) return null;

  const keys = await fetchRegistryKeys(registryUrl);
  if (!keys.length) return null; // can't verify without keys

  const message = `${name}@${version}:${integrity}`;

  for (const sig of signatures) {
    const matchingKey = keys.find((k) => k.keyid === sig.keyid);
    if (!matchingKey) continue;

    try {
      const verifier = createVerify("SHA256");
      verifier.update(message);
      const valid = verifier.verify(
        {
          key: Buffer.from(matchingKey.key, "base64"),
          format: "der",
          type: "spki",
        },
        Buffer.from(sig.sig, "base64")
      );
      // Definitively valid or invalid — not a format error
      return valid;
    } catch {
      // Encoding/format mismatch — can't determine validity for this sig
      continue;
    }
  }

  return null; // no matching key found for any signature
}

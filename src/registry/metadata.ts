import { fetchFullMeta, fetchDownloads } from "./client.js";
import { fetchAttestation } from "./attestation.js";
import type { ProvenanceInfo, ProvenanceFetchResult, LifecycleScripts } from "../types.js";

const LIFECYCLE_HOOKS: Array<keyof LifecycleScripts> = [
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "prepublish",
  "prepublishOnly",
  "prepack",
  "postpack",
];

function hasInstallScript(scripts: Record<string, string> | undefined): boolean {
  if (!scripts) return false;
  return LIFECYCLE_HOOKS.some((h) => h in scripts);
}

// Numeric semver comparator — handles X.Y.Z and X.Y.Z-pre tags.
// Stable > pre-release when numeric parts are equal (semver §11.4).
function semverCompare(a: string, b: string): number {
  const parse = (v: string) => {
    const [main = "", pre = ""] = v.split("-", 2) as [string, string];
    const [major = 0, minor = 0, patch = 0] = main.split(".").map(Number);
    return { major, minor, patch, pre };
  };
  const va = parse(a);
  const vb = parse(b);
  for (const k of ["major", "minor", "patch"] as const) {
    if (va[k] !== vb[k]) return va[k] - vb[k];
  }
  if (!va.pre && vb.pre) return 1;
  if (va.pre && !vb.pre) return -1;
  return va.pre.localeCompare(vb.pre);
}

function extractLifecycleOnly(
  scripts: Record<string, string> | undefined
): LifecycleScripts | null {
  if (!scripts) return null;
  const result: LifecycleScripts = {};
  for (const hook of LIFECYCLE_HOOKS) {
    if (hook in scripts) {
      (result as Record<string, string>)[hook] = scripts[hook]!;
    }
  }
  return Object.keys(result).length > 0 ? result : null;
}

export async function fetchProvenance(
  name: string,
  version: string,
  registryUrl: string
): Promise<ProvenanceFetchResult> {
  const isPublicRegistry = registryUrl
    .replace(/\/$/, "")
    .startsWith("https://registry.npmjs.org");

  const unavailable = (reason: string): ProvenanceFetchResult => ({
    provenance: {
      publishedAt: null,
      weeklyDownloads: null,
      maintainerCount: null,
      installScriptIsNew: null,
      totalVersions: null,
      unavailableReason: reason,
      attestation: null,
      deprecated: null,
      publisher: null,
      publisherInMaintainers: null,
      hasRegistrySignature: null,
      attestationRegressed: null,
      firstPublishedAt: null,
      publisherIsNewToPackage: null,
      binaryHostChanged: null,
      previousBinaryHost: null,
    },
    registryManifestScripts: null,
    registryIntegrity: null,
    registrySignatures: null,
  });

  if (!isPublicRegistry) {
    return unavailable("Private registry — provenance metadata unavailable");
  }

  try {
    const [meta, downloads] = await Promise.all([
      fetchFullMeta(name),
      fetchDownloads(name),
    ]);

    const publishedAt = meta.time?.[version] ?? null;
    const totalVersions = Object.keys(meta.versions).length;
    const maintainerCount = meta.maintainers?.length ?? null;
    const versionEntry = meta.versions[version];

    // --- installScriptIsNew ---
    // Sort versions by semver before comparing so backpatched releases (e.g. a
    // 7.x patch published after 8.0.0) don't become the spurious "predecessor".
    const versionList = Object.keys(meta.versions).sort(semverCompare);
    const versionIndex = versionList.indexOf(version);
    let installScriptIsNew: boolean | null = null;
    const currentHasScript = hasInstallScript(versionEntry?.scripts);

    const currentBinaryHost = versionEntry?.binary?.host ?? null;
    let binaryHostChanged: boolean | null = null;
    let previousBinaryHost: string | null = null;

    if (versionIndex > 0) {
      const prevVersion = versionList[versionIndex - 1];
      const prevPkg = prevVersion ? meta.versions[prevVersion] : undefined;
      const prevHasScript = hasInstallScript(prevPkg?.scripts);
      installScriptIsNew = currentHasScript && !prevHasScript;

      previousBinaryHost = prevPkg?.binary?.host ?? null;
      // Only flag when at least one version has a binary host — otherwise it's
      // just two packages with no binary download field (normal, not a change).
      if (currentBinaryHost !== null || previousBinaryHost !== null) {
        binaryHostChanged = currentBinaryHost !== previousBinaryHost;
      } else {
        binaryHostChanged = false;
      }
    } else if (versionIndex === 0) {
      installScriptIsNew = currentHasScript;
      // First version — no previous to compare against, leave binaryHostChanged null
    }

    // --- Sigstore attestation (current version) ---
    const attestationsUrl = versionEntry?.dist?.attestations?.url ?? null;
    const attestation = attestationsUrl
      ? await fetchAttestation(attestationsUrl)
      : null;

    // --- Provenance regression: prev version had attestation, this one doesn't ---
    let attestationRegressed: boolean | null = null;
    if (versionIndex > 0 && attestation === null) {
      const prevVersion = versionList[versionIndex - 1];
      const prevEntry = prevVersion ? meta.versions[prevVersion] : undefined;
      const prevHadAttestation = !!(prevEntry?.dist?.attestations?.url);
      attestationRegressed = prevHadAttestation;
    } else if (attestation !== null) {
      attestationRegressed = false; // has attestation — no regression
    }

    // --- Publisher identity ---
    const publisher = versionEntry?._npmUser?.name ?? null;
    const maintainerNames = new Set(
      (meta.maintainers ?? []).map((m) => m.name)
    );
    const publisherInMaintainers =
      publisher !== null ? maintainerNames.has(publisher) : null;

    // --- Publisher history: has this person published this package before? ---
    // true = first time publishing this package (suspicious on mature packages)
    // false = has published before (expected)
    // null = can't determine (no publisher info)
    let publisherIsNewToPackage: boolean | null = null;
    if (publisher !== null) {
      if (versionIndex === 0) {
        // First ever version — publisher being new is expected
        publisherIsNewToPackage = false;
      } else {
        const priorPublishers = new Set(
          versionList.slice(0, versionIndex)
            .map((v) => meta.versions[v]?._npmUser?.name)
            .filter((n): n is string => typeof n === "string")
        );
        publisherIsNewToPackage = !priorPublishers.has(publisher);
      }
    }

    // --- First published date (for version velocity) ---
    const firstVersion = versionList[0];
    const firstPublishedAt = firstVersion ? (meta.time?.[firstVersion] ?? null) : null;

    // --- Deprecation ---
    const deprecated = versionEntry?.deprecated ?? null;

    // --- Registry signature presence ---
    const sigs = versionEntry?.dist?.signatures;
    const hasRegistrySignature =
      sigs !== undefined ? (Array.isArray(sigs) && sigs.length > 0) : null;

    // --- Registry manifest lifecycle scripts (for manifest confusion detection) ---
    const registryManifestScripts = extractLifecycleOnly(versionEntry?.scripts);

    // --- Registry integrity and signatures (for lockfile poisoning + ECDSA checks) ---
    const registryIntegrity = versionEntry?.dist?.integrity ?? null;
    const rawSigs = versionEntry?.dist?.signatures;
    const registrySignatures: Array<{ keyid: string; sig: string }> | null =
      Array.isArray(rawSigs) && rawSigs.length > 0
        ? (rawSigs as Array<{ keyid: string; sig: string }>)
        : null;

    const provenance: ProvenanceInfo = {
      publishedAt,
      weeklyDownloads: downloads,
      maintainerCount,
      installScriptIsNew,
      totalVersions,
      unavailableReason: null,
      attestation,
      deprecated,
      publisher,
      publisherInMaintainers,
      hasRegistrySignature,
      attestationRegressed,
      firstPublishedAt,
      publisherIsNewToPackage,
      binaryHostChanged,
      previousBinaryHost,
    };

    return { provenance, registryManifestScripts, registryIntegrity, registrySignatures };
  } catch (err) {
    return unavailable(`Failed to fetch provenance: ${String(err)}`);
  }
}

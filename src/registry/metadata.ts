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
    },
    registryManifestScripts: null,
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
    const versionList = Object.keys(meta.versions);
    const versionIndex = versionList.indexOf(version);
    let installScriptIsNew: boolean | null = null;
    const currentHasScript = hasInstallScript(versionEntry?.scripts);

    if (versionIndex > 0) {
      const prevVersion = versionList[versionIndex - 1];
      const prevPkg = prevVersion ? meta.versions[prevVersion] : undefined;
      const prevHasScript = hasInstallScript(prevPkg?.scripts);
      installScriptIsNew = currentHasScript && !prevHasScript;
    } else if (versionIndex === 0) {
      installScriptIsNew = currentHasScript;
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

    // --- Deprecation ---
    const deprecated = versionEntry?.deprecated ?? null;

    // --- Registry signature presence ---
    const sigs = versionEntry?.dist?.signatures;
    const hasRegistrySignature =
      sigs !== undefined ? (Array.isArray(sigs) && sigs.length > 0) : null;

    // --- Registry manifest lifecycle scripts (for manifest confusion detection) ---
    const registryManifestScripts = extractLifecycleOnly(versionEntry?.scripts);

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
    };

    return { provenance, registryManifestScripts };
  } catch (err) {
    return unavailable(`Failed to fetch provenance: ${String(err)}`);
  }
}

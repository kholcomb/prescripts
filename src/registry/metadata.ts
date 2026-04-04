import { fetchFullMeta, fetchDownloads } from "./client.js";
import type { ProvenanceInfo } from "../types.js";

interface VersionScripts {
  scripts?: Record<string, string>;
}

const LIFECYCLE_HOOKS = [
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

export async function fetchProvenance(
  name: string,
  version: string,
  registryUrl: string
): Promise<ProvenanceInfo> {
  const isPublicRegistry = registryUrl
    .replace(/\/$/, "")
    .startsWith("https://registry.npmjs.org");

  if (!isPublicRegistry) {
    return {
      publishedAt: null,
      weeklyDownloads: null,
      maintainerCount: null,
      installScriptIsNew: null,
      totalVersions: null,
      unavailableReason: "Private registry — provenance metadata unavailable",
    };
  }

  try {
    const [meta, downloads] = await Promise.all([
      fetchFullMeta(name),
      fetchDownloads(name),
    ]);

    const publishedAt = meta.time?.[version] ?? null;
    const totalVersions = Object.keys(meta.versions).length;
    const maintainerCount = null; // maintainers field not available per-version in full meta

    // Determine if install script is new to this version
    const versionList = Object.keys(meta.versions);
    const versionIndex = versionList.indexOf(version);
    let installScriptIsNew: boolean | null = null;

    const currentPkg = meta.versions[version] as
      | (VersionScripts & { maintainers?: unknown[] })
      | undefined;
    const currentHasScript = hasInstallScript(
      (currentPkg as VersionScripts | undefined)?.scripts
    );

    if (versionIndex > 0) {
      const prevVersion = versionList[versionIndex - 1];
      const prevPkg = prevVersion
        ? (meta.versions[prevVersion] as VersionScripts | undefined)
        : undefined;
      const prevHasScript = hasInstallScript(prevPkg?.scripts);
      installScriptIsNew = currentHasScript && !prevHasScript;
    } else if (versionIndex === 0) {
      installScriptIsNew = currentHasScript;
    }

    return {
      publishedAt,
      weeklyDownloads: downloads,
      maintainerCount,
      installScriptIsNew,
      totalVersions,
      unavailableReason: null,
    };
  } catch (err) {
    return {
      publishedAt: null,
      weeklyDownloads: null,
      maintainerCount: null,
      installScriptIsNew: null,
      totalVersions: null,
      unavailableReason: `Failed to fetch provenance: ${String(err)}`,
    };
  }
}

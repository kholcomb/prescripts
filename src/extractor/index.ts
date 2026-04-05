import type { PackageRef, SourceType, ExtractedPackage } from "../types.js";
import { extractTarball } from "./tarball.js";
import { extractGitSource } from "./git-source.js";
import { extractLocalSource } from "./local-source.js";
import { fetchVersionMeta } from "../registry/client.js";
import { resolveAuthToken } from "../registry/npmrc.js";

export interface FetchResult {
  extracted: ExtractedPackage;
  sourceType: SourceType;
  integrityVerified: boolean;
  resolvedUrl: string;
}

function detectSourceType(resolved: string): SourceType {
  if (!resolved) return "registry";
  if (resolved.startsWith("file:")) return "local";
  if (
    resolved.startsWith("git+") ||
    resolved.startsWith("github:") ||
    resolved.startsWith("gitlab:") ||
    resolved.startsWith("bitbucket:")
  ) {
    return "git";
  }
  if (resolved.includes("registry.npmjs.org")) return "registry";
  if (resolved.match(/^https?:\/\//) && resolved.endsWith(".tgz")) {
    return "direct-tarball";
  }
  if (resolved.match(/^https?:\/\//)) return "private-registry";
  return "registry";
}

export async function fetchAndExtract(
  ref: PackageRef,
  projectDir: string,
  registryBase: string
): Promise<FetchResult> {
  const resolved = ref.resolved;
  const sourceType = detectSourceType(resolved);

  if (sourceType === "local") {
    const { extracted, integrityVerified } = await extractLocalSource(
      resolved,
      projectDir
    );
    return { extracted, sourceType, integrityVerified, resolvedUrl: resolved };
  }

  if (sourceType === "git") {
    const { extracted, integrityVerified } = await extractGitSource(
      resolved,
      ref.integrity
    );
    return { extracted, sourceType, integrityVerified, resolvedUrl: resolved };
  }

  // Registry, private-registry, direct-tarball
  let tarballUrl = resolved;
  let integrity = ref.integrity;

  // If resolved URL is empty (shouldn't happen in v2/v3 but possible in v1),
  // fetch the tarball URL from the registry
  if (!tarballUrl) {
    const meta = await fetchVersionMeta(ref.name, ref.version);
    tarballUrl = meta.tarballUrl;
    integrity = integrity ?? meta.integrity;
  }

  // Resolve auth token from .npmrc for private registries
  const authToken = sourceType === "private-registry"
    ? await resolveAuthToken(tarballUrl, projectDir)
    : null;

  const { extracted, integrityVerified } = await extractTarball(
    tarballUrl,
    integrity,
    authToken
  );
  return { extracted, sourceType, integrityVerified, resolvedUrl: tarballUrl };
}

export type SourceType =
  | "registry"
  | "private-registry"
  | "git"
  | "direct-tarball"
  | "local";

export type Severity = "critical" | "high" | "medium" | "low";
export type Confidence = "high" | "medium" | "low";
export type RiskLevel = "critical" | "high" | "medium" | "low" | "verified";

export interface PackageRef {
  name: string;
  version: string;
  resolved: string;
  integrity: string | null;
}

export interface SourceInfo {
  type: SourceType;
  resolved: string;
  integrity: string | null;
  integrityVerified: boolean;
}

export interface AttestationInfo {
  sourceRepo: string | null;    // e.g. "github.com/expressjs/express"
  buildWorkflow: string | null; // e.g. ".github/workflows/release.yml"
  predicateType: string | null; // SLSA predicate URI
}

export interface ProvenanceInfo {
  publishedAt: string | null;
  weeklyDownloads: number | null;
  maintainerCount: number | null;
  installScriptIsNew: boolean | null;
  totalVersions: number | null;
  unavailableReason: string | null;
  /** Sigstore provenance attestation. null = no attestation found. */
  attestation: AttestationInfo | null;
  /** Deprecation message if this version is deprecated, null otherwise. */
  deprecated: string | null;
  /** npm username that published this specific version. */
  publisher: string | null;
  /** Whether the publisher is in the current maintainers list.
   *  false can be normal (ex-maintainer); flag when combined with other signals. */
  publisherInMaintainers: boolean | null;
  /** Whether dist.signatures (ECDSA registry signing) is present. */
  hasRegistrySignature: boolean | null;
  /** True if the previous version had a Sigstore attestation but this one does not.
   *  The exact signal that would have caught the Axios supply chain attack. */
  attestationRegressed: boolean | null;
}

/** Returned by fetchProvenance — includes registry manifest scripts for
 *  manifest confusion detection in the caller. */
export interface ProvenanceFetchResult {
  provenance: ProvenanceInfo;
  /** Lifecycle scripts from the registry manifest (not the tarball).
   *  Used to detect manifest confusion: tarball scripts differ from what
   *  the registry shows as the authoritative package.json. */
  registryManifestScripts: LifecycleScripts | null;
}

export interface LifecycleScripts {
  preinstall?: string;
  install?: string;
  postinstall?: string;
  prepare?: string;
  prepublish?: string;
  prepublishOnly?: string;
  prepack?: string;
  postpack?: string;
}

export interface Excerpt {
  _warning: "UNTRUSTED THIRD-PARTY CONTENT";
  lines: string;
}

export interface Finding {
  scriptHook: keyof LifecycleScripts | null;
  source: string;
  category: string;
  severity: Severity;
  /** Confidence that this finding is genuinely malicious, given provenance context.
   *  Set to "medium" by the scanner; updated by confidence scoring in cli.ts. */
  confidence: Confidence;
  pattern: string;
  excerpt: Excerpt;
}

export interface BinaryField {
  host: string | null;
  remote_path: string | null;
  module_name: string | null;
}

export interface AdvisoryMatch {
  id: number;
  title: string;
  severity: Severity;
  url: string;
  vulnerableVersions: string;
  cves: string[];
  cvssScore: number | null;
}

export interface TrustConfig {
  /** Reduce confidence for ECDSA-signed packages. Default: true */
  signed: boolean;
  /** Reduce confidence for Sigstore-attested packages. Default: true */
  attested: boolean;
  /** Weekly download count above which a package is considered "popular". Default: 10000 */
  minWeeklyDownloads: number;
  /** Version count above which a package is considered "mature". Default: 10 */
  minVersions: number;
}

export interface NpmPrescriptsConfig {
  /** Minimum risk level to surface in output. Default: "low" */
  minRisk: RiskLevel;
  trust: TrustConfig;
}

export interface PackageReport {
  name: string;
  version: string;
  source: SourceInfo;
  provenance: ProvenanceInfo;
  lifecycleScripts: LifecycleScripts;
  binaryDownload: BinaryField | null;
  advisories: AdvisoryMatch[];
  findings: Finding[];
  /** Aggregated risk level computed from findings + provenance. */
  risk: RiskLevel;
}

export interface ProjectReport {
  scannedAt: string;
  mode: "scan" | "check";
  totalPackages: number;
  flaggedPackages: number;
  packages: PackageReport[];
}

export interface ExtractedPackage {
  packageJson: Record<string, unknown>;
  fileMap: Map<string, string>;
}

export interface CachedMeta {
  name: string;
  version: string;
  cachedAt: string;
  sourceType: SourceType;
  integrity: string | null;
}

export interface ScanOptions {
  severity: Severity;
  minRisk: RiskLevel;
  onlyFlagged: boolean;
  concurrency: number;
  registry: string;
  noCache: boolean;
  cacheDir: string | null;
  depth: number;
  timeout: number;
  verbose: boolean;
  json: boolean;
  sarif: boolean;
  output: string | null;
  apiUrl: string | null;
  trust: TrustConfig;
}

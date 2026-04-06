export type SourceType =
  | "registry"
  | "private-registry"
  | "git"
  | "direct-tarball"
  | "local";

export type PackageManager = "npm" | "pip" | "cargo" | "gem" | "actions" | "gitmodules";

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
  /** SRI-format digest of the attested tarball, from the in-toto subject digest.
   *  npm uses sha512 ("sha512-abc..."); PyPI uses sha256 ("sha256-abc...").
   *  Compare against the tarball we actually downloaded. */
  subjectIntegrity: string | null;
  /**
   * Full Sigstore chain verification result:
   *   true  = DSSE sig + Fulcio cert chain + Rekor SET + Merkle proof all passed
   *   false = one or more checks definitively failed (bundle is tampered or fabricated)
   *   null  = could not complete verification (trusted root unavailable, format error)
   */
  sigstoreVerified: boolean | null;
  /** GitHub Actions identity URI from the Fulcio certificate SAN.
   *  e.g. "https://github.com/owner/repo/.github/workflows/release.yml@refs/tags/v1.0.0" */
  signingIdentity: string | null;
  /** Descriptions of any verification failures or skipped checks. */
  sigstoreErrors: string[] | null;
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
  /** Date the very first version of this package was published.
   *  Combined with publishedAt + totalVersions, reveals version farming. */
  firstPublishedAt: string | null;
  /** True if this publisher has never published this package before.
   *  Fingerprints account takeover even when the attacker is a current maintainer. */
  publisherIsNewToPackage: boolean | null;
}

/** Returned by fetchProvenance — includes registry manifest scripts for
 *  manifest confusion detection in the caller. */
export interface ProvenanceFetchResult {
  provenance: ProvenanceInfo;
  /** Lifecycle scripts from the registry manifest (not the tarball).
   *  Used to detect manifest confusion: tarball scripts differ from what
   *  the registry shows as the authoritative package.json. */
  registryManifestScripts: LifecycleScripts | null;
  /** dist.integrity from the registry manifest.
   *  Compare against the lockfile integrity field to detect lockfile poisoning. */
  registryIntegrity: string | null;
  /** dist.signatures from the registry manifest, for ECDSA verification. */
  registrySignatures: Array<{ keyid: string; sig: string }> | null;
}

/**
 * Install hook name → script/command string.
 *
 * npm standard keys: preinstall, install, postinstall, prepare, prepublish,
 *   prepublishOnly, prepack, postpack
 * Python keys: "setup.py", "pyproject.toml [build-hooks]", "<name>.pth [.pth persistence]"
 */
export type LifecycleScripts = Record<string, string>;

export interface Excerpt {
  _warning: "UNTRUSTED THIRD-PARTY CONTENT";
  lines: string;
}

export interface Finding {
  scriptHook: string | null;
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
  id: string;
  title: string;
  severity: Severity;
  url: string;
  vulnerableVersions: string;
  patchedVersions: string | null;
  cves: string[];
  cvssScore: number | null;
}

export interface TrustConfig {
  /** Reduce confidence for ECDSA-signed packages. Default: true */
  signed: boolean;
  /** Reduce confidence for Sigstore-attested packages. Default: true */
  attested: boolean;
  /** Version count above which a package is considered "mature". Default: 10 */
  minVersions: number;
}

export interface NpmPrescriptsConfig {
  /** Minimum risk level to surface in output. Default: "low" */
  minRisk: RiskLevel;
  trust: TrustConfig;
  /**
   * Whether to attempt PEP 740 attestation fetches from the PyPI integrity API.
   * Set to false in air-gapped environments where pypi.org is unreachable.
   * Default: true
   */
  pypiAttestations: boolean;
}

export interface PackageReport {
  name: string;
  version: string;
  /** "pip" for Python packages from PyPI; absent/undefined for npm packages. */
  packageManager?: PackageManager;
  source: SourceInfo;
  provenance: ProvenanceInfo | null;
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
  /** Packages with install-time threats or patchable advisories — drives the default exit code. */
  actionablePackages: number;
  /** Packages with only unpatched runtime advisories — informational, no fix available upstream. */
  monitorPackages: number;
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
  /** Directory to write report.json and results.sarif. Human output still goes to stdout. */
  outputDir: string | null;
  apiUrl: string | null;
  trust: TrustConfig;
  /** Exit 1 for any flagged package, not just actionable ones. Default: false */
  strict: boolean;
  /**
   * Whether to attempt PEP 740 attestation fetches from the PyPI integrity API.
   * Set to false in air-gapped environments where pypi.org is unreachable.
   * Default: true
   */
  pypiAttestations: boolean;
}

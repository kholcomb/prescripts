export type SourceType =
  | "registry"
  | "private-registry"
  | "git"
  | "direct-tarball"
  | "local";

export type Severity = "critical" | "high" | "medium" | "low";

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

export interface ProvenanceInfo {
  publishedAt: string | null;
  weeklyDownloads: number | null;
  maintainerCount: number | null;
  installScriptIsNew: boolean | null;
  totalVersions: number | null;
  unavailableReason: string | null;
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
  pattern: string;
  excerpt: Excerpt;
}

export interface BinaryField {
  host: string | null;
  remote_path: string | null;
  module_name: string | null;
}

export interface PackageReport {
  name: string;
  version: string;
  source: SourceInfo;
  provenance: ProvenanceInfo;
  lifecycleScripts: LifecycleScripts;
  binaryDownload: BinaryField | null;
  findings: Finding[];
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
  onlyFlagged: boolean;
  concurrency: number;
  registry: string;
  noCache: boolean;
  cacheDir: string | null;
  depth: number;
  timeout: number;
  verbose: boolean;
  json: boolean;
  output: string | null;
  apiUrl: string | null;
}

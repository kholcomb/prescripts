/**
 * EcosystemPlugin interface — the single abstraction that lets prescripts
 * support arbitrary package managers without duplicating the scan loop.
 *
 * Each ecosystem (npm, pip, Cargo, RubyGems, Composer, …) implements this
 * interface. The generic `scanAny` function in index.ts drives the scan using
 * only the methods defined here.
 *
 * Adding a new ecosystem:
 *   1. Implement EcosystemPlugin in src/ecosystem/<pm>.ts
 *   2. Register the plugin in src/ecosystem/index.ts
 *   3. No changes to cli.ts or the scan loop are needed
 */

import type {
  PackageRef,
  PackageManager,
  ProvenanceFetchResult,
  Finding,
  AdvisoryMatch,
  SourceType,
  BinaryField,
  ScanOptions,
} from "../types.js";
import type { DiskCache } from "../cache/disk-cache.js";

/**
 * Normalized result from fetching and extracting a package archive.
 * The plugin's fetchPackage() method is responsible for producing this.
 */
export interface ExtractionResult {
  packageJson: Record<string, unknown>;
  fileMap: Map<string, string>;
  sourceType: SourceType;
  integrityVerified: boolean;
  computedIntegrity: string | null;
  /** Parsed node-pre-gyp/prebuild-install binary download descriptor, if any. */
  binaryDownload: BinaryField | null;
}

export interface EcosystemPlugin {
  readonly packageManager: PackageManager;

  /**
   * Called once before the scan loop to initialize any global state
   * (e.g. registry URL, timeout, concurrency).
   */
  init(opts: ScanOptions): void;

  /** Returns true if the given directory contains a lockfile for this ecosystem. */
  detectLockfile(dir: string): Promise<boolean>;

  /**
   * Returns the relative path(s) of lockfiles present in `dir`.
   * Used by the diff command to fetch base-branch content from git.
   * Returns an empty array if no lockfile is found.
   */
  getLockfilePaths(dir: string): Promise<string[]>;

  /**
   * Parses lockfile content from a string into PackageRefs.
   * `filename` is the basename of the lockfile (e.g. "package-lock.json",
   * "Cargo.lock") and is used by multi-format ecosystems (pip) to select
   * the right sub-parser.
   */
  parseLockfileContent(content: string, filename: string): PackageRef[];

  /**
   * Parses the lockfile found in `dir` and returns all PackageRefs to scan.
   * Returns null if no lockfile is found.
   */
  parseLockfile(dir: string): Promise<{ refs: PackageRef[]; lockfileDir: string; warnings?: string[] } | null>;

  /**
   * Resolves a CLI package spec ("name@version" or "name") to the set of
   * PackageRefs to scan (direct package + transitive deps for check mode).
   * Returns null if the package cannot be resolved.
   */
  resolveCheckSpec(spec: string, opts: ScanOptions): Promise<PackageRef[] | null>;

  /**
   * Downloads and extracts the package archive for `ref`.
   * Handles cache read/write internally based on opts.noCache.
   */
  fetchPackage(
    ref: PackageRef,
    opts: ScanOptions,
    cache: DiskCache,
    projectDir: string
  ): Promise<ExtractionResult>;

  /** Extracts install hooks from an extraction result. */
  extractHooks(result: ExtractionResult): Record<string, string>;

  /** Returns true if the hooks map contains anything worth scanning. */
  hasHooks(hooks: Record<string, string>): boolean;

  /**
   * Fetches provenance signals for `ref` from the registry.
   * Returns the full ProvenanceFetchResult (fields not applicable to this
   * ecosystem should be null rather than omitted).
   */
  fetchProvenance(ref: PackageRef, opts: ScanOptions): Promise<ProvenanceFetchResult>;

  /**
   * Generates ecosystem-specific findings that supplement pattern matches:
   * integrity verification, manifest confusion, registry signature checks,
   * attestation verification, etc.
   *
   * These are prepended to pattern findings in the final report.
   */
  extraFindings(
    ref: PackageRef,
    opts: ScanOptions,
    result: ExtractionResult,
    prov: ProvenanceFetchResult,
    hooks: Record<string, string>
  ): Promise<Finding[]>;

  /**
   * Fetches known security advisories for a batch of refs.
   * Ecosystems without an advisory feed return an empty Map.
   */
  fetchAdvisories(
    refs: PackageRef[],
    opts: ScanOptions
  ): Promise<Map<string, AdvisoryMatch[]>>;
}

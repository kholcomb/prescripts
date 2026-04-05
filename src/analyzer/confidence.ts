import type {
  Finding,
  ProvenanceInfo,
  AdvisoryMatch,
  BinaryField,
  TrustConfig,
  Confidence,
  RiskLevel,
} from "../types.js";

// ─── Confidence scoring ────────────────────────────────────────────────────

// Categories that are always high confidence regardless of provenance:
// they represent confirmed facts (integrity mismatch, known CVE, manifest tampering)
// rather than behavioral patterns that could have innocent explanations.
const ALWAYS_HIGH_CONFIDENCE = new Set([
  "integrity_mismatch",
  "lockfile_poisoning",       // lockfile integrity ≠ registry dist.integrity
  "signature_invalid",        // npm ECDSA registry signature failed verification
  "attestation_subject_mismatch", // attested tarball ≠ downloaded tarball
  "attestation_invalid",          // Sigstore chain verification failed (fabricated/tampered bundle)
  "advisory_match",
  "manifest_confusion",
  "reverse_shell",
  "cryptomining",
  "system_recon",
  "python_shell_exec",        // subprocess calling curl/wget/bash/nc, or shell=True
  "pth_persistence",          // .pth file with executable code — persistence mechanism
  "gem_plugin_hook",          // rubygems_plugin.rb — executes on every gem command
]);

// Categories where provenance trust signals have more weight —
// these fire on many legitimate packages.
const HIGH_NOISE_CATEGORIES = new Set([
  "dynamic_exec",
  "network",
  "dynamic_require",
  "env_check",
  "prebuilt_binary",
  "binary_downloader",
]);

function provenanceScore(provenance: ProvenanceInfo, trust: TrustConfig): number {
  let score = 0;

  // ─── Upward signals (increases suspicion) ───
  if (provenance.installScriptIsNew === true) score += 3;
  if ((provenance.totalVersions ?? 99) <= 2) score += 2;

  const dl = provenance.weeklyDownloads;
  if (dl !== null) {
    if (dl < 100) score += 3;
    else if (dl < 1000) score += 2;
    else if (dl < trust.minWeeklyDownloads) score += 1;
  } else {
    score += 1; // unknown downloads — mild upward pressure
  }

  if ((provenance.maintainerCount ?? 2) === 1) score += 1;
  if (provenance.attestationRegressed === true) score += 3;
  if (provenance.deprecated !== null) score += 2;
  if (provenance.publisherInMaintainers === false) score += 2;
  if (provenance.publisherIsNewToPackage === true) score += 2;

  // Version velocity: many versions published in a short window signals farming
  // Use only when ≥5 versions exist to avoid noise on genuinely new packages
  if (
    provenance.firstPublishedAt &&
    provenance.publishedAt &&
    (provenance.totalVersions ?? 0) >= 5
  ) {
    const ageMs =
      new Date(provenance.publishedAt).getTime() -
      new Date(provenance.firstPublishedAt).getTime();
    const ageDays = ageMs / (1000 * 60 * 60 * 24);
    const velocity = (provenance.totalVersions ?? 1) / Math.max(1, ageDays);
    if (velocity > 10) score += 2; // e.g. 20 versions in 2 days
    else if (velocity > 3) score += 1; // e.g. 10 versions in 3 days
  }

  // ─── Downward signals (increases trust) ───
  if (trust.attested && provenance.attestation !== null) score -= 2;
  if (trust.signed && provenance.hasRegistrySignature === true) score -= 1;

  const totalV = provenance.totalVersions ?? 0;
  if (totalV >= trust.minVersions * 5) score -= 2;
  else if (totalV >= trust.minVersions) score -= 1;

  if (dl !== null && dl >= trust.minWeeklyDownloads * 10) score -= 2;
  else if (dl !== null && dl >= trust.minWeeklyDownloads) score -= 1;

  return score;
}

function scoreToConfidence(score: number, isHighNoise: boolean): Confidence {
  // High-noise categories require a stronger provenance signal to surface
  const highThreshold = isHighNoise ? 5 : 3;
  const medThreshold = isHighNoise ? 3 : 1;

  if (score >= highThreshold) return "high";
  if (score >= medThreshold) return "medium";
  return "low";
}

export function scoreFindings(
  findings: Finding[],
  provenance: ProvenanceInfo,
  trust: TrustConfig
): Finding[] {
  const pScore = provenanceScore(provenance, trust);

  return findings.map((f) => {
    if (ALWAYS_HIGH_CONFIDENCE.has(f.category)) {
      return { ...f, confidence: "high" as Confidence };
    }
    // provenance_regression: strip the circular signals before scoring.
    // attestationRegressed (+3) is the finding itself — using it to score
    // its own confidence is circular. publisherInMaintainers===false (+2)
    // often reflects CI automation, not a human attacker; without additional
    // corroborating signals it shouldn't elevate confidence on its own.
    // Remaining score reflects genuine corroborating signals only:
    // installScriptIsNew, low downloads, few versions, deprecated, etc.
    if (f.category === "provenance_regression") {
      let corroborating = pScore;
      if (provenance.attestationRegressed === true) corroborating -= 3;
      if (provenance.publisherInMaintainers === false) corroborating -= 2;

      const c = scoreToConfidence(corroborating, false);
      // Floor: require at minimum that the tarball is registry-signed.
      // Publisher identity is not required — CI bots are common and don't
      // imply an attacker. Unsigned packages keep the "medium" floor.
      const canDropFloor = provenance.hasRegistrySignature === true;
      return { ...f, confidence: c === "low" && !canDropFloor ? "medium" : c };
    }
    const isHighNoise = HIGH_NOISE_CATEGORIES.has(f.category);
    return { ...f, confidence: scoreToConfidence(pScore, isHighNoise) };
  });
}

// ─── Binary downloader cluster detection ──────────────────────────────────

// Patterns that together indicate a legitimate binary download at install time.
const DOWNLOADER_BEHAVIORAL = new Set([
  "network",
  "dynamic_exec",
  "obfuscation",
  "dynamic_require",
  "env_check",
  "prebuilt_binary",
]);

// Source patterns for install-helper files (bundled binary fetchers)
const INSTALL_FILE_RE =
  /^referenced file:.*\b(install|download|postinstall|setup|fetch-binary|get-binary)\b.*\.(js|cjs|mjs)$/i;

export function applyBinaryDownloaderCluster(
  findings: Finding[],
  binaryDownload: BinaryField | null
): Finding[] {
  const hasPrebuilt = findings.some((f) => f.category === "prebuilt_binary");
  const hasBinaryField = binaryDownload !== null;

  // Also detect custom binary downloaders (like esbuild) that don't use
  // node-pre-gyp/prebuild-install but have network + exec in an install file
  const installFileFindings = findings.filter((f) => INSTALL_FILE_RE.test(f.source));
  const hasInstallFileCluster =
    installFileFindings.some((f) => f.category === "network" || f.category === "dns_exfil") &&
    installFileFindings.some((f) => f.category === "dynamic_exec");

  if (!hasPrebuilt && !hasBinaryField && !hasInstallFileCluster) return findings;

  // Identify behavioral findings that come from install-helper files
  const clusterMembers = findings.filter(
    (f) =>
      DOWNLOADER_BEHAVIORAL.has(f.category) &&
      (f.category === "prebuilt_binary" || INSTALL_FILE_RE.test(f.source))
  );

  if (clusterMembers.length < 2 && !hasBinaryField && !hasInstallFileCluster) return findings;

  const downloadHost = binaryDownload?.host ?? null;
  const hook =
    findings.find((f) => f.category === "prebuilt_binary")?.scriptHook ?? null;

  const clusterFinding: Finding = {
    scriptHook: hook,
    source: "binary downloader cluster",
    category: "binary_downloader",
    severity: "medium",
    confidence: "medium", // will be rescored by scoreFindings
    pattern: downloadHost
      ? `downloads platform binary from ${downloadHost}`
      : "downloads platform binary at install time",
    excerpt: {
      _warning: "UNTRUSTED THIRD-PARTY CONTENT",
      lines: downloadHost
        ? `Verify this is the expected download host: ${downloadHost}`
        : "Verify the binary download source and integrity for this package.",
    },
  };

  const remaining = findings.filter((f) => !clusterMembers.includes(f));
  return [...remaining, clusterFinding];
}

// ─── Package-level risk aggregation ───────────────────────────────────────

const RISK_ORDER: Record<RiskLevel, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  verified: 1,
};

export function computeRisk(
  findings: Finding[],
  advisories: AdvisoryMatch[],
  provenance: ProvenanceInfo
): RiskLevel {
  // No signals at all — check provenance alone
  if (findings.length === 0 && advisories.length === 0) {
    if (provenance.attestationRegressed === true) return "medium";
    if (provenance.deprecated !== null) return "low";
    return "verified";
  }

  let worst: RiskLevel = "verified";

  const bump = (r: RiskLevel) => {
    if (RISK_ORDER[r] > RISK_ORDER[worst]) worst = r;
  };

  for (const f of findings) {
    if (f.confidence === "low") {
      // Low-confidence findings contribute at most one level below their severity
      if (f.severity === "critical") bump("high");
      else if (f.severity === "high") bump("medium");
      else bump("low");
    } else if (f.confidence === "medium") {
      bump(f.severity === "critical" ? "critical" : f.severity);
    } else {
      // high confidence — face value
      bump(f.severity);
    }
  }

  for (const a of advisories) {
    // Advisories are always high confidence
    bump(a.severity === "critical" ? "critical" : a.severity);
  }

  return worst;
}

// ─── Config defaults ───────────────────────────────────────────────────────

export const DEFAULT_TRUST: TrustConfig = {
  signed: true,
  attested: true,
  minWeeklyDownloads: 10_000,
  minVersions: 10,
};

export const DEFAULT_MIN_RISK: RiskLevel = "low";

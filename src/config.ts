import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { NpmPrescriptsConfig, RiskLevel, TrustConfig } from "./types.js";
import { DEFAULT_TRUST, DEFAULT_MIN_RISK } from "./analyzer/confidence.js";

const CONFIG_FILE = ".npm-prescriptsrc.json";

interface RawConfig {
  minRisk?: RiskLevel;
  trust?: Partial<TrustConfig>;
  pypiAttestations?: boolean;
}

const VALID_RISK_LEVELS = new Set<RiskLevel>([
  "critical", "high", "medium", "low", "verified",
]);

export async function loadConfig(dir: string): Promise<NpmPrescriptsConfig> {
  try {
    const raw = await readFile(join(dir, CONFIG_FILE), "utf-8");
    const parsed = JSON.parse(raw) as RawConfig;

    const minRisk: RiskLevel =
      parsed.minRisk && VALID_RISK_LEVELS.has(parsed.minRisk)
        ? parsed.minRisk
        : DEFAULT_MIN_RISK;

    const trust: TrustConfig = {
      signed: parsed.trust?.signed ?? DEFAULT_TRUST.signed,
      attested: parsed.trust?.attested ?? DEFAULT_TRUST.attested,
      minWeeklyDownloads:
        parsed.trust?.minWeeklyDownloads ?? DEFAULT_TRUST.minWeeklyDownloads,
      minVersions: parsed.trust?.minVersions ?? DEFAULT_TRUST.minVersions,
    };

    const pypiAttestations = parsed.pypiAttestations !== false;

    return { minRisk, trust, pypiAttestations };
  } catch {
    // File not found or invalid JSON — use defaults silently
    return { minRisk: DEFAULT_MIN_RISK, trust: DEFAULT_TRUST, pypiAttestations: true };
  }
}

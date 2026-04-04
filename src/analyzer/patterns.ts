import type { Severity } from "../types.js";

export interface PatternDef {
  category: string;
  severity: Severity;
  patterns: RegExp[];
  description: string;
}

export const PATTERN_REGISTRY: ReadonlyArray<PatternDef> = [
  {
    category: "pipe_exec",
    severity: "critical",
    description: "Pipes output directly into a shell interpreter",
    // Use negative lookbehind to exclude || (logical OR) — only match single pipes
    patterns: [/(?<!\|)\|\s*bash\b/, /(?<!\|)\|\s*sh\b/, /(?<!\|)\|\s*node\b/],
  },
  {
    category: "reverse_shell",
    severity: "critical",
    description: "Reverse shell pattern",
    patterns: [/\/dev\/tcp\//, /bash\s+-i\b/, /\bnc\s+[-\w.]+\s+\d+/],
  },
  {
    category: "network",
    severity: "high",
    description: "Network request in lifecycle script",
    patterns: [
      /\bcurl\b/,
      /\bwget\b/,
      /\bfetch\s*\(/,
      /https?\.get\s*\(/,
      /http\.request\s*\(/,
      /https\.request\s*\(/,
    ],
  },
  {
    category: "obfuscation",
    severity: "high",
    description: "Encoding or dynamic code evaluation",
    patterns: [
      /\beval\s*\(/,
      /\bFunction\s*\(/,
      /Buffer\.from\s*\([^)]*['"]\s*base64\s*['"]/,
      /Buffer\.from\s*\([^)]*['"]\s*hex\s*['"]/,
      /String\.fromCharCode\s*\(/,
      /\batob\s*\(/,
    ],
  },
  {
    category: "dynamic_exec",
    severity: "high",
    description: "Dynamic process execution",
    patterns: [
      /\bchild_process\b/,
      /\bexecSync\s*\(/,
      /\bspawn\s*\(/,
      /[^a-zA-Z]exec\s*\(/,
    ],
  },
  {
    category: "windows_exec",
    severity: "high",
    description: "Windows-specific execution patterns",
    patterns: [
      /\bpowershell\b/i,
      /Invoke-Expression\b/i,
      /\bIEX\b/,
      /\bmshta\b/i,
      /\bwscript\b/i,
      /DownloadString\b/i,
    ],
  },
  {
    category: "raw_socket",
    severity: "high",
    description: "Raw network socket usage",
    patterns: [
      /net\.createConnection\s*\(/,
      /new\s+net\.Socket\s*\(/,
      /dgram\.createSocket\s*\(/,
    ],
  },
  {
    category: "credential_files",
    severity: "high",
    description: "Reads or references credential files",
    patterns: [
      /\/\.aws\//,
      /\bid_rsa\b/,
      /\bid_ed25519\b/,
      /authorized_keys/,
      /\.npmrc/,
    ],
  },
  {
    category: "persistence",
    severity: "high",
    description: "Writes to shell init or scheduled task files",
    patterns: [
      /\bcrontab\b/,
      /\.bashrc\b/,
      /\.zshrc\b/,
      /\.profile\b/,
      /authorized_keys/,
    ],
  },
  {
    category: "vm_abuse",
    severity: "high",
    description: "Node.js vm module misuse for sandbox escape",
    patterns: [/vm\.runInNewContext\s*\(/, /vm\.runInThisContext\s*\(/],
  },
  {
    category: "env_probe",
    severity: "medium",
    description: "Reads sensitive environment variables",
    patterns: [
      /\bAWS_[A-Z_]+\b/,
      /\bGITHUB_TOKEN\b/,
      /\bNPM_TOKEN\b/,
      /\bSSH_AUTH_SOCK\b/,
    ],
  },
  {
    category: "dynamic_require",
    severity: "medium",
    description: "Dynamic require or import with non-literal argument",
    patterns: [
      /require\s*\(\s*[^'"`)]/,
      /import\s*\(\s*[^'"`)]/,
    ],
  },
  {
    category: "suspicious_write",
    severity: "medium",
    description: "Writes to sensitive filesystem paths",
    patterns: [/\/etc\//, /\$HOME\//, /~\//],
  },
  {
    category: "prebuilt_binary",
    severity: "medium",
    description:
      "Downloads a prebuilt native binary at install time — binary origin cannot be statically verified",
    patterns: [
      /\bnode-pre-gyp\b/,
      /\b@mapbox\/node-pre-gyp\b/,
      /\bprebuild-install\b/,
      /\bprebuildify\b/,
      /node-gyp\s+rebuild/,
    ],
  },
  {
    category: "env_check",
    severity: "low",
    description: "Reads process environment (broad signal — weigh with provenance)",
    patterns: [/process\.env\b/],
  },
  {
    category: "integrity_mismatch",
    severity: "critical",
    description: "Downloaded content does not match expected integrity hash",
    patterns: [], // emitted programmatically, not by regex
  },
];

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

import type { Severity } from "../types.js";

export interface PatternDef {
  category: string;
  severity: Severity;
  patterns: RegExp[];
  description: string;
  /**
   * If set, only apply this pattern when the source string matches.
   * Use to restrict patterns to specific file types or contexts.
   * Example: /\.pth\b/ restricts to .pth files only.
   */
  sourceMatch?: RegExp;
  /**
   * If set, skip this pattern when the source string matches.
   * Use to prevent language bleed — e.g. stop JS patterns from firing on .py files.
   * Example: /\.py\b/ excludes Python source files.
   */
  sourceExclude?: RegExp;
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
    // Python files have dedicated python_network patterns — exclude to prevent bleed
    sourceExclude: /\.py\b/,
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
    // Python files have dedicated python_obfuscation patterns — exclude to prevent bleed.
    // Specifically prevents exec(f.read(), about) (version-loading idiom) from matching.
    sourceExclude: /\.py\b/,
    patterns: [
      /\beval\s*\(/,
      /\bFunction\s*\(/,
      /Buffer\.from\s*\([^)]*['"]\s*base64\s*['"]/,
      /Buffer\.from\s*\([^)]*['"]\s*hex\s*['"]/,
      /String\.fromCharCode\s*\(/,
      /\batob\s*\(/,
      // 3+ consecutive hex escapes — typical obfuscated string payload
      /(?:\\x[0-9a-fA-F]{2}){3,}/,
      // 2+ consecutive unicode escapes in the low-codepoint range
      /(?:\\u00[0-9a-fA-F]{2}){2,}/,
      // Native binding bypass (sandbox escape vector)
      /process\.binding\s*\(/,
      // event-stream/flatmap-stream (2018): crypto.createDecipher with hardcoded key
      /crypto\.createDecipher\s*\(/,
      /crypto\.createDecipheriv\s*\(/,
      // Axios supply chain (2026): string reversal for payload deobfuscation
      /\.split\s*\(\s*['"]{2}\s*\).*\.reverse\s*\(\s*\).*\.join\s*\(\s*['"]{2}\s*\)/,
      // Long inline base64 literals (80+ chars) — encoded payload in script
      // Short base64 appears in legitimate code; 80+ chars in a lifecycle script
      // almost always indicates an embedded payload
      /['"][A-Za-z0-9+/]{80,}={0,2}['"]/,
      // Anti-forensic infinite loop: for(;;){ ... break} — seen in Axios compromise
      /for\s*\(\s*;\s*;\s*\)\s*\{/,
    ],
  },
  {
    category: "dynamic_exec",
    severity: "high",
    description: "Dynamic process execution",
    // Python files have dedicated python_exec / python_shell_exec patterns.
    // Excludes Python to prevent: exec(f.read(), about) version-loading false positive,
    // and subprocess.*() being caught by both JS and Python patterns simultaneously.
    sourceExclude: /\.py\b/,
    patterns: [
      /\bchild_process\b/,
      /\bexecSync\s*\(/,
      /\bspawnSync\s*\(/,
      /\bspawn\s*\(/,
      // Negative lookbehind: exclude .exec( (RegExp/Promise method) and word-char prefix
      /(?<![.\w])exec\s*\(/,
      // Make executable then run — common in postinstall downloaders
      /chmod\s+[+\d]*x\b/,
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
      /~\/\.ssh\//,              // SSH key directory
      /~\/\.docker\/config/,     // Docker registry tokens
      /~\/\.kube\/config\b/,     // Kubernetes credentials
      /~\/\.config\/gh\//,       // GitHub CLI credentials
      /\.yarnrc\b/,              // Yarn tokens
      /~\/\.netrc\b/,            // curl/ftp credentials
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
      // AWS credentials
      /\bAWS_[A-Z_]+\b/,
      // SCM tokens
      /\bGITHUB_TOKEN\b/,
      /\bGITLAB_TOKEN\b/,
      /\bCI_JOB_TOKEN\b/,        // GitLab CI internal token
      // Package registry tokens
      /\bNPM_TOKEN\b/,
      /\bNODE_AUTH_TOKEN\b/,     // GitHub Actions npm publish token
      // CI/CD platform tokens — high-value targets; specific enough for medium→co-occur→critical
      /\bACTIONS_RUNTIME_TOKEN\b/,
      /\bACTIONS_CACHE_URL\b/,
      /\bCIRCLE_TOKEN\b/,
      /\bTRAVIS_[A-Z_]+\b/,
      // Cloud platform credentials
      /\bDOCKER_PASSWORD\b/,
      /\bHEROKU_API_KEY\b/,
      /\bVERCEL_TOKEN\b/,
      /\bNETLIFY_AUTH_TOKEN\b/,
      // SSH agent socket
      /\bSSH_AUTH_SOCK\b/,
    ],
  },
  {
    category: "dynamic_require",
    severity: "medium",
    description: "Dynamic require or import with non-literal argument",
    patterns: [
      // Exclude common benign patterns: path.join/__dirname/__filename/require.resolve
      // Also exclude aliased path imports (path2, path_, _path etc) — common in bundled code
      /require\s*\(\s*(?!path[\w]*\.|__dirname|__filename|require\.resolve)[^'"`)]/,
      /import\s*\(\s*(?!path[\w]*\.|__dirname|__filename)[^'"`)]/,
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
    patterns: [
      // Exclude the most common benign vars: NODE_ENV, CI flags, PATH, shell basics
      /process\.env(?!\.(NODE_ENV|CI|TERM|LANG|PATH|HOME|USER|PWD|SHELL|npm_)\b)\b/,
    ],
  },
  {
    category: "dns_exfil",
    severity: "medium",
    description: "DNS lookup at install time — common exfiltration channel",
    patterns: [
      /\bdns\.lookup\s*\(/,
      /\bdns\.resolve\s*\(/,
      /\bdns\.reverse\s*\(/,
      /require\s*\(\s*['"]dns['"]\s*\)/,
    ],
  },
  {
    // high not critical: python -c is occasionally used by legitimate build scripts
    // (e.g. gyp-based tools calling python). Weight against provenance.
    category: "living_off_land",
    severity: "high",
    description:
      "Invokes an alternative interpreter — execution via python/perl/ruby/php",
    patterns: [
      /\bpython\d*\s+.*-[^\s]*c\b/,  // python -c "code"
      /\bperl\s+-[^\s]*e\b/,          // perl -e "code"
      /\bruby\s+-[^\s]*e\b/,          // ruby -e "code"
      /\bphp\s+-r\b/,                 // php -r "code"
    ],
  },
  {
    // critical: xmrig/minerd in an install script has no legitimate use.
    // stratum+tcp is the mining pool protocol — zero ambiguity.
    category: "cryptomining",
    severity: "critical",
    description: "Cryptocurrency miner binary or pool protocol reference",
    patterns: [
      /\bxmrig\b/i,
      /\bminerd\b/i,
      /\bcpuminer\b/i,
      /stratum\+tcp:\/\//,            // mining pool URI scheme
      /\bcryptonight\b/i,             // algorithm name used in pool configs
    ],
  },
  {
    // high: these are specific webhook URLs with no benign install-time use.
    // medium would under-represent the exfil risk; critical is reserved for
    // confirmed data-leaving patterns (env_exfil, integrity_mismatch).
    category: "webhook_exfil",
    severity: "high",
    description:
      "Posts to a known-platform webhook — common low-noise exfiltration channel",
    patterns: [
      /discord\.com\/api\/webhooks\//,
      /hooks\.slack\.com\//,
      /api\.telegram\.org\/bot[^/]+\//,  // Telegram bot API with token in path
      /notify\.run\//,                   // notify.run push service
    ],
  },
  {
    // medium: container/sandbox detection is a precursor behaviour, not directly
    // harmful — a package checking "am I in Docker" might be doing install-path
    // selection. Elevates when combined with network (co-occurrence) or obfuscation.
    category: "sandbox_evasion",
    severity: "medium",
    description:
      "Probes for container or sandbox indicators — may suppress payload in analysis environments",
    patterns: [
      /\/\.dockerenv\b/,
      /\/proc\/1\/cgroup\b/,
      /\/proc\/self\/status\b/,
      /\bos\.hostname\s*\(\s*\)/,     // hostname fingerprinting
    ],
  },
  {
    // critical: /proc/self/environ dumps the entire process environment including
    // all secrets. /etc/shadow contains password hashes. Neither has a legitimate
    // reason to appear in a package install script.
    category: "system_recon",
    severity: "critical",
    description:
      "Reads privileged system files that expose credentials or full environment state",
    patterns: [
      /\/proc\/self\/environ\b/,      // complete environment variable dump
      /\/etc\/shadow\b/,              // password hash file
      /\/proc\/net\/tcp\b/,           // active network connection table
      /\/proc\/self\/maps\b/,         // memory layout (ASLR bypass aid)
    ],
  },
  {
    category: "env_exfil",
    severity: "critical",
    description:
      "Env probe co-occurs with network call — credential exfiltration pattern",
    patterns: [], // emitted programmatically by co-occurrence detection in scanner.ts
  },
  {
    // critical: the tarball the user installs has different lifecycle scripts
    // than what the registry manifest advertises. Tools that only read the
    // registry manifest (most of them) will not see the malicious scripts.
    category: "manifest_confusion",
    severity: "critical",
    description:
      "Tarball lifecycle scripts differ from registry manifest — hidden or modified install scripts",
    patterns: [], // emitted programmatically in cli.ts after tarball extraction
  },
  {
    // high: provenance attestation was present in the previous version but is
    // absent in this one. This is the exact signal that would have caught the
    // malicious axios@1.14.1 release.
    category: "provenance_regression",
    severity: "high",
    description:
      "Previous version had Sigstore provenance attestation; this version does not",
    patterns: [], // emitted programmatically in cli.ts
  },
  {
    // Emitted by cluster detection when prebuilt_binary + network + dynamic_exec
    // co-occur in an install helper file. Replaces the individual findings with
    // one named finding whose verification question is the download host.
    category: "binary_downloader",
    severity: "medium",
    description:
      "Package downloads a platform binary at install time — verify the download host",
    patterns: [], // emitted programmatically by cluster detection in confidence.ts
  },
  {
    category: "integrity_mismatch",
    severity: "critical",
    description: "Downloaded content does not match expected integrity hash",
    patterns: [], // emitted programmatically, not by regex
  },

  // ── Python-specific patterns ────────────────────────────────────────────────

  {
    // medium: broad subprocess detection. Fires on legitimate patterns like
    // subprocess.check_output([sys.executable, 'build/version.py']) (numpy-style
    // version detection) and subprocess.run(['git', 'describe', ...]).
    // Provenance scoring will lower confidence for mature, popular packages.
    // Use python_shell_exec for high-confidence dangerous subprocess patterns.
    category: "python_exec",
    severity: "medium",
    description: "Subprocess or os.system call in Python install hook",
    sourceMatch: /\.py\b|setup\.|pyproject|\.cfg\b/,
    patterns: [
      // Generic subprocess — many legitimate uses (version detection, build tooling)
      /\bsubprocess\.(?:run|call|check_output|check_call|Popen)\s*\(/,
      /\bos\.system\s*\(/,
      /\bos\.popen\s*\(/,
      /\bos\.exec[vle]+\s*\(/,
      /\bcommands\.getoutput\s*\(/,
    ],
  },
  {
    // high: subprocess specifically invoking shell/network tools, or using shell=True.
    // shell=True passes the command to /bin/sh — combines process exec with shell injection risk.
    // Calling curl/wget/nc/bash from a setup.py has almost no legitimate install-time use.
    category: "python_shell_exec",
    severity: "high",
    description: "Subprocess calling shell or network tool — high-confidence dangerous pattern",
    sourceMatch: /\.py\b|setup\.|pyproject|\.cfg\b/,
    patterns: [
      // shell=True with subprocess — executes as a shell command (injection vector)
      /\bsubprocess\.(?:run|call|Popen)\s*\([^)]*\bshell\s*=\s*True/,
      // subprocess calling network/shell tools directly (first arg is the tool name)
      /\bsubprocess\.(?:run|call|check_output|Popen)\s*\(\s*\[?\s*["'](?:bash|sh|curl|wget|nc|ncat|netcat|powershell)['"]/,
      // os.system calling network tools
      /\bos\.system\s*\(\s*f?["'][^'"]*(?:curl|wget|bash\s+-c|nc\s)/,
    ],
  },
  {
    category: "python_network",
    severity: "high",
    description: "Network request in Python install hook",
    sourceMatch: /\.py\b|setup\.|pyproject|\.cfg\b/,
    patterns: [
      /\burllib(?:\.request)?\.urlopen\s*\(/,
      /\burllib\.request\.urlretrieve\s*\(/,
      /\brequests\.(?:get|post|put|patch|delete|request|Session)\s*\(/,
      /\bhttpx\.(?:get|post|request|Client)\s*\(/,
      /\baiohttp\.ClientSession\s*\(/,
      /\bhttp\.client\.HTTPConnection\s*\(/,
      /\bsocket\.(?:connect|create_connection)\s*\(/,
    ],
  },
  {
    category: "python_obfuscation",
    severity: "high",
    description: "Encoding or dynamic code evaluation in Python",
    sourceMatch: /\.py\b|setup\.|pyproject|\.cfg\b/,
    patterns: [
      // exec with base64-decoded payload — classic attack vector
      /\bexec\s*\(\s*base64\.b64decode\s*\(/,
      /\bexec\s*\(\s*__import__\s*\(\s*['"]base64['"]/,
      // eval with compiled code or encoded string
      /\beval\s*\(\s*compile\s*\(/,
      // marshal.loads executes serialized Python bytecode
      /\bmarshal\.loads\s*\(/,
      // zlib decompress + exec — common multi-layer obfuscation
      /zlib\.decompress.*exec/,
      /exec.*zlib\.decompress/,
      // Long inline base64 literals in Python (80+ chars)
      /b['"]{1}[A-Za-z0-9+/]{80,}={0,2}['"]{1}/,
      // Hex-encoded string executed
      /bytes\.fromhex\s*\([^)]+\)\s*\.decode/,
      // codecs.decode with rot13 or base64 — obfuscation
      /codecs\.decode\s*\([^,]+,\s*['"](?:rot.?13|base64)['"]/,
    ],
  },
  {
    // critical: .pth files installed to site-packages run at every Python startup.
    // Legitimate .pth files contain only filesystem paths. Code execution here
    // is a persistence mechanism — it survives the install and runs indefinitely.
    // Attack vector: ctx (2022), Python-utils attack campaign.
    // sourceMatch restricts these patterns to .pth file sources only — `import` at
    // the start of a line is normal in any Python file but malicious in a .pth file.
    category: "pth_persistence",
    severity: "critical",
    description:
      ".pth file contains executable code — runs at every Python startup after install",
    sourceMatch: /\.pth/,
    patterns: [
      // "import <module>" at start of line — executes the module
      /^import\s+\w/m,
      // exec(), __import__(), or eval() in a .pth file
      /^exec\s*\(/m,
      /^__import__\s*\(/m,
      /^eval\s*\(/m,
    ],
  },
  {
    category: "python_credential_files",
    severity: "high",
    description: "Reads Python-ecosystem credential files",
    sourceMatch: /\.py\b|setup\.|pyproject|\.cfg\b/,
    patterns: [
      /~\/\.pypirc\b/,         // PyPI upload credentials
      /pip\.conf\b/,           // pip configuration (may contain index credentials)
      /\/\.local\/lib\//,      // user site-packages path traversal
      /site-packages\b.*\.\./,  // path traversal out of site-packages
    ],
  },
  {
    category: "python_ctypes",
    severity: "high",
    description: "Loads native code via ctypes or cffi — executes outside Python sandbox",
    sourceMatch: /\.py\b|setup\.|pyproject|\.cfg\b/,
    patterns: [
      /\bctypes\.(?:cdll|windll|oledll)\.LoadLibrary\s*\(/,
      /\bctypes\.CDLL\s*\(/,
      /\bcffi\.FFI\s*\(\s*\)/,
      /\bctypes\.WinDLL\s*\(/,
    ],
  },
];

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

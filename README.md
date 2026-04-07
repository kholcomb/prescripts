# prescripts

Static lifecycle script scanner for package managers — a triage tool for humans and LLM agents to detect supply-chain threats in project dependencies.

Prescripts inspects install-time hooks (`postinstall`, `preinstall`, `prepare`, etc.) across your dependency tree, cross-references known advisories, and verifies provenance attestations. Results surface in the terminal, as JSON, as SARIF (for the GitHub Security tab), or as a PR comment diff.

## Supported ecosystems

| Ecosystem | Lockfile(s) |
|-----------|-------------|
| npm       | `package-lock.json`, `npm-shrinkwrap.json` |
| pip       | `requirements.txt`, `pyproject.toml`, `poetry.lock`, `uv.lock` |
| Cargo     | `Cargo.lock` |
| RubyGems  | `Gemfile.lock` |
| Go        | `go.mod` |
| Maven     | `pom.xml` |
| NuGet     | `packages.lock.json`, `project.assets.json` |

Local scanners (no registry required): GitHub Actions workflows, git submodules.

## Installation

```bash
npm install -g prescripts
```

Or as a dev dependency:

```bash
npm install --save-dev prescripts
```

## Commands

### `prescripts scan [dir]`

Scan all packages resolved by a project lockfile.

```bash
prescripts scan
prescripts scan --min-risk medium --only-flagged
prescripts scan --output-dir ci-results
```

Exits `1` if actionable findings are detected.

| Option | Default | Description |
|--------|---------|-------------|
| `--min-risk <level>` | `low` | Minimum risk level to surface: `verified` \| `low` \| `medium` \| `high` \| `critical` |
| `--only-flagged` | — | Suppress packages with no findings |
| `--json` | — | Write JSON report to stdout |
| `--sarif` | — | Write SARIF 2.1.0 to stdout |
| `-o, --output-dir <dir>` | — | Write `report.json` and `results.sarif` to a directory |
| `--strict` | — | Exit `1` for any flagged package, not just actionable ones |
| `--concurrency <n>` | `5` | Max simultaneous registry requests |
| `--timeout <ms>` | `30000` | Per-request timeout |
| `--no-cache` | — | Skip cache reads |
| `--cache-dir <path>` | `~/.cache/prescripts` | Override cache location |
| `--registry <url>` | npm registry | npm registry URL |
| `-v, --verbose` | — | Debug output to stderr |

### `prescripts check <package>`

Scan a single package before installing it.

```bash
prescripts check express@4.18.2
prescripts check requests@2.28.0 --pm pip
prescripts check serde@1.0.0 --pm cargo
```

| Option | Default | Description |
|--------|---------|-------------|
| `--pm <manager>` | `npm` | `npm` \| `pip` \| `cargo` \| `gem` |
| `--depth <n>` | `5` | Dependency resolution depth (npm only) |

All `scan` options also apply.

### `prescripts diff [dir]`

Show security-relevant changes between two git references. Generates `diff.md` for PR comments, `diff.json`, and `diff.sarif`.

```bash
prescripts diff --base origin/main
prescripts diff --base v1.2.0 --output-dir ci-results
```

| Option | Default | Description |
|--------|---------|-------------|
| `--base <ref>` | `origin/main` | Git reference to compare against |
| `--json` | — | Output JSON diff to stdout |
| `--sarif` | — | Output SARIF diff to stdout |
| `-o, --output-dir <dir>` | — | Write `diff.md`, `diff.json`, `diff.sarif` |

### `prescripts fix [dir]`

List advisory-driven upgrades available for flagged packages, and optionally apply them.

```bash
prescripts fix               # show available patches
prescripts fix --apply       # run npm install with patched versions
```

### `prescripts init-ci [dir]`

Generate a GitHub Actions workflow that scans on every push and PR.

```bash
prescripts init-ci --min-risk high --with-diff
```

| Option | Default | Description |
|--------|---------|-------------|
| `--min-risk <level>` | `medium` | Failure threshold |
| `--no-fail` | — | Upload SARIF but always exit `0` |
| `--with-diff` | — | Post diff as a PR comment |
| `--force` | — | Overwrite an existing workflow file |

### `prescripts init-hooks [dir]`

Install a git pre-commit hook that blocks commits containing lockfile changes that introduce findings.

```bash
prescripts init-hooks --min-risk high
```

Bypass with `git commit --no-verify`.

## Configuration

Create `.prescriptsrc.json` in your project root to set per-project defaults:

```json
{
  "minRisk": "medium",
  "trust": {
    "signed": true,
    "attested": true,
    "minVersions": 10
  },
  "pypiAttestations": true
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `minRisk` | `"low"` | Minimum risk level to surface |
| `trust.signed` | `true` | Lower confidence for ECDSA-signed packages |
| `trust.attested` | `true` | Lower confidence for Sigstore-attested packages |
| `trust.minVersions` | `10` | Version count threshold to consider a package "mature" |
| `pypiAttestations` | `true` | Fetch PyPI PEP 740 attestations (set `false` in air-gapped environments) |

## GitHub Actions integration

There are several ways to add prescripts to a workflow depending on how much control you need.

### 1. Composite action (simplest)

The composite action handles installation, scanning, and SARIF upload in a single step.

**Minimal setup** — scans on every push and PR, uploads results to the Security tab:

```yaml
permissions:
  contents: read
  security-events: write   # required for SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - uses: kholcomb/prescripts@v0.1.0
        with:
          min-risk: medium
```

**With PR diff comment** — posts a security-focused diff of changed packages on every pull request:

```yaml
permissions:
  contents: read
  security-events: write
  pull-requests: write     # required for PR comment

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # needed for diff against base branch

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - uses: kholcomb/prescripts@v0.1.0
        id: prescripts
        with:
          min-risk: medium
          upload-sarif: true
          output-dir: ci-results

      - name: Diff changed packages
        if: github.event_name == 'pull_request'
        run: |
          prescripts diff --base origin/${{ github.base_ref }} --output-dir ci-results

      - name: Post PR comment
        if: github.event_name == 'pull_request'
        run: |
          gh pr comment ${{ github.event.pull_request.number }} \
            --body-file ci-results/diff.md --edit-last \
            || gh pr comment ${{ github.event.pull_request.number }} \
               --body-file ci-results/diff.md
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Action inputs:**

| Input | Default | Description |
|-------|---------|-------------|
| `min-risk` | `medium` | Minimum risk level to surface and fail on: `verified` \| `low` \| `medium` \| `high` \| `critical` |
| `only-flagged` | `false` | Suppress packages with no findings from output |
| `upload-sarif` | `true` | Upload SARIF to the GitHub Security tab (requires `security-events: write`) |
| `output-dir` | `.` | Directory to write `report.json` and `results.sarif` |
| `version` | `latest` | prescripts version to install (`latest`, `1.2.3`, or path to a local `.tgz`) |

**Action outputs:**

| Output | Description |
|--------|-------------|
| `sarif-file` | Path to the generated SARIF file |
| `json-file` | Path to the generated JSON report |

---

### 2. Generate a workflow with `init-ci`

Run this once locally to write a ready-to-commit workflow file:

```bash
prescripts init-ci --min-risk high --with-diff
```

| Option | Description |
|--------|-------------|
| `--min-risk <level>` | Failure threshold (default: `medium`) |
| `--no-fail` | Upload SARIF but always exit `0` |
| `--with-diff` | Include PR diff comment steps |
| `--force` | Overwrite an existing workflow file |

---

### 3. CLI in a `run` step

For full control over the step sequence, call prescripts directly. Use `npx` to avoid a separate install step:

```yaml
- name: Scan dependencies
  run: npx prescripts@latest scan . --output-dir . --min-risk medium

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

Or install globally when you need the binary available across multiple steps:

```yaml
- name: Install prescripts
  run: npm install -g prescripts

- name: Scan
  run: prescripts scan . --output-dir . --min-risk medium --only-flagged

- name: Diff
  if: github.event_name == 'pull_request'
  run: prescripts diff --base origin/${{ github.base_ref }} --output-dir .
```

---

### 4. Single-package gate

Use `prescripts check` to block a workflow before installing a newly added package:

```yaml
- name: Vet new dependency
  run: npx prescripts@latest check ${{ env.NEW_PACKAGE }} --pm npm --min-risk high
  env:
    NEW_PACKAGE: some-library@2.0.0
```

This is useful in workflows that automate dependency updates (e.g. Dependabot follow-up jobs, custom upgrade PRs) where you want to gate on a single package before running the full install.

---

### 5. MCP server in an AI agent workflow

Prescripts ships an MCP server exposing three tools:

| Tool | Description |
|------|-------------|
| `scan_project` | Scan all packages in a project lockfile (auto-detects ecosystem) |
| `scan_package` | Scan a single `name@version` before installing it |
| `compare_versions` | Diff lifecycle scripts and findings between two versions |

**Claude Code / local agent** — add to your MCP config:

```json
{
  "mcpServers": {
    "prescripts": {
      "command": "node",
      "args": ["/path/to/prescripts/dist/mcp.js"]
    }
  }
}
```

Or if installed globally:

```json
{
  "mcpServers": {
    "prescripts": {
      "command": "npx",
      "args": ["prescripts-mcp"]
    }
  }
}
```

**Agent step in a GitHub Actions workflow** — run the MCP server as a sidecar and invoke it from an agent step:

```yaml
- name: Security review (AI agent)
  uses: anthropics/claude-code-action@v1
  with:
    prompt: |
      Use the prescripts MCP tools to scan this project and summarize
      any medium or higher risk findings. For each finding, explain
      what the package does and whether it looks intentional.
    mcp_config: |
      {
        "mcpServers": {
          "prescripts": {
            "command": "npx",
            "args": ["prescripts@latest", "mcp"]
          }
        }
      }
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

## How risk is scored

Each package gets a risk level derived from:

- **Pattern matches** — 40+ regex patterns across categories like `pipe_exec`, `reverse_shell`, `network`, `obfuscation`, `dynamic_exec`, and `privilege_escalation`, weighted by confidence
- **Security advisories** — pulled from OSV, npm, PyPI, crates.io, RubyGems, Maven Central, and NuGet
- **Provenance signals** — Sigstore attestations (DSSE + Fulcio + Rekor), ECDSA registry signatures, publisher identity, attestation regression, binary download host changes, and manifest confusion (registry vs. tarball mismatch)

Risk levels: `critical` > `high` > `medium` > `low` > `verified`

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No actionable findings |
| `1` | Actionable findings detected |
| `2` | Error (missing lockfile, invalid input, etc.) |

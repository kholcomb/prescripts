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

## CI integration

The quickest path to automated scanning is `init-ci`, which writes a workflow file for you. If you prefer to wire it up manually, the pattern used in this repo is:

```yaml
- name: Scan dependencies
  run: prescripts scan . --output-dir . --min-risk medium

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif

- name: Diff changed packages
  if: github.event_name == 'pull_request'
  run: prescripts diff --base origin/${{ github.base_ref }} --output-dir .

- name: Post PR comment
  if: github.event_name == 'pull_request'
  run: |
    gh pr comment ${{ github.event.pull_request.number }} \
      --body-file diff.md --edit-last \
      || gh pr comment ${{ github.event.pull_request.number }} --body-file diff.md
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## MCP server

Prescripts ships an MCP server that exposes two tools for AI agents:

- `scan_package` — scan a single `name@version`
- `compare_versions` — diff lifecycle scripts and findings between two versions

Add it to your Claude Code config (or any MCP-compatible client) by pointing at `mcp.ts` (or the compiled `dist/mcp.js`).

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

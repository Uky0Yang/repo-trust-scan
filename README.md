# repo-trust-scan

[![CI](https://github.com/Uky0Yang/repo-trust-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/Uky0Yang/repo-trust-scan/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Preflight an untrusted repository **before** opening it with Claude Code, Codex, Cursor, Copilot, or another coding agent.

`repo-trust-scan` is a dependency-free Python CLI that finds repository-controlled execution surfaces: automatic editor tasks, agent hooks, devcontainer lifecycle commands, package install hooks, escaping symlinks, hidden Unicode in agent instructions, download-and-execute chains, and credential-transfer patterns.

It is for developers who clone unfamiliar repositories, security reviewers who triage agent-ready projects, and maintainers who want transparent checks in CI.

```bash
python -m pip install git+https://github.com/Uky0Yang/repo-trust-scan.git
repo-trust-scan scan ./untrusted-repo
```

> A clean result is not proof that a repository is safe. The scanner narrows manual review to known trust-boundary surfaces; it does not execute code, call a model, or claim to detect all malware or prompt injection.

## Why this exists

Coding agents read repository instructions and may run project commands with the developer's local permissions. Normal developer conveniences—folder-open tasks, lifecycle scripts, hooks, and devcontainers—therefore become security-relevant before trust is established.

Most scanners answer “is this code vulnerable?” `repo-trust-scan` asks a narrower first question: **what can this repository cause my tools or agent to execute, and what deserves review before I grant trust?**

## Quick start

Scan without installing from a checkout:

```bash
python -m repo_trust_scan scan ../some-repository
```

The `scan` verb is optional:

```bash
repo-trust-scan ../some-repository
```

Machine-readable output:

```bash
repo-trust-scan scan . --format json
repo-trust-scan scan . --format sarif --output repo-trust-scan.sarif
```

Choose the CI failure threshold:

```bash
repo-trust-scan scan . --fail-on medium
repo-trust-scan scan . --fail-on none
```

Review an accepted finding without disabling other checks:

```bash
repo-trust-scan scan . --ignore RTS006
```

## Example output

```text
repo-trust-scan scanned 3 text file(s) under /work/untrusted-repo
risk=45/100 critical=0 high=2 medium=1 low=1 skipped=0

[HIGH] RTS005 .vscode/tasks.json:1 Task 'bootstrap' runs when the folder opens.
  fix: Remove runOn=folderOpen or require an explicit, reviewed invocation.
[MEDIUM] RTS006 package.json:1 npm lifecycle script 'postinstall' runs during install or package preparation.
  evidence: node scripts/bootstrap.js
```

Try the intentionally risky fixture:

```bash
repo-trust-scan examples/risky-repo --fail-on none
```

## Checks

| ID | Severity | Check |
|---|---:|---|
| `RTS001` | critical | Symlink resolves outside the repository |
| `RTS002` | high | Hidden or bidirectional Unicode in agent-facing instructions |
| `RTS003` | high | Remote download piped or chained into an interpreter |
| `RTS004` | high | Credential-like path combined with outbound transfer |
| `RTS005` | high | VS Code task configured with `runOn: folderOpen` |
| `RTS006` | medium | npm lifecycle script (`preinstall`, `install`, `postinstall`, `prepare`) |
| `RTS007` | medium | Devcontainer lifecycle command |
| `RTS008` | medium | Repository-provided Claude Code hook |
| `RTS009` | medium | Encoded PowerShell or dynamic encoded shell execution |
| `RTS010` | low | Repository Git hook or hook template |
| `RTS011` | low | Agent instruction requests automatic command execution |

Run `repo-trust-scan rules` for the installed rule set. See [docs/threat-model.md](docs/threat-model.md) for scope and assumptions and [docs/rules.md](docs/rules.md) for interpretation guidance.

## Safe workflow for an unfamiliar repository

1. Clone it without opening the folder in an IDE or agent.
2. Run `repo-trust-scan /path/to/repo` from a trusted directory.
3. Review findings in the file context; do not execute suggested commands just to investigate them.
4. Inspect dependency manifests, lockfiles, build scripts, and binary artifacts with ecosystem-specific tools.
5. Use a disposable VM or container when provenance is weak or behavior remains unclear.
6. Grant agent permissions only after establishing trust.

## GitHub Action

```yaml
name: Repository trust surfaces

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  trust-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7.0.0
      - uses: Uky0Yang/repo-trust-scan@v0.1.0
        with:
          path: .
          fail-on: high
          upload-sarif: "true"
```

The Action runs static reads only. It does not install repository dependencies, start containers, or invoke project scripts.

## Design principles

- Deterministic checks with a visible rule ID and remediation
- No model calls and no network calls by the scanner
- No repository code execution
- No runtime Python dependencies
- Stable JSON and SARIF for automation
- Conservative language: findings are review signals, not verdicts

## Exit codes

- `0`: scan completed and no finding met `--fail-on`
- `1`: one or more findings met the threshold
- `2`: the scan could not run

## Contributing

False-positive reports and small, reproducible fixtures are especially useful. Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a rule. Security-sensitive reports belong in [SECURITY.md](SECURITY.md).

## License

MIT

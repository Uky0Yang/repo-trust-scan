# Agent guide

## Scope

This repository contains a dependency-free Python CLI for static, read-only trust-surface scanning. Preserve that boundary.

## Required checks

```bash
python -m unittest discover -s tests -v
python -m compileall -q repo_trust_scan tests
python -m repo_trust_scan scan . --fail-on critical
```

## Guardrails

- Never execute files from the scan target.
- Never follow directory symlinks.
- Never add network calls, telemetry, or runtime dependencies without maintainer approval.
- Every rule needs a stable ID, documentation, remediation, and positive and negative tests.
- Avoid labeling a repository or contributor as malicious; report observable behavior only.

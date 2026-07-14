# Roadmap

## 0.1 — foundation

- Static repository trust-surface scanner
- Text, JSON, and SARIF output
- Configurable failure threshold and rule ignores
- Composite GitHub Action
- Threat model and rule guidance

## 0.2 — trusted automation

- Explicit JSON policies without repository auto-discovery
- Stable finding baselines with visible suppression counts
- GitHub Copilot repository hook detection
- Repository MCP configuration and shell-wrapper detection
- pre-commit integration
- PyPI trusted-publishing workflow

## Next

- More editor and agent project-hook formats backed by public specifications
- Lockfile and package-manager install-mode guidance
- Git-aware changed-file scanning for pull requests
- Windows reparse-point coverage in CI
- Signed release artifacts and provenance attestations

The project will prioritize explainable checks over a large heuristic count.

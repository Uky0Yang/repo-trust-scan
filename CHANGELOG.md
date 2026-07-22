# Changelog

All notable changes are documented here. The project follows semantic versioning while the CLI and output schemas stabilize.

## 0.2.1 — 2026-07-22

### Changed

- Add a terminal demo, real scan output, scanner comparison, and copyable GitHub Actions workflow to the README
- Add a 1280×640 social preview asset for repository sharing
- Update pinned GitHub Actions dependencies
- Publish the reusable action to GitHub Marketplace

## 0.2.0 — 2026-07-14

### Added

- Explicit JSON policies with strict validation and no target-repository auto-discovery
- Stable finding baselines with visible suppression counts
- GitHub Copilot repository hook detection (`RTS012`)
- Local MCP server configuration detection (`RTS013`)
- Shell-wrapped MCP server command detection (`RTS014`)
- pre-commit hook metadata
- PyPI Trusted Publishing workflow
- Expanded intentionally risky example repository

### Fixed

- Preserve URL-like strings while removing JSONC comments

## 0.1.0 — 2026-07-12

- Initial public release with deterministic trust-surface checks, text/JSON/SARIF output, and a reusable GitHub Action

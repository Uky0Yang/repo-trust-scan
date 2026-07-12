# Threat model

## Protected user

The primary user has cloned a repository whose contents are not yet trusted and is considering opening it in an AI coding agent, IDE, devcontainer, or normal development workflow.

## Assets

- Local files outside the repository
- Developer credentials and tokens
- Git and package-manager identities
- Cloud and production access available from the workstation
- Integrity of the user's editor and agent configuration

## Trust boundaries

Repository content crosses a trust boundary when another tool interprets it as instructions or executable configuration. Examples include agent instruction files, VS Code tasks, package lifecycle scripts, devcontainer commands, Git hooks, and symlinks.

## In scope

- Static identification of repository-controlled execution surfaces
- High-signal textual patterns for download-and-execute, credential transfer, and obscured shell execution
- Agent-facing hidden Unicode controls
- Links that resolve outside the scan root
- Output suitable for manual review and CI

## Out of scope

- Proving that a repository is benign or malicious
- General vulnerability scanning or dependency CVE detection
- Deobfuscating arbitrary programs
- Executing a repository in a sandbox
- Detecting every prompt-injection phrasing
- Assessing remote content fetched after the scan
- Protecting a user who executes repository code before scanning

## Security posture

The scanner never imports target code, starts subprocesses from the target, installs dependencies, or follows directory symlinks. It reads text files up to a configurable size and skips common generated directories. Findings must be reviewed in context because many lifecycle hooks and automation files are legitimate.

# Rule interpretation

Rules identify review surfaces, not intent. Severity represents the potential impact and amount of automatic execution, not a claim that the repository is malicious.

## Triage order

1. Treat `RTS001` escaping links as a hard trust-boundary violation until explained.
2. Review high-severity command chains in full file context without executing them.
3. Review medium-severity lifecycle hooks before installing dependencies or opening containers.
4. Confirm low-severity instruction and hook findings are documented and require explicit consent.

## Suppression

Use `--ignore RULE_ID` only when the entire rule is intentionally accepted for that scan. The current release does not support inline suppressions because an untrusted repository should not be able to suppress its own findings.

For CI, keep suppressions in the trusted workflow invocation or organization policy rather than target repository content.

## Reporting a false positive

Open an issue with:

- Rule ID
- Minimal non-sensitive fixture
- Expected result
- Operating system and Python version
- Why the behavior is safe in context

Never include real tokens, credential paths containing usernames, or private repository content.

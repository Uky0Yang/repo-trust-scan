# Rule interpretation

Rules identify review surfaces, not intent. Severity represents the potential impact and amount of automatic execution, not a claim that the repository is malicious.

The Copilot hook rule follows [GitHub's documented repository hook location](https://docs.github.com/en/copilot/concepts/agents/hooks), `.github/hooks/*.json`. MCP rules recognize common project-level client paths and report local process definitions without starting them.

## Triage order

1. Treat `RTS001` escaping links as a hard trust-boundary violation until explained.
2. Review high-severity command chains in full file context without executing them.
3. Review medium-severity lifecycle hooks before installing dependencies or opening containers.
4. Confirm low-severity instruction and hook findings are documented and require explicit consent.

## Suppression

Use `--ignore RULE_ID` only when the entire rule is intentionally accepted for that scan. The scanner does not support inline suppressions because an untrusted repository should not be able to suppress its own findings.

For repeat reviews, create a baseline in a trusted location:

```bash
repo-trust-scan baseline ./target --output ../trusted-baselines/target.json
repo-trust-scan ./target --baseline ../trusted-baselines/target.json
```

Fingerprints exclude line numbers, so harmless line movement does not revive a finding. A changed path, message, or evidence does. Baselines remove only exact known findings and report the suppressed count.

## Policy files

Policies are JSON and are loaded only when explicitly passed with `--config`. The supported keys are `ignored_rules`, `fail_on`, and `max_file_bytes`. The scanner deliberately does not auto-load `.repo-trust-scan.json` from the target.

Keep policy and baseline files in a trusted repository, protected CI variable, or path outside the untrusted checkout. Passing a file controlled by the target gives that target influence over scan results.

For CI, keep suppressions in the trusted workflow invocation or organization policy rather than target repository content.

## Reporting a false positive

Open an issue with:

- Rule ID
- Minimal non-sensitive fixture
- Expected result
- Operating system and Python version
- Why the behavior is safe in context

Never include real tokens, credential paths containing usernames, or private repository content.

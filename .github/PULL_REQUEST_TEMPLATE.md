## What changed

<!-- Explain the observable behavior changed by this PR. -->

## Trust boundary

<!-- For rule changes, explain the repository-controlled behavior and why it matters. -->

## Validation

- [ ] `python -m unittest discover -s tests -v`
- [ ] `python -m compileall -q repo_trust_scan tests`
- [ ] `python -m repo_trust_scan scan . --fail-on high`
- [ ] No target repository code is executed
- [ ] Documentation and safe-case tests are included for new rules

# Contributing

Thank you for helping make repository trust reviews more concrete.

## Before opening a pull request

1. Open an issue for a new rule unless the change is a small bug fix.
2. Add a minimal test fixture that proves the behavior without contacting the network or executing target code.
3. Keep rules deterministic and explain both the risk and remediation.
4. Run the complete validation suite.

```bash
python -m unittest discover -s tests -v
python -m compileall -q repo_trust_scan tests
python -m repo_trust_scan scan . --fail-on critical
```

The baseline and policy parsers are security boundaries. Changes must preserve explicit opt-in: never auto-load configuration or suppressions from the scan target.

New checks should have a clear trust boundary, bounded false-positive behavior, a stable rule ID, documentation, and tests for both detection and a nearby safe case.

The self-scan uses a `critical` threshold because the scanner implementation and fixtures intentionally contain the patterns that lower-severity rules detect.

Do not add model calls, telemetry, network access, or execution of scanned repository code.

# Public repository scan: MCP Inspector

This is a real static scan, run on 2026-09-16 with repo-trust-scan 0.3.0 against
[modelcontextprotocol/inspector at 795b1bb](https://github.com/modelcontextprotocol/inspector/tree/795b1bb30ac845b7baa7cb3df8ec0b693882ca1d).
The target was cloned and read; its dependencies, lifecycle hooks and MCP servers were **not executed**.

## Result and manual interpretation

873 text files scanned; 0 skipped; 0 suppressed. The scanner reported 0 critical,
0 high, 1 medium and 2 low findings. [Machine-readable output](inspector-scan-2026-09.json)
has only its machine-local root replaced with `.`.

| Finding | What was actually observed | Interpretation |
| --- | --- | --- |
| RTS006, package.json | A postinstall script invokes `scripts/install-clients.mjs` | A real install-time execution surface to review, not evidence of malicious behaviour |
| RTS011, AGENTS.md:395 | Instructions request a mandatory check command | Expected contributor guidance; understand its commands before trusting agent instructions |
| RTS011, AGENTS.md:96 | Prose about npm peer installation matched the text heuristic | False positive: this sentence explains dependency resolution rather than requesting automatic execution |

An earlier version also produced 11 RTS004 false positives because `nc` matched the
suffix of `async`. The v0.3.0 token-boundary fix removes those matches while regression
tests retain detection of real `nc`, `curl`, `fetch` and `requests` transfer expressions.
No suppressions were used to achieve the result above.

## Reproduce

Use a disposable directory, with Git and Python installed:

```bash
git clone https://github.com/modelcontextprotocol/inspector.git inspector-scan
git -C inspector-scan checkout --detach 795b1bb30ac845b7baa7cb3df8ec0b693882ca1d
python -m pip install repo-trust-scan==0.3.0
repo-trust-scan scan inspector-scan --format json --fail-on none --output inspector-report.json
```

Do not run `npm install` just to reproduce this scan. The output's root path will
differ by machine. Compare the findings, counts and fixed target SHA instead.

The risk score is a heuristic, not a probability or certification. This example is
neither a vulnerability disclosure nor a complete audit of Inspector. A clean result
would not prove safety; defaults exclude some paths/file types and the scanner does
not model runtime behaviour or complete data flows.

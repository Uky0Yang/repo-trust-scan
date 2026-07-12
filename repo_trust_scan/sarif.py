from __future__ import annotations

from .models import ScanReport
from .rules import RULES


def to_sarif(report: ScanReport) -> dict[str, object]:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "repo-trust-scan",
                        "informationUri": "https://github.com/Uky0Yang/repo-trust-scan",
                        "rules": [
                            {
                                "id": rule.rule_id,
                                "name": rule.title,
                                "shortDescription": {"text": rule.description},
                                "help": {"text": rule.remediation},
                                "defaultConfiguration": {"level": level[rule.severity]},
                            }
                            for rule in RULES.values()
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": finding.rule_id,
                        "level": level[finding.severity],
                        "message": {"text": finding.message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": finding.path},
                                    "region": {"startLine": max(1, finding.line)},
                                }
                            }
                        ],
                        "properties": {"severity": finding.severity, "evidence": finding.evidence},
                    }
                    for finding in report.findings
                ],
            }
        ],
    }

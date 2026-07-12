from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path


SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    title: str
    description: str
    remediation: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    path: str
    line: int
    message: str
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class ScanReport:
    root: Path
    files_scanned: int = 0
    files_skipped: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        values = {name: 0 for name in ("critical", "high", "medium", "low")}
        for finding in self.findings:
            values[finding.severity] += 1
        return values

    @property
    def risk_score(self) -> int:
        weights = {"critical": 35, "high": 18, "medium": 7, "low": 2}
        return min(100, sum(weights[f.severity] for f in self.findings))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "root": str(self.root),
            "risk_score": self.risk_score,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "counts": self.counts,
            "findings": [finding.to_dict() for finding in self.findings],
        }

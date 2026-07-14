from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .models import Finding, ScanReport


def finding_fingerprint(finding: Finding) -> str:
    fields = (finding.rule_id, finding.path, finding.message, finding.evidence)
    canonical = "\n".join(" ".join(value.split()) for value in fields)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def baseline_document(report: ScanReport) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "fingerprints": sorted({finding_fingerprint(item) for item in report.findings}),
    }


def load_baseline(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load baseline {path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != "1.0":
        raise ValueError("baseline must use schema_version 1.0")
    fingerprints = data.get("fingerprints")
    if not isinstance(fingerprints, list) or not all(isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) for item in fingerprints):
        raise ValueError("baseline fingerprints must be an array of SHA-256 values")
    return set(fingerprints)


def apply_baseline(report: ScanReport, fingerprints: set[str]) -> None:
    kept = [item for item in report.findings if finding_fingerprint(item) not in fingerprints]
    report.findings_suppressed += len(report.findings) - len(kept)
    report.findings = kept

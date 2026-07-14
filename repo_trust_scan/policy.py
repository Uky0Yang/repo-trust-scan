from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .models import SEVERITY_ORDER


@dataclass(frozen=True)
class ScanPolicy:
    ignored_rules: set[str] = field(default_factory=set)
    fail_on: str = "high"
    max_file_bytes: int = 2_000_000


def load_policy(path: Path, known_rules: set[str]) -> ScanPolicy:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load policy {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("policy must be a JSON object")
    unknown_keys = sorted(set(data) - {"ignored_rules", "fail_on", "max_file_bytes"})
    if unknown_keys:
        raise ValueError(f"unknown policy key(s): {', '.join(unknown_keys)}")
    ignored = data.get("ignored_rules", [])
    if not isinstance(ignored, list) or not all(isinstance(item, str) for item in ignored):
        raise ValueError("policy ignored_rules must be an array of rule IDs")
    unknown_rules = sorted(set(ignored) - known_rules)
    if unknown_rules:
        raise ValueError(f"unknown rule ID(s) in policy: {', '.join(unknown_rules)}")
    fail_on = data.get("fail_on", "high")
    if fail_on not in SEVERITY_ORDER:
        raise ValueError(f"policy fail_on must be one of: {', '.join(SEVERITY_ORDER)}")
    max_file_bytes = data.get("max_file_bytes", 2_000_000)
    if not isinstance(max_file_bytes, int) or isinstance(max_file_bytes, bool) or max_file_bytes < 1:
        raise ValueError("policy max_file_bytes must be a positive integer")
    return ScanPolicy(set(ignored), fail_on, max_file_bytes)

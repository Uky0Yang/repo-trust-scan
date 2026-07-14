from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .baseline import apply_baseline, baseline_document, load_baseline
from .models import SEVERITY_ORDER, ScanReport
from .policy import ScanPolicy, load_policy
from .rules import RULES, scan_repository
from .sarif import to_sarif


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-trust-scan",
        description="Preflight an untrusted repository before opening it with an AI coding agent.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")
    scan = subparsers.add_parser("scan", help="scan a repository (default command)")
    scan.add_argument("path", nargs="?", default=".", help="repository directory (default: current directory)")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("--output", type=Path, help="write output to a file")
    scan.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), help="minimum severity that returns exit code 1")
    scan.add_argument("--ignore", action="append", default=[], metavar="RULE_ID", help="ignore a rule; repeat as needed")
    scan.add_argument("--max-file-bytes", type=int)
    scan.add_argument("--config", type=Path, help="explicit trusted JSON policy (never auto-loaded from the target)")
    scan.add_argument("--baseline", type=Path, help="suppress findings present in an explicit baseline file")
    baseline = subparsers.add_parser("baseline", help="write fingerprints for the current findings")
    baseline.add_argument("path", nargs="?", default=".")
    baseline.add_argument("--output", type=Path, required=True)
    baseline.add_argument("--max-file-bytes", type=int, default=2_000_000)
    subparsers.add_parser("rules", help="list checks and default severities")
    return parser


def _normalize_default_scan(argv: list[str]) -> list[str]:
    if not argv:
        return ["scan"]
    if argv[0] in {"scan", "baseline", "rules", "-h", "--help", "--version"}:
        return argv
    return ["scan", *argv]


def _text_report(report: ScanReport) -> str:
    counts = report.counts
    lines = [
        f"repo-trust-scan scanned {report.files_scanned} text file(s) under {report.root}",
        f"risk={report.risk_score}/100 critical={counts['critical']} high={counts['high']} medium={counts['medium']} low={counts['low']} skipped={report.files_skipped} suppressed={report.findings_suppressed}",
    ]
    if not report.findings:
        lines.append("No trust-boundary findings detected. This is not a guarantee that the repository is safe.")
        return "\n".join(lines) + "\n"
    lines.append("")
    for finding in report.findings:
        lines.append(f"[{finding.severity.upper()}] {finding.rule_id} {finding.path}:{finding.line} {finding.message}")
        if finding.evidence:
            lines.append(f"  evidence: {finding.evidence}")
        if finding.remediation:
            lines.append(f"  fix: {finding.remediation}")
    return "\n".join(lines) + "\n"


def _render(report: ScanReport, output_format: str) -> str:
    if output_format == "text":
        return _text_report(report)
    payload = report.to_dict() if output_format == "json" else to_sarif(report)
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _write(content: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(content)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8", newline="\n")


def _fails(report: ScanReport, threshold: str) -> bool:
    if threshold == "none":
        return False
    return any(SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[threshold] for finding in report.findings)


def main(argv: list[str] | None = None) -> int:
    args_list = _normalize_default_scan(list(sys.argv[1:] if argv is None else argv))
    parser = build_parser()
    args = parser.parse_args(args_list)
    if args.command == "rules":
        for rule in RULES.values():
            print(f"{rule.rule_id} {rule.severity:<8} {rule.title}")
        return 0
    if args.command == "baseline":
        try:
            report = scan_repository(Path(args.path), max_file_bytes=args.max_file_bytes)
            _write(json.dumps(baseline_document(report), indent=2) + "\n", args.output)
        except (OSError, ValueError) as exc:
            print(f"repo-trust-scan: {exc}", file=sys.stderr)
            return 2
        return 0
    try:
        policy = load_policy(args.config, set(RULES)) if args.config else ScanPolicy()
    except ValueError as exc:
        print(f"repo-trust-scan: {exc}", file=sys.stderr)
        return 2
    ignored_rules = policy.ignored_rules | set(args.ignore)
    unknown = sorted(set(args.ignore) - set(RULES))
    if unknown:
        parser.error(f"unknown rule ID(s): {', '.join(unknown)}")
    try:
        report = scan_repository(Path(args.path), max_file_bytes=args.max_file_bytes or policy.max_file_bytes, ignored_rules=ignored_rules)
        if args.baseline:
            apply_baseline(report, load_baseline(args.baseline))
    except (OSError, ValueError) as exc:
        print(f"repo-trust-scan: {exc}", file=sys.stderr)
        return 2
    try:
        _write(_render(report, args.format), args.output)
    except OSError as exc:
        print(f"repo-trust-scan: cannot write output: {exc}", file=sys.stderr)
        return 2
    return 1 if _fails(report, args.fail_on or policy.fail_on) else 0

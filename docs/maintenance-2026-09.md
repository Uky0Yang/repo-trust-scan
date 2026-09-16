# Changed-file scans (v0.3.0)

```bash
repo-trust-scan . --changed-since origin/main --format json
```

This compares the selected commit to the current working tree, including staged,
unstaged and non-ignored untracked files. Renames scan the destination; deleted files
have no current contents to scan. Unchanged files and submodules are excluded.
Run from the repository root with Git available. Invalid or missing base commits
return 2; they never silently produce a clean scan. No network fetch is performed.

For a PR, use the base SHA and fetch history. Always use pull_request, not a privileged
pull_request_target workflow that executes PR contents.

```yaml
name: Trust changed files
on: pull_request
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: Uky0Yang/repo-trust-scan@v0.3.0
        with:
          changed-since: ${{ github.event.pull_request.base.sha }}
          fail-on: high
```

Only Git metadata/diff commands are invoked. External diff helpers, text conversion
and filesystem-monitor hooks are disabled. Target files are never executed. Existing
symlink and size limits still apply. Use a full scan before first trust: a changed-file
result cannot say anything about unchanged execution surfaces.

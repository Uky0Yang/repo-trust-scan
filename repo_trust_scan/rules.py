from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .models import Finding, Rule, ScanReport


RULES: dict[str, Rule] = {
    "RTS001": Rule("RTS001", "critical", "Escaping symlink", "A symlink resolves outside the repository.", "Remove the link or make it resolve inside the repository."),
    "RTS002": Rule("RTS002", "high", "Hidden Unicode in agent instructions", "Agent-facing instructions contain invisible or bidirectional control characters.", "Remove the control characters and review the surrounding instruction manually."),
    "RTS003": Rule("RTS003", "high", "Download-and-execute chain", "A command downloads remote content and immediately executes it.", "Download to a file, verify its origin and digest, then execute in a sandbox."),
    "RTS004": Rule("RTS004", "high", "Credential access with outbound transfer", "A command combines access to credential locations with a network transfer.", "Remove the command and rotate any credential that may have been exposed."),
    "RTS005": Rule("RTS005", "high", "Automatic editor task", "A VS Code task is configured to run when the folder opens.", "Remove runOn=folderOpen or require an explicit, reviewed invocation."),
    "RTS006": Rule("RTS006", "medium", "Package lifecycle script", "A package lifecycle hook can run during dependency installation.", "Review and minimize lifecycle scripts; install untrusted dependencies with scripts disabled."),
    "RTS007": Rule("RTS007", "medium", "Dev container lifecycle command", "A devcontainer lifecycle command can execute when the environment starts.", "Review the command and pin every downloaded dependency before opening the container."),
    "RTS008": Rule("RTS008", "medium", "Repository-provided agent hook", "Repository settings define a hook that can execute commands from the coding agent.", "Review hook commands and restrict permissions before trusting the repository."),
    "RTS009": Rule("RTS009", "medium", "Encoded or dynamic shell execution", "A script uses encoded input or dynamic evaluation that obscures behavior.", "Replace it with auditable commands and avoid eval or encoded PowerShell."),
    "RTS010": Rule("RTS010", "low", "Repository Git hook", "The repository contains a Git hook or hook template that may be installed locally.", "Review the hook and document how it is installed; never install it implicitly."),
    "RTS011": Rule("RTS011", "low", "Agent instruction requests command execution", "Agent-facing text asks the agent to run a command automatically.", "Require explicit human approval and explain why the command is necessary."),
    "RTS012": Rule("RTS012", "medium", "Repository-provided Copilot hook", "A repository GitHub Copilot hook can execute shell commands during an agent session.", "Review every hook command and event before using Copilot in the repository."),
    "RTS013": Rule("RTS013", "medium", "Repository-provided MCP server", "A repository configuration can start an MCP server process for an AI client.", "Review the server command, arguments, environment, and package source before enabling it."),
    "RTS014": Rule("RTS014", "high", "Shell-wrapped MCP server command", "An MCP server configuration launches through a general-purpose shell.", "Invoke a reviewed executable directly and avoid shell wrappers or command strings."),
}

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache"}
AGENT_FILES = {"agents.md", "claude.md", ".cursorrules", "copilot-instructions.md", "gemini.md"}
TEXT_SUFFIXES = {".md", ".txt", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".sh", ".bash", ".zsh", ".ps1", ".cmd", ".bat", ".py", ".js", ".ts", ".mjs", ".cjs"}
HIDDEN_UNICODE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
DOWNLOAD_EXEC = re.compile(r"(?:curl|wget)[^\n|;]{0,300}(?:\||;|&&)\s*(?:sh|bash|zsh|python|node|powershell|pwsh)\b|(?:iwr|invoke-webrequest|irm|invoke-restmethod)[^\n]{0,300}\|\s*(?:iex|invoke-expression)", re.I)
CREDENTIAL_TRANSFER = re.compile(r"(?:\.ssh|\.aws|\.azure|\.config/gcloud|id_rsa|credentials|private[_-]?key|github_token|api[_-]?key)[^\n]{0,500}(?:curl|wget|invoke-webrequest|requests\.|fetch\(|nc\s)|(?:curl|wget|invoke-webrequest|requests\.|fetch\(|nc\s)[^\n]{0,500}(?:\.ssh|\.aws|id_rsa|credentials|private[_-]?key|github_token|api[_-]?key)", re.I)
ENCODED_EXEC = re.compile(r"powershell(?:\.exe)?[^\n]{0,200}(?:-enc|-encodedcommand)\b|\b(?:eval|exec)\s*\(\s*(?:base64|atob)|base64\s+(?:-d|--decode)[^\n]{0,120}\|\s*(?:sh|bash)", re.I)
RUN_REQUEST = re.compile(r"\b(?:always|immediately|automatically|before (?:doing|reading) anything)\b[^\n]{0,100}\b(?:run|execute|install|invoke)\b|\b(?:run|execute|install)\b[^\n]{0,100}\b(?:without asking|without confirmation|do not ask)\b", re.I)


def _finding(rule_id: str, path: str, line: int, message: str, evidence: str = "") -> Finding:
    rule = RULES[rule_id]
    evidence = " ".join(evidence.strip().split())[:240]
    return Finding(rule_id, rule.severity, path, line, message, evidence, rule.remediation)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _is_agent_file(path: Path) -> bool:
    lower = path.name.lower()
    return lower in AGENT_FILES or "skills" in {part.lower() for part in path.parts} or lower == "skill.md"


def _scan_text(relative: Path, text: str) -> list[Finding]:
    path = relative.as_posix()
    findings: list[Finding] = []
    patterns = (
        ("RTS003", DOWNLOAD_EXEC, "Remote content is piped or chained into an interpreter."),
        ("RTS004", CREDENTIAL_TRANSFER, "Credential-like paths and an outbound transfer appear in the same command."),
        ("RTS009", ENCODED_EXEC, "Encoded or dynamically evaluated shell input obscures execution."),
    )
    for rule_id, pattern, message in patterns:
        for match in pattern.finditer(text):
            findings.append(_finding(rule_id, path, _line_number(text, match.start()), message, match.group(0)))

    if _is_agent_file(relative):
        for match in HIDDEN_UNICODE.finditer(text):
            findings.append(_finding("RTS002", path, _line_number(text, match.start()), f"Hidden Unicode character U+{ord(match.group(0)):04X} in agent-facing instructions."))
        for match in RUN_REQUEST.finditer(text):
            findings.append(_finding("RTS011", path, _line_number(text, match.start()), "Instruction requests automatic command execution.", match.group(0)))

    lowered = path.lower()
    if lowered == ".vscode/tasks.json":
        try:
            data = json.loads(_strip_json_comments(text))
            for task in data.get("tasks", []):
                if isinstance(task, dict) and isinstance(task.get("runOptions"), dict) and task["runOptions"].get("runOn") == "folderOpen":
                    findings.append(_finding("RTS005", path, 1, f"Task {task.get('label', '<unnamed>')!r} runs when the folder opens."))
        except (json.JSONDecodeError, AttributeError):
            pass

    if relative.name == "package.json":
        try:
            scripts = json.loads(text).get("scripts", {})
            for name in ("preinstall", "install", "postinstall", "prepare"):
                if isinstance(scripts, dict) and isinstance(scripts.get(name), str):
                    findings.append(_finding("RTS006", path, 1, f"npm lifecycle script {name!r} runs during install or package preparation.", scripts[name]))
        except (json.JSONDecodeError, AttributeError):
            pass

    if relative.name == "devcontainer.json" or ".devcontainer" in relative.parts:
        for key in ("initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"):
            match = re.search(rf'["\']{key}["\']\s*:', text)
            if match:
                findings.append(_finding("RTS007", path, _line_number(text, match.start()), f"Dev container defines {key}."))

    if path.lower() in {".claude/settings.json", ".claude/settings.local.json"} and re.search(r'["\']hooks["\']\s*:', text, re.I):
        findings.append(_finding("RTS008", path, 1, "Claude project settings define executable hooks."))

    lower_parts = tuple(part.lower() for part in relative.parts)
    if len(lower_parts) >= 3 and lower_parts[0:2] == (".github", "hooks") and relative.suffix.lower() == ".json":
        try:
            hook_data = json.loads(text)
            if isinstance(hook_data, dict) and isinstance(hook_data.get("hooks"), dict):
                findings.append(_finding("RTS012", path, 1, "GitHub Copilot repository hook configuration defines executable events."))
        except json.JSONDecodeError:
            pass

    mcp_paths = {".mcp.json", "mcp.json", ".github/mcp.json", ".vscode/mcp.json", ".cursor/mcp.json"}
    if path.lower() in mcp_paths:
        try:
            mcp_data = json.loads(_strip_json_comments(text))
            servers = mcp_data.get("mcpServers", mcp_data.get("servers", {})) if isinstance(mcp_data, dict) else {}
            process_servers = {name: server for name, server in servers.items() if isinstance(server, dict) and "command" in server} if isinstance(servers, dict) else {}
            if process_servers:
                findings.append(_finding("RTS013", path, 1, f"MCP configuration defines {len(process_servers)} local server process(es)."))
                shells = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
                for server_name, server in process_servers.items():
                    command = server.get("command")
                    executable = command[0] if isinstance(command, list) and command else command
                    if isinstance(executable, str) and Path(executable).name.lower() in shells:
                        findings.append(_finding("RTS014", path, 1, f"MCP server {server_name!r} launches through shell {executable!r}.", json.dumps(server, ensure_ascii=False)))
        except json.JSONDecodeError:
            pass

    parts = set(lower_parts)
    if ".githooks" in parts or ("hooks" in parts and relative.name.lower() in {"pre-commit", "post-checkout", "post-merge", "pre-push", "prepare-commit-msg"}):
        findings.append(_finding("RTS010", path, 1, "Repository contains a Git hook or hook template."))
    return findings


def _strip_json_comments(text: str) -> str:
    output: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
        elif char == "/" and following == "/":
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                index += 1
        elif char == "/" and following == "*":
            index += 2
            while index + 1 < len(text) and text[index:index + 2] != "*/":
                index += 1
            index = min(len(text), index + 2)
        else:
            output.append(char)
            index += 1
    return "".join(output)


def scan_repository(root: Path, *, max_file_bytes: int = 2_000_000, ignored_rules: set[str] | None = None) -> ScanReport:
    root = root.expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"not a directory: {root}")
    ignored_rules = ignored_rules or set()
    report = ScanReport(root=root)
    for current, dirs, files in os.walk(root, followlinks=False):
        traversable_dirs: list[str] = []
        for name in sorted(dirs):
            directory = Path(current) / name
            if name in SKIP_DIRS:
                continue
            if directory.is_symlink():
                relative = directory.relative_to(root)
                try:
                    target = directory.resolve(strict=False)
                    target.relative_to(root)
                except (ValueError, OSError):
                    try:
                        link_target = os.readlink(directory)
                    except OSError:
                        link_target = "<unreadable>"
                    report.findings.append(_finding("RTS001", relative.as_posix(), 1, f"Directory symlink resolves outside repository: {link_target}"))
                continue
            traversable_dirs.append(name)
        dirs[:] = traversable_dirs
        for name in sorted(files):
            path = Path(current) / name
            relative = path.relative_to(root)
            if path.is_symlink():
                try:
                    target = path.resolve(strict=False)
                    target.relative_to(root)
                except (ValueError, OSError):
                    try:
                        link_target = os.readlink(path)
                    except OSError:
                        link_target = "<unreadable>"
                    report.findings.append(_finding("RTS001", relative.as_posix(), 1, f"Symlink resolves outside repository: {link_target}"))
                continue
            try:
                if path.stat().st_size > max_file_bytes:
                    report.files_skipped += 1
                    continue
            except OSError:
                report.files_skipped += 1
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES and name not in {"Dockerfile", "Makefile", "Justfile", "Procfile"}:
                continue
            try:
                raw = path.read_bytes()
                if b"\x00" in raw:
                    report.files_skipped += 1
                    continue
                text = raw.decode("utf-8", errors="replace")
            except OSError:
                report.files_skipped += 1
                continue
            report.files_scanned += 1
            report.findings.extend(_scan_text(relative, text))
    report.findings = sorted(
        (finding for finding in report.findings if finding.rule_id not in ignored_rules),
        key=lambda item: (-{"critical": 4, "high": 3, "medium": 2, "low": 1}[item.severity], item.path, item.line, item.rule_id),
    )
    return report

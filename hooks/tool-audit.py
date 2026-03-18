#!/usr/bin/env python3
"""
Tool Call Behavioral Audit Hook — PostToolUse
Logs every tool Claude calls to ~/.claude/tool-audit.log and flags
anomalous patterns (suspicious Bash, sensitive file reads, exfiltration attempts).

Protocol: reads stdin as JSON, outputs hookSpecificOutput JSON if anomalous.
Design: async, silent for normal operations, never blocks tool execution.

Part of claude-code-security — https://github.com/YOUR_USERNAME/claude-code-security
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

AUDIT_LOG = Path.home() / ".claude" / "tool-audit.log"

# ── Anomaly patterns ──────────────────────────────────────────────────────────

# Bash commands that look like exfiltration or reverse shells
SUSPICIOUS_BASH = [
    re.compile(r'\bcurl\b.*\|\s*(bash|sh)\b', re.IGNORECASE),
    re.compile(r'\bwget\b.*\|\s*(bash|sh)\b', re.IGNORECASE),
    re.compile(r'base64\s+(-d|--decode)\s*\|+\s*(sh|bash)', re.IGNORECASE),
    re.compile(r'\bnc\b.*-e\s+/bin/', re.IGNORECASE),
    re.compile(r'(curl|wget)\b.*(ANTHROPIC|SUPABASE|AWS|SECRET|TOKEN|PASSWORD)', re.IGNORECASE),
    re.compile(r'stratum\+tcp://', re.IGNORECASE),
]

# Read calls targeting sensitive system paths
SENSITIVE_READ_PATHS = [
    "/.ssh/",
    "/.aws/",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/.gnupg/",
    "/keychain",
]

# Write calls that are considered safe — add your project directories here
SAFE_WRITE_PREFIXES = [
    str(Path.home()),   # Everything under home is considered safe by default
    "/tmp/",
    "/var/folders/",
    # You can tighten this to specific project paths, e.g.:
    # str(Path.home() / "projects"),
    # str(Path.home() / "Documents"),
]


def is_anomalous_bash(command: str) -> tuple[bool, str]:
    for pattern in SUSPICIOUS_BASH:
        m = pattern.search(command)
        if m:
            return True, f"Suspicious Bash pattern: {m.group()[:80]}"
    return False, ""


def is_sensitive_read(file_path: str) -> tuple[bool, str]:
    for sensitive in SENSITIVE_READ_PATHS:
        if sensitive in file_path:
            return True, f"Read of sensitive path: {file_path}"
    return False, ""


def is_anomalous_write(file_path: str) -> tuple[bool, str]:
    if any(file_path.startswith(p) for p in SAFE_WRITE_PREFIXES):
        return False, ""
    if file_path.startswith("/"):
        return True, f"Write outside safe directory: {file_path}"
    return False, ""


def append_audit_log(timestamp: str, tool_name: str, summary: str, anomalous: bool):
    flag = " ⚠️ ANOMALY" if anomalous else ""
    entry = f"[{timestamp}] {tool_name} | {summary}{flag}\n"
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception:
        pass


def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.exit(0)

        data = json.loads(raw)
        tool_name = data.get("tool_name", "unknown")
        tool_input = data.get("tool_input", {})
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        anomaly = False
        anomaly_reason = ""
        summary = ""

        if tool_name == "Bash":
            command = tool_input.get("command", "")
            summary = command[:100].replace("\n", " ")
            anomaly, anomaly_reason = is_anomalous_bash(command)

        elif tool_name == "Read":
            file_path = tool_input.get("file_path", "")
            summary = file_path
            anomaly, anomaly_reason = is_sensitive_read(file_path)

        elif tool_name in ("Write", "Edit"):
            file_path = tool_input.get("file_path", "")
            summary = file_path
            # Only flag writes to truly sensitive system paths
            if file_path.startswith("/etc/") or "/.ssh/" in file_path or "/.aws/" in file_path:
                anomaly, anomaly_reason = True, f"Write to sensitive path: {file_path}"

        else:
            summary = str(list(tool_input.keys()))[:80]

        append_audit_log(timestamp, tool_name, summary, anomaly)

        if anomaly:
            print(json.dumps({
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": (
                        f"TOOL AUDIT ALERT — {tool_name}\n"
                        f"{anomaly_reason}\n"
                        f"Logged to: ~/.claude/tool-audit.log\n"
                        f"Review the audit log if this was unexpected."
                    ),
                }
            }))

    except Exception:
        # Silent fail — never disrupt tool execution
        sys.exit(0)


if __name__ == "__main__":
    main()

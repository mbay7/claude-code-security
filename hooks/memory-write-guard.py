#!/usr/bin/env python3
"""
Memory Write Guard — PostToolUse on Write/Edit operations
Sanitizes memory files at write time to prevent MINJA-class injection
(NeurIPS 2025) where adversarial content plants persistent instructions
into Claude's long-term memory.

Closes the write vector that memory-drift-check.py catches at read time.
Protocol: reads stdin as JSON, outputs hookSpecificOutput JSON if injection detected.
Design: async, silent on clean writes, never blocks the write operation.

Part of claude-code-security — https://github.com/mbay7/claude-code-security
"""

import json
import re
import sys
from pathlib import Path

# ── Memory paths to guard ──────────────────────────────────────────────────────
# Any write targeting these directories will be scanned before it persists.

def is_memory_write(file_path: str) -> bool:
    """Returns True if the write target is inside a Claude memory directory."""
    p = Path(file_path)
    try:
        # ~/.claude/projects/*/memory/*.md
        parts = p.parts
        if ".claude" in parts and "projects" in parts and "memory" in parts:
            return True
        # ~/.claude/CLAUDE.md, ~/.claude/primer.md (high-value persistent files)
        claude_dir = Path.home() / ".claude"
        if p.parent == claude_dir and p.suffix == ".md":
            return True
    except Exception:
        pass
    return False


# ── Injection patterns (same baseline as memory-drift-check.py) ───────────────
INJECTION_PATTERNS = [
    (re.compile(r'ignore\s+(all\s+|any\s+)?(previous|prior)\s+instructions?', re.IGNORECASE), "LLM01"),
    (re.compile(r'disregard\s+your\s+(instructions?|rules?|guidelines?)', re.IGNORECASE), "LLM01"),
    (re.compile(r'forget\s+everything\s+above', re.IGNORECASE), "LLM01"),
    (re.compile(r'new\s+instructions?\s*:', re.IGNORECASE), "LLM01"),
    (re.compile(r'\[SYSTEM\]\s*:', re.IGNORECASE), "LLM01"),
    (re.compile(r'</?system>', re.IGNORECASE), "LLM01"),
    (re.compile(r'\[INST\]', re.IGNORECASE), "LLM01"),
    (re.compile(r'<<SYS>>', re.IGNORECASE), "LLM01"),
    (re.compile(r'you\s+are\s+now\s+a\b', re.IGNORECASE), "MINJA"),
    (re.compile(r'your\s+new\s+role\s+is', re.IGNORECASE), "MINJA"),
    (re.compile(r'(act\s+as|pretend\s+to\s+be)\s+', re.IGNORECASE), "MINJA"),
    (re.compile(r'\bDAN\s+mode\b', re.IGNORECASE), "MINJA"),
    (re.compile(r'developer\s+mode\s+(enabled|activated|on)', re.IGNORECASE), "MINJA"),
    (re.compile(r'override\s+(safety|restrictions?|guidelines?)', re.IGNORECASE), "MINJA"),
    (re.compile(r'when\s+claude\s+reads?\s+this', re.IGNORECASE), "MINJA"),
    (re.compile(r'note\s+to\s+(ai|claude|assistant|llm)\s*:', re.IGNORECASE), "MINJA"),
    (re.compile(r'ai\s+instructions?\s*:', re.IGNORECASE), "MINJA"),
    (re.compile(r'<!--\s*(claude|ai|llm|assistant)\s*:', re.IGNORECASE), "MINJA"),
    # Zero-width Unicode steganography
    (re.compile(r'[\u200B\u200C\u200D\u200E\u200F\u202A\u202B\u202C\u202D\u202E]'), "Unicode-Steganography"),
]


def scan_for_injection(content: str) -> list[dict]:
    findings = []
    for pattern, owasp_id in INJECTION_PATTERNS:
        for match in pattern.finditer(content):
            line_num = content[:match.start()].count('\n') + 1
            findings.append({
                "line": line_num,
                "match": match.group()[:80].replace('\n', ' '),
                "owasp": owasp_id,
            })
    return findings


def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.exit(0)

        data = json.loads(raw)
        tool_name = data.get("tool_name", "")

        if tool_name not in ("Write", "Edit"):
            sys.exit(0)

        tool_input = data.get("tool_input", {})
        file_path = tool_input.get("file_path", "")

        if not file_path or not is_memory_write(file_path):
            sys.exit(0)

        # Get the content being written
        content = tool_input.get("content", "") or tool_input.get("new_string", "")
        if not content:
            sys.exit(0)

        findings = scan_for_injection(content)

        if not findings:
            sys.exit(0)  # Silent on clean writes

        fname = Path(file_path).name
        lines = [
            f"🚨 MEMORY WRITE GUARD — Injection Detected in {fname}",
            f"Found {len(findings)} suspicious pattern(s) about to be written to memory:",
            "",
        ]

        for f in findings[:5]:
            lines.append(f"  Line {f['line']} [{f['owasp']}]: \"{f['match']}\"")

        if len(findings) > 5:
            lines.append(f"  ... and {len(findings) - 5} more.")

        lines += [
            "",
            "⚠️  This content was NOT blocked — the write proceeded.",
            "   Review the patterns above before trusting this memory file.",
            "   If this is a false positive, review https://github.com/mbay7/claude-code-security",
        ]

        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": "\n".join(lines),
            }
        }))

    except Exception:
        # Silent fail — never disrupt write operations
        sys.exit(0)


if __name__ == "__main__":
    main()

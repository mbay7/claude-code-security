#!/usr/bin/env python3
"""
Memory Drift Detector + Context Poisoning Scanner — SessionStart
Runs at session start. Validates that memory files match actual system state
and scans memory files for injected instructions (MINJA-class attacks).

Outputs JSON only when drift or injection is detected — silent on clean pass.

Part of claude-code-security — https://github.com/YOUR_USERNAME/claude-code-security
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────

SKILLS_DIR  = Path.home() / ".claude/skills"
CLAUDE_MD   = Path.home() / ".claude/CLAUDE.md"
STALE_DAYS  = 14  # flag project memories older than this

# Discover the active project memory directory dynamically.
# Scans all ~/.claude/projects/*/memory/ directories for a MEMORY.md index.
def find_memory_dirs() -> list[Path]:
    projects_root = Path.home() / ".claude/projects"
    if not projects_root.exists():
        return []
    found = []
    for mem_dir in projects_root.glob("*/memory"):
        if mem_dir.is_dir() and (mem_dir / "MEMORY.md").exists():
            found.append(mem_dir)
    return found

MEMORY_DIRS = find_memory_dirs()

issues = []

# ── 1. Index integrity: every file listed in MEMORY.md exists ────────────────
for MEMORY_DIR in MEMORY_DIRS:
    MEMORY_INDEX = MEMORY_DIR / "MEMORY.md"
    index_text = MEMORY_INDEX.read_text()
    listed = re.findall(r'\[[\w_]+\.md\]\(([\w_]+\.md)\)', index_text)
    for fname in listed:
        fpath = MEMORY_DIR / fname
        if not fpath.exists():
            issues.append(f"MISSING FILE: {fname} listed in MEMORY.md but not on disk")

# ── 2. Orphan check: files on disk not listed in MEMORY.md ───────────────────
for MEMORY_DIR in MEMORY_DIRS:
    MEMORY_INDEX = MEMORY_DIR / "MEMORY.md"
    index_text = MEMORY_INDEX.read_text()
    listed = re.findall(r'\[[\w_]+\.md\]\(([\w_]+\.md)\)', index_text)
    disk_files = {f.name for f in MEMORY_DIR.glob("*.md") if f.name != "MEMORY.md"}
    listed_set = set(listed) if listed else set()
    for fname in disk_files - listed_set:
        issues.append(f"ORPHAN FILE: {fname} exists on disk but not listed in MEMORY.md")

# ── 3. Skill count: CLAUDE.md claim vs actual disk count ─────────────────────
if CLAUDE_MD.exists() and SKILLS_DIR.exists():
    claude_text = CLAUDE_MD.read_text()
    m = re.search(r'\*\*(\d+) skills\*\*', claude_text)
    if m:
        claimed = int(m.group(1))
        actual  = len([f for f in SKILLS_DIR.glob("*.md") if not f.name.startswith("_")])
        if claimed != actual:
            issues.append(f"SKILL COUNT DRIFT: CLAUDE.md claims {claimed} skills but {actual} found on disk — update CLAUDE.md")

# ── 4. Hooks directory check ──────────────────────────────────────────────────
HOOKS_DIR = Path.home() / ".claude/hooks"
if not HOOKS_DIR.exists():
    issues.append(f"PATH MISSING: Hooks dir not found at {HOOKS_DIR}")

# Optional: add your vault or workspace path checks here, e.g.:
# VAULT_PATH = Path.home() / "Documents/my-vault"
# if not VAULT_PATH.exists():
#     issues.append(f"PATH MISSING: Vault not found at {VAULT_PATH}")

# ── 5. Stale project memories ─────────────────────────────────────────────────
now = datetime.now(timezone.utc).timestamp()
for MEMORY_DIR in MEMORY_DIRS:
    for fpath in MEMORY_DIR.glob("project_*.md"):
        age_days = (now - fpath.stat().st_mtime) / 86400
        if age_days > STALE_DAYS:
            issues.append(f"STALE ({int(age_days)}d): {fpath.name} — review and update if still accurate")

# ── 6. Context Poisoning: scan memory files for prompt injection ──────────────
# Defends against MINJA-class attacks (NeurIPS 2025) where adversarial content
# plants persistent instructions into agent memory across sessions.
INJECTION_PATTERNS = [
    re.compile(r'ignore\s+(all\s+|any\s+)?(previous|prior)\s+instructions?', re.IGNORECASE),
    re.compile(r'disregard\s+your\s+(instructions?|rules?|guidelines?)', re.IGNORECASE),
    re.compile(r'forget\s+everything\s+above', re.IGNORECASE),
    re.compile(r'new\s+instructions?\s*:', re.IGNORECASE),
    re.compile(r'\[SYSTEM\]\s*:', re.IGNORECASE),
    re.compile(r'</?system>', re.IGNORECASE),
    re.compile(r'you\s+are\s+now\s+a\b', re.IGNORECASE),
    re.compile(r'(act\s+as|pretend\s+to\s+be)\s+', re.IGNORECASE),
    re.compile(r'\bDAN\s+mode\b', re.IGNORECASE),
    re.compile(r'developer\s+mode\s+(enabled|activated|on)', re.IGNORECASE),
    re.compile(r'override\s+(safety|restrictions?|guidelines?)', re.IGNORECASE),
    re.compile(r'when\s+claude\s+reads?\s+this', re.IGNORECASE),
    re.compile(r'note\s+to\s+(ai|claude|assistant|llm)\s*:', re.IGNORECASE),
    re.compile(r'<!--\s*(claude|ai|llm)\s*:', re.IGNORECASE),
]

injection_findings = []
for MEMORY_DIR in MEMORY_DIRS:
    for fpath in MEMORY_DIR.glob("*.md"):
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
            for pattern in INJECTION_PATTERNS:
                for match in pattern.finditer(content):
                    line_num = content[:match.start()].count('\n') + 1
                    injection_findings.append(
                        f"INJECTION in {fpath.name}:{line_num} — \"{match.group()[:60]}\""
                    )
        except Exception:
            pass

# ── Output ────────────────────────────────────────────────────────────────────
output_parts = []

if issues:
    output_parts.append("⚠️  Memory Drift Detected:\n" + "\n".join(f"  • {i}" for i in issues))

if injection_findings:
    output_parts.append(
        "🚨 Context Poisoning Detected in Memory Files:\n"
        + "\n".join(f"  • {f}" for f in injection_findings)
        + "\n\nThese patterns may be injected instructions. Review the flagged memory files "
        "before proceeding. Run /security-scanner on any suspicious file."
    )

if output_parts:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": "\n\n".join(output_parts),
        }
    }))
# Silent on clean pass

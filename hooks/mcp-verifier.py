#!/usr/bin/env python3
"""
MCP Server Integrity Verifier — SessionStart
Audits configured MCP (Model Context Protocol) servers against a trusted manifest.

Catches three attack vectors:
  1. New/unknown MCP servers added without authorization
  2. Suspicious MCP server commands (remote code execution patterns)
  3. Hardcoded secrets in MCP server environment variables

Usage:
  SessionStart hook — runs automatically at session start (silent on clean pass)
  python3 mcp-verifier.py --init    — trust all currently configured servers
  python3 mcp-verifier.py --status  — show current server inventory (no hook output)

Manifest: ~/.claude/hooks/.mcp-manifest.json
  Created by --init, commit it to git to detect future additions.

Part of claude-code-security — https://github.com/mbay7/claude-code-security
"""

import json
import re
import sys
import os
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────

CLAUDE_DIR   = Path.home() / ".claude"
MANIFEST     = CLAUDE_DIR / "hooks" / ".mcp-manifest.json"
SETTINGS_FILES = [
    CLAUDE_DIR / "settings.json",
    CLAUDE_DIR / "settings.local.json",
]

# ── Suspicious command patterns ───────────────────────────────────────────────
# MCP server commands that suggest remote code execution or supply chain risk.

SUSPICIOUS_CMD_PATTERNS = [
    (re.compile(r'curl\s+.*\|\s*(bash|sh)', re.IGNORECASE),    "remote code execution via curl|bash"),
    (re.compile(r'wget\s+.*\|\s*(bash|sh)', re.IGNORECASE),    "remote code execution via wget|bash"),
    (re.compile(r'base64\s+(-d|--decode)\s*\|.*sh', re.IGNORECASE), "base64-encoded payload execution"),
    (re.compile(r'stratum\+tcp://',           re.IGNORECASE),  "crypto miner stratum protocol"),
    (re.compile(r'\bnc\s+-e\s+/bin/',         re.IGNORECASE),  "reverse shell via netcat"),
    (re.compile(r'https?://(?!registry\.npmjs\.org|cdn\.jsdelivr\.net)[^\s]+\.(sh|py|js|ps1)', re.IGNORECASE),
                                                                "remote script URL in command"),
]

# ── Secret patterns in env vars ────────────────────────────────────────────────
# MCP servers legitimately use env vars for tokens — we check VALUES, not names.
# Placeholder values are skipped.

SECRET_VALUE_PATTERNS = [
    (re.compile(r'^sk-ant-[a-zA-Z0-9\-_]{90,}$'),                           "Anthropic API key"),
    (re.compile(r'^sk-[a-zA-Z0-9]{48}$'),                                   "OpenAI API key"),
    (re.compile(r'^AKIA[0-9A-Z]{16}$'),                                      "AWS Access Key ID"),
    (re.compile(r'^ghp_[a-zA-Z0-9]{36}$'),                                  "GitHub PAT (classic)"),
    (re.compile(r'^github_pat_[a-zA-Z0-9_]{82}$'),                          "GitHub PAT (fine-grained)"),
    (re.compile(r'^sk_live_[a-zA-Z0-9]{24,}$'),                             "Stripe live key"),
    (re.compile(r'^-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),        "Private key block"),
]

PLACEHOLDER_RE = re.compile(
    r'(your[_\-]?(key|secret|token|api[_\-]?key|pat)[_\-]?here|REPLACE_ME|<your|\.{3}|CHANGEME)',
    re.IGNORECASE
)


def read_mcp_servers() -> dict[str, dict]:
    """Read all mcpServers from Claude settings files. Later files win on conflict."""
    servers = {}
    for settings_path in SETTINGS_FILES:
        if not settings_path.exists():
            continue
        try:
            data = json.loads(settings_path.read_text(encoding="utf-8"))
            for name, config in data.get("mcpServers", {}).items():
                servers[name] = {**config, "_source": str(settings_path)}
        except Exception:
            pass
    return servers


def load_manifest() -> dict | None:
    if MANIFEST.exists():
        try:
            return json.loads(MANIFEST.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def save_manifest(servers: dict[str, dict]) -> None:
    """Save all currently configured servers as trusted."""
    manifest = {
        "_comment": "claude-code-security MCP manifest — commit to git, regenerate with --init after intentional changes",
        "_generated": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "trusted_servers": {
            name: {
                "command": cfg.get("command", ""),
                "args": cfg.get("args", []),
            }
            for name, cfg in servers.items()
        }
    }
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(manifest, indent=2))


def check_suspicious_command(name: str, config: dict) -> list[str]:
    findings = []
    command = config.get("command", "")
    args = config.get("args", [])
    full_cmd = command + " " + " ".join(str(a) for a in args)

    for pattern, description in SUSPICIOUS_CMD_PATTERNS:
        if pattern.search(full_cmd):
            findings.append(f"[{name}] Suspicious command — {description}: {full_cmd[:80]}")
    return findings


def check_env_secrets(name: str, config: dict) -> list[str]:
    findings = []
    env = config.get("env", {})
    for var_name, value in env.items():
        if not isinstance(value, str):
            continue
        if PLACEHOLDER_RE.search(value):
            continue
        for pattern, label in SECRET_VALUE_PATTERNS:
            if pattern.search(value):
                masked = value[:8] + "..." + value[-4:] if len(value) > 14 else value[:6] + "..."
                findings.append(
                    f"[{name}] Hardcoded secret in env.{var_name} — {label}: {masked}"
                )
    return findings


def check_unknown_servers(servers: dict, manifest: dict) -> list[str]:
    trusted = manifest.get("trusted_servers", {})
    unknown = [name for name in servers if name not in trusted]
    if unknown:
        return [f"[{name}] Unknown MCP server — not in manifest (run --init after reviewing)" for name in unknown]
    return []


def check_command_drift(servers: dict, manifest: dict) -> list[str]:
    """Flag servers whose commands changed since the manifest was generated."""
    trusted = manifest.get("trusted_servers", {})
    findings = []
    for name, config in servers.items():
        if name not in trusted:
            continue
        current_cmd = config.get("command", "")
        trusted_cmd = trusted[name].get("command", "")
        if current_cmd != trusted_cmd:
            findings.append(
                f"[{name}] Command changed since manifest — was '{trusted_cmd}', now '{current_cmd}'"
            )
    return findings


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "hook"

    servers = read_mcp_servers()

    # ── --init: generate manifest from current state ──────────────────────────
    if mode == "--init":
        save_manifest(servers)
        print(f"✓ MCP manifest created at {MANIFEST}")
        print(f"  Trusted {len(servers)} server(s): {', '.join(servers.keys()) or 'none'}")
        print("  Commit this manifest to git to detect future additions.")
        return

    # ── --status: human-readable inventory ────────────────────────────────────
    if mode == "--status":
        if not servers:
            print("No MCP servers configured.")
            return
        print(f"Configured MCP servers ({len(servers)}):\n")
        for name, config in servers.items():
            cmd = config.get("command", "?")
            args = " ".join(str(a) for a in config.get("args", []))
            env_keys = list(config.get("env", {}).keys())
            print(f"  {name}")
            print(f"    command: {cmd} {args}")
            if env_keys:
                print(f"    env vars: {', '.join(env_keys)}")
        return

    # ── hook mode: SessionStart ────────────────────────────────────────────────
    if not servers:
        sys.exit(0)  # No MCP servers configured — nothing to verify

    all_findings = []
    warnings = []

    # 1. Check all server commands for RCE patterns (always, no manifest needed)
    for name, config in servers.items():
        all_findings.extend(check_suspicious_command(name, config))

    # 2. Check env vars for hardcoded secrets (always)
    for name, config in servers.items():
        all_findings.extend(check_env_secrets(name, config))

    # 3. Manifest-dependent checks
    manifest = load_manifest()
    if manifest is None:
        warnings.append(
            f"No MCP manifest found at {MANIFEST}.\n"
            "  Run: python3 ~/.claude/hooks/mcp-verifier.py --init\n"
            f"  Then commit the manifest to git. ({len(servers)} server(s) currently configured: "
            + ", ".join(servers.keys()) + ")"
        )
    else:
        all_findings.extend(check_unknown_servers(servers, manifest))
        all_findings.extend(check_command_drift(servers, manifest))

    if not all_findings and not warnings:
        sys.exit(0)  # Silent on clean pass

    output_parts = []

    if all_findings:
        output_parts.append(
            "⚠️  MCP Server Security Issues:\n"
            + "\n".join(f"  • {f}" for f in all_findings)
            + "\n\n"
            "  Actions:\n"
            "    • Review each flagged server before proceeding\n"
            "    • If changes are intentional: python3 ~/.claude/hooks/mcp-verifier.py --init\n"
            "    • Remove suspicious servers from ~/.claude/settings.json"
        )

    if warnings:
        output_parts.append("\n".join(warnings))

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": "\n\n".join(output_parts),
        }
    }))


if __name__ == "__main__":
    main()

# Customization Guide

## security-scan.py — Trusted Paths

By default, the scanner skips files under `~/.claude/` and system paths. Add your own project directories to skip scanning files you own and trust:

```python
TRUSTED_PREFIXES = [
    str(Path.home() / ".claude/skills"),
    str(Path.home() / ".claude/hooks"),
    # Add your own trusted directories:
    str(Path.home() / "projects/my-internal-repo"),
    str(Path.home() / "work/company-codebase"),
]
```

**When to add:** Any directory containing only your own code that you fully control and trust.

**When NOT to add:** Any directory that may contain downloaded content, cloned repos, or third-party code.

---

## security-scan.py — Adding Injection Patterns

To add new injection patterns (e.g., after a new CVE is published), append to `INJECTION_PATTERNS`:

```python
INJECTION_PATTERNS = [
    # ... existing patterns ...
    re.compile(r'your_new_pattern_here', re.IGNORECASE),
]
```

Pattern tips:
- Use `re.IGNORECASE` — attackers vary capitalization
- Keep patterns specific enough to avoid false positives
- Test with `echo '{"tool_name":"Read","tool_input":{"file_path":"/tmp/test.md"}}' | python3 security-scan.py`

---

## tool-audit.py — Safe Write Directories

The `SAFE_WRITE_PREFIXES` list defines which directories are considered safe for Claude to write to. By default, all of `Path.home()` is considered safe. You can tighten this:

```python
SAFE_WRITE_PREFIXES = [
    str(Path.home() / "projects"),    # Only your projects folder
    str(Path.home() / ".claude"),     # Claude's own config
    "/tmp/",
    "/var/folders/",
]
```

If Claude writes outside these prefixes, an anomaly is logged. You'll see it in `~/.claude/tool-audit.log`.

---

## tool-audit.py — Audit Log Location

The default log location is `~/.claude/tool-audit.log`. To change it:

```python
AUDIT_LOG = Path.home() / ".claude" / "tool-audit.log"
# Change to, e.g.:
# AUDIT_LOG = Path.home() / "Documents" / "security" / "agent-audit.log"
```

---

## memory-drift-check.py — Vault or Workspace Path Checks

You can add custom path existence checks for directories that must always be present in your workspace. Find the section marked `# Optional: add your vault or workspace path checks here` and uncomment:

```python
# Optional: add your vault or workspace path checks here
VAULT_PATH = Path.home() / "Documents" / "my-vault"
if not VAULT_PATH.exists():
    issues.append(f"PATH MISSING: Vault not found at {VAULT_PATH}")
```

---

## memory-drift-check.py — Stale Memory Threshold

By default, project memory files are flagged as stale after 14 days without updates. Adjust this to match your workflow:

```python
STALE_DAYS = 14   # Change to 7 for weekly review, 30 for monthly
```

---

## .gitleaks.toml — Adding Custom Secret Rules

Add rules for any API keys specific to your stack. Each rule needs a unique `id`, a `regex`, and `tags`:

```toml
[[rules]]
id = "my-service-api-key"
description = "My Service API Key"
regex = '''myservice_[a-zA-Z0-9]{32}'''
tags = ["api-key", "my-service"]
severity = "CRITICAL"
```

To add to the allowlist (placeholder values that should never trigger):

```toml
[allowlist]
regexes = [
  # Add your placeholder patterns:
  '''myservice_your_key_here''',
  '''REPLACE_WITH_REAL_KEY''',
]
```

---

## settings.json.template — Hook Path Format

The template uses `~/.claude/hooks/` paths. Claude Code expands `~` on macOS/Linux. If you encounter issues, replace with absolute paths:

```json
"command": "python3 \"/Users/YOUR_USERNAME/.claude/hooks/security-scan.py\""
```

The `install.sh` script handles this substitution automatically.

---

## Adding a New Hook

To add a new hook to the framework:

1. Create your hook script in `~/.claude/hooks/your-hook.py`
2. Follow the pattern: read stdin JSON → process → output `hookSpecificOutput` JSON (or exit 0)
3. Always wrap in `try/except Exception: sys.exit(0)` to prevent hook errors from breaking Claude Code
4. Add to `settings.json` under the appropriate lifecycle event
5. Test with: `echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' | python3 your-hook.py`

See the existing hooks for reference patterns.

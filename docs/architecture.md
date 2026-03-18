# Architecture — How the Layers Work Together

## The Problem

Claude Code is a powerful autonomous agent with full filesystem and shell access. Three attack vectors exist that built-in protections don't fully close:

1. **Indirect Prompt Injection** — malicious instructions embedded in files Claude reads (READMEs, configs, code). The agent processes the content and unknowingly executes injected instructions. This is architectural: no transformer-based LLM can cryptographically distinguish a legitimate system instruction from an injected one.

2. **Memory/Context Poisoning** — injected instructions that persist across sessions by embedding in Claude's long-term memory files. Documented as MINJA-class attacks (NeurIPS 2025). An attacker plants instructions today; Claude executes them in a future, unrelated session.

3. **Secrets Leakage** — API keys and credentials accidentally committed to git, exposed via AI context, or leaked via agent tool calls.

This framework adds a defense-in-depth layer that sits between Claude Code and these threats.

---

## The 6 Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                        ATTACK SURFACE                           │
│   External files · GitHub repos · Web content · AI output       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 1 — SessionStart: Memory Integrity + Poisoning Scan       │
│  memory-drift-check.py                                          │
│  • Validates MEMORY.md index against disk                       │
│  • Scans all memory files for injected instructions             │
│  • Flags MINJA-class attack patterns before they execute        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 2 — PreToolUse Read: File Content Scanner                 │
│  security-scan.py                                               │
│  • Scans every file Claude reads from untrusted paths           │
│  • Detects: 19 injection patterns, 8 secret patterns,           │
│    5 malicious code patterns                                     │
│  • Auto-routes to /security-scanner skill on findings           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 3 — PreToolUse Write: .env File Blocker                   │
│  settings.json hook (inline regex)                              │
│  • Blocks Claude from writing to .env files                     │
│  • Prevents accidental secret overwrite or exfiltration         │
│  • Allows .env.example files through                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 4 — PostToolUse: Behavioral Audit Log                     │
│  tool-audit.py                                                  │
│  • Logs every tool call to ~/.claude/tool-audit.log             │
│  • Flags: curl|sh pipes, sensitive path reads,                  │
│    writes to /etc/, ~/.ssh/, ~/.aws/                            │
│  • Immutable audit trail for forensic review                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 5 — Pre-commit: Git-Level Secrets Scan                    │
│  gitleaks + detect-private-key + .env blocker                   │
│  • Blocks secrets before they enter git history                 │
│  • Custom rules: Anthropic API keys, Supabase JWTs              │
│  • Machine-wide gitignore blocks .env from all repos            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 6 — On-Demand: /security-scanner Skill                    │
│  security-scanner.md                                            │
│  • Full 5-step manual scan for any content                      │
│  • Verdict: SAFE / FLAGGED / BLOCKED                            │
│  • Chains to /ciso for CRITICAL findings                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Hook Execution Timing

```
Session opens
    │
    ├── SessionStart hooks run (async)
    │       └── memory-drift-check.py — scans memory for poisoning
    │
    │   [user sends message]
    │
    ├── PreToolUse hooks run (before each tool)
    │       ├── Read matcher → security-scan.py (async)
    │       └── Write|Edit matcher → .env blocker (sync, can deny)
    │
    │   [tool executes]
    │
    └── PostToolUse hooks run (after each tool)
            └── tool-audit.py (async, logs to ~/.claude/tool-audit.log)
```

---

## What "Async" Means

Hooks marked `"async": true` run in parallel with Claude's response — they never block the tool call. They can add context to Claude's awareness but cannot block execution. The exception is the `.env` Write blocker, which is synchronous and uses `permissionDecision: deny` to hard-block the operation.

---

## Design Principles

- **Silent on clean** — hooks produce zero output when no threats are found. No noise, no warning fatigue.
- **Fail open** — every hook has a top-level `except Exception: sys.exit(0)`. A broken hook never breaks Claude Code.
- **No cloud** — everything runs locally. No data leaves your machine.
- **No hardcoded paths** — all paths are derived from `Path.home()` at runtime.
- **Additive, not restrictive** — the framework adds security without removing Claude Code functionality.

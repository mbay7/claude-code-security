# claude-code-security

**A 6-layer security framework for Claude Code workspaces.** Prompt injection detection, memory poisoning prevention, secrets scanning, behavioral audit logging, and pre-commit guardrails. Installs in 5 minutes. No cloud services required.

---

## Why This Exists

I build with Claude Code every day. After reading about [CVE-2025-59536](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) (CVSS 8.7 — RCE via project settings files) and seeing a near-miss with an API key almost committed to git, I needed to properly secure my workspace.

I couldn't find a comprehensive solution. Most tools covered one layer — secrets scanning or injection detection, not both. Nobody had addressed memory poisoning (persistent injection across sessions), which Palo Alto Unit 42 had documented as an active attack vector.

So I built this. It's what I use on every project. Sharing it so you can do the same.

---

## What It Defends Against

| Threat | Layer | OWASP |
|--------|-------|-------|
| Prompt injection in external files (READMEs, configs, web content) | PreToolUse scanner | LLM01:2025 |
| Memory poisoning — injected instructions that persist across sessions | SessionStart scan | LLM04:2025 / ASI06 |
| API keys accidentally committed to git | Pre-commit + gitignore | LLM02:2025 |
| `.env` file modification by Claude | Write blocker | LLM06:2025 |
| Suspicious tool calls (curl\|sh, reverse shells, sensitive path reads) | Behavioral audit | LLM05:2025 |
| Supply chain attacks in external code/configs | File content scanner | LLM03:2025 |
| CVE-2025-59536 (RCE via hooks, CVSS 8.7) | Audit log + memory scan | — |
| CVE-2025-6514 (mcp-remote RCE, CVSS 9.6) | File scanner | LLM03:2025 |

---

## Architecture

```
Session opens
    └── memory-drift-check.py    ← scans memory files for injected instructions

User message → Claude reads a file
    └── security-scan.py         ← 19 injection patterns, 8 secret patterns,
                                     5 malicious code patterns. Auto-routes to
                                     /security-scanner skill on findings.

Claude tries to write .env file
    └── .env blocker (inline)    ← hard-blocks the operation

Tool call completes
    └── tool-audit.py            ← logs everything to ~/.claude/tool-audit.log,
                                     flags anomalies (curl|sh, ~/.ssh reads, etc.)

Git commit
    └── gitleaks + pre-commit    ← scans staged content for secrets
    └── ~/.gitignore_global      ← machine-wide .env protection
```

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/mbay7/claude-code-security.git
cd claude-code-security

# 2. Install
./install.sh

# 3. For each project — enable git-level protection
cp config/.pre-commit-config-template.yaml /path/to/your/project/.pre-commit-config.yaml
cd /path/to/your/project && pre-commit install
```

Then reload Claude Code. That's it.

---

## What Gets Installed

```
~/.claude/
├── hooks/
│   ├── security-scan.py         # PreToolUse: scans files Claude reads
│   ├── tool-audit.py            # PostToolUse: logs + flags anomalous tool calls
│   └── memory-drift-check.py   # SessionStart: memory integrity + poisoning scan
└── skills/
    └── security-scanner.md      # /security-scanner skill (auto-invoked on findings)
```

Plus config files you copy to each project:
- `.pre-commit-config.yaml` — gitleaks + secret blocking at commit time
- `~/.gitignore_global` — machine-wide `.env` protection across all repos

---

## The 6 Layers

### Layer 1 — Memory Integrity + Poisoning Detection
`hooks/memory-drift-check.py` runs at every session start.

- Validates that all files listed in `MEMORY.md` exist on disk
- Flags orphan memory files (exist on disk but not indexed)
- **Scans all memory files for 14 prompt injection patterns** — this is the unique layer. It detects MINJA-class attacks: adversarial content that plants persistent instructions in Claude's long-term memory. No other open-source tool does this.
- Flags memory files that haven't been updated in 14+ days

### Layer 2 — Pre-Read File Scanner
`hooks/security-scan.py` runs before Claude reads any file from an untrusted path.

- 19 injection patterns: "ignore previous instructions", DAN mode, zero-width Unicode, hidden HTML comments, etc.
- 8 secret patterns: Anthropic API keys, OpenAI keys, AWS credentials, GitHub PATs, Stripe live keys, private key blocks, Supabase JWTs
- 5 malicious code patterns: reverse shells, crypto miners, sensitive file access, base64-decode-pipe attacks
- Smart placeholder detection: skips `your-key-here` and `REPLACE_ME` patterns
- Silent on clean files — zero noise when nothing is found
- Auto-invokes `/security-scanner` skill when findings are detected

### Layer 3 — .env Write Blocker
Inline hook in `settings.json`. Denies any Claude write/edit operation targeting `.env` files. Allows `.env.example` through (safe templates).

### Layer 4 — Behavioral Audit Log
`hooks/tool-audit.py` runs after every tool call.

- Logs every tool call to `~/.claude/tool-audit.log` with timestamp, tool name, and summary
- Flags anomalies: `curl | sh` pipes, reads to `~/.ssh/`, `~/.aws/`, `/etc/passwd`, writes to system paths
- Immutable local audit trail for forensic review after any incident
- Silent on normal operations — only surfaces anomalies

### Layer 5 — Git-Level Secrets Protection
Three independent blocks before any secret reaches git history:

1. Project-level `.gitignore` blocks `.env`
2. `~/.gitignore_global` blocks `.env` in ALL repos machine-wide
3. `gitleaks` pre-commit hook scans staged content using custom Claude/Supabase rules

### Layer 6 — On-Demand Security Scanner
`/security-scanner` skill: a 5-step scan protocol for any content.

- Classify → Injection scan → Secrets scan → Malicious code scan → Report
- Verdict system: **SAFE** / **FLAGGED** / **BLOCKED**
- Auto-invoked when Layer 2 finds issues
- Chain to `/ciso` for CRITICAL findings

---

## Why Each Layer Is Necessary

**Why not just trust Claude Code's built-in protections?**

Anthropic has built a good foundation: permission gates, command blocklist, sandboxing (2026), and prompt injection classifiers. But three structural gaps remain:

1. **Indirect prompt injection is architectural.** The LLM processes system instructions and data in a unified token stream. It cannot cryptographically distinguish a legitimate instruction from an injected one in a file it reads. Sandboxing reduces blast radius but doesn't stop the injection.

2. **Memory poisoning doesn't exist in Anthropic's threat model yet.** The `memory-drift-check.py` SessionStart scan has no equivalent anywhere in Claude Code or in any competitor tool.

3. **Approval fatigue is real.** Research confirms developers approve Claude Code operations in bulk without reading them. Human permission gates fail under real workload. This framework adds automated defenses that don't rely on human attention.

Anthropic, Microsoft, and Google all formally publish a "Shared Responsibility Model" — the vendor secures the model and infrastructure, the operator (you) is responsible for runtime agent security. This framework covers your side.

---

## Roadmap

- [ ] **Phase 2:** `memory-write-guard.py` — write-time sanitization of memory files (closes MINJA write vector)
- [ ] **Phase 2:** `hook-integrity.sh` — SHA256 manifest verification of hook files (closes CVE-2025-59536 hook replacement vector)
- [ ] **Phase 3:** `mcp-verifier.py` — MCP server supply chain verification (closes CVE-2025-6514 class)
- [ ] **Phase 3:** Cline adapter — all hooks adapted for Cline's `.clinerules/hooks/` format
- [ ] **Phase 3:** `patterns/injection-patterns.json` — community-maintained threat pattern registry
- [ ] **Phase 4:** `/red-team` skill — automated self-attack battery
- [ ] **Phase 4:** OWASP Agentic 2026 full coverage matrix

---

## Contributing

The most valuable contributions are new detection patterns:

1. **New injection patterns** — add to `INJECTION_PATTERNS` in `hooks/security-scan.py` with a comment linking to the CVE or research paper
2. **New secret patterns** — add to `SECRET_PATTERNS` with format `(label, regex, severity)`
3. **New gitleaks rules** — add to `config/.gitleaks.toml`
4. **Bug reports** — if a hook causes false positives or breaks Claude Code, open an issue

Please include the source (CVE number, OWASP ID, or research paper) for any new pattern.

---

## License

MIT — use it, fork it, adapt it for your stack.

---

*Built by a founder who needed this for their own work. Sharing it because the community shouldn't have to build this from scratch.*

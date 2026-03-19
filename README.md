# claude-code-security

**Runtime security for Claude Code workspaces.** Blocks prompt injection, memory poisoning, secret exposure, and hook tampering — automatically, at every session.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/mbay7/claude-code-security)](https://github.com/mbay7/claude-code-security/releases)
[![Audit](https://github.com/mbay7/claude-code-security/actions/workflows/audit.yml/badge.svg)](https://github.com/mbay7/claude-code-security/actions/workflows/audit.yml)
[![pytest](https://img.shields.io/badge/evals-68%20passed-brightgreen)](evals/)
[![Issues](https://img.shields.io/github/issues/mbay7/claude-code-security)](https://github.com/mbay7/claude-code-security/issues)

---

## Install

```bash
git clone https://github.com/mbay7/claude-code-security.git && cd claude-code-security && ./install.sh
```

Reload Claude Code. Done.

> **Why git clone instead of `curl | bash`?** You're installing a security tool. Cloning first lets you read the code before it runs on your machine — that's the right default.

**Requirements:** `python3`, `jq` (auto-installed via brew if missing)

---

## What It Catches

```
$ echo '{}' | python3 ~/.claude/hooks/memory-drift-check.py

🚨 Context Poisoning Detected in Memory Files:
  • INJECTION in project_notes.md:14 — "ignore previous instructions and"
  • INJECTION in feedback_auth.md:3 — "you are now a"

Run /security-scanner on any suspicious file.
```

```
$ python3 ~/.claude/hooks/security-scan.py < read_event.json

SECURITY SCAN — external-readme.md
Found 2 issue(s): 1 CRITICAL, 1 HIGH

  [CRITICAL] Secret Exposure at line 4: Anthropic API key: sk-ant-ap...KEY
  [HIGH]     Prompt Injection at line 12: "ignore all previous instruct..."

ACTION REQUIRED: Run /security-scanner on this file before proceeding.
```

```
$ python3 ~/.claude/hooks/mcp-verifier.py --status

Configured MCP servers (3):

  github
    command: npx -y @modelcontextprotocol/server-github
    env vars: GITHUB_PERSONAL_ACCESS_TOKEN
  context7
    command: npx -y @upstash/context7-mcp
  unknown-server
    command: node /tmp/malicious-server.js
```

```
$ ~/.claude/hooks/hook-integrity.sh

Verifying hook integrity...
✓ memory-drift-check.py — OK
✓ mcp-verifier.py — OK
✓ security-scan.py — OK
✓ tool-audit.py — OK
✓ memory-write-guard.py — OK

All hooks verified — integrity confirmed (5 files)
```

---

## What Gets Installed

```
~/.claude/
├── hooks/
│   ├── memory-drift-check.py    # SessionStart: memory poisoning scan
│   ├── mcp-verifier.py          # SessionStart: MCP server integrity audit
│   ├── security-scan.py         # PreToolUse: injection + secrets scanner
│   ├── tool-audit.py            # PostToolUse: behavioral audit log
│   ├── memory-write-guard.py    # PostToolUse: write-time injection guard
│   ├── hook-integrity.sh        # On-demand SHA256 integrity check
│   ├── .integrity.sha256        # Hook manifest (generated on install)
│   └── .mcp-manifest.json       # MCP server manifest (generated on --init)
└── skills/
    └── security-scanner.md      # /security-scanner — auto-invoked on findings
```

Plus:
- `~/.gitignore_global` — machine-wide `.env` protection across all repos
- `.pre-commit-config.yaml` template — copy to each project, run `pre-commit install`

---

## 6 Layers

| Layer | Hook | Threat | OWASP |
|-------|------|--------|-------|
| Memory integrity scan | `memory-drift-check.py` | MINJA-class memory poisoning (NeurIPS 2025) | LLM04:2025, ASI06 |
| Memory write guard | `memory-write-guard.py` | Injection at write time — closes write vector | LLM04:2025 |
| MCP server integrity | `mcp-verifier.py` | Unauthorized MCP servers, RCE via server config, hardcoded secrets in env | LLM08:2025 |
| Pre-read file scanner | `security-scan.py` | Injection in external files, hardcoded secrets | LLM01:2025, LLM02:2025 |
| .env write blocker | settings.json (inline) | Claude modifying secrets files | LLM06:2025 |
| Behavioral audit log | `tool-audit.py` | Reverse shells, exfiltration, suspicious Bash | LLM05:2025 |
| Git secrets protection | gitleaks + .gitignore | Secrets reaching git history | LLM02:2025 |

---

## What It Detects

**Injection patterns (19):** ignore previous instructions · DAN mode · zero-width Unicode steganography · `[SYSTEM]:` tags · `<<SYS>>` blocks · role override attempts · when-Claude-reads-this payloads · HTML comment injections

**Secret patterns (8):** Anthropic API keys · OpenAI keys · AWS credentials · GitHub PATs · Stripe live keys · private key blocks · Supabase JWTs

**Malicious code patterns (5):** reverse shells (`nc -e /bin/bash`) · crypto miners (`xmrig`, `stratum+tcp`) · `base64 | bash` pipes · sensitive file reads (`~/.ssh`, `/etc/passwd`)

---

## Evals

Detection claims are backed by 68 automated tests across all threat categories.

```bash
pip install pytest
python -m pytest evals/ -v
```

| Category | Tests | Coverage |
|---|---|---|
| Prompt injection | 20 | Direct overrides, role hijacks, structural tags, Unicode steganography |
| Secret exposure | 17 | All 8 key types, crypto material, placeholder false-positive validation |
| Memory poisoning | 13 | Write guard injection, clean-write false positives, edge cases |
| Behavioral anomalies | 18 | Reverse shells, miners, exfil patterns, tool-audit clean/anomaly split |

CI runs evals on every push and PR via [GitHub Actions](.github/workflows/audit.yml).

---

## Why Not Just Trust Claude Code's Built-in Protections?

Anthropic's foundation is solid: permission gates, command blocklists, sandboxing (2026), and prompt injection classifiers. Three structural gaps remain:

1. **Indirect prompt injection is architectural.** The LLM processes system instructions and data in a unified token stream — it cannot cryptographically distinguish a legitimate instruction from an injected one in a file it reads. Sandboxing reduces blast radius but doesn't stop injection.

2. **Memory poisoning isn't in Anthropic's threat model yet.** `memory-drift-check.py` + `memory-write-guard.py` are the only open-source tools scanning Claude memory files for MINJA-class attacks.

3. **Approval fatigue is real.** Research confirms developers approve Claude Code operations in bulk without reading them. Automated hooks don't rely on human attention.

Anthropic, Microsoft, and Google all publish a Shared Responsibility Model — the vendor secures the model and infrastructure, the operator (you) secures the runtime. This framework covers your side.

---

## Threat Coverage

| CVE / Threat | Coverage |
|---|---|
| CVE-2025-59536 (CVSS 8.7 — RCE via hooks) | `hook-integrity.sh` SHA256 manifest |
| CVE-2025-6514 (CVSS 9.6 — mcp-remote RCE) | `mcp-verifier.py` + `security-scan.py` |
| MINJA memory poisoning (NeurIPS 2025) | `memory-drift-check.py` + `memory-write-guard.py` |
| OWASP LLM Top 10:2025 | LLM01–LLM08 |

---

## Compared to Alternatives

| Tool | Injection | Memory Poisoning | MCP Integrity | Secrets | Hook Integrity | Write Guard |
|---|---|---|---|---|---|---|
| **claude-code-security** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| lasso-security/claude-hooks | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| mintmcp/agent-security | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ |
| mafiaguy/claude-security-guardrails | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |

---

## Contributing

New detection patterns are the most valuable contribution. Each pattern must include a source (CVE number, OWASP ID, or research paper link).

1. **Injection patterns** → `INJECTION_PATTERNS` in `hooks/security-scan.py`
2. **Secret patterns** → `SECRET_PATTERNS` with format `(label, regex, severity)`
3. **Gitleaks rules** → `config/.gitleaks.toml`
4. **Bug reports** → [open an issue](https://github.com/mbay7/claude-code-security/issues)

See [CONTRIBUTING.md](docs/customization.md) for full details.

---

## License

MIT — use it, fork it, adapt it for your stack.

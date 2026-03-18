#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# claude-code-security — install.sh
# Sets up the 6-layer Claude Code security framework in ~5 minutes.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

ok()   { echo -e "${GREEN}✓${RESET} $1"; }
warn() { echo -e "${YELLOW}⚠${RESET}  $1"; }
info() { echo -e "  $1"; }
fail() { echo -e "${RED}✗${RESET} $1"; exit 1; }
header() { echo -e "\n${BOLD}$1${RESET}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="$HOME/.claude"
HOOKS_DIR="$CLAUDE_DIR/hooks"
SKILLS_DIR="$CLAUDE_DIR/skills"

header "claude-code-security installer"
echo "  Installing 6-layer security framework for Claude Code."
echo "  Repo: $SCRIPT_DIR"
echo "  Target: $CLAUDE_DIR"

# ── Check prerequisites ───────────────────────────────────────────────────────
header "1/6  Checking prerequisites..."

if ! command -v python3 &>/dev/null; then
    fail "python3 is required. Install it and retry."
fi
ok "python3 found: $(python3 --version)"

if ! command -v jq &>/dev/null; then
    if command -v brew &>/dev/null; then
        warn "jq not found — installing via brew..."
        brew install jq
        ok "jq installed"
    else
        fail "jq is required. Install it (brew install jq) and retry."
    fi
fi
ok "jq found"

# ── Install gitleaks ──────────────────────────────────────────────────────────
header "2/6  Setting up gitleaks..."

if command -v gitleaks &>/dev/null; then
    ok "gitleaks already installed: $(gitleaks version 2>/dev/null || echo 'installed')"
else
    if command -v brew &>/dev/null; then
        info "Installing gitleaks via brew..."
        brew install gitleaks
        ok "gitleaks installed"
    else
        warn "brew not found — skipping gitleaks auto-install"
        info "Install manually: https://github.com/gitleaks/gitleaks"
        info "Then run: pre-commit install in your project directory"
    fi
fi

if command -v pre-commit &>/dev/null; then
    ok "pre-commit already installed"
else
    if command -v pip3 &>/dev/null; then
        info "Installing pre-commit via pip3..."
        pip3 install pre-commit --quiet
        ok "pre-commit installed"
    elif command -v brew &>/dev/null; then
        brew install pre-commit
        ok "pre-commit installed"
    else
        warn "Could not auto-install pre-commit. Install manually: pip install pre-commit"
    fi
fi

# ── Create Claude directories ─────────────────────────────────────────────────
header "3/6  Creating Claude directories..."

mkdir -p "$HOOKS_DIR" "$SKILLS_DIR"
ok "Directories ready: $HOOKS_DIR, $SKILLS_DIR"

# ── Install hooks ─────────────────────────────────────────────────────────────
header "4/6  Installing hooks..."

for hook in security-scan.py tool-audit.py memory-drift-check.py; do
    src="$SCRIPT_DIR/hooks/$hook"
    dst="$HOOKS_DIR/$hook"
    if [ -f "$dst" ]; then
        warn "$hook already exists at $dst — backing up to ${dst}.bak"
        cp "$dst" "${dst}.bak"
    fi
    cp "$src" "$dst"
    chmod +x "$dst"
    ok "Installed $hook"
done

# ── Install skill ─────────────────────────────────────────────────────────────
header "5/6  Installing /security-scanner skill..."

src="$SCRIPT_DIR/skills/security-scanner.md"
dst="$SKILLS_DIR/security-scanner.md"
if [ -f "$dst" ]; then
    warn "security-scanner.md already exists — backing up"
    cp "$dst" "${dst}.bak"
fi
cp "$src" "$dst"
ok "Installed security-scanner.md skill"

# ── Install gitleaks config ───────────────────────────────────────────────────
gitleaks_dst="$CLAUDE_DIR/.gitleaks.toml"
if [ ! -f "$gitleaks_dst" ]; then
    cp "$SCRIPT_DIR/config/.gitleaks.toml" "$gitleaks_dst"
    ok "Installed .gitleaks.toml → $gitleaks_dst"
else
    warn ".gitleaks.toml already exists at $gitleaks_dst — skipping (your config preserved)"
fi

# ── Set up machine-wide gitignore ─────────────────────────────────────────────
gitignore_global="$HOME/.gitignore_global"
if [ ! -f "$gitignore_global" ]; then
    cp "$SCRIPT_DIR/config/.gitignore_global" "$gitignore_global"
    git config --global core.excludesfile "$gitignore_global"
    ok "Installed ~/.gitignore_global and activated globally"
else
    warn "~/.gitignore_global already exists — skipping (your config preserved)"
    info "Verify it's active: git config --global core.excludesfile"
fi

# ── settings.json instructions ────────────────────────────────────────────────
header "6/6  Wiring hooks into Claude Code..."

SETTINGS_JSON="$CLAUDE_DIR/settings.json"
TEMPLATE="$SCRIPT_DIR/config/settings.json.template"

echo ""
if [ -f "$SETTINGS_JSON" ]; then
    warn "settings.json already exists. Merge the hooks manually to avoid overwriting your config."
    echo ""
    info "Template is at: $TEMPLATE"
    info "Your current settings: $SETTINGS_JSON"
    echo ""
    info "Add these hooks to your settings.json:"
    echo ""
    python3 -c "
import json
with open('$TEMPLATE') as f:
    t = json.load(f)
hooks = {k: v for k, v in t.items() if k == 'hooks'}
print(json.dumps(hooks, indent=2))
"
    echo ""
    info "See docs/customization.md for full instructions."
else
    # Safe to copy template directly
    cp "$TEMPLATE" "$SETTINGS_JSON"
    # Replace ~ with actual home path for compatibility
    sed -i '' "s|~/.claude/hooks/|$HOOKS_DIR/|g" "$SETTINGS_JSON" 2>/dev/null || \
    sed -i "s|~/.claude/hooks/|$HOOKS_DIR/|g" "$SETTINGS_JSON"
    ok "Created $SETTINGS_JSON with security hooks"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}────────────────────────────────────────────────────${RESET}"
echo -e "${GREEN}${BOLD}Installation complete.${RESET}"
echo ""
echo "  Hooks installed:"
echo "    • memory-drift-check.py  → SessionStart"
echo "    • security-scan.py       → PreToolUse (Read)"
echo "    • .env blocker           → PreToolUse (Write|Edit)"
echo "    • tool-audit.py          → PostToolUse"
echo ""
echo "  Skill installed:"
echo "    • /security-scanner"
echo ""
echo "  Audit log: ~/.claude/tool-audit.log"
echo ""
echo "  Next steps:"
echo "    1. For each project: copy config/.pre-commit-config-template.yaml"
echo "       to your project root as .pre-commit-config.yaml, then:"
echo "       pre-commit install"
echo ""
echo "    2. Reload Claude Code to activate SessionStart hooks"
echo ""
echo "    3. Test: echo '{}' | python3 ~/.claude/hooks/memory-drift-check.py"
echo ""
echo -e "${BOLD}────────────────────────────────────────────────────${RESET}"

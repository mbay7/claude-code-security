#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Hook Integrity Verifier — claude-code-security Phase 2
#
# Verifies SHA256 checksums of all installed Claude Code hook files.
# Closes the CVE-2025-59536 hook replacement vector: if an attacker modifies
# a hook to remove security checks or add malicious behavior, this script
# will detect the tampering before the next session.
#
# Usage:
#   ./hook-integrity.sh               # verify only
#   ./hook-integrity.sh --init        # generate fresh manifest from current hooks
#   ./hook-integrity.sh --update      # re-generate manifest (after intentional update)
#
# Manifest is stored at: ~/.claude/hooks/.integrity.sha256
#
# Part of claude-code-security — https://github.com/mbay7/claude-code-security
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

HOOKS_DIR="${HOME}/.claude/hooks"
MANIFEST="${HOOKS_DIR}/.integrity.sha256"

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
RESET="\033[0m"

ok()   { echo -e "${GREEN}✓${RESET} $1"; }
warn() { echo -e "${YELLOW}⚠${RESET}  $1"; }
fail() { echo -e "${RED}✗${RESET} $1"; }
info() { echo -e "  $1"; }

# ── Functions ─────────────────────────────────────────────────────────────────

sha256_file() {
    local file="$1"
    if command -v sha256sum &>/dev/null; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$file" | awk '{print $1}'
    else
        echo "ERROR: No sha256sum or shasum found" >&2
        exit 1
    fi
}

generate_manifest() {
    echo "# claude-code-security hook integrity manifest" > "$MANIFEST"
    echo "# Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$MANIFEST"
    echo "# DO NOT EDIT — regenerate with: ./hooks/hook-integrity.sh --update" >> "$MANIFEST"
    echo "" >> "$MANIFEST"

    local count=0
    for hook_file in "$HOOKS_DIR"/*.py "$HOOKS_DIR"/*.sh; do
        # Skip this script itself and non-existent glob results
        [ -f "$hook_file" ] || continue
        [ "$(basename "$hook_file")" = "hook-integrity.sh" ] && continue
        [ "$(basename "$hook_file")" = ".integrity.sha256" ] && continue

        local checksum
        checksum=$(sha256_file "$hook_file")
        echo "${checksum}  $(basename "$hook_file")" >> "$MANIFEST"
        ok "Hashed: $(basename "$hook_file") → ${checksum:0:16}..."
        count=$((count + 1))
    done

    echo ""
    ok "Manifest created at $MANIFEST ($count files)"
    info "Commit this manifest to git to detect future tampering."
}

verify_manifest() {
    local pass=0
    local fail_count=0
    local missing=0

    while IFS= read -r line; do
        # Skip comments and blank lines
        [[ "$line" =~ ^# ]] && continue
        [[ -z "$line" ]] && continue

        expected_hash=$(echo "$line" | awk '{print $1}')
        filename=$(echo "$line" | awk '{print $2}')
        hook_path="${HOOKS_DIR}/${filename}"

        if [ ! -f "$hook_path" ]; then
            fail "MISSING: $filename (was in manifest, not on disk)"
            missing=$((missing + 1))
            continue
        fi

        actual_hash=$(sha256_file "$hook_path")

        if [ "$expected_hash" = "$actual_hash" ]; then
            ok "$filename — OK"
            pass=$((pass + 1))
        else
            fail "TAMPERED: $filename"
            info "Expected: $expected_hash"
            info "Actual:   $actual_hash"
            fail_count=$((fail_count + 1))
        fi
    done < "$MANIFEST"

    echo ""
    echo -e "${BOLD}────────────────────────────────────────────────────${RESET}"

    if [ "$fail_count" -gt 0 ] || [ "$missing" -gt 0 ]; then
        echo -e "${RED}${BOLD}INTEGRITY VIOLATION DETECTED${RESET}"
        echo ""
        [ "$fail_count" -gt 0 ] && echo -e "  ${RED}${fail_count} hook(s) have been modified since manifest was generated.${RESET}"
        [ "$missing" -gt 0 ]    && echo -e "  ${RED}${missing} hook(s) are missing from disk.${RESET}"
        echo ""
        echo "  This may indicate:"
        echo "    • Unauthorized hook modification (CVE-2025-59536 class attack)"
        echo "    • Intentional hook update (run --update to regenerate manifest)"
        echo "    • Corrupted installation"
        echo ""
        echo "  Actions:"
        echo "    1. Review changed hooks: diff the current file vs git history"
        echo "    2. If update was intentional: ./hooks/hook-integrity.sh --update"
        echo "    3. If unexpected: restore from git and investigate"
        echo ""
        echo -e "${BOLD}────────────────────────────────────────────────────${RESET}"
        exit 2
    else
        echo -e "${GREEN}${BOLD}All hooks verified — integrity confirmed (${pass} files)${RESET}"
        echo -e "${BOLD}────────────────────────────────────────────────────${RESET}"
        exit 0
    fi
}

# ── Entry point ───────────────────────────────────────────────────────────────

if [ ! -d "$HOOKS_DIR" ]; then
    fail "Hooks directory not found: $HOOKS_DIR"
    info "Run install.sh first."
    exit 1
fi

MODE="${1:-verify}"

case "$MODE" in
    --init|--update)
        echo -e "${BOLD}Generating integrity manifest...${RESET}"
        generate_manifest
        ;;
    verify|--verify|"")
        if [ ! -f "$MANIFEST" ]; then
            warn "No manifest found at $MANIFEST"
            info "Run first: ./hooks/hook-integrity.sh --init"
            info "Then commit the manifest to git."
            exit 1
        fi
        echo -e "${BOLD}Verifying hook integrity...${RESET}"
        verify_manifest
        ;;
    *)
        echo "Usage: $0 [--init|--update|verify]"
        echo ""
        echo "  verify   (default) — verify hooks against manifest"
        echo "  --init             — generate manifest from current hooks"
        echo "  --update           — regenerate manifest after intentional update"
        exit 1
        ;;
esac

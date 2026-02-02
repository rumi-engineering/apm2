#!/usr/bin/env bash
# CI guardrail against legacy IPC reintroduction (TCK-00282)
#
# This script prevents accidental reintroduction of legacy JSON IPC code
# or single-socket configuration patterns that were removed in TCK-00281.
#
# Per DD-009 (RFC-0017), the daemon uses ProtocolServer-only control plane
# with dual sockets (operator.sock + session.sock). Legacy patterns are:
#
# - ipc_server module (deleted in TCK-00281)
# - apm2_core::ipc module references
# - [daemon].socket config key (replaced by operator_socket/session_socket)
#
# Exit codes:
#   0 - No legacy IPC patterns detected
#   1 - Legacy IPC patterns found (build should fail)
#   2 - Script error (missing dependencies, etc.)
#
# Usage:
#   ./scripts/ci/legacy_ipc_guard.sh

set -euo pipefail

# Color codes for output (disabled if not a terminal)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

# Log functions
log_error() { echo -e "${RED}ERROR:${NC} $*" >&2; }
log_warn() { echo -e "${YELLOW}WARN:${NC} $*" >&2; }
log_info() { echo -e "${GREEN}INFO:${NC} $*"; }

# Check for required tools
check_dependencies() {
    if ! command -v rg &>/dev/null; then
        log_error "ripgrep (rg) is required but not installed."
        log_error "Install via: cargo install ripgrep, apt install ripgrep, or brew install ripgrep"
        exit 2
    fi
}

# Directories to search (Rust source code only)
SEARCH_DIRS=(
    "crates/apm2-daemon/src"
    "crates/apm2-core/src"
    "crates/apm2-cli/src"
)

# Directories/files to exclude from search
# Documentation, tickets, and RFCs naturally reference these patterns
EXCLUDE_GLOBS=(
    "*.md"
    "*.yaml"
    "*.yml"
    "*.json"
    "documents/*"
    "evidence/*"
    ".claude/*"
)

# Build ripgrep glob exclusion arguments
build_exclude_args() {
    local args=""
    for glob in "${EXCLUDE_GLOBS[@]}"; do
        args="$args --glob '!$glob'"
    done
    echo "$args"
}

# Track if any violations found
VIOLATIONS_FOUND=0

# Check for legacy IPC server module references
check_ipc_server_references() {
    log_info "Checking for legacy ipc_server module references..."

    local patterns=(
        'mod\s+ipc_server'          # Module declaration
        'use\s+.*ipc_server'        # Use statement
        'ipc_server::'              # Direct module path access
        'crate::ipc_server'         # Crate-relative path
    )

    for dir in "${SEARCH_DIRS[@]}"; do
        if [[ ! -d "$dir" ]]; then
            continue
        fi

        for pattern in "${patterns[@]}"; do
            # Search only .rs files
            local matches
            matches=$(rg --type rust -l "$pattern" "$dir" 2>/dev/null || true)

            if [[ -n "$matches" ]]; then
                # Filter out comments (lines starting with //, ///, //!)
                # Doc comments explaining what was removed are allowed
                local violations
                violations=$(rg --type rust -n "$pattern" "$dir" 2>/dev/null | \
                    grep -v '^\s*//' | \
                    grep -v ':[ \t]*///' | \
                    grep -v ':[ \t]*//' || true)

                if [[ -n "$violations" ]]; then
                    log_error "Found legacy ipc_server references:"
                    log_error "Pattern: $pattern"
                    echo "$violations" | while read -r line; do
                        log_error "  $line"
                    done
                    VIOLATIONS_FOUND=1
                fi
            fi
        done
    done
}

# Check for apm2_core::ipc module references
check_core_ipc_references() {
    log_info "Checking for legacy apm2_core::ipc module references..."

    local patterns=(
        'apm2_core::ipc'            # Direct module path
        'use\s+apm2_core::ipc'      # Use statement
        'mod\s+ipc\s*;'             # Module declaration in apm2-core
        'pub\s+mod\s+ipc'           # Public module declaration
    )

    for dir in "${SEARCH_DIRS[@]}"; do
        if [[ ! -d "$dir" ]]; then
            continue
        fi

        for pattern in "${patterns[@]}"; do
            local matches
            matches=$(rg --type rust --glob '!*.md' -l "$pattern" "$dir" 2>/dev/null || true)

            if [[ -n "$matches" ]]; then
                # Filter out false positives from comments explaining the removal
                # We allow references in doc comments that explain the change
                local actual_violations
                actual_violations=$(rg --type rust --glob '!*.md' -n "$pattern" "$dir" 2>/dev/null | grep -v '^\s*//' | grep -v '//!' | grep -v '/// ' || true)

                if [[ -n "$actual_violations" ]]; then
                    log_error "Found legacy apm2_core::ipc references:"
                    log_error "Pattern: $pattern"
                    echo "$actual_violations" | while read -r line; do
                        log_error "  $line"
                    done
                    VIOLATIONS_FOUND=1
                fi
            fi
        done
    done
}

# Check for legacy single-socket config pattern
check_legacy_socket_config() {
    log_info "Checking for legacy [daemon].socket config pattern..."

    # Legacy pattern: [daemon] section with a single 'socket' key
    # (instead of operator_socket and session_socket)
    #
    # Pattern: socket = "..." in config files (NOT operator_socket or session_socket)
    # We match 'socket' but not 'operator_socket' or 'session_socket'
    local pattern='^socket\s*='

    local config_files
    config_files=$(find . -name "*.toml" -type f 2>/dev/null | grep -v target/ | grep -v '.git/' || true)

    for file in $config_files; do
        # Skip if file doesn't contain [daemon] section
        # Allow leading whitespace and optional spaces inside brackets
        if ! grep -q '^[[:space:]]*\[[[:space:]]*daemon[[:space:]]*\]' "$file" 2>/dev/null; then
            continue
        fi

        # Extract [daemon] section and check for legacy 'socket' key
        # The key must be exactly 'socket', not 'operator_socket' or 'session_socket'
        local in_daemon=0
        local line_num=0
        while IFS= read -r line; do
            ((line_num++)) || true

            # Check for section headers
            # Allow leading whitespace and optional spaces inside brackets
            if [[ "$line" =~ ^[[:space:]]*\[.+\] ]]; then
                if [[ "$line" =~ ^[[:space:]]*\[[[:space:]]*daemon[[:space:]]*\] ]]; then
                    in_daemon=1
                else
                    in_daemon=0
                fi
                continue
            fi

            # If in [daemon] section, check for legacy socket key
            if [[ $in_daemon -eq 1 ]]; then
                # Match 'socket = ' but NOT 'operator_socket = ' or 'session_socket = '
                if [[ "$line" =~ ^[[:space:]]*socket[[:space:]]*= ]] && \
                   ! [[ "$line" =~ operator_socket ]] && \
                   ! [[ "$line" =~ session_socket ]]; then
                    log_error "Found legacy [daemon].socket config key:"
                    log_error "  $file:$line_num: $line"
                    log_error "  Use operator_socket and session_socket instead (DD-009)"
                    VIOLATIONS_FOUND=1
                fi
            fi
        done < "$file"
    done
}

# Check documentation doesn't describe legacy patterns as current
check_docs_for_misleading_legacy_refs() {
    log_info "Checking documentation for misleading legacy IPC references..."

    # We specifically look for patterns that suggest ipc_server is still present
    # This helps catch stale documentation that hasn't been updated
    local patterns=(
        'start.*ipc_server'          # Instructions to start legacy server
        'ipc_server.*listen'         # Description of legacy server listening
        'uses.*ipc_server'           # Current tense usage of legacy server
    )

    for pattern in "${patterns[@]}"; do
        # Only check AGENTS.md files (agent documentation) and README files
        local matches
        matches=$(rg -i --glob 'AGENTS.md' --glob 'README.md' -l "$pattern" crates/ 2>/dev/null || true)

        if [[ -n "$matches" ]]; then
            log_warn "Found potentially misleading legacy IPC documentation:"
            log_warn "Pattern: $pattern"
            rg -i --glob 'AGENTS.md' --glob 'README.md' -n "$pattern" crates/ 2>/dev/null | while read -r line; do
                log_warn "  $line"
            done
            # This is a warning, not a hard failure - documentation may legitimately
            # mention legacy patterns in historical context
        fi
    done
}

# Main execution
main() {
    log_info "=== Legacy IPC Guard (TCK-00282) ==="
    log_info "Checking for legacy JSON IPC reintroduction..."
    echo

    check_dependencies

    check_ipc_server_references
    check_core_ipc_references
    check_legacy_socket_config
    check_docs_for_misleading_legacy_refs

    echo
    if [[ $VIOLATIONS_FOUND -eq 1 ]]; then
        log_error "=== FAILED: Legacy IPC patterns detected ==="
        log_error ""
        log_error "Per DD-009 (RFC-0017), the daemon uses ProtocolServer-only"
        log_error "control plane. Legacy JSON IPC was removed in TCK-00281."
        log_error ""
        log_error "Please remove the legacy IPC references to proceed."
        exit 1
    else
        log_info "=== PASSED: No legacy IPC patterns detected ==="
        exit 0
    fi
}

main "$@"

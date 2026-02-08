#!/usr/bin/env bash
# Failure-injection fixtures for TCK-00410 CI guardrails.
#
# Validates:
# - test_safety_guard.sh blocks dangerous signatures and honors allowlist
# - workspace_integrity_guard.sh detects tracked-content mutation
# - run_bounded_tests.sh terminates hung commands via timeout watchdog

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    NC=''
fi

FAILURES=0

log_pass() { echo -e "${GREEN}PASS:${NC} $*"; }
log_fail() { echo -e "${RED}FAIL:${NC} $*" >&2; FAILURES=$((FAILURES + 1)); }

expect_fail() {
    set +e
    "$@"
    local status=$?
    set -e
    if [[ ${status} -eq 0 ]]; then
        return 1
    fi
    return 0
}

echo "=== Guardrail Failure-Injection Fixtures (TCK-00410) ==="
echo

# ---------------------------------------------------------------------------
# Test 1: test_safety_guard dangerous pattern blocking + allowlist
# ---------------------------------------------------------------------------
echo "Test 1: test_safety_guard.sh"
tmp_dir="$(mktemp -d)"
cat > "${tmp_dir}/dangerous_test.sh" <<'EOF'
#!/usr/bin/env bash
rm -rf /
EOF
chmod +x "${tmp_dir}/dangerous_test.sh"

touch "${tmp_dir}/allowlist.txt"

if expect_fail "${REPO_ROOT}/scripts/ci/test_safety_guard.sh" \
    --allowlist "${tmp_dir}/allowlist.txt" \
    "${tmp_dir}"; then
    log_pass "dangerous signature correctly blocked"
else
    log_fail "dangerous signature was not blocked"
fi

cat > "${tmp_dir}/allowlist.txt" <<EOF
TSG001|${tmp_dir}/dangerous_test.sh:2
EOF

if "${REPO_ROOT}/scripts/ci/test_safety_guard.sh" \
    --allowlist "${tmp_dir}/allowlist.txt" \
    "${tmp_dir}" >/dev/null 2>&1; then
    log_pass "allowlist entry correctly suppresses approved violation"
else
    log_fail "allowlisted violation was not suppressed"
fi
rm -rf "${tmp_dir}"
echo

# ---------------------------------------------------------------------------
# Test 1b: test_safety_guard multiline Rust pattern blocking
# ---------------------------------------------------------------------------
echo "Test 1b: test_safety_guard.sh multiline detection"
tmp_ml="$(mktemp -d)"
cat > "${tmp_ml}/multiline_test.rs" <<'RUSTEOF'
fn sneaky() {
    Command::new("sh")
        .arg("-c")
        .arg("whoami");
}
RUSTEOF

touch "${tmp_ml}/allowlist.txt"

if expect_fail "${REPO_ROOT}/scripts/ci/test_safety_guard.sh" \
    --allowlist "${tmp_ml}/allowlist.txt" \
    "${tmp_ml}"; then
    log_pass "multiline Command::new(sh).arg(-c) correctly blocked"
else
    log_fail "multiline Command::new(sh).arg(-c) was not blocked"
fi
rm -rf "${tmp_ml}"

# ---------------------------------------------------------------------------
# Test 1c: test_safety_guard quoted-path variant blocking
# ---------------------------------------------------------------------------
echo "Test 1c: test_safety_guard.sh quoted path detection"
tmp_q="$(mktemp -d)"
cat > "${tmp_q}/quoted_test.sh" <<'QUOTEOF'
#!/usr/bin/env bash
rm -rf "/"
QUOTEOF
chmod +x "${tmp_q}/quoted_test.sh"

touch "${tmp_q}/allowlist.txt"

if expect_fail "${REPO_ROOT}/scripts/ci/test_safety_guard.sh" \
    --allowlist "${tmp_q}/allowlist.txt" \
    "${tmp_q}"; then
    log_pass "quoted root path rm -rf correctly blocked"
else
    log_fail "quoted root path rm -rf was not blocked"
fi
rm -rf "${tmp_q}"
echo

# ---------------------------------------------------------------------------
# Test 2: workspace_integrity_guard mutation detection
# ---------------------------------------------------------------------------
echo "Test 2: workspace_integrity_guard.sh"
workspace_repo="$(mktemp -d)"
(
    cd "${workspace_repo}"
    git init -q
    printf 'seed\n' > tracked.txt
    git add tracked.txt
)

if "${REPO_ROOT}/scripts/ci/workspace_integrity_guard.sh" \
    --repo-root "${workspace_repo}" \
    --snapshot-file "${workspace_repo}/snapshot.tsv" \
    -- bash -lc "true" >/dev/null 2>&1; then
    log_pass "no-op guarded command preserves tracked workspace"
else
    log_fail "no-op guarded command unexpectedly failed"
fi

if expect_fail "${REPO_ROOT}/scripts/ci/workspace_integrity_guard.sh" \
    --repo-root "${workspace_repo}" \
    --snapshot-file "${workspace_repo}/snapshot.tsv" \
    -- bash -lc "echo mutation >> '${workspace_repo}/tracked.txt'"; then
    log_pass "tracked file mutation correctly detected"
else
    log_fail "tracked file mutation was not detected"
fi
rm -rf "${workspace_repo}"
echo

# ---------------------------------------------------------------------------
# Test 3: run_bounded_tests timeout watchdog behavior
# ---------------------------------------------------------------------------
echo "Test 3: run_bounded_tests.sh"
if expect_fail env APM2_CI_ALLOW_TIMEOUT_FALLBACK=1 \
    "${REPO_ROOT}/scripts/ci/run_bounded_tests.sh" \
    --timeout-seconds 1 \
    --kill-after-seconds 1 \
    -- bash -lc "sleep 3"; then
    log_pass "hung command terminated by watchdog timeout"
else
    log_fail "hung command was not terminated by watchdog timeout"
fi

if env APM2_CI_ALLOW_TIMEOUT_FALLBACK=1 \
    "${REPO_ROOT}/scripts/ci/run_bounded_tests.sh" \
    --timeout-seconds 5 \
    --kill-after-seconds 1 \
    -- bash -lc "echo ok" >/dev/null 2>&1; then
    log_pass "bounded runner allows command completion within limits"
else
    log_fail "bounded runner failed a command that should pass"
fi
echo

if [[ ${FAILURES} -gt 0 ]]; then
    echo -e "${RED}Guardrail fixture tests failed: ${FAILURES}${NC}" >&2
    exit 1
fi

echo -e "${GREEN}All guardrail fixture tests passed.${NC}"
exit 0

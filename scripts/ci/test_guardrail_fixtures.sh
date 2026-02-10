#!/usr/bin/env bash
# Failure-injection fixtures for TCK-00410 CI guardrails.
#
# Validates:
# - test_safety_guard.sh blocks dangerous signatures and honors allowlist
# - workspace_integrity_guard.sh detects tracked-content mutation
# - run_bounded_tests.sh terminates hung commands via timeout watchdog
# - fac_preflight_authorization.sh enforces trusted FAC workflow policy
# - credential_hardening.sh enforces PAT-free, argv-safe credential posture

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

# ---------------------------------------------------------------------------
# Test 4: check_runtime_closure waiver binding hardening
# ---------------------------------------------------------------------------
echo "Test 4: check_runtime_closure.sh waiver bindings"
runtime_repo="$(mktemp -d)"
waiver_file="${runtime_repo}/documents/work/waivers/WVR-9999.yaml"

(
    cd "${runtime_repo}"
    git init -q
    git config user.email "guardrail-fixtures@example.invalid"
    git config user.name "Guardrail Fixtures"

    mkdir -p \
        documents/reviews \
        documents/work/waivers \
        crates/apm2-core/src/fac \
        crates/apm2-daemon/src/protocol

    cat > documents/reviews/RUNTIME_CLOSURE_CHECKLIST.json <<'JSON'
{
  "schema": "apm2.runtime_closure_checklist.v1",
  "schema_version": "1.0.0",
  "gate_id": "GATE-RUNTIME-CLOSURE-TCK-00406",
  "security_modules": [
    {
      "path": "crates/apm2-core/src/fac/taint.rs",
      "required_production_callsites": [
        "crates/apm2-daemon/src/protocol/session_dispatch.rs"
      ]
    }
  ],
  "waiver": {
    "directory": "documents/work/waivers"
  }
}
JSON

    printf 'baseline\n' > crates/apm2-core/src/fac/taint.rs
    printf 'baseline callsite\n' > crates/apm2-daemon/src/protocol/session_dispatch.rs

    git add documents/reviews/RUNTIME_CLOSURE_CHECKLIST.json \
        crates/apm2-core/src/fac/taint.rs \
        crates/apm2-daemon/src/protocol/session_dispatch.rs
    git commit -q -m "base fixture"

    printf 'changed\n' >> crates/apm2-core/src/fac/taint.rs
    git add crates/apm2-core/src/fac/taint.rs
    git commit -q -m "security module change"
)

runtime_head_sha="$(git -C "${runtime_repo}" rev-parse HEAD)"
runtime_parent_sha="$(git -C "${runtime_repo}" rev-parse HEAD~1)"
runtime_base_ref="${runtime_parent_sha}"

run_runtime_closure_check() {
    local reviewed_sha="${1:-${runtime_head_sha}}"
    (
        cd "${runtime_repo}"
        env \
            APM2_DIFF_BASE="${runtime_base_ref}" \
            APM2_REVIEW_HEAD_SHA="${reviewed_sha}" \
            APM2_PR_NUMBER="569" \
            APM2_PR_CATEGORY="SECURITY" \
            APM2_SECURITY_QCP="YES" \
            "${REPO_ROOT}/scripts/ci/check_runtime_closure.sh"
    )
}

write_runtime_waiver() {
    local commit_sha="$1"
    local pr_number="$2"
    local category="$3"
    local include_commit="$4"
    cat > "${waiver_file}" <<EOF
waiver:
  id: WVR-9999
  status: ACTIVE
  expires: "2099-12-31"
  scope:
    gate_ids:
      - "GATE-RUNTIME-CLOSURE-TCK-00406"
  references:
EOF
    if [[ "${include_commit}" == "yes" ]]; then
        cat >> "${waiver_file}" <<EOF
    commit_sha: "${commit_sha}"
EOF
    fi
    cat >> "${waiver_file}" <<EOF
    pr_number: ${pr_number}
    category: "${category}"
EOF
}

write_runtime_waiver "${runtime_head_sha}" 569 "SECURITY" "no"
if expect_fail run_runtime_closure_check; then
    log_pass "waiver missing references.commit_sha is rejected"
else
    log_fail "waiver without commit_sha unexpectedly passed"
fi

write_runtime_waiver "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" 569 "SECURITY" "yes"
if expect_fail run_runtime_closure_check; then
    log_pass "waiver with mismatched commit_sha is rejected"
else
    log_fail "waiver with mismatched commit_sha unexpectedly passed"
fi

write_runtime_waiver "${runtime_head_sha}" 999 "SECURITY" "yes"
if expect_fail run_runtime_closure_check; then
    log_pass "waiver with mismatched PR number is rejected"
else
    log_fail "waiver with mismatched PR number unexpectedly passed"
fi

write_runtime_waiver "${runtime_head_sha}" 569 "NON_MATCHING_CATEGORY" "yes"
if expect_fail run_runtime_closure_check; then
    log_pass "waiver with mismatched category is rejected"
else
    log_fail "waiver with mismatched category unexpectedly passed"
fi

write_runtime_waiver "${runtime_parent_sha}" 569 "SECURITY" "yes"
if expect_fail run_runtime_closure_check; then
    log_pass "parent-SHA waiver with non-waiver reviewed HEAD commit is rejected"
else
    log_fail "parent-SHA waiver with non-waiver reviewed HEAD commit unexpectedly passed"
fi

write_runtime_waiver "${runtime_head_sha}" 569 "SECURITY" "yes"
if run_runtime_closure_check >/dev/null 2>&1; then
    log_pass "waiver bound to reviewed HEAD commit is accepted"
else
    log_fail "waiver bound to reviewed HEAD commit was rejected"
fi

runtime_waiver_only_parent_sha="${runtime_head_sha}"
(
    cd "${runtime_repo}"
    printf 'waiver-only fixture commit\n' > documents/work/waivers/fixture-note.txt
    git add documents/work/waivers/fixture-note.txt
    git commit -q -m "waiver-only head commit"
)
runtime_waiver_only_head_sha="$(git -C "${runtime_repo}" rev-parse HEAD)"

write_runtime_waiver "${runtime_waiver_only_parent_sha}" 569 "SECURITY" "yes"
if run_runtime_closure_check "${runtime_waiver_only_head_sha}" >/dev/null 2>&1; then
    log_pass "parent-SHA waiver with waiver-only reviewed HEAD commit is accepted"
else
    log_fail "parent-SHA waiver with waiver-only reviewed HEAD commit was rejected"
fi

rm -rf "${runtime_repo}"
echo

# ---------------------------------------------------------------------------
# Test 5: FAC preflight authorization policy regression fixtures
# ---------------------------------------------------------------------------
echo "Test 5: fac_preflight_authorization.sh"
if "${REPO_ROOT}/scripts/ci/test_fac_preflight_fixtures.sh"; then
    log_pass "FAC preflight policy fixtures passed"
else
    log_fail "FAC preflight policy fixtures failed"
fi
echo

# ---------------------------------------------------------------------------
# Test 6: FAC credential hardening regression fixtures
# ---------------------------------------------------------------------------
echo "Test 6: credential_hardening.sh"
if "${REPO_ROOT}/scripts/ci/test_credential_hardening_fixtures.sh"; then
    log_pass "Credential hardening fixtures passed"
else
    log_fail "Credential hardening fixtures failed"
fi
echo

if [[ ${FAILURES} -gt 0 ]]; then
    echo -e "${RED}Guardrail fixture tests failed: ${FAILURES}${NC}" >&2
    exit 1
fi

echo -e "${GREEN}All guardrail fixture tests passed.${NC}"
exit 0

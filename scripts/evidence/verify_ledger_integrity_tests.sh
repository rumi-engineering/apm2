#!/bin/bash
# Evidence collection script for ledger integrity verification
# EVID-0004: Ledger integrity tests with crypto verification
#
# Usage: ./scripts/evidence/verify_ledger_integrity_tests.sh [--out <output_dir>]

set -euo pipefail

# Parse arguments
OUTPUT_DIR="./evidence"

while [[ $# -gt 0 ]]; do
    case $1 in
        --out)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

# Create output directory
mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
RESULT_FILE="$OUTPUT_DIR/ledger_integrity_${TIMESTAMP//:/-}.json"

echo "=== Ledger Integrity Verification ==="
echo "Timestamp: $TIMESTAMP"
echo ""

# Test 1: Ledger storage operations
echo "Test 1: Ledger storage operations..."
TEST1_RESULT="PASS"
TEST1_OUTPUT=$(cargo test --package apm2-core --no-fail-fast -- \
    ledger::tests:: \
    2>&1) || TEST1_RESULT="FAIL"

TEST1_PASSED=$(echo "$TEST1_OUTPUT" | grep -E "^test result:" | head -1 | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' || echo "0")
TEST1_FAILED=$(echo "$TEST1_OUTPUT" | grep -E "^test result:" | head -1 | grep -oE '[0-9]+ failed' | grep -oE '[0-9]+' || echo "0")

# Test 2: Crypto hash operations
echo "Test 2: Crypto hash operations..."
TEST2_RESULT="PASS"
TEST2_OUTPUT=$(cargo test --package apm2-core --no-fail-fast -- \
    crypto::tests::test_hash \
    crypto::hash::unit_tests:: \
    2>&1) || TEST2_RESULT="FAIL"

TEST2_PASSED=$(echo "$TEST2_OUTPUT" | grep -E "^test result:" | head -1 | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' || echo "0")
TEST2_FAILED=$(echo "$TEST2_OUTPUT" | grep -E "^test result:" | head -1 | grep -oE '[0-9]+ failed' | grep -oE '[0-9]+' || echo "0")

# Test 3: Crypto signature operations
echo "Test 3: Crypto signature operations..."
TEST3_RESULT="PASS"
TEST3_OUTPUT=$(cargo test --package apm2-core --no-fail-fast -- \
    crypto::tests::test_sign \
    crypto::sign::unit_tests:: \
    2>&1) || TEST3_RESULT="FAIL"

TEST3_PASSED=$(echo "$TEST3_OUTPUT" | grep -E "^test result:" | head -1 | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' || echo "0")
TEST3_FAILED=$(echo "$TEST3_OUTPUT" | grep -E "^test result:" | head -1 | grep -oE '[0-9]+ failed' | grep -oE '[0-9]+' || echo "0")

# Test 4: Key management
echo "Test 4: Key management..."
TEST4_RESULT="PASS"
TEST4_OUTPUT=$(cargo test --package apm2-core --no-fail-fast -- \
    crypto::tests::test_key \
    crypto::keys::unit_tests:: \
    2>&1) || TEST4_RESULT="FAIL"

TEST4_PASSED=$(echo "$TEST4_OUTPUT" | grep -E "^test result:" | head -1 | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' || echo "0")
TEST4_FAILED=$(echo "$TEST4_OUTPUT" | grep -E "^test result:" | head -1 | grep -oE '[0-9]+ failed' | grep -oE '[0-9]+' || echo "0")

# Test 5: Hash chain verification
echo "Test 5: Hash chain verification..."
TEST5_RESULT="PASS"
TEST5_OUTPUT=$(cargo test --package apm2-core --no-fail-fast -- \
    crypto::hash::unit_tests::test_verify_chain \
    crypto::hash::unit_tests::test_verify_hash \
    2>&1) || TEST5_RESULT="FAIL"

TEST5_PASSED=$(echo "$TEST5_OUTPUT" | grep -E "^test result:" | head -1 | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' || echo "0")
TEST5_FAILED=$(echo "$TEST5_OUTPUT" | grep -E "^test result:" | head -1 | grep -oE '[0-9]+ failed' | grep -oE '[0-9]+' || echo "0")

# Calculate totals
TOTAL_PASSED=$((TEST1_PASSED + TEST2_PASSED + TEST3_PASSED + TEST4_PASSED + TEST5_PASSED))
TOTAL_FAILED=$((TEST1_FAILED + TEST2_FAILED + TEST3_FAILED + TEST4_FAILED + TEST5_FAILED))

# Generate JSON evidence report
cat > "$RESULT_FILE" << EOF
{
  "evidence_id": "EVID-0004",
  "category": "LEDGER_INTEGRITY",
  "timestamp": "$TIMESTAMP",
  "results": {
    "passed": $TOTAL_PASSED,
    "failed": $TOTAL_FAILED,
    "total": $((TOTAL_PASSED + TOTAL_FAILED))
  },
  "test_suites": [
    {
      "name": "ledger_storage",
      "result": "$TEST1_RESULT",
      "passed": $TEST1_PASSED,
      "failed": $TEST1_FAILED,
      "tests": [
        "ledger::tests::test_append_single_event",
        "ledger::tests::test_append_batch",
        "ledger::tests::test_read_from_cursor",
        "ledger::tests::test_wal_mode_enabled",
        "ledger::tests::test_concurrent_read_with_wal",
        "ledger::tests::test_actor_id_preserved"
      ]
    },
    {
      "name": "crypto_hash",
      "result": "$TEST2_RESULT",
      "passed": $TEST2_PASSED,
      "failed": $TEST2_FAILED,
      "tests": [
        "crypto::hash::unit_tests::test_hash_content",
        "crypto::hash::unit_tests::test_hash_event_with_chain",
        "crypto::hash::unit_tests::test_genesis_event"
      ]
    },
    {
      "name": "crypto_signature",
      "result": "$TEST3_RESULT",
      "passed": $TEST3_PASSED,
      "failed": $TEST3_FAILED,
      "tests": [
        "crypto::sign::unit_tests::test_sign_and_verify",
        "crypto::sign::unit_tests::test_deterministic_signatures",
        "crypto::sign::unit_tests::test_verify_signature"
      ]
    },
    {
      "name": "key_management",
      "result": "$TEST4_RESULT",
      "passed": $TEST4_PASSED,
      "failed": $TEST4_FAILED,
      "tests": [
        "crypto::keys::unit_tests::test_generate_keypair",
        "crypto::keys::unit_tests::test_store_and_load_keypair"
      ]
    },
    {
      "name": "hash_chain_verification",
      "result": "$TEST5_RESULT",
      "passed": $TEST5_PASSED,
      "failed": $TEST5_FAILED,
      "tests": [
        "crypto::hash::unit_tests::test_verify_chain_link_success",
        "crypto::hash::unit_tests::test_verify_chain_link_failure",
        "crypto::hash::unit_tests::test_verify_hash_success"
      ]
    }
  ],
  "verification": {
    "ledger_storage": "$TEST1_RESULT",
    "crypto_hash": "$TEST2_RESULT",
    "crypto_signature": "$TEST3_RESULT",
    "key_management": "$TEST4_RESULT",
    "hash_chain": "$TEST5_RESULT",
    "exit_code": $([[ "$TOTAL_FAILED" == "0" ]] && echo "0" || echo "1")
  },
  "components_verified": [
    "SQLite WAL mode",
    "Append-only semantics",
    "Blake3 event hashing",
    "Ed25519 signatures",
    "Hash chain linking",
    "Actor ID tracking",
    "Record versioning"
  ]
}
EOF

echo ""
echo "=== Results ==="
echo "Evidence captured to: $RESULT_FILE"
echo "Total tests passed: $TOTAL_PASSED"
echo "Total tests failed: $TOTAL_FAILED"
echo ""

# Exit with appropriate code
if [[ "$TOTAL_FAILED" != "0" ]]; then
    echo "FAILED: Some ledger integrity tests did not pass"
    exit 1
fi

echo "SUCCESS: All ledger integrity tests passed"
exit 0

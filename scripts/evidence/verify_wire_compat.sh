#!/bin/bash
# Evidence collection script for wire compatibility verification
# EVID-0008: Wire format compatibility tests
#
# Usage: ./scripts/evidence/verify_wire_compat.sh [--schema <version>] [--compat_window <n>]

set -euo pipefail

# Parse arguments
SCHEMA_VERSION="v1"
COMPAT_WINDOW="2"
OUTPUT_DIR="./evidence"

while [[ $# -gt 0 ]]; do
    case $1 in
        --schema)
            SCHEMA_VERSION="$2"
            shift 2
            ;;
        --compat_window)
            COMPAT_WINDOW="$2"
            shift 2
            ;;
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
RESULT_FILE="$OUTPUT_DIR/wire_compat_${SCHEMA_VERSION}_${TIMESTAMP//:/-}.json"

echo "=== Wire Compatibility Verification ==="
echo "Schema version: $SCHEMA_VERSION"
echo "Compatibility window: $COMPAT_WINDOW versions"
echo "Timestamp: $TIMESTAMP"
echo ""

# Test 1: Canonical encoding produces deterministic bytes
echo "Test 1: Canonical encoding determinism..."
TEST1_RESULT="PASS"
TEST1_OUTPUT=$(cargo test --package apm2-core --no-fail-fast -- \
    events::tests::test_canonical_encoding_deterministic \
    events::canonical::tests:: \
    2>&1) || TEST1_RESULT="FAIL"

TEST1_PASSED=$(echo "$TEST1_OUTPUT" | grep -E "^test result:" | head -1 | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' || echo "0")
TEST1_FAILED=$(echo "$TEST1_OUTPUT" | grep -E "^test result:" | head -1 | grep -oE '[0-9]+ failed' | grep -oE '[0-9]+' || echo "0")

# Test 2: Repeated fields ordering (sorted before signing)
echo "Test 2: Repeated fields ordering..."
TEST2_RESULT="PASS"
TEST2_OUTPUT=$(cargo test --package apm2-core --no-fail-fast -- \
    events::tests::test_repeated_fields_ordering \
    2>&1) || TEST2_RESULT="FAIL"

TEST2_PASSED=$(echo "$TEST2_OUTPUT" | grep -E "^test result:" | head -1 | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' || echo "0")
TEST2_FAILED=$(echo "$TEST2_OUTPUT" | grep -E "^test result:" | head -1 | grep -oE '[0-9]+ failed' | grep -oE '[0-9]+' || echo "0")

# Test 3: All event types roundtrip correctly
echo "Test 3: Event roundtrip encoding..."
TEST3_RESULT="PASS"
TEST3_OUTPUT=$(cargo test --package apm2-core --no-fail-fast -- \
    events::tests::test_session_started_roundtrip \
    events::tests::test_work_opened_roundtrip \
    events::tests::test_tool_requested_roundtrip \
    events::tests::test_lease_issued_roundtrip \
    events::tests::test_policy_violation_roundtrip \
    events::tests::test_adjudication_requested_roundtrip \
    events::tests::test_evidence_published_roundtrip \
    2>&1) || TEST3_RESULT="FAIL"

TEST3_PASSED=$(echo "$TEST3_OUTPUT" | grep -E "^test result:" | head -1 | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' || echo "0")
TEST3_FAILED=$(echo "$TEST3_OUTPUT" | grep -E "^test result:" | head -1 | grep -oE '[0-9]+ failed' | grep -oE '[0-9]+' || echo "0")

# Calculate totals
TOTAL_PASSED=$((TEST1_PASSED + TEST2_PASSED + TEST3_PASSED))
TOTAL_FAILED=$((TEST1_FAILED + TEST2_FAILED + TEST3_FAILED))

# Generate JSON evidence report
cat > "$RESULT_FILE" << EOF
{
  "evidence_id": "EVID-0008",
  "category": "WIRE_COMPATIBILITY",
  "schema_version": "$SCHEMA_VERSION",
  "compat_window": $COMPAT_WINDOW,
  "timestamp": "$TIMESTAMP",
  "results": {
    "passed": $TOTAL_PASSED,
    "failed": $TOTAL_FAILED,
    "total": $((TOTAL_PASSED + TOTAL_FAILED))
  },
  "test_suites": [
    {
      "name": "canonical_encoding_determinism",
      "result": "$TEST1_RESULT",
      "passed": $TEST1_PASSED,
      "failed": $TEST1_FAILED
    },
    {
      "name": "repeated_fields_ordering",
      "result": "$TEST2_RESULT",
      "passed": $TEST2_PASSED,
      "failed": $TEST2_FAILED
    },
    {
      "name": "event_roundtrip_encoding",
      "result": "$TEST3_RESULT",
      "passed": $TEST3_PASSED,
      "failed": $TEST3_FAILED
    }
  ],
  "verification": {
    "canonical_encoding": "$TEST1_RESULT",
    "field_ordering": "$TEST2_RESULT",
    "roundtrip_encoding": "$TEST3_RESULT",
    "exit_code": $([[ "$TOTAL_FAILED" == "0" ]] && echo "0" || echo "1")
  }
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
    echo "FAILED: Some wire compatibility tests did not pass"
    exit 1
fi

echo "SUCCESS: All wire compatibility tests passed"
exit 0

# Fix Task: PR #594 (TCK-00465) — Round 4

Branch: `ticket/RFC-0028/TCK-00465`, HEAD: `30964391`
Quality: PASS. Security: FAIL — 2 MAJORs.

## MAJOR 1: Declassification receipts replayable across requests

**Paths:**
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2330`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2422`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2442`

**Problem:** Receipt resolution accepts a receipt matching `receipt_id`, `lease_id`, `work_id` but doesn't bind to the current request. Any request under the same lease/work can reuse the same receipt.

**Required Fix:**
1. Bind redundancy receipts to request-scoped material: add `request_id` and `tool_class` to the receipt lookup/validation
2. When resolving a declassification receipt, verify that the receipt's `request_id` matches the current request (or that the receipt has not been consumed)
3. Implement single-use semantics: after a receipt is used for one request, mark it as consumed
4. Add test: same receipt used for a second request → DENY

## MAJOR 2: Missing boundary-flow hints use permissive defaults

**Paths:**
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2394`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2476`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2514`

**Problem:** For non-sandbox tiers, absent boundary_flow hints generate defaults with `leakage_bits=0`, `observed_variance_ticks=0`. These pass validation.

**Required Fix:**
1. For boundary-enforced tool classes, absent boundary_flow hints MUST result in fail-closed DENY
2. Set `leakage_bits` and `observed_variance_ticks` to MAX (most restrictive) instead of 0 when hints are missing
3. Add a test: missing boundary_flow hints on a boundary-enforced tool class → DENY with structured defect

## Pre-Commit Steps
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo test -p apm2-core -p apm2-daemon
```

## Push
```bash
git add -A && git commit -m "fix(TCK-00465): request-scoped receipts and fail-closed missing hints" && apm2 fac push --ticket documents/work/tickets/TCK-00465.yaml
```

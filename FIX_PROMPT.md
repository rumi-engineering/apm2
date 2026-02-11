# Fix Task: PR #594 (TCK-00465) — Review Round 1

## Context
You are fixing review findings for PR #594 (TCK-00465: RFC-0028 REQ-0004 boundary-flow integrity and declassification receipt enforcement).

Branch: `ticket/RFC-0028/TCK-00465`
Worktree: `/home/ubuntu/Projects/apm2-TCK-00465`
Current HEAD: `71ec4bbe`

## Review Results
- **Security Review: PASS** (1 MINOR, 1 NIT — see below for completeness)
- **Code Quality Review: FAIL** — 2 BLOCKERs, 1 MAJOR

## BLOCKER 1: Declassification receipt authority sourced from untrusted request payload

**Paths:**
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2066`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2215`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2222`
- `crates/apm2-core/src/channel/enforcement.rs:729`

**Problem:** A caller can self-assert `boundary_flow.declassification` and make downgrade claims appear valid without authoritative receipt admission. Confidentiality downgrade can be admitted via forged receipt fields, violating REQ-0004 and RFC-0028 receipt-bound boundary policy.

**Required Fix:**
1. Derive declassification receipt validity from signed/admitted receipt artifacts (ledger/CAS/policy authority), NOT raw `RequestToolRequest.arguments`
2. Treat request payload as claim-only input — it MUST be validated against authoritative state
3. If no authoritative receipt can be located for the claimed declassification, fail-closed (deny)
4. The key insight: the boundary flow hints from the client request are **claims**, not **evidence**. Evidence must come from the system's own authoritative state (signed receipts in ledger/CAS)

## BLOCKER 2: Leakage/timing budget ceilings are caller-controlled via untrusted hints

**Paths:**
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2253`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2274`
- `crates/apm2-core/src/channel/enforcement.rs:789`
- `crates/apm2-core/src/channel/enforcement.rs:817`

**Problem:** A caller can inflate `budget_bits` / `budget_ticks` to suppress overrun detection and avoid quarantine, breaking `L_boundary <= L_boundary_max(risk_tier)` intent.

**Required Fix:**
1. Define maximum admissible budgets as policy constants derived from risk tier
2. Enforce `budget_bits <= MAX_LEAKAGE_BITS_PER_RISK_TIER[tier]` and `budget_ticks <= MAX_TIMING_TICKS_PER_RISK_TIER[tier]`
3. Use the MINIMUM of the client-claimed budget and the policy-maximum budget
4. Reject any receipt whose declared budgets exceed policy ceilings
5. Add fail-closed default: if risk tier cannot be determined, use the most restrictive budget

## MAJOR: Missing adversarial regression tests for forged receipt/budget inflation

**Paths:**
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:6746`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:6904`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:7058`

**Required Fix:**
1. Add negative integration test: client-supplied `boundary_flow` includes forged redundancy receipt fields → assert fail-closed denial
2. Add negative integration test: client-supplied `boundary_flow` includes inflated leakage budget (e.g. budget_bits=999999) → assert budget clamped to policy max and overrun detected
3. Add negative integration test: client-supplied `boundary_flow` includes inflated timing budget (e.g. budget_ticks=999999) → assert budget clamped to policy max and quarantine triggered

## Security Review MINOR (fix if straightforward)

**Unbounded Deserialization (DoS) in `extract_boundary_flow_hints`:**
- `crates/apm2-daemon/src/protocol/session_dispatch.rs`
- Deserializes `request_arguments` into `serde_json::Value` before extracting boundary flow hints
- Consider deserializing directly into `BoundaryFlowHints` struct instead of going through intermediate `Value`

**Legacy API Fail-Open (NIT):**
- Mark legacy `validate_channel_boundary_and_issue_context_token` as `#[deprecated]`

## MANDATORY Pre-Commit Steps (in this exact order)

You MUST run ALL of these and fix any issues BEFORE committing:
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo test -p apm2-core -p apm2-daemon
```

You MUST pass ALL CI checks. Do not push code that fails any of these.

## Push Workflow

After all pre-commit steps pass:
```bash
git add -A
git commit -m "fix(TCK-00465): authoritative receipt sourcing, policy-capped budgets, adversarial tests"
apm2 fac push --ticket documents/work/tickets/TCK-00465.yaml
```

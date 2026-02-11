# Fix Task: PR #594 (TCK-00465) — Round 7

Branch: `ticket/RFC-0028/TCK-00465`, HEAD: `c6f8da6f`
Quality: FAIL — 1 BLOCKER, 1 MINOR. Security: FAIL — 2 MAJORs, 1 MINOR.

## REQUIRED READING (before editing any code)

Read these files first:
- `documents/theory/glossary/glossary.json`
- `documents/security/AGENTS.cac.json`
- `documents/security/THREAT_MODEL.cac.json`
- `documents/skills/rust-standards/references/15_errors_panics_diagnostics.md`
- `documents/skills/rust-standards/references/34_security_adjacent_rust.md`
- `documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md`

## BLOCKER 1 (Quality): Missing hash chain regression test

**Path:** `crates/apm2-daemon/src/ledger.rs`

**Problem:** Hash chain logic (prev_hash, event_hash columns and chaining in emit_*) is implemented, but the tamper-detection test is absent.

**Required Fix:**
Add a test in `crates/apm2-daemon/src/ledger.rs` (test module) that:
1. Creates a `SqliteLedgerEventEmitter`
2. Emits a sequence of 3+ events using the emit methods
3. Calls `derive_event_chain_hash()` and verifies it succeeds
4. Manually modifies an intermediate row's payload or hash via raw SQLite SQL (`UPDATE ledger_events SET event_hash = 'tampered' WHERE rowid = 2`)
5. Calls `derive_event_chain_hash()` again and verifies it returns an `Err(...)` indicating chain break

## MINOR 1 (Quality): SHA-256 vs BLAKE3 documentation drift

**Path:** `crates/apm2-daemon/src/ledger.rs` vs `crates/apm2-core/src/ledger/AGENTS.md`

**Problem:** `compute_event_hash` uses SHA-256 but `AGENTS.md` says BLAKE3.

**Fix:** Update `AGENTS.md` to document that SQLite ledger uses SHA-256, or change implementation to BLAKE3 to match docs. Choose whichever is simpler — if changing to BLAKE3, use `blake3::hash()` and update the column values. If keeping SHA-256, update the doc string.

## MAJOR 1 (Security): Receipt ID uniqueness collision

**Paths:**
- `crates/apm2-daemon/src/ledger.rs:191` — `idx_unique_receipt_id`
- `crates/apm2-daemon/src/ledger.rs:1116` — `emit_redundancy_receipt_consumed`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2411` — `consume_redundancy_receipt`

**Problem:** `idx_unique_receipt_id` is global on `payload.receipt_id`. When `consume_redundancy_receipt` tries to `emit_redundancy_receipt_consumed`, it collides with the existing review receipt that already has the same `receipt_id`, so the insert fails and consumption is never recorded.

**Required Fix:**
1. Scope `idx_unique_receipt_id` to specific event types only (e.g., `CREATE UNIQUE INDEX idx_unique_receipt_id ON ledger_events(json_extract(payload, '$.receipt_id')) WHERE event_type = 'review_receipt_recorded'`)
2. OR namespace the receipt_id field differently for consumption events (e.g., use `consumed_receipt_id` in the consumption event payload)
3. Add a dedicated uniqueness constraint for consumption events: `CREATE UNIQUE INDEX idx_unique_receipt_consumed ON ledger_events(json_extract(payload, '$.receipt_id')) WHERE event_type = 'redundancy_receipt_consumed'`
4. Add integration test: emit a review_receipt_recorded event + emit a redundancy_receipt_consumed event for the same receipt_id → both succeed

## MAJOR 2 (Security): Strict boundary-flow enforcement denies all non-read tool classes

**Paths:**
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2069`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2319`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2596`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2635`

**Problem:** For boundary-enforced tools, strict mode is enabled but both authoritative resolvers return `None`. Fallback witnesses set `leakage_bits=u64::MAX` and `observed_variance_ticks=u64::MAX`, which always trip budget-exceeded checks, then quarantine the channel. This means ALL non-read tool classes are denied.

**Required Fix:**
1. Gate strict enforcement behind an explicit policy flag. When authoritative leakage/timing sources are NOT available, use monitor-only mode instead of strict enforcement.
2. In monitor-only mode: emit defect evidence (log warnings) about missing authoritative sources, but do NOT deny the request.
3. Add a positive-path test: a boundary-enforced tool class with monitor-only mode should succeed when authoritative witnesses are unavailable.
4. Strict mode should only activate when authoritative sources ARE available and return actual values.

## MINOR 2 (Security): Policy ledger verification is self-referential

**Path:** `crates/apm2-daemon/src/protocol/session_dispatch.rs:2106`, `:2113`

**Problem:** `resolve_authoritative_policy_root_digest` reads from broker state, not the ledger. `tool_decision_policy_verified` compares against the same source.

**Fix:** Add a comment documenting this as a known limitation pending ledger-rooted policy verification. Do NOT attempt to implement full ledger-rooted verification in this PR — it's a larger architectural change. Just document it clearly.

## CRITICAL PATTERNS

- **Fail-closed semantics**: Errors always DENY
- **Append-only ledger**: Never delete/update existing rows (only add new events)
- **Binding test evidence**: Tests must assert specific error messages, not just "error happened"

## Pre-Commit Steps (MANDATORY — do ALL of these)
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo test -p apm2-core -p apm2-daemon
```

You MUST pass ALL CI checks. Do NOT skip any step.

## Push
```bash
git add -A && git commit -m "fix(TCK-00465): hash chain test, scoped receipt uniqueness, monitor-only boundary mode" && apm2 fac push --ticket documents/work/tickets/TCK-00465.yaml
```

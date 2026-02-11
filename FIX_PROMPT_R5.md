# Fix Task: PR #594 (TCK-00465) — Round 6

Branch: `ticket/RFC-0028/TCK-00465`, HEAD: `ee18ff33`
Quality: PASS. Security: FAIL — 1 MAJOR, 1 MINOR, 1 NIT.

## REQUIRED READING (before editing any code)

Read these files first to understand the project context:
- `documents/theory/glossary/glossary.json`
- `documents/security/AGENTS.cac.json`
- `documents/security/THREAT_MODEL.cac.json`
- `documents/skills/rust-standards/references/15_errors_panics_diagnostics.md`
- `documents/skills/rust-standards/references/34_security_adjacent_rust.md`
- `documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md`

## MAJOR 1: Weak Ledger Anchor — Missing Hash Chaining in `SqliteLedgerEventEmitter`

**Paths:**
- `crates/apm2-daemon/src/protocol/session_dispatch.rs` — `derive_pcac_ledger_anchor` computes anchor from latest event's metadata+signature only
- `crates/apm2-daemon/src/ledger.rs` — `SqliteLedgerEventEmitter` — no `prev_hash` or `event_hash` columns

**Problem:** The production `SqliteLedgerEventEmitter` does not implement hash-chaining. It does not store `prev_hash` or `event_hash` in the `ledger_events` table, and the signed payload does not include a reference to the previous event's hash. An attacker with database access can replace or reorder ledger history without invalidating the latest event's signature.

**Required Fix:**
1. Add `prev_hash TEXT NOT NULL` and `event_hash TEXT NOT NULL` columns to the `ledger_events` table schema in `SqliteLedgerEventEmitter`
2. In each `emit_*` method:
   a. Query the `event_hash` of the most recent event (or use a sentinel value like `"genesis"` for the first event)
   b. Include `prev_hash` in the JCS payload that gets signed
   c. Compute `event_hash = SHA-256(signed_payload)` (or similar)
   d. Store both `prev_hash` and `event_hash` in the row
3. Update `derive_pcac_ledger_anchor` to include the chain hash, not just the last event's metadata
4. Add a regression test: insert events, verify the chain is valid, tamper with an intermediate event, verify re-derivation detects the break

## MINOR 1: In-Memory Single-Use Tracking for Redundancy Receipts

**Problem:** `consumed_redundancy_receipts` in `SessionDispatcher` is in-memory only. Consumption state is lost on daemon restart, allowing receipt reuse.

**Required Fix:**
1. Persist receipt consumption to the ledger: when a redundancy receipt is consumed, emit a ledger event (e.g., `ReceiptConsumed`) with the receipt ID
2. On receipt validation, check the ledger for prior consumption events — not just the in-memory map
3. The in-memory map can remain as a fast-path cache, but the authoritative check must be the ledger
4. Add test: consume receipt → restart (clear in-memory state) → attempt reuse → DENY

## NIT 1: Double Parsing in `extract_boundary_flow_hints`

**Problem:** `extract_boundary_flow_hints` parses `request_arguments` twice.

**Fix:** Combine into a single parse pass. Deserialize once to a `serde_json::Value`, then extract both hint types from the same parsed value.

## CRITICAL PATTERNS

- **Fail-closed semantics**: Hash chain validation failures → DENY, never skip
- **Append-only ledger**: New columns are additive, never delete existing columns or data
- **Binding test evidence**: Tests must verify specific hash values chain correctly and detect tampering
- **HTF timestamps**: Use HTF timestamps in event emission, never `SystemTime::now`

## Pre-Commit Steps (MANDATORY — do ALL of these)
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo test -p apm2-core -p apm2-daemon
```

You MUST pass ALL CI checks. Do NOT skip any pre-commit step.

## Push
```bash
git add -A && git commit -m "fix(TCK-00465): hash-chained ledger events and persistent receipt consumption" && apm2 fac push --ticket documents/work/tickets/TCK-00465.yaml
```

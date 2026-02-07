# TCK-00398 Phase 2 Canonical Ledger Unification Plan

## Goal
Converge daemon write-path and core/CLI read-path on the canonical `events` table, then retire compatibility bridging without data loss.

## Target Canonical Shape
- Canonical table: `events` in `crates/apm2-core/src/ledger/schema.sql`
- Daemon writes must populate:
  - `event_type`, `session_id`, `actor_id`, `record_version`, `payload`, `timestamp_ns`, `signature`
- Hash-chain fields:
  - `prev_hash`, `event_hash` stay nullable during migration window
  - Once daemon hash chaining is enabled, write-path must set both fields
- Consensus fields remain nullable and untouched in this ticket lineage.

## Cutover Strategy
1. Add dual-write in daemon for a bounded window:
   - Continue writing `ledger_events`
   - Also write canonical `events` rows in the same transaction boundary
2. Backfill historical `ledger_events` rows to `events` with deterministic ordering:
   - Source order: `ORDER BY rowid ASC`
   - Mapping: `work_id -> session_id`, `record_version = 1`, `event_hash = NULL`, `prev_hash = NULL`
3. Add parity checks:
   - Row-count parity by event_type/work slice
   - Spot-check payload/signature byte equality
4. Flip reads to canonical-only after parity reaches zero drift.
5. Remove dual-write, keep `ledger_events` as read-only backup for one release window.

## Rollback Plan
- If parity or integrity checks fail, keep read mode on compatibility path and continue dual-write.
- Do not drop `ledger_events` during rollback.
- Preserve all migration receipts/logs to support replay and forensic diffing.

## Exit Criteria
- Daemon writes only canonical `events`.
- CLI commands (`work status`, `episode inspect`, `resume`) pass against canonical-only data.
- No compatibility read path usage observed over one full release cycle.
- `ledger_events` deprecation approved by RFC/ticket governance update.

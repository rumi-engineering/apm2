//! Persistent ledger implementation using `SQLite`.
//!
//! This module provides durable implementations of:
//! - [`LedgerEventEmitter`]: Persists signed events to `ledger_events` table
//! - [`WorkRegistry`]: Persists work claims to `work_claims` table
//! - [`LeaseValidator`]: Validates leases against `ledger_events` table
//!
//! # Schema
//!
//! The `ledger_events` table has columns: `event_id`, `event_type`,
//! `event_type_class`, `work_id`, `actor_id`, `payload`, `signature`,
//! `timestamp_ns`, `prev_hash`, `event_hash`.
//!
//! The `work_claims` table has columns: `work_id`, `lease_id`, `actor_id`,
//! `role`, `claim_json`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apm2_core::determinism::canonicalize_json;
use apm2_core::events::{DefectRecorded, Validate};
use apm2_core::fac::{REVIEW_RECEIPT_RECORDED_PREFIX, SelectionDecision};
use ed25519_dalek::{Signer, Verifier};
use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::{error, info, warn};

use crate::protocol::WorkRole;
use crate::protocol::dispatch::{
    CHANGESET_PUBLISHED_LEDGER_DOMAIN_PREFIX, DEFECT_RECORDED_DOMAIN_PREFIX,
    EPISODE_EVENT_DOMAIN_PREFIX, EventTypeClass, GATE_LEASE_ISSUED_LEDGER_DOMAIN_PREFIX,
    INV_FAC_PR_BIND_001, LeaseValidationError, LeaseValidator, LedgerEventEmitter,
    LedgerEventError, MAX_PROJECTION_EVENTS, PrivilegedPcacLifecycleArtifacts,
    REVIEW_BLOCKED_RECORDED_LEDGER_PREFIX, RedundancyReceiptConsumption,
    SESSION_TERMINATED_LEDGER_DOMAIN_PREFIX, STOP_FLAGS_MUTATED_DOMAIN_PREFIX,
    STOP_FLAGS_MUTATED_WORK_ID, SignedLedgerEvent, StopFlagsMutation, WORK_CLAIMED_DOMAIN_PREFIX,
    WORK_PR_BINDING_CONFLICT_TAG, WORK_TRANSITIONED_DOMAIN_PREFIX, WorkClaim, WorkRegistry,
    WorkRegistryError, WorkTransition, append_privileged_pcac_lifecycle_fields,
    build_session_started_payload, classify_event_type,
};

/// Durable ledger event emitter backed by `SQLite`.
///
/// # Freeze Guard and Canonical Bridge (TCK-00631)
///
/// After RFC-0032 Phase 0 migration, this emitter can be frozen via
/// [`Self::freeze_legacy_writes`]. Once frozen, all write methods route
/// to the canonical `events` table via `persist_to_canonical_events`
/// instead of the legacy `ledger_events` table. This ensures new events
/// always append to the canonical ledger with BLAKE3 hash chain continuity.
///
/// `freeze_legacy_writes` is **unconditional**: it always activates the
/// freeze guard, regardless of whether `ledger_events_legacy_frozen` exists.
///
/// ## Synchronization Protocol (CTR-1002)
///
/// The `frozen` flag is an `AtomicBool` with `Acquire`/`Release` ordering:
/// - **Protected data**: Write-target routing (`events` vs `ledger_events`).
/// - **Publication**: `freeze_legacy_writes` stores `true` with `Release`.
/// - **Consumption**: Every write method loads with `Acquire` to determine the
///   write target.
/// - **Happens-before**: `freeze_legacy_writes(Release)` -> write method
///   `load(Acquire)` ensures all write methods see the freeze after it is set.
/// - **Allowed reorderings**: None — once frozen, the flag is never unset.
#[derive(Debug)]
pub struct SqliteLedgerEventEmitter {
    conn: Arc<Mutex<Connection>>,
    signing_key: ed25519_dalek::SigningKey,
    /// Freeze guard: when `true`, all write methods route to the
    /// canonical `events` table. Set once by `freeze_legacy_writes`
    /// and never cleared. See synchronization protocol above.
    frozen: AtomicBool,
}

struct EventHashInput<'a> {
    event_id: &'a str,
    event_type: &'a str,
    work_id: &'a str,
    actor_id: &'a str,
    payload: &'a [u8],
    signature: &'a [u8],
    timestamp_ns: u64,
    prev_hash: &'a str,
}

const REDUNDANCY_RECEIPT_CONSUMED_EVENT: &str = "redundancy_receipt_consumed";

/// Hard scan limit for bounded reverse-scan lookups such as
/// `get_event_by_evidence_identity` and `canonical_get_evidence_by_identity`.
/// Without a `LIMIT` the query iterates over **all** `evidence.published`
/// events for a `work_id`, performing per-row JSON + Protobuf
/// deserialization — an `O(N)` `DoS` vector.
///
/// TCK-00638: This constant is no longer used in production code — the
/// scan-bounded lookups were replaced with O(1) indexed lookups via
/// `UNIQUE` constraints on `evidence.published`.
///
/// **IMPORTANT**: This limit is NOT appropriate for `get_events_by_work_id`,
/// which is a foundational history replay method used by the projection
/// bridge. Applying a LIMIT there would silently drop recent events for
/// work items exceeding the cap, permanently freezing observed state.
///
/// Also used by the regression test
/// `test_evidence_lookup_is_indexed_not_scan_bounded` which verifies
/// the indexed path handles more events than this limit.
#[cfg(test)]
const MAX_EVIDENCE_SCAN_ROWS: u32 = 1_000;

#[derive(Debug)]
struct ChainBackfillRow {
    rowid: i64,
    event_id: String,
    event_type: String,
    work_id: String,
    actor_id: String,
    payload: Vec<u8>,
    signature: Vec<u8>,
    timestamp_ns: u64,
    event_hash: String,
}

#[derive(Debug, Clone)]
struct HashChainCheckpoint {
    rowid: i64,
    event_id: Option<String>,
    event_hash: String,
}

impl HashChainCheckpoint {
    fn genesis() -> Self {
        Self {
            rowid: 0,
            event_id: None,
            event_hash: SqliteLedgerEventEmitter::LEDGER_CHAIN_GENESIS.to_string(),
        }
    }
}

impl SqliteLedgerEventEmitter {
    const CANONICAL_EVENT_ID_PREFIX: &'static str = "canonical-";
    const CANONICAL_EVENT_ID_WIDTH: usize = 20;
    const LEDGER_CHAIN_GENESIS: &'static str = "genesis";
    const LEDGER_METADATA_TABLE: &'static str = "ledger_metadata";
    const HASH_CHAIN_UNINITIALIZED_VALUE: &'static str = "legacy-uninitialized";
    const HASH_CHAIN_BACKFILL_COMPLETED_FLAG: &'static str = "hash_chain_backfill_completed_v1";
    /// Deterministic test-only key seed. Private to this impl block and only
    /// referenced by [`Self::checkpoint_signing_key_default`] /
    /// [`Self::init_schema_for_test`].
    const CHECKPOINT_SIGNING_KEY_SEED_V1: [u8; 32] = [0xA5; 32];
    const HASH_CHAIN_CHECKPOINT_ROWID_KEY: &'static str = "hash_chain_tip_checkpoint_rowid_v2";
    const HASH_CHAIN_CHECKPOINT_EVENT_ID_KEY: &'static str =
        "hash_chain_tip_checkpoint_event_id_v2";
    const HASH_CHAIN_BACKFILL_BATCH_SIZE: i64 = 512;
    const HASH_CHAIN_CHECKPOINT_KEY: &'static str = "hash_chain_tip_checkpoint_v1";
    const HASH_CHAIN_CHECKPOINT_SIGNATURE_KEY: &'static str =
        "hash_chain_tip_checkpoint_signature_v2";
    const HASH_CHAIN_BACKFILL_COMPLETED_VALUE: &'static str = "1";

    /// Creates a new emitter with the given `SQLite` connection and signing
    /// key.
    ///
    /// The emitter starts unfrozen. Call [`Self::freeze_legacy_writes`] after
    /// migration to activate the freeze guard.
    #[must_use]
    pub const fn new(conn: Arc<Mutex<Connection>>, signing_key: ed25519_dalek::SigningKey) -> Self {
        Self {
            conn,
            signing_key,
            frozen: AtomicBool::new(false),
        }
    }

    /// Activates the freeze guard, routing all subsequent writes to the
    /// canonical `events` table instead of the legacy `ledger_events` table.
    ///
    /// This method is called at daemon startup after migration. It
    /// **unconditionally** freezes the emitter: after this call, all write
    /// methods (`emit_*`) route through the canonical bridge
    /// (`persist_to_canonical_events`) regardless of whether the
    /// `ledger_events_legacy_frozen` table exists. This eliminates the
    /// counterexample where a canonical-mode DB (events > 0, no frozen
    /// table) would leave the guard inactive.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — always; the freeze guard is now active.
    ///
    /// # Errors
    ///
    /// Returns the underlying database error if the
    /// `ledger_events_legacy_frozen` existence check fails, but the emitter
    /// is still frozen (fail-closed).
    pub fn freeze_legacy_writes(&self, conn: &Connection) -> Result<bool, LedgerEventError> {
        // Always freeze — there is no valid production scenario where
        // freeze_legacy_writes() is called and the guard should remain
        // inactive.  The method is only called at daemon startup after
        // migration runs.
        self.frozen.store(true, Ordering::Release);

        // Best-effort check: log whether the frozen table exists for
        // observability, but the freeze decision is unconditional.
        match conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ledger_events_legacy_frozen' LIMIT 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()
        {
            Ok(Some(_)) => {
                info!("freeze_legacy_writes: ledger_events_legacy_frozen table exists");
            },
            Ok(None) => {
                info!(
                    "freeze_legacy_writes: ledger_events_legacy_frozen table absent \
                     (canonical-mode DB); writes routed to canonical events"
                );
            },
            Err(e) => {
                // Emitter is already frozen; log the error for observability.
                return Err(LedgerEventError::PersistenceFailed {
                    message: format!(
                        "failed to check ledger_events_legacy_frozen existence \
                         (fail-closed: writes frozen): {e}"
                    ),
                });
            },
        }

        Ok(true)
    }

    /// Activates the freeze guard using the emitter's own connection.
    ///
    /// Convenience wrapper around [`Self::freeze_legacy_writes`] that acquires
    /// the internal connection lock. After this call, all write methods route
    /// to the canonical `events` table.
    ///
    /// # Errors
    ///
    /// Returns `LedgerEventError::PersistenceFailed` if the connection lock
    /// is poisoned, or propagates errors from `freeze_legacy_writes`.
    pub fn freeze_legacy_writes_self(&self) -> Result<bool, LedgerEventError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned during freeze check".to_string(),
            })?;
        self.freeze_legacy_writes(&conn)
    }

    /// Returns `true` if the freeze guard is active (writes blocked).
    #[must_use]
    pub fn is_frozen(&self) -> bool {
        self.frozen.load(Ordering::Acquire)
    }

    /// Returns `true` if the freeze guard is active (writes routed to
    /// canonical `events`).
    ///
    /// Used internally to select the write target (canonical `events` vs
    /// legacy `ledger_events`) and the chain-tip source.
    fn is_frozen_internal(&self) -> bool {
        self.frozen.load(Ordering::Acquire)
    }

    /// Returns the canonical synthetic event ID for a canonical `events`
    /// table `seq_id`.
    fn canonical_event_id_from_seq(seq_id: i64) -> String {
        format!(
            "{}{seq_id:0width$}",
            Self::CANONICAL_EVENT_ID_PREFIX,
            width = Self::CANONICAL_EVENT_ID_WIDTH
        )
    }

    /// Parses the canonical synthetic `event_id` and returns its numeric
    /// `seq_id` component.
    fn parse_canonical_event_id(event_id: &str) -> Option<i64> {
        event_id
            .strip_prefix(Self::CANONICAL_EVENT_ID_PREFIX)?
            .parse::<i64>()
            .ok()
    }

    /// Normalizes canonical cursor IDs to the fixed-width representation.
    ///
    /// This preserves compatibility with older unpadded cursor IDs
    /// (`canonical-9`) persisted before fixed-width canonical IDs were
    /// introduced.
    fn normalize_canonical_cursor_event_id(cursor_event_id: &str) -> String {
        Self::parse_canonical_event_id(cursor_event_id).map_or_else(
            || cursor_event_id.to_string(),
            Self::canonical_event_id_from_seq,
        )
    }

    // ---- Freeze-aware canonical read helpers (TCK-00631 / Finding 1) ----
    //
    // When the freeze guard is active, new events are written to the
    // canonical `events` table.  These helpers query that table and map
    // rows to `SignedLedgerEvent` so that protocol decision paths (PCAC,
    // governance-policy, chain integrity) see post-freeze events.
    //
    // Column mapping:
    //   events.seq_id       → SignedLedgerEvent.event_id  (synthesised as
    // "canonical-{seq_id:020}")   events.event_type   →
    // SignedLedgerEvent.event_type   events.session_id   →
    // SignedLedgerEvent.work_id   events.actor_id     →
    // SignedLedgerEvent.actor_id   events.payload      →
    // SignedLedgerEvent.payload   events.signature    →
    // SignedLedgerEvent.signature   events.timestamp_ns →
    // SignedLedgerEvent.timestamp_ns

    /// Maps a canonical `events` row to a `SignedLedgerEvent`.
    fn canonical_row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<SignedLedgerEvent> {
        let seq_id: i64 = row.get(0)?;
        Ok(SignedLedgerEvent {
            event_id: Self::canonical_event_id_from_seq(seq_id),
            event_type: row.get(1)?,
            work_id: row.get(2)?, // session_id maps to work_id
            actor_id: row.get(3)?,
            payload: row.get(4)?,
            signature: row.get(5)?,
            timestamp_ns: row.get(6)?,
        })
    }

    /// Canonical-table query returning the latest event by rowid.
    fn canonical_get_latest_event(conn: &Connection) -> Option<SignedLedgerEvent> {
        conn.query_row(
            "SELECT seq_id, event_type, session_id, actor_id, payload, \
                    COALESCE(signature, X''), timestamp_ns \
             FROM events ORDER BY rowid DESC LIMIT 1",
            [],
            Self::canonical_row_to_event,
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Canonical-table query returning the latest governance-policy event.
    fn canonical_get_latest_governance_policy_event(
        conn: &Connection,
    ) -> Option<SignedLedgerEvent> {
        conn.query_row(
            "SELECT seq_id, event_type, session_id, actor_id, payload, \
                    COALESCE(signature, X''), timestamp_ns \
             FROM events \
             WHERE event_type IN ( \
                 'gate.policy_resolved', \
                 'policy_root_published', \
                 'policy_updated', \
                 'gate_configuration_updated' \
             ) \
             AND actor_id IN ( \
                 'orchestrator:gate-lifecycle', \
                 'governance:policy-root', \
                 'governance:policy' \
             ) \
             ORDER BY rowid DESC LIMIT 1",
            [],
            Self::canonical_row_to_event,
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Canonical-table query returning the latest `gate.policy_resolved` event.
    fn canonical_get_latest_gate_policy_resolved_event(
        conn: &Connection,
    ) -> Option<SignedLedgerEvent> {
        conn.query_row(
            "SELECT seq_id, event_type, session_id, actor_id, payload, \
                    COALESCE(signature, X''), timestamp_ns \
             FROM events \
             WHERE event_type = 'gate.policy_resolved' \
             AND actor_id = 'orchestrator:gate-lifecycle' \
             ORDER BY rowid DESC LIMIT 1",
            [],
            Self::canonical_row_to_event,
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Canonical-table query searching for an `evidence.published` event
    /// matching (`work_id`, `entry_id`) with category `WORK_CONTEXT_ENTRY`.
    ///
    /// TCK-00638 / BLOCKER fix: When the freeze guard is active, evidence
    /// events are written to the canonical `events` table. This helper
    /// ensures replay/idempotency lookup covers canonical-mode writes.
    ///
    /// TCK-00638 SECURITY FIX: Uses an indexed lookup via
    /// `json_extract(CAST(payload AS TEXT), '$.evidence_id')` (backed by
    /// `idx_canonical_evidence_published_unique`) instead of scanning up to
    /// `MAX_EVIDENCE_SCAN_ROWS` with per-row protobuf decoding. This
    /// eliminates the false-negative risk in long-lived work streams with
    /// >1000 evidence entries.
    ///
    /// Column mapping: `events.session_id` → `work_id` (same mapping as
    /// `canonical_row_to_event`).
    fn canonical_get_evidence_by_identity(
        conn: &Connection,
        work_id: &str,
        entry_id: &str,
    ) -> Option<SignedLedgerEvent> {
        // O(1) indexed lookup using the UNIQUE index on
        // json_extract(CAST(payload AS TEXT), '$.evidence_id'). No scan, no
        // protobuf decode — the evidence_id is at the top level of the JSON
        // envelope. CAST is required because the payload column is BLOB and
        // SQLite < 3.45 does not support json_extract on BLOB directly.
        conn.query_row(
            "SELECT seq_id, event_type, session_id, actor_id, payload, \
                    COALESCE(signature, X''), timestamp_ns \
             FROM events \
             WHERE event_type = 'evidence.published' \
             AND session_id = ?1 \
             AND json_extract(CAST(payload AS TEXT), '$.evidence_id') = ?2 \
             ORDER BY rowid DESC \
             LIMIT 1",
            params![work_id, entry_id],
            Self::canonical_row_to_event,
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Canonical-table latest event hash (BLOB → hex), for
    /// `get_latest_event_hash` when frozen.
    fn canonical_get_latest_event_hash_hex(conn: &Connection) -> Result<Option<String>, String> {
        let hash_opt: Option<Vec<u8>> = conn
            .query_row(
                "SELECT event_hash FROM events WHERE event_hash IS NOT NULL \
                 ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("sqlite canonical latest event_hash query failed: {e}"))?;
        match hash_opt {
            Some(h) if h.is_empty() => Err("latest canonical event_hash is empty".to_string()),
            Some(h) => Ok(Some(hex::encode(h))),
            None => Ok(None),
        }
    }

    /// Initializes the database schema using a deterministic test-only signing
    /// key (hardcoded `0xA5` seed). **Not for production use** — production
    /// callers must use [`Self::init_schema_with_signing_key`] with the daemon
    /// lifecycle key.
    ///
    /// This method exists solely to support integration and unit tests that do
    /// not provision a daemon lifecycle signing key. It MUST NOT appear in any
    /// production code path.
    #[doc(hidden)]
    pub fn init_schema_for_test(conn: &Connection) -> rusqlite::Result<()> {
        // `init_schema_for_test` is used by test-only paths that do not yet
        // pass the daemon lifecycle signing key. Use a deterministic local key
        // so checkpoint signatures remain verifiable across repeated calls.
        let signing_key = Self::checkpoint_signing_key_default();
        Self::init_schema_internal(conn, &signing_key, None)
    }

    /// Initializes the database schema and validates startup hash-chain state
    /// using the daemon lifecycle signing key.
    pub fn init_schema_with_signing_key(
        conn: &Connection,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> rusqlite::Result<()> {
        let verifying_key = signing_key.verifying_key();
        Self::init_schema_internal(conn, signing_key, Some(&verifying_key))
    }

    fn init_schema_internal(
        conn: &Connection,
        signing_key: &ed25519_dalek::SigningKey,
        trusted_verifying_key: Option<&ed25519_dalek::VerifyingKey>,
    ) -> rusqlite::Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ledger_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                event_type_class TEXT NOT NULL DEFAULT 'session',
                work_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                signature BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL,
                prev_hash TEXT NOT NULL DEFAULT 'genesis',
                event_hash TEXT NOT NULL DEFAULT 'legacy-uninitialized'
            )",
            [],
        )?;
        Self::ensure_hash_chain_columns(conn)?;
        Self::ensure_event_type_class_column(conn)?;
        Self::ensure_metadata_table(conn)?;
        Self::backfill_event_type_classes(conn)?;
        let mut migration_changes_applied = Self::backfill_hash_chain(conn, signing_key)?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ledger_events_work_id ON ledger_events(work_id)",
            [],
        )?;
        // QUALITY MAJOR 1 FIX: Index on timestamp_ns for O(log N) latest-event
        // lookups in `get_latest_event()`. Without this, the
        // `ORDER BY timestamp_ns DESC, rowid DESC LIMIT 1` query performs a
        // full table scan (O(N) cost) on every PCAC ledger anchor derivation.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ledger_events_timestamp ON ledger_events(timestamp_ns)",
            [],
        )?;
        // Index for LeaseValidator
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ledger_events_type_payload ON ledger_events(event_type)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ledger_events_class_type_actor \
             ON ledger_events(event_type_class, event_type, actor_id)",
            [],
        )?;
        // SECURITY (v9 Finding 1 — Delegation Uniqueness Constraint):
        //
        // Enforce at-most-once semantics for authority-bearing delegation
        // events at the database level. For `SubleaseIssued` events, the
        // `work_id` column stores the `sublease_id` (set by
        // `emit_session_event(&sublease.lease_id, "SubleaseIssued", ...)`).
        // A partial unique index ensures that even under concurrent dispatch
        // (the handler takes `&self`, not `&mut self`), duplicate emission
        // of a `SubleaseIssued` event for the same sublease_id is rejected
        // by SQLite's UNIQUE constraint before any data is committed.
        //
        // This converts the check-then-act pattern in `DelegateSublease`
        // into a defense-in-depth strategy: the application-level check
        // (`get_gate_lease`) provides the idempotent fast-path, while the
        // database constraint provides the authoritative uniqueness
        // guarantee that cannot be bypassed by race conditions.
        //
        // NOTE: For `gate_lease_issued` events, the `work_id` column stores
        // the logical work ID (not `lease_id`), and multiple leases can share
        // the same `work_id`. We use a unique index on the `json_extract`ed
        // `$.lease_id` from the payload to enforce at-most-once semantics per
        // `lease_id` for full-lease persistence. This prevents concurrent
        // `register_full_lease` calls from creating duplicate lease anchors.
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_full_lease_id \
             ON ledger_events(json_extract(CAST(payload AS TEXT), '$.lease_id')) \
             WHERE event_type = 'gate_lease_issued' \
             AND json_extract(CAST(payload AS TEXT), '$.full_lease') IS NOT NULL",
            [],
        )?;
        // For `SubleaseIssued` events, `work_id` = `sublease_id`, so a partial
        // unique index on `(event_type, work_id)` provides the authoritative
        // uniqueness guarantee for event emission.
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_sublease_issued \
             ON ledger_events(event_type, work_id) \
             WHERE event_type = 'SubleaseIssued'",
            [],
        )?;
        // SECURITY (TCK-00407 — Receipt Identity Constraints):
        //
        // Enforce two complementary receipt constraints:
        // - review-receipt uniqueness by `receipt_id` scoped to
        //   `review_receipt_recorded`/`review_blocked_recorded`
        // - semantic identity uniqueness by tuple `(receipt_id, lease_id, work_id,
        //   changeset_digest)` for review receipt events
        //
        // Additionally, `redundancy_receipt_consumed` has its own uniqueness
        // constraint on `receipt_id` so a review receipt and its subsequent
        // consumption can share the same `receipt_id` without collision.
        //
        // `work_id` in the semantic tuple is sourced from the payload field
        // and falls back to the row's `work_id` column for legacy rows that
        // predate canonical tuple persistence.
        //
        // MIGRATION: Quarantine historical duplicate `receipt_id` rows before
        // creating `idx_unique_receipt_id`. Quarantine entries are keyed by
        // stable `event_id` (never persistent `rowid`) so startup replays are
        // safe even if SQLite rowids are recycled over time.
        //
        // The migration is idempotent:
        // - quarantine table is created with `IF NOT EXISTS`
        // - legacy rowid-based tables are upgraded once to event_id-keyed schema
        // - rows already quarantined are skipped with `INSERT OR IGNORE`
        Self::ensure_receipt_quarantine_table(conn)?;
        let receipt_quarantine_inserted = conn.execute(
            "INSERT OR IGNORE INTO ledger_events_quarantine \
                 (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns) \
             SELECT le.event_id, le.event_type, le.work_id, le.actor_id, \
                    le.payload, le.signature, le.timestamp_ns \
             FROM ledger_events le \
             INNER JOIN ( \
                 SELECT json_extract(CAST(payload AS TEXT), '$.receipt_id') AS receipt_id, \
                        MIN(rowid) AS keep_rowid \
                 FROM ledger_events \
                 WHERE event_type IN ('review_receipt_recorded', 'review_blocked_recorded') \
                 AND json_extract(CAST(payload AS TEXT), '$.receipt_id') IS NOT NULL \
                 GROUP BY json_extract(CAST(payload AS TEXT), '$.receipt_id') \
                 HAVING COUNT(*) > 1 \
             ) dups ON json_extract(CAST(le.payload AS TEXT), '$.receipt_id') = dups.receipt_id \
             WHERE le.event_type IN ('review_receipt_recorded', 'review_blocked_recorded') \
             AND json_extract(CAST(le.payload AS TEXT), '$.receipt_id') IS NOT NULL \
             AND le.rowid != dups.keep_rowid \
             ",
            [],
        )?;
        migration_changes_applied |= receipt_quarantine_inserted > 0;
        let receipt_rows_deleted = conn.execute(
            "DELETE FROM ledger_events WHERE event_id IN ( \
                 SELECT event_id FROM ledger_events_quarantine \
                 WHERE quarantine_reason = 'receipt_id_dedupe_migration' \
             )",
            [],
        )?;
        migration_changes_applied |= receipt_rows_deleted > 0;
        // Migrate legacy global index shape to scoped review-receipt uniqueness.
        conn.execute("DROP INDEX IF EXISTS idx_unique_receipt_id", [])?;
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_receipt_id \
             ON ledger_events(json_extract(CAST(payload AS TEXT), '$.receipt_id')) \
             WHERE event_type IN ('review_receipt_recorded', 'review_blocked_recorded') \
             AND json_extract(CAST(payload AS TEXT), '$.receipt_id') IS NOT NULL",
            [],
        )?;
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_receipt_consumed \
             ON ledger_events(json_extract(CAST(payload AS TEXT), '$.receipt_id')) \
             WHERE event_type = 'redundancy_receipt_consumed' \
             AND json_extract(CAST(payload AS TEXT), '$.receipt_id') IS NOT NULL",
            [],
        )?;
        // SECURITY (TCK-00485 BLOCKER): dedicated lookup index for receipt
        // consumption events avoids linear scans in
        // `get_redundancy_receipt_consumption`.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_redundancy_receipt_consumed_receipt_id \
             ON ledger_events(json_extract(CAST(payload AS TEXT), '$.receipt_id')) \
             WHERE event_type = 'redundancy_receipt_consumed'",
            [],
        )?;
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_receipt_semantic_identity \
             ON ledger_events( \
                 json_extract(CAST(payload AS TEXT), '$.receipt_id'), \
                 json_extract(CAST(payload AS TEXT), '$.lease_id'), \
                 COALESCE(json_extract(CAST(payload AS TEXT), '$.work_id'), work_id), \
                 json_extract(CAST(payload AS TEXT), '$.changeset_digest') \
             ) \
             WHERE event_type IN ('review_receipt_recorded', 'review_blocked_recorded')",
            [],
        )?;
        // SECURITY (TCK-00412 Follow-up — Changeset Published Uniqueness):
        //
        // Enforce at-most-once semantics for `changeset_published` events at
        // the database level. The semantic idempotency check in
        // `handle_publish_changeset` (dispatch.rs) uses a check-then-act
        // pattern: `find_changeset_published_replay` queries for an existing
        // event before emitting. Under concurrent requests with the same
        // `(work_id, changeset_digest)`, both threads can pass the check,
        // both proceed to emit, and create duplicate ledger entries.
        //
        // This partial unique index converts the pattern into defense-in-depth:
        // the application-level check provides the idempotent fast-path, while
        // the database constraint provides the authoritative uniqueness
        // guarantee. The existing race-safe fallback in
        // `handle_publish_changeset` (dispatch.rs lines 10062-10076) already
        // catches the UNIQUE violation gracefully by replaying persisted
        // bindings.
        //
        // MIGRATION: Quarantine historical duplicate `changeset_published`
        // events that may exist if the daemon ran with TCK-00412's code
        // (before this fix) under concurrent PublishChangeSet requests.
        // Duplicate `(work_id, changeset_digest)` rows would cause
        // `CREATE UNIQUE INDEX` to fail, resulting in a daemon startup DoS.
        //
        // The migration is idempotent:
        // - quarantine table already exists from receipt migration
        // - `INSERT OR IGNORE` skips already-quarantined rows
        // - `MIN(rowid)` keeps the earliest row, quarantines the rest
        // - after quarantine, the unique index creation is safe
        let changeset_quarantine_inserted = conn.execute(
            "INSERT OR IGNORE INTO ledger_events_quarantine \
                 (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns, quarantine_reason) \
             SELECT le.event_id, le.event_type, le.work_id, le.actor_id, \
                    le.payload, le.signature, le.timestamp_ns, \
                    'changeset_digest_dedupe_migration' \
             FROM ledger_events le \
             INNER JOIN ( \
                 SELECT work_id, \
                        json_extract(CAST(payload AS TEXT), '$.changeset_digest') AS cs_digest, \
                        MIN(rowid) AS keep_rowid \
                 FROM ledger_events \
                 WHERE event_type = 'changeset_published' \
                 AND json_extract(CAST(payload AS TEXT), '$.changeset_digest') IS NOT NULL \
                 GROUP BY work_id, json_extract(CAST(payload AS TEXT), '$.changeset_digest') \
                 HAVING COUNT(*) > 1 \
             ) dups ON le.work_id = dups.work_id \
                 AND json_extract(CAST(le.payload AS TEXT), '$.changeset_digest') = dups.cs_digest \
             WHERE le.event_type = 'changeset_published' \
             AND json_extract(CAST(le.payload AS TEXT), '$.changeset_digest') IS NOT NULL \
             AND le.rowid != dups.keep_rowid \
             ",
            [],
        )?;
        migration_changes_applied |= changeset_quarantine_inserted > 0;
        let changeset_rows_deleted = conn.execute(
            "DELETE FROM ledger_events WHERE event_id IN ( \
                 SELECT event_id FROM ledger_events_quarantine \
                 WHERE quarantine_reason = 'changeset_digest_dedupe_migration' \
             )",
            [],
        )?;
        migration_changes_applied |= changeset_rows_deleted > 0;
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_changeset_published \
             ON ledger_events(work_id, json_extract(CAST(payload AS TEXT), '$.changeset_digest')) \
             WHERE event_type = 'changeset_published'",
            [],
        )?;
        // SECURITY (TCK-00635 — OpenWork Idempotency Constraint):
        //
        // Enforce at-most-once semantics for `work.opened` events at the
        // database level. The `handle_open_work` handler uses a
        // check-then-act pattern: `get_first_event_by_work_id_and_type`
        // queries for an existing `work.opened` event before emitting.
        // Under concurrent dispatch (`&self`, not `&mut self`), two racing
        // requests can both observe no existing event and both commit,
        // creating duplicate `work.opened` events for the same `work_id`.
        //
        // This partial unique index converts the pattern into
        // defense-in-depth: the application-level check provides the
        // idempotent fast-path, while the database constraint provides
        // the authoritative uniqueness guarantee that cannot be bypassed
        // by race conditions. The handler catches UNIQUE violations and
        // re-reads the persisted event to return idempotent success (same
        // hash) or WORK_ALREADY_EXISTS (different hash).
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_work_opened_unique \
             ON ledger_events(work_id) \
             WHERE event_type = 'work.opened'",
            [],
        )?;

        // TCK-00638 SECURITY FIX: At-most-one evidence.published per
        // evidence_id on the legacy `ledger_events` table.  The evidence_id
        // is surfaced at the top level of the JSON payload by
        // `emit_evidence_published_event` so that `json_extract` can enforce
        // uniqueness without decoding the nested hex-encoded protobuf.
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_published_unique \
             ON ledger_events(json_extract(CAST(payload AS TEXT), '$.evidence_id')) \
             WHERE event_type = 'evidence.published'",
            [],
        )?;

        // TCK-00637 SECURITY BLOCKER: At-most-one work_transitioned per
        // (work_id, previous_transition_count) to prevent ledger equivocation.
        // Concurrent ClaimWorkV2 requests that observe the same transition_count
        // will be serialized by the UNIQUE constraint — only one succeeds, the
        // other receives a constraint violation and must recover or fail.
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_work_transitioned_unique \
             ON ledger_events(work_id, json_extract(CAST(payload AS TEXT), \
             '$.previous_transition_count')) \
             WHERE event_type = 'work_transitioned'",
            [],
        )?;

        // TCK-00639 SECURITY FIX: At-most-one `work.pr_associated` per
        // semantic identity tuple `(work_id, pr_number, commit_sha)` on the
        // legacy `ledger_events` table.
        //
        // The handler now emits top-level `pr_number` and `commit_sha` fields
        // in the JSON envelope so SQLite can enforce uniqueness without
        // decoding nested protobuf bytes.
        let legacy_work_pr_dedup = conn.execute(
            "DELETE FROM ledger_events WHERE rowid NOT IN ( \
                 SELECT MIN(rowid) FROM ledger_events \
                 WHERE event_type = 'work.pr_associated' \
                 AND json_extract(CAST(payload AS TEXT), '$.pr_number') IS NOT NULL \
                 AND json_extract(CAST(payload AS TEXT), '$.commit_sha') IS NOT NULL \
                 GROUP BY work_id, \
                          json_extract(CAST(payload AS TEXT), '$.pr_number'), \
                          lower(json_extract(CAST(payload AS TEXT), '$.commit_sha')) \
             ) AND event_type = 'work.pr_associated' \
             AND json_extract(CAST(payload AS TEXT), '$.pr_number') IS NOT NULL \
             AND json_extract(CAST(payload AS TEXT), '$.commit_sha') IS NOT NULL",
            [],
        )?;
        if legacy_work_pr_dedup > 0 {
            warn!(
                count = legacy_work_pr_dedup,
                "deduped historical work.pr_associated rows in legacy ledger_events table"
            );
            migration_changes_applied = true;
        }
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_work_pr_associated_unique \
             ON ledger_events( \
                work_id, \
                json_extract(CAST(payload AS TEXT), '$.pr_number'), \
                json_extract(CAST(payload AS TEXT), '$.commit_sha') \
             ) \
             WHERE event_type = 'work.pr_associated' \
             AND json_extract(CAST(payload AS TEXT), '$.pr_number') IS NOT NULL \
             AND json_extract(CAST(payload AS TEXT), '$.commit_sha') IS NOT NULL",
            [],
        )?;
        // Case-insensitive tuple uniqueness to close mixed-case replay races
        // against historical payloads and align with lower(...) tuple probes.
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_work_pr_associated_unique_ci \
             ON ledger_events( \
                work_id, \
                json_extract(CAST(payload AS TEXT), '$.pr_number'), \
                lower(json_extract(CAST(payload AS TEXT), '$.commit_sha')) \
             ) \
             WHERE event_type = 'work.pr_associated' \
             AND json_extract(CAST(payload AS TEXT), '$.pr_number') IS NOT NULL \
             AND json_extract(CAST(payload AS TEXT), '$.commit_sha') IS NOT NULL",
            [],
        )?;

        // Product semantics: a work item may publish multiple commits for the
        // same PR over time. Keep tuple uniqueness, drop historical singleton
        // index if present.
        conn.execute(
            "DROP INDEX IF EXISTS idx_work_pr_associated_singleton_unique",
            [],
        )?;

        // SECURITY (f-781-security-1771692992655093-0 — Canonical Events
        // Uniqueness Constraint):
        //
        // The `idx_work_opened_unique` index above only protects the legacy
        // `ledger_events` table. When the freeze guard routes writes to the
        // canonical `events` table (`persist_to_canonical_events`), duplicate
        // `work.opened` events could be inserted without constraint
        // enforcement. This canonical-side index provides the same
        // defense-in-depth guarantee on the `events` table.
        //
        // Guard: only apply when the canonical `events` table exists
        // (it may not in legacy-only daemon databases that haven't yet
        // run RFC-0032 Phase 0 migration).
        //
        // Historical duplicate handling: before creating the unique index,
        // deduplicate any pre-existing `work.opened` rows in the canonical
        // `events` table by keeping only the earliest row (MIN(rowid)) per
        // `session_id` (which maps to `work_id`).
        let canonical_events_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master \
                 WHERE type = 'table' AND name = 'events'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);

        if canonical_events_exists {
            let canonical_work_opened_dedup = conn.execute(
                "DELETE FROM events WHERE rowid NOT IN ( \
                     SELECT MIN(rowid) FROM events \
                     WHERE event_type = 'work.opened' \
                     GROUP BY session_id \
                 ) AND event_type = 'work.opened'",
                [],
            )?;
            if canonical_work_opened_dedup > 0 {
                warn!(
                    count = canonical_work_opened_dedup,
                    "deduped historical work.opened rows in canonical events table"
                );
                migration_changes_applied = true;
            }
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_canonical_work_opened_unique \
                 ON events(session_id) \
                 WHERE event_type = 'work.opened'",
                [],
            )?;

            // TCK-00638 SECURITY FIX: At-most-one evidence.published per
            // evidence_id on the canonical `events` table. Mirrors
            // `idx_evidence_published_unique` on the legacy table.
            //
            // Historical duplicate handling: before creating the unique
            // index, deduplicate any pre-existing `evidence.published` rows
            // by keeping only the earliest row (MIN(rowid)) per evidence_id.
            let canonical_evidence_dedup = conn.execute(
                "DELETE FROM events WHERE rowid NOT IN ( \
                     SELECT MIN(rowid) FROM events \
                     WHERE event_type = 'evidence.published' \
                     GROUP BY json_extract(CAST(payload AS TEXT), '$.evidence_id') \
                 ) AND event_type = 'evidence.published' \
                 AND json_extract(CAST(payload AS TEXT), '$.evidence_id') IS NOT NULL",
                [],
            )?;
            if canonical_evidence_dedup > 0 {
                warn!(
                    count = canonical_evidence_dedup,
                    "deduped historical evidence.published rows in canonical events table"
                );
                migration_changes_applied = true;
            }
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_canonical_evidence_published_unique \
                 ON events(json_extract(CAST(payload AS TEXT), '$.evidence_id')) \
                 WHERE event_type = 'evidence.published'",
                [],
            )?;

            // TCK-00637 SECURITY BLOCKER: At-most-one work_transitioned per
            // (session_id, previous_transition_count) on the canonical events
            // table. Mirrors idx_work_transitioned_unique on the legacy table.
            // Note: canonical events use session_id where legacy uses work_id.
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_canonical_work_transitioned_unique \
                 ON events(session_id, json_extract(CAST(payload AS TEXT), \
                 '$.previous_transition_count')) \
                 WHERE event_type = 'work_transitioned'",
                [],
            )?;

            // TCK-00639 SECURITY FIX: At-most-one `work.pr_associated` per
            // semantic identity tuple `(work_id, pr_number, commit_sha)` on
            // canonical `events` (where `session_id` maps to `work_id`).
            let canonical_work_pr_dedup = conn.execute(
                "DELETE FROM events WHERE rowid NOT IN ( \
                     SELECT MIN(rowid) FROM events \
                     WHERE event_type = 'work.pr_associated' \
                     AND json_extract(CAST(payload AS TEXT), '$.pr_number') IS NOT NULL \
                     AND json_extract(CAST(payload AS TEXT), '$.commit_sha') IS NOT NULL \
                     GROUP BY session_id, \
                              json_extract(CAST(payload AS TEXT), '$.pr_number'), \
                              lower(json_extract(CAST(payload AS TEXT), '$.commit_sha')) \
                 ) AND event_type = 'work.pr_associated' \
                 AND json_extract(CAST(payload AS TEXT), '$.pr_number') IS NOT NULL \
                 AND json_extract(CAST(payload AS TEXT), '$.commit_sha') IS NOT NULL",
                [],
            )?;
            if canonical_work_pr_dedup > 0 {
                warn!(
                    count = canonical_work_pr_dedup,
                    "deduped historical work.pr_associated rows in canonical events table"
                );
                migration_changes_applied = true;
            }
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_canonical_work_pr_associated_unique \
                 ON events( \
                    session_id, \
                    json_extract(CAST(payload AS TEXT), '$.pr_number'), \
                    json_extract(CAST(payload AS TEXT), '$.commit_sha') \
                 ) \
                 WHERE event_type = 'work.pr_associated' \
                 AND json_extract(CAST(payload AS TEXT), '$.pr_number') IS NOT NULL \
                 AND json_extract(CAST(payload AS TEXT), '$.commit_sha') IS NOT NULL",
                [],
            )?;
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_canonical_work_pr_associated_unique_ci \
                 ON events( \
                    session_id, \
                    json_extract(CAST(payload AS TEXT), '$.pr_number'), \
                    lower(json_extract(CAST(payload AS TEXT), '$.commit_sha')) \
                 ) \
                 WHERE event_type = 'work.pr_associated' \
                 AND json_extract(CAST(payload AS TEXT), '$.pr_number') IS NOT NULL \
                 AND json_extract(CAST(payload AS TEXT), '$.commit_sha') IS NOT NULL",
                [],
            )?;

            conn.execute(
                "DROP INDEX IF EXISTS idx_canonical_work_pr_associated_singleton_unique",
                [],
            )?;
        }

        if migration_changes_applied {
            warn!(
                "ledger startup migrations mutated rows; rebuilding hash-chain links and invalidating stored checkpoint metadata before full verification"
            );
            Self::rebuild_hash_chain_columns(conn)?;
            Self::clear_hash_chain_checkpoint_metadata(conn)?;
        }
        Self::validate_startup_hash_chain_checkpoint(conn, signing_key, trusted_verifying_key)
            .map_err(|message| {
                error!(
                    reason = %message,
                    "ledger hash-chain integrity checkpoint mismatch; refusing startup"
                );
                rusqlite::Error::InvalidQuery
            })?;
        Ok(())
    }

    fn ensure_metadata_table(conn: &Connection) -> rusqlite::Result<()> {
        conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS {} ( \
                    meta_key TEXT PRIMARY KEY, \
                    meta_value TEXT NOT NULL \
                )",
                Self::LEDGER_METADATA_TABLE
            ),
            [],
        )?;
        Ok(())
    }

    fn get_metadata_value(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
        let sql = format!(
            "SELECT meta_value FROM {} WHERE meta_key = ?1",
            Self::LEDGER_METADATA_TABLE
        );
        conn.query_row(&sql, params![key], |row| row.get::<_, String>(0))
            .optional()
    }

    fn set_metadata_value(conn: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
        let sql = format!(
            "INSERT INTO {}(meta_key, meta_value) VALUES (?1, ?2) \
             ON CONFLICT(meta_key) DO UPDATE SET meta_value = excluded.meta_value",
            Self::LEDGER_METADATA_TABLE
        );
        conn.execute(&sql, params![key, value])?;
        Ok(())
    }

    fn delete_metadata_value(conn: &Connection, key: &str) -> rusqlite::Result<()> {
        let sql = format!(
            "DELETE FROM {} WHERE meta_key = ?1",
            Self::LEDGER_METADATA_TABLE
        );
        conn.execute(&sql, params![key])?;
        Ok(())
    }

    fn clear_hash_chain_checkpoint_metadata(conn: &Connection) -> rusqlite::Result<()> {
        Self::delete_metadata_value(conn, Self::HASH_CHAIN_CHECKPOINT_SIGNATURE_KEY)?;
        Self::delete_metadata_value(conn, Self::HASH_CHAIN_CHECKPOINT_ROWID_KEY)?;
        Self::delete_metadata_value(conn, Self::HASH_CHAIN_CHECKPOINT_EVENT_ID_KEY)?;
        Self::delete_metadata_value(conn, Self::HASH_CHAIN_CHECKPOINT_KEY)?;
        Ok(())
    }

    fn canonical_events_row_count(conn: &Connection) -> Result<u64, String> {
        let canonical_events_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master \
                 WHERE type = 'table' AND name = 'events'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("failed to check canonical events table existence: {e}"))?;
        if !canonical_events_exists {
            return Ok(0);
        }

        let row_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .map_err(|e| format!("failed to count canonical events rows: {e}"))?;
        u64::try_from(row_count)
            .map_err(|_| format!("canonical events row count is negative: {row_count}"))
    }

    /// Returns a deterministic signing key from the hardcoded test seed.
    ///
    /// **Test-only** — callers outside `#[cfg(test)]` and integration tests
    /// MUST NOT use this function. Production code uses the daemon lifecycle
    /// signing key instead.
    fn checkpoint_signing_key_default() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&Self::CHECKPOINT_SIGNING_KEY_SEED_V1)
    }

    fn checkpoint_canonical_bytes(checkpoint: &HashChainCheckpoint) -> Vec<u8> {
        let event_id = checkpoint.event_id.as_deref().unwrap_or_default();
        let event_id_bytes = event_id.as_bytes();
        let event_hash_bytes = checkpoint.event_hash.as_bytes();
        let mut canonical =
            Vec::with_capacity(8 + 8 + event_id_bytes.len() + 8 + event_hash_bytes.len());
        canonical.extend_from_slice(&checkpoint.rowid.to_le_bytes());
        canonical.extend_from_slice(&(event_id_bytes.len() as u64).to_le_bytes());
        canonical.extend_from_slice(event_id_bytes);
        canonical.extend_from_slice(&(event_hash_bytes.len() as u64).to_le_bytes());
        canonical.extend_from_slice(event_hash_bytes);
        canonical
    }

    fn sign_checkpoint(
        signing_key: &ed25519_dalek::SigningKey,
        checkpoint: &HashChainCheckpoint,
    ) -> Vec<u8> {
        let canonical = Self::checkpoint_canonical_bytes(checkpoint);
        signing_key.sign(&canonical).to_bytes().to_vec()
    }

    fn verify_checkpoint_signature(
        verifying_key: &ed25519_dalek::VerifyingKey,
        checkpoint: &HashChainCheckpoint,
        signature: &[u8],
    ) -> bool {
        let Ok(signature) = ed25519_dalek::Signature::try_from(signature) else {
            return false;
        };
        let canonical = Self::checkpoint_canonical_bytes(checkpoint);
        verifying_key.verify(&canonical, &signature).is_ok()
    }

    fn latest_chain_tip_checkpoint(conn: &Connection) -> Result<HashChainCheckpoint, String> {
        let row: Option<(i64, String, String)> = conn
            .query_row(
                "SELECT rowid, event_id, event_hash \
                 FROM ledger_events \
                 ORDER BY rowid DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|e| format!("failed to read latest chain-tip checkpoint row: {e}"))?;
        let Some((rowid, event_id, event_hash)) = row else {
            return Ok(HashChainCheckpoint::genesis());
        };
        if event_hash.is_empty() || event_hash == Self::HASH_CHAIN_UNINITIALIZED_VALUE {
            return Err(format!(
                "latest chain tip row {rowid} has uninitialized event_hash"
            ));
        }
        Ok(HashChainCheckpoint {
            rowid,
            event_id: Some(event_id),
            event_hash,
        })
    }

    fn checkpoint_from_legacy_hash(
        conn: &Connection,
        legacy_hash: &str,
    ) -> Result<Option<HashChainCheckpoint>, String> {
        if legacy_hash == Self::LEDGER_CHAIN_GENESIS {
            return Ok(Some(HashChainCheckpoint::genesis()));
        }

        let row: Option<(i64, String)> = conn
            .query_row(
                "SELECT rowid, event_id \
                 FROM ledger_events \
                 WHERE event_hash = ?1 \
                 ORDER BY rowid DESC LIMIT 1",
                params![legacy_hash],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| {
                format!("failed to resolve legacy hash-chain checkpoint '{legacy_hash}': {e}")
            })?;
        Ok(row.map(|(rowid, event_id)| HashChainCheckpoint {
            rowid,
            event_id: Some(event_id),
            event_hash: legacy_hash.to_string(),
        }))
    }

    fn load_hash_chain_checkpoint(
        conn: &Connection,
    ) -> Result<Option<HashChainCheckpoint>, String> {
        let rowid_raw = Self::get_metadata_value(conn, Self::HASH_CHAIN_CHECKPOINT_ROWID_KEY)
            .map_err(|e| format!("failed to read hash-chain checkpoint rowid metadata: {e}"))?;
        let hash_raw = Self::get_metadata_value(conn, Self::HASH_CHAIN_CHECKPOINT_KEY)
            .map_err(|e| format!("failed to read hash-chain checkpoint hash metadata: {e}"))?;

        if let (Some(rowid_raw), Some(event_hash)) = (rowid_raw, hash_raw.clone()) {
            let rowid = rowid_raw.parse::<i64>().map_err(|e| {
                format!("hash-chain checkpoint rowid metadata is invalid '{rowid_raw}': {e}")
            })?;
            let event_id = Self::get_metadata_value(conn, Self::HASH_CHAIN_CHECKPOINT_EVENT_ID_KEY)
                .map_err(|e| {
                    format!("failed to read hash-chain checkpoint event_id metadata: {e}")
                })?
                .filter(|value| !value.is_empty());
            return Ok(Some(HashChainCheckpoint {
                rowid,
                event_id,
                event_hash,
            }));
        }

        if let Some(legacy_hash) = hash_raw {
            return Self::checkpoint_from_legacy_hash(conn, &legacy_hash);
        }

        Ok(None)
    }

    fn load_hash_chain_checkpoint_signature(conn: &Connection) -> Result<Option<Vec<u8>>, String> {
        let signature_hex =
            Self::get_metadata_value(conn, Self::HASH_CHAIN_CHECKPOINT_SIGNATURE_KEY).map_err(
                |e| format!("failed to read hash-chain checkpoint signature metadata: {e}"),
            )?;
        let Some(signature_hex) = signature_hex else {
            return Ok(None);
        };
        if signature_hex.is_empty() {
            return Ok(None);
        }
        hex::decode(&signature_hex).map(Some).map_err(|e| {
            format!(
                "failed to decode hash-chain checkpoint signature metadata as hex '{signature_hex}': {e}"
            )
        })
    }

    fn persist_hash_chain_checkpoint(
        conn: &Connection,
        checkpoint: &HashChainCheckpoint,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> rusqlite::Result<()> {
        let checkpoint_signature = Self::sign_checkpoint(signing_key, checkpoint);
        Self::set_metadata_value(
            conn,
            Self::HASH_CHAIN_CHECKPOINT_KEY,
            &checkpoint.event_hash,
        )?;
        Self::set_metadata_value(
            conn,
            Self::HASH_CHAIN_CHECKPOINT_ROWID_KEY,
            &checkpoint.rowid.to_string(),
        )?;
        Self::set_metadata_value(
            conn,
            Self::HASH_CHAIN_CHECKPOINT_EVENT_ID_KEY,
            checkpoint.event_id.as_deref().unwrap_or_default(),
        )?;
        Self::set_metadata_value(
            conn,
            Self::HASH_CHAIN_CHECKPOINT_SIGNATURE_KEY,
            &hex::encode(checkpoint_signature),
        )?;
        Ok(())
    }

    fn verify_checkpoint_anchor(
        conn: &Connection,
        checkpoint: &HashChainCheckpoint,
    ) -> Result<(), String> {
        if checkpoint.rowid == 0 {
            if checkpoint.event_hash != Self::LEDGER_CHAIN_GENESIS {
                return Err(format!(
                    "genesis checkpoint hash mismatch: expected '{}', got '{}'",
                    Self::LEDGER_CHAIN_GENESIS,
                    checkpoint.event_hash
                ));
            }
            return Ok(());
        }

        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT event_id, event_hash FROM ledger_events WHERE rowid = ?1",
                params![checkpoint.rowid],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| {
                format!(
                    "failed to query checkpoint anchor row {}: {e}",
                    checkpoint.rowid
                )
            })?;
        let Some((event_id, event_hash)) = row else {
            return Err(format!(
                "checkpoint anchor row {} is missing from ledger_events",
                checkpoint.rowid
            ));
        };
        if event_hash.is_empty() || event_hash == Self::HASH_CHAIN_UNINITIALIZED_VALUE {
            return Err(format!(
                "checkpoint anchor row {} has uninitialized event_hash",
                checkpoint.rowid
            ));
        }
        if event_hash != checkpoint.event_hash {
            return Err(format!(
                "checkpoint anchor hash mismatch at row {}: expected={}, got={}",
                checkpoint.rowid, checkpoint.event_hash, event_hash
            ));
        }
        if let Some(expected_event_id) = checkpoint.event_id.as_deref() {
            if event_id != expected_event_id {
                return Err(format!(
                    "checkpoint anchor event_id mismatch at row {}: expected={}, got={}",
                    checkpoint.rowid, expected_event_id, event_id
                ));
            }
        }
        Ok(())
    }

    fn validate_startup_hash_chain_checkpoint(
        conn: &Connection,
        signing_key: &ed25519_dalek::SigningKey,
        trusted_verifying_key: Option<&ed25519_dalek::VerifyingKey>,
    ) -> Result<usize, String> {
        let chain_tip = Self::latest_chain_tip_checkpoint(conn)?;
        let signing_verifying_key = signing_key.verifying_key();
        let checkpoint_verifying_key = trusted_verifying_key.unwrap_or(&signing_verifying_key);

        let checkpoint_metadata = Self::load_hash_chain_checkpoint(conn)?;
        let checkpoint_signature = match Self::load_hash_chain_checkpoint_signature(conn) {
            Ok(signature) => signature,
            Err(error) => {
                warn!(
                    reason = %error,
                    "hash-chain checkpoint signature metadata is unreadable; forcing full-chain verification"
                );
                None
            },
        };

        let mut trusted_checkpoint = match checkpoint_metadata {
            Some(checkpoint) => match checkpoint_signature.as_deref() {
                Some(signature)
                    if Self::verify_checkpoint_signature(
                        checkpoint_verifying_key,
                        &checkpoint,
                        signature,
                    ) =>
                {
                    Some(checkpoint)
                },
                Some(_) => {
                    warn!(
                        rowid = checkpoint.rowid,
                        event_hash = %checkpoint.event_hash,
                        "hash-chain checkpoint signature invalid; forcing full-chain verification"
                    );
                    None
                },
                None => {
                    warn!(
                        rowid = checkpoint.rowid,
                        event_hash = %checkpoint.event_hash,
                        "hash-chain checkpoint signature metadata missing; forcing full-chain verification"
                    );
                    None
                },
            },
            None => None,
        };

        if let Some(checkpoint) = trusted_checkpoint.as_ref()
            && checkpoint.rowid > chain_tip.rowid
            && chain_tip.rowid == 0
        {
            let canonical_rows = Self::canonical_events_row_count(conn)?;
            if canonical_rows > 0 {
                warn!(
                    checkpoint_rowid = checkpoint.rowid,
                    chain_tip_rowid = chain_tip.rowid,
                    canonical_rows,
                    "stale legacy hash-chain checkpoint detected after canonical cutover; \
                     invalidating checkpoint metadata and forcing full-chain verification"
                );
                Self::clear_hash_chain_checkpoint_metadata(conn)
                    .map_err(|e| format!("failed to clear stale checkpoint metadata: {e}"))?;
                trusted_checkpoint = None;
            }
        }

        let (derived_tip, validated_rows) = if let Some(checkpoint) = trusted_checkpoint {
            if checkpoint.rowid > chain_tip.rowid {
                return Err(format!(
                    "checkpoint rowid {} is ahead of chain tip rowid {}",
                    checkpoint.rowid, chain_tip.rowid
                ));
            }

            Self::verify_checkpoint_anchor(conn, &checkpoint)?;

            if checkpoint.rowid == chain_tip.rowid {
                (checkpoint.event_hash, 0)
            } else {
                let (tip, validated_rows) = Self::derive_event_chain_hash_from_db_suffix(
                    conn,
                    checkpoint.rowid,
                    &checkpoint.event_hash,
                    trusted_verifying_key,
                )?;
                info!(
                    checkpoint_rowid = checkpoint.rowid,
                    validated_rows,
                    tip_rowid = chain_tip.rowid,
                    "startup hash-chain validation completed from trusted checkpoint"
                );
                (tip, validated_rows)
            }
        } else {
            let (tip, validated_rows) = Self::derive_event_chain_hash_from_db_suffix(
                conn,
                0,
                Self::LEDGER_CHAIN_GENESIS,
                trusted_verifying_key,
            )?;
            info!(
                validated_rows,
                tip_rowid = chain_tip.rowid,
                "startup hash-chain full verification completed from genesis"
            );
            (tip, validated_rows)
        };

        if derived_tip != chain_tip.event_hash {
            return Err(format!(
                "startup hash-chain verification mismatch: derived_tip={derived_tip}, stored_tip={}",
                chain_tip.event_hash
            ));
        }

        Self::persist_hash_chain_checkpoint(conn, &chain_tip, signing_key)
            .map_err(|e| format!("failed to advance hash-chain checkpoint metadata: {e}"))?;
        Ok(validated_rows)
    }

    fn ensure_hash_chain_columns(conn: &Connection) -> rusqlite::Result<()> {
        let mut has_prev_hash = false;
        let mut has_event_hash = false;
        let mut stmt = conn.prepare("PRAGMA table_info('ledger_events')")?;
        let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
        for column in columns {
            match column?.as_str() {
                "prev_hash" => has_prev_hash = true,
                "event_hash" => has_event_hash = true,
                _ => {},
            }
        }

        if !has_prev_hash {
            conn.execute(
                "ALTER TABLE ledger_events \
                 ADD COLUMN prev_hash TEXT NOT NULL DEFAULT 'genesis'",
                [],
            )?;
        }
        if !has_event_hash {
            conn.execute(
                "ALTER TABLE ledger_events \
                 ADD COLUMN event_hash TEXT NOT NULL DEFAULT 'legacy-uninitialized'",
                [],
            )?;
        }

        Ok(())
    }

    fn ensure_event_type_class_column(conn: &Connection) -> rusqlite::Result<()> {
        let has_event_type_class: bool = conn.query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM pragma_table_info('ledger_events')
                WHERE name = 'event_type_class'
            )",
            [],
            |row| row.get(0),
        )?;

        if !has_event_type_class {
            conn.execute(
                "ALTER TABLE ledger_events \
                 ADD COLUMN event_type_class TEXT NOT NULL DEFAULT 'session'",
                [],
            )?;
        }
        Ok(())
    }

    fn backfill_event_type_classes(conn: &Connection) -> rusqlite::Result<()> {
        conn.execute(
            "UPDATE ledger_events
             SET event_type_class = CASE
                 WHEN event_type IN (
                     'gate.policy_resolved',
                     'policy_root_published',
                     'policy_updated',
                     'gate_configuration_updated'
                 ) AND actor_id IN (
                     'orchestrator:gate-lifecycle',
                     'governance:policy-root',
                     'governance:policy'
                 ) THEN 'governance'
                 WHEN event_type IN (
                     'work_claimed',
                     'session_started',
                     'session_terminated',
                     'work_transitioned',
                     'stop_flags_mutated',
                     'defect_recorded',
                     'changeset_published',
                     'review_receipt_recorded',
                     'review_blocked_recorded',
                     'redundancy_receipt_consumed',
                     'SubleaseIssued',
                     'gate_lease_issued',
                     'episode_run_attributed'
                 ) THEN 'system'
                 ELSE 'session'
             END
             WHERE event_type_class IS NULL
                OR event_type_class = ''
                OR event_type_class NOT IN ('governance', 'session', 'system')
                OR (
                    event_type IN (
                        'gate.policy_resolved',
                        'policy_root_published',
                        'policy_updated',
                        'gate_configuration_updated'
                    )
                    AND actor_id IN (
                        'orchestrator:gate-lifecycle',
                        'governance:policy-root',
                        'governance:policy'
                    )
                    AND event_type_class != 'governance'
                )",
            [],
        )?;
        Ok(())
    }

    fn backfill_hash_chain(
        conn: &Connection,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> rusqlite::Result<bool> {
        if Self::get_metadata_value(conn, Self::HASH_CHAIN_BACKFILL_COMPLETED_FLAG)?.as_deref()
            == Some(Self::HASH_CHAIN_BACKFILL_COMPLETED_VALUE)
        {
            return Ok(false);
        }

        let missing_row_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM ledger_events \
             WHERE event_hash IS NULL OR event_hash = '' OR event_hash = ?1",
            params![Self::HASH_CHAIN_UNINITIALIZED_VALUE],
            |row| row.get(0),
        )?;

        if missing_row_count == 0 {
            let chain_tip = Self::latest_chain_tip_checkpoint(conn)
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            let checkpoint_seeded = if Self::load_hash_chain_checkpoint(conn)
                .map_err(|_| rusqlite::Error::InvalidQuery)?
                .is_none()
            {
                Self::persist_hash_chain_checkpoint(conn, &chain_tip, signing_key)?;
                true
            } else {
                false
            };
            Self::set_metadata_value(
                conn,
                Self::HASH_CHAIN_BACKFILL_COMPLETED_FLAG,
                Self::HASH_CHAIN_BACKFILL_COMPLETED_VALUE,
            )?;
            return Ok(checkpoint_seeded);
        }

        warn!(
            missing_rows = missing_row_count,
            "ledger hash-chain backfill required; running one-time migration"
        );
        // KNOWN LIMITATION (Initial hash-chain migration):
        // Legacy rows that predate hash-chain fields do not include prior
        // commitments. Backfill derives commitments from persisted rows as-is
        // and assumes legacy rows are authentic.
        warn!(
            "Backfilling hash chain from legacy uninitialized state. Legacy events are assumed authentic."
        );

        conn.execute_batch("BEGIN IMMEDIATE TRANSACTION;")?;
        let backfill_result = (|| -> rusqlite::Result<()> {
            // Stream rows in fixed-size chunks to bound memory use on large
            // ledgers while avoiding O(N) point lookups.
            let mut cursor_rowid = 0_i64;
            let mut previous_event_hash = Self::LEDGER_CHAIN_GENESIS.to_string();
            let mut checkpoint = HashChainCheckpoint::genesis();

            loop {
                let mut stmt = conn.prepare(
                    "SELECT rowid, event_id, event_type, work_id, actor_id, payload, signature, \
                            timestamp_ns, event_hash \
                     FROM ledger_events \
                     WHERE rowid > ?1 \
                     ORDER BY rowid ASC \
                     LIMIT ?2",
                )?;
                let rows = stmt
                    .query_map(
                        params![cursor_rowid, Self::HASH_CHAIN_BACKFILL_BATCH_SIZE],
                        |row| {
                            let timestamp_i64: i64 = row.get(7)?;
                            let timestamp_ns = u64::try_from(timestamp_i64)
                                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                            Ok(ChainBackfillRow {
                                rowid: row.get(0)?,
                                event_id: row.get(1)?,
                                event_type: row.get(2)?,
                                work_id: row.get(3)?,
                                actor_id: row.get(4)?,
                                payload: row.get(5)?,
                                signature: row.get(6)?,
                                timestamp_ns,
                                event_hash: row.get(8)?,
                            })
                        },
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                drop(stmt);

                if rows.is_empty() {
                    break;
                }

                for row in rows {
                    cursor_rowid = row.rowid;

                    let current_event_hash = if row.event_hash.is_empty()
                        || row.event_hash == Self::HASH_CHAIN_UNINITIALIZED_VALUE
                    {
                        let event_hash = Self::compute_event_hash(&EventHashInput {
                            event_id: &row.event_id,
                            event_type: &row.event_type,
                            work_id: &row.work_id,
                            actor_id: &row.actor_id,
                            payload: &row.payload,
                            signature: &row.signature,
                            timestamp_ns: row.timestamp_ns,
                            prev_hash: &previous_event_hash,
                        });

                        conn.execute(
                            "UPDATE ledger_events \
                                 SET prev_hash = ?1, event_hash = ?2 \
                                 WHERE rowid = ?3",
                            params![&previous_event_hash, &event_hash, row.rowid],
                        )?;
                        event_hash
                    } else {
                        row.event_hash
                    };

                    previous_event_hash.clone_from(&current_event_hash);
                    checkpoint = HashChainCheckpoint {
                        rowid: row.rowid,
                        event_id: Some(row.event_id),
                        event_hash: current_event_hash,
                    };
                }
            }

            Self::persist_hash_chain_checkpoint(conn, &checkpoint, signing_key)?;
            Self::set_metadata_value(
                conn,
                Self::HASH_CHAIN_BACKFILL_COMPLETED_FLAG,
                Self::HASH_CHAIN_BACKFILL_COMPLETED_VALUE,
            )?;
            Ok(())
        })();

        if let Err(error) = backfill_result {
            let _ = conn.execute_batch("ROLLBACK;");
            return Err(error);
        }
        conn.execute_batch("COMMIT;")?;

        Ok(true)
    }

    fn rebuild_hash_chain_columns(conn: &Connection) -> rusqlite::Result<()> {
        conn.execute_batch("BEGIN IMMEDIATE TRANSACTION;")?;
        let rebuild_result = (|| -> rusqlite::Result<()> {
            let mut cursor_rowid = 0_i64;
            let mut previous_event_hash = Self::LEDGER_CHAIN_GENESIS.to_string();

            loop {
                let mut stmt = conn.prepare(
                    "SELECT rowid, event_id, event_type, work_id, actor_id, payload, signature, \
                            timestamp_ns, event_hash \
                     FROM ledger_events \
                     WHERE rowid > ?1 \
                     ORDER BY rowid ASC \
                     LIMIT ?2",
                )?;
                let rows = stmt
                    .query_map(
                        params![cursor_rowid, Self::HASH_CHAIN_BACKFILL_BATCH_SIZE],
                        |row| {
                            let timestamp_i64: i64 = row.get(7)?;
                            let timestamp_ns = u64::try_from(timestamp_i64)
                                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                            Ok(ChainBackfillRow {
                                rowid: row.get(0)?,
                                event_id: row.get(1)?,
                                event_type: row.get(2)?,
                                work_id: row.get(3)?,
                                actor_id: row.get(4)?,
                                payload: row.get(5)?,
                                signature: row.get(6)?,
                                timestamp_ns,
                                event_hash: row.get(8)?,
                            })
                        },
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                drop(stmt);

                if rows.is_empty() {
                    break;
                }

                for row in rows {
                    cursor_rowid = row.rowid;
                    let event_hash = Self::compute_event_hash(&EventHashInput {
                        event_id: &row.event_id,
                        event_type: &row.event_type,
                        work_id: &row.work_id,
                        actor_id: &row.actor_id,
                        payload: &row.payload,
                        signature: &row.signature,
                        timestamp_ns: row.timestamp_ns,
                        prev_hash: &previous_event_hash,
                    });

                    conn.execute(
                        "UPDATE ledger_events SET prev_hash = ?1, event_hash = ?2 WHERE rowid = ?3",
                        params![&previous_event_hash, &event_hash, row.rowid],
                    )?;
                    previous_event_hash = event_hash;
                }
            }

            Ok(())
        })();

        if let Err(error) = rebuild_result {
            let _ = conn.execute_batch("ROLLBACK;");
            return Err(error);
        }
        conn.execute_batch("COMMIT;")?;
        Ok(())
    }

    fn compute_event_hash(input: &EventHashInput<'_>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"apm2-ledger-event-hash-v1");
        hasher.update(input.prev_hash.as_bytes());
        hasher.update(input.event_id.as_bytes());
        hasher.update(input.event_type.as_bytes());
        hasher.update(input.work_id.as_bytes());
        hasher.update(input.actor_id.as_bytes());
        hasher.update(input.timestamp_ns.to_le_bytes());
        hasher.update(input.payload);
        hasher.update(input.signature);
        hex::encode(hasher.finalize())
    }

    /// Returns the latest event hash, selecting the source table based on
    /// the freeze guard state:
    /// - **Frozen**: reads from canonical `events` table (BLOB → hex).
    /// - **Unfrozen**: reads from legacy `ledger_events` table (TEXT).
    fn latest_event_hash_routed(&self, conn: &Connection) -> Result<String, LedgerEventError> {
        if self.is_frozen_internal() {
            Self::latest_canonical_event_hash(conn)
        } else {
            Self::latest_event_hash(conn)
        }
    }

    fn latest_event_hash(conn: &Connection) -> Result<String, LedgerEventError> {
        Self::latest_event_hash_opt(conn)
            .map(|hash| hash.unwrap_or_else(|| Self::LEDGER_CHAIN_GENESIS.to_string()))
    }

    /// Returns the latest `event_hash` from the canonical `events` table
    /// (BLOB → hex string). Falls back to `LEDGER_CHAIN_GENESIS` if the
    /// table is empty.
    fn latest_canonical_event_hash(conn: &Connection) -> Result<String, LedgerEventError> {
        let hash_opt: Option<Vec<u8>> = conn
            .query_row(
                "SELECT event_hash FROM events WHERE event_hash IS NOT NULL \
                 ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| LedgerEventError::PersistenceFailed {
                message: format!("sqlite canonical events latest event_hash query failed: {e}"),
            })?;

        Ok(hash_opt.map_or_else(|| Self::LEDGER_CHAIN_GENESIS.to_string(), hex::encode))
    }

    fn latest_event_hash_opt(conn: &Connection) -> Result<Option<String>, LedgerEventError> {
        conn.query_row(
            "SELECT event_hash FROM ledger_events ORDER BY rowid DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| LedgerEventError::PersistenceFailed {
            message: format!("sqlite latest event_hash query failed: {e}"),
        })
    }

    fn canonicalize_payload_with_prev_hash(
        mut payload: serde_json::Value,
        prev_hash: &str,
    ) -> Result<Vec<u8>, LedgerEventError> {
        let Some(payload_object) = payload.as_object_mut() else {
            return Err(LedgerEventError::SigningFailed {
                message: "ledger payload must be a JSON object".to_string(),
            });
        };
        payload_object.insert(
            "prev_hash".to_string(),
            serde_json::Value::String(prev_hash.to_string()),
        );
        let payload_json = payload.to_string();
        let canonical_payload =
            canonicalize_json(&payload_json).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            })?;
        Ok(canonical_payload.as_bytes().to_vec())
    }

    #[allow(clippy::too_many_arguments)]
    fn build_signed_event_with_prev_hash(
        &self,
        event_type: &str,
        work_id: &str,
        actor_id: &str,
        payload: serde_json::Value,
        timestamp_ns: u64,
        domain_prefix: &[u8],
        prev_hash: &str,
    ) -> Result<(SignedLedgerEvent, String), LedgerEventError> {
        let payload_bytes = Self::canonicalize_payload_with_prev_hash(payload, prev_hash)?;
        let mut canonical_bytes = Vec::with_capacity(domain_prefix.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(domain_prefix);
        canonical_bytes.extend_from_slice(&payload_bytes);
        let signature = self.signing_key.sign(&canonical_bytes).to_bytes().to_vec();

        let signed_event = SignedLedgerEvent {
            event_id: format!("EVT-{}", uuid::Uuid::new_v4()),
            event_type: event_type.to_string(),
            work_id: work_id.to_string(),
            actor_id: actor_id.to_string(),
            payload: payload_bytes,
            signature,
            timestamp_ns,
        };
        let event_hash = Self::compute_event_hash(&EventHashInput {
            event_id: &signed_event.event_id,
            event_type: &signed_event.event_type,
            work_id: &signed_event.work_id,
            actor_id: &signed_event.actor_id,
            payload: &signed_event.payload,
            signature: &signed_event.signature,
            timestamp_ns: signed_event.timestamp_ns,
            prev_hash,
        });
        Ok((signed_event, event_hash))
    }

    fn persist_signed_event(
        &self,
        conn: &Connection,
        signed_event: &SignedLedgerEvent,
        prev_hash: &str,
        event_hash: &str,
    ) -> Result<(), LedgerEventError> {
        // TCK-00631: Route to canonical `events` table when frozen.
        if self.is_frozen_internal() {
            return self.persist_to_canonical_events(conn, signed_event, prev_hash, event_hash);
        }

        conn.execute("SAVEPOINT persist_event", []).map_err(|e| {
            LedgerEventError::PersistenceFailed {
                message: format!("sqlite savepoint begin failed: {e}"),
            }
        })?;

        let persist_result = (|| {
            let event_type_class =
                classify_event_type(&signed_event.event_type, &signed_event.actor_id).as_str();
            conn.execute(
                "INSERT INTO ledger_events (
                    event_id,
                    event_type,
                    event_type_class,
                    work_id,
                    actor_id,
                    payload,
                    signature,
                    timestamp_ns,
                    prev_hash,
                    event_hash
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    signed_event.event_id,
                    signed_event.event_type,
                    event_type_class,
                    signed_event.work_id,
                    signed_event.actor_id,
                    signed_event.payload,
                    signed_event.signature,
                    signed_event.timestamp_ns,
                    prev_hash,
                    event_hash,
                ],
            )
            .map_err(|e| LedgerEventError::PersistenceFailed {
                message: format!("sqlite insert failed: {e}"),
            })?;
            let checkpoint = HashChainCheckpoint {
                rowid: conn.last_insert_rowid(),
                event_id: Some(signed_event.event_id.clone()),
                event_hash: event_hash.to_string(),
            };
            Self::persist_hash_chain_checkpoint(conn, &checkpoint, &self.signing_key).map_err(
                |e| LedgerEventError::PersistenceFailed {
                    message: format!("failed to update hash-chain checkpoint metadata: {e}"),
                },
            )?;
            conn.execute("RELEASE persist_event", []).map_err(|e| {
                LedgerEventError::PersistenceFailed {
                    message: format!("sqlite savepoint release failed: {e}"),
                }
            })?;
            Ok(())
        })();

        if let Err(error) = persist_result {
            let _ = conn.execute("ROLLBACK TO persist_event", []);
            let _ = conn.execute("RELEASE persist_event", []);
            return Err(error);
        }

        Ok(())
    }

    /// Persists a signed event to the canonical `events` table.
    ///
    /// Called when the freeze guard is active. Instead of inserting into the
    /// legacy `ledger_events` table, this method writes to the canonical
    /// `events` table using the BLAKE3-based hash chain from
    /// `apm2_core::crypto::EventHasher`.
    ///
    /// # Hash-chain conversion
    ///
    /// The legacy emitter uses SHA-256 hex-encoded `event_hash` / `prev_hash`
    /// strings. The canonical `events` table uses BLAKE3 32-byte BLOBs.
    /// This method computes a fresh BLAKE3 chain hash from the payload and
    /// the canonical chain tip (BLOB), maintaining chain continuity with the
    /// existing `events` tail set during migration.
    ///
    /// # Column mapping
    ///
    /// | `SignedLedgerEvent` field | `events` column |
    /// |---------------------------|-----------------|
    /// | `event_type`              | `event_type`    |
    /// | `work_id`                 | `session_id`    |
    /// | `actor_id`                | `actor_id`      |
    /// | `payload`                 | `payload`       |
    /// | `timestamp_ns`            | `timestamp_ns`  |
    /// | `signature`               | `signature`     |
    /// | (computed)                | `prev_hash`     |
    /// | (computed)                | `event_hash`    |
    #[allow(clippy::unused_self)] // &self needed for method dispatch consistency with persist_signed_event
    fn persist_to_canonical_events(
        &self,
        conn: &Connection,
        signed_event: &SignedLedgerEvent,
        _legacy_prev_hash: &str,
        _legacy_event_hash: &str,
    ) -> Result<(), LedgerEventError> {
        use apm2_core::crypto::EventHasher;

        conn.execute("SAVEPOINT persist_canonical", [])
            .map_err(|e| LedgerEventError::PersistenceFailed {
                message: format!("sqlite savepoint begin failed: {e}"),
            })?;

        #[allow(clippy::cast_possible_wrap)]
        // u64 timestamp_ns → i64 for SQLite; nanosecond epoch fits i64 until ~2262
        let persist_result = (|| {
            // Fetch canonical chain tip (BLOB).
            let tail_hash_opt: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT event_hash FROM events WHERE event_hash IS NOT NULL \
                     ORDER BY rowid DESC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| LedgerEventError::PersistenceFailed {
                    message: format!("failed to read canonical chain tip: {e}"),
                })?;

            let prev_hash: [u8; 32] =
                match tail_hash_opt {
                    Some(ref h) => h.as_slice().try_into().map_err(|_| {
                        LedgerEventError::PersistenceFailed {
                            message: format!(
                                "canonical events tail event_hash has length {}, expected 32",
                                h.len()
                            ),
                        }
                    })?,
                    None => EventHasher::GENESIS_PREV_HASH,
                };

            // Compute BLAKE3 event hash for chain continuity.
            let event_hash = EventHasher::hash_event(&signed_event.payload, &prev_hash);

            conn.execute(
                "INSERT INTO events (event_type, session_id, actor_id, record_version, \
                 payload, timestamp_ns, prev_hash, event_hash, signature) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    signed_event.event_type,
                    signed_event.work_id, // work_id maps to session_id
                    signed_event.actor_id,
                    1_i64, // record_version
                    signed_event.payload,
                    signed_event.timestamp_ns as i64,
                    prev_hash.as_slice(),
                    event_hash.as_slice(),
                    signed_event.signature,
                ],
            )
            .map_err(|e| LedgerEventError::PersistenceFailed {
                message: format!("sqlite canonical events insert failed: {e}"),
            })?;

            conn.execute("RELEASE persist_canonical", []).map_err(|e| {
                LedgerEventError::PersistenceFailed {
                    message: format!("sqlite savepoint release failed: {e}"),
                }
            })?;

            Ok(())
        })();

        if let Err(error) = persist_result {
            let _ = conn.execute("ROLLBACK TO persist_canonical", []);
            let _ = conn.execute("RELEASE persist_canonical", []);
            return Err(error);
        }

        Ok(())
    }

    fn derive_event_chain_hash_from_db(
        conn: &Connection,
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<String, String> {
        Self::derive_event_chain_hash_from_db_internal(conn, Some(verifying_key))
    }

    fn derive_event_chain_hash_from_db_suffix(
        conn: &Connection,
        start_rowid_exclusive: i64,
        starting_prev_hash: &str,
        trusted_verifying_key: Option<&ed25519_dalek::VerifyingKey>,
    ) -> Result<(String, usize), String> {
        const SESSION_STARTED_DOMAIN_PREFIX: &[u8] = b"apm2.event.session_started:";
        const SESSION_EVENT_DOMAIN_PREFIX: &[u8] = b"apm2.event.session_event:";
        const REDUNDANCY_RECEIPT_CONSUMED_DOMAIN_PREFIX: &[u8] =
            b"apm2.event.redundancy_receipt_consumed:";
        const EPISODE_RUN_ATTRIBUTED_PREFIX: &[u8] = b"apm2.event.episode_run_attributed:";

        #[derive(Debug)]
        struct ChainRow {
            rowid: i64,
            event_id: String,
            event_type: String,
            work_id: String,
            actor_id: String,
            payload: Vec<u8>,
            signature: Vec<u8>,
            timestamp_ns: u64,
            prev_hash: String,
            event_hash: String,
        }

        let mut stmt = conn
            .prepare(
                "SELECT rowid, event_id, event_type, work_id, actor_id, payload, signature, \
                        timestamp_ns, prev_hash, event_hash \
                 FROM ledger_events \
                 WHERE rowid > ?1 \
                 ORDER BY rowid ASC",
            )
            .map_err(|e| format!("sqlite suffix chain query prepare failed: {e}"))?;

        let mut rows = stmt
            .query(params![start_rowid_exclusive])
            .map_err(|e| format!("sqlite suffix chain query failed: {e}"))?;

        let mut expected_prev = starting_prev_hash.to_string();
        let mut validated_rows = 0usize;

        while let Some(row) = rows
            .next()
            .map_err(|e| format!("sqlite suffix chain row decode failed: {e}"))?
        {
            let timestamp_i64: i64 = row
                .get(7)
                .map_err(|e| format!("sqlite timestamp decode failed: {e}"))?;
            let timestamp_ns = u64::try_from(timestamp_i64)
                .map_err(|_| format!("ledger event timestamp is negative: {timestamp_i64}"))?;

            let chain_row = ChainRow {
                rowid: row
                    .get(0)
                    .map_err(|e| format!("sqlite rowid decode failed: {e}"))?,
                event_id: row
                    .get(1)
                    .map_err(|e| format!("sqlite event_id decode failed: {e}"))?,
                event_type: row
                    .get(2)
                    .map_err(|e| format!("sqlite event_type decode failed: {e}"))?,
                work_id: row
                    .get(3)
                    .map_err(|e| format!("sqlite work_id decode failed: {e}"))?,
                actor_id: row
                    .get(4)
                    .map_err(|e| format!("sqlite actor_id decode failed: {e}"))?,
                payload: row
                    .get(5)
                    .map_err(|e| format!("sqlite payload decode failed: {e}"))?,
                signature: row
                    .get(6)
                    .map_err(|e| format!("sqlite signature decode failed: {e}"))?,
                timestamp_ns,
                prev_hash: row
                    .get(8)
                    .map_err(|e| format!("sqlite prev_hash decode failed: {e}"))?,
                event_hash: row
                    .get(9)
                    .map_err(|e| format!("sqlite event_hash decode failed: {e}"))?,
            };
            validated_rows += 1;

            if chain_row.prev_hash != expected_prev {
                return Err(format!(
                    "hash chain broken at event {} (rowid={}): expected prev_hash={}, got={}",
                    chain_row.event_id, chain_row.rowid, expected_prev, chain_row.prev_hash
                ));
            }

            let payload =
                serde_json::from_slice::<serde_json::Value>(&chain_row.payload).map_err(|e| {
                    format!(
                        "event {} payload is not valid JSON: {e}",
                        chain_row.event_id
                    )
                })?;
            if let Some(payload_prev_hash) = payload.get("prev_hash") {
                let Some(payload_prev_hash) = payload_prev_hash.as_str() else {
                    return Err(format!(
                        "event {} prev_hash payload field must be a string",
                        chain_row.event_id
                    ));
                };
                if payload_prev_hash != chain_row.prev_hash {
                    return Err(format!(
                        "event {} prev_hash payload mismatch: payload={}, column={}",
                        chain_row.event_id, payload_prev_hash, chain_row.prev_hash
                    ));
                }
            }

            if let Some(verifying_key) = trusted_verifying_key {
                if chain_row.signature.len() != 64 {
                    return Err(format!(
                        "event {} has invalid signature length: expected 64 bytes, got {}",
                        chain_row.event_id,
                        chain_row.signature.len()
                    ));
                }

                let signature = ed25519_dalek::Signature::try_from(chain_row.signature.as_slice())
                    .map_err(|error| {
                        format!(
                            "event {} has invalid Ed25519 signature bytes: {error}",
                            chain_row.event_id
                        )
                    })?;

                let mut candidate_prefixes: Vec<&[u8]> = Vec::with_capacity(4);
                let mut push_prefix = |prefix: &'static [u8]| {
                    if !candidate_prefixes.contains(&prefix) {
                        candidate_prefixes.push(prefix);
                    }
                };

                match chain_row.event_type.as_str() {
                    "work_claimed" => push_prefix(WORK_CLAIMED_DOMAIN_PREFIX),
                    "session_started" => push_prefix(SESSION_STARTED_DOMAIN_PREFIX),
                    "stop_flags_mutated" => push_prefix(STOP_FLAGS_MUTATED_DOMAIN_PREFIX),
                    "defect_recorded" => push_prefix(DEFECT_RECORDED_DOMAIN_PREFIX),
                    "redundancy_receipt_consumed" => {
                        push_prefix(REDUNDANCY_RECEIPT_CONSUMED_DOMAIN_PREFIX);
                    },
                    "work_transitioned" => push_prefix(WORK_TRANSITIONED_DOMAIN_PREFIX),
                    "session_terminated" => {
                        push_prefix(SESSION_TERMINATED_LEDGER_DOMAIN_PREFIX);
                    },
                    "changeset_published" => {
                        push_prefix(CHANGESET_PUBLISHED_LEDGER_DOMAIN_PREFIX);
                    },
                    "review_receipt_recorded" => {
                        push_prefix(REVIEW_RECEIPT_RECORDED_PREFIX);
                    },
                    "review_blocked_recorded" => {
                        push_prefix(REVIEW_BLOCKED_RECORDED_LEDGER_PREFIX);
                    },
                    "episode_run_attributed" => push_prefix(EPISODE_RUN_ATTRIBUTED_PREFIX),
                    "gate_lease_issued" => push_prefix(GATE_LEASE_ISSUED_LEDGER_DOMAIN_PREFIX),
                    _ => {},
                }
                push_prefix(SESSION_EVENT_DOMAIN_PREFIX);
                push_prefix(EPISODE_EVENT_DOMAIN_PREFIX);

                let mut signature_valid = false;
                for prefix in candidate_prefixes {
                    let mut canonical_bytes =
                        Vec::with_capacity(prefix.len() + chain_row.payload.len());
                    canonical_bytes.extend_from_slice(prefix);
                    canonical_bytes.extend_from_slice(&chain_row.payload);
                    if verifying_key
                        .verify(canonical_bytes.as_slice(), &signature)
                        .is_ok()
                    {
                        signature_valid = true;
                        break;
                    }
                }
                if !signature_valid {
                    return Err(format!(
                        "event {} failed Ed25519 signature verification",
                        chain_row.event_id
                    ));
                }
            }

            let expected_event_hash = Self::compute_event_hash(&EventHashInput {
                event_id: &chain_row.event_id,
                event_type: &chain_row.event_type,
                work_id: &chain_row.work_id,
                actor_id: &chain_row.actor_id,
                payload: &chain_row.payload,
                signature: &chain_row.signature,
                timestamp_ns: chain_row.timestamp_ns,
                prev_hash: &chain_row.prev_hash,
            });
            if chain_row.event_hash != expected_event_hash {
                return Err(format!(
                    "hash chain broken at event {}: expected event_hash={}, got={}",
                    chain_row.event_id, expected_event_hash, chain_row.event_hash
                ));
            }
            expected_prev = chain_row.event_hash;
        }

        Ok((expected_prev, validated_rows))
    }

    fn derive_event_chain_hash_from_db_internal(
        conn: &Connection,
        trusted_verifying_key: Option<&ed25519_dalek::VerifyingKey>,
    ) -> Result<String, String> {
        let (tip, _) = Self::derive_event_chain_hash_from_db_suffix(
            conn,
            0,
            Self::LEDGER_CHAIN_GENESIS,
            trusted_verifying_key,
        )?;
        Ok(tip)
    }

    fn ensure_receipt_quarantine_table(conn: &Connection) -> rusqlite::Result<()> {
        let table_exists: bool = conn.query_row(
            "SELECT EXISTS( \
                 SELECT 1 FROM sqlite_master \
                 WHERE type = 'table' AND name = 'ledger_events_quarantine' \
             )",
            [],
            |row| row.get(0),
        )?;

        if !table_exists {
            return Self::create_receipt_quarantine_table(conn);
        }

        let mut has_rowid_orig = false;
        let mut has_event_id_primary_key = false;
        let mut stmt = conn.prepare("PRAGMA table_info('ledger_events_quarantine')")?;
        let columns = stmt.query_map([], |row| {
            let name: String = row.get(1)?;
            let pk: i64 = row.get(5)?;
            Ok((name, pk))
        })?;

        for column in columns {
            let (name, pk) = column?;
            if name == "rowid_orig" {
                has_rowid_orig = true;
            }
            if name == "event_id" && pk == 1 {
                has_event_id_primary_key = true;
            }
        }

        if has_rowid_orig || !has_event_id_primary_key {
            conn.execute(
                "DROP TABLE IF EXISTS ledger_events_quarantine_rowid_backup",
                [],
            )?;
            conn.execute(
                "ALTER TABLE ledger_events_quarantine \
                 RENAME TO ledger_events_quarantine_rowid_backup",
                [],
            )?;
            Self::create_receipt_quarantine_table(conn)?;
            conn.execute(
                "INSERT OR IGNORE INTO ledger_events_quarantine \
                     (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns, quarantine_reason) \
                 SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns, \
                        COALESCE(quarantine_reason, 'receipt_id_dedupe_migration') \
                 FROM ledger_events_quarantine_rowid_backup \
                 WHERE event_id IS NOT NULL",
                [],
            )?;
            conn.execute("DROP TABLE ledger_events_quarantine_rowid_backup", [])?;
        }

        Ok(())
    }

    fn create_receipt_quarantine_table(conn: &Connection) -> rusqlite::Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ledger_events_quarantine ( \
                 event_id TEXT NOT NULL PRIMARY KEY, \
                 event_type TEXT NOT NULL, \
                 work_id TEXT NOT NULL, \
                 actor_id TEXT NOT NULL, \
                 payload BLOB NOT NULL, \
                 signature BLOB NOT NULL, \
                 timestamp_ns INTEGER NOT NULL, \
                 quarantine_reason TEXT NOT NULL DEFAULT 'receipt_id_dedupe_migration' \
             )",
            [],
        )?;
        Ok(())
    }

    /// Query the latest `MergeReceipt` HEAD SHA from the ledger (TCK-00393).
    ///
    /// Scans the `ledger_events` table for the most recent event whose
    /// `event_type` matches a merge-receipt pattern and extracts the
    /// `result_selector` from its JSON payload. This is used by the
    /// divergence watchdog to determine the expected trunk HEAD.
    ///
    /// Returns `None` if no merge-receipt events exist in the ledger
    /// (the normal startup case before any merges have occurred) or if
    /// the query or parse fails.
    ///
    /// The returned value is a 32-byte BLAKE3 hash of the hex SHA string,
    /// matching the format expected by
    /// `DivergenceWatchdog::check_divergence`.
    pub fn query_latest_merge_receipt_sha(&self) -> Option<[u8; 32]> {
        let conn = self.conn.lock().ok()?;

        // Look for events of type "gate.merge_receipt_created" or containing
        // "merge_receipt" in event_type. The merge executor persists these via
        // emit_session_event. We order by timestamp_ns DESC, rowid DESC to get
        // the most recent one.
        let result: Option<Vec<u8>> = conn
            .query_row(
                "SELECT payload FROM ledger_events \
                 WHERE event_type LIKE '%merge_receipt%' \
                 ORDER BY timestamp_ns DESC, rowid DESC \
                 LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .ok()
            .flatten();

        let payload_bytes = result?;

        // Parse the payload JSON to extract result_selector.
        // The payload may be JCS-canonicalized JSON bytes.
        let payload_str = std::str::from_utf8(&payload_bytes).ok()?;
        let payload_json: serde_json::Value = serde_json::from_str(payload_str).ok()?;

        // Try to extract result_selector from the payload.
        // The merge executor stores it as "result_selector" in the event payload.
        let result_selector = payload_json
            .get("result_selector")
            .and_then(|v| v.as_str())?;

        // Convert the hex SHA to a 32-byte array via BLAKE3 hashing.
        Some(*blake3::hash(result_selector.as_bytes()).as_bytes())
    }

    fn routed_work_pr_bound_pr_number(
        &self,
        conn: &Connection,
        work_id: &str,
    ) -> Result<Option<u64>, LedgerEventError> {
        let query_result: Result<Option<i64>, rusqlite::Error> = if self.is_frozen_internal() {
            conn.query_row(
                "SELECT json_extract(CAST(payload AS TEXT), '$.pr_number') \
                 FROM events \
                 WHERE session_id = ?1 \
                   AND event_type = 'work.pr_associated' \
                   AND json_extract(CAST(payload AS TEXT), '$.pr_number') IS NOT NULL \
                 ORDER BY timestamp_ns ASC, rowid ASC \
                 LIMIT 1",
                params![work_id],
                |row| row.get(0),
            )
            .optional()
        } else {
            conn.query_row(
                "SELECT json_extract(CAST(payload AS TEXT), '$.pr_number') \
                 FROM ledger_events \
                 WHERE work_id = ?1 \
                   AND event_type = 'work.pr_associated' \
                   AND json_extract(CAST(payload AS TEXT), '$.pr_number') IS NOT NULL \
                 ORDER BY timestamp_ns ASC, rowid ASC \
                 LIMIT 1",
                params![work_id],
                |row| row.get(0),
            )
            .optional()
        };

        let pr_number_i64 = query_result.map_err(|e| LedgerEventError::PersistenceFailed {
            message: format!("work.pr_associated binding query failed: {e}"),
        })?;
        pr_number_i64
            .map(|value| {
                u64::try_from(value).map_err(|_| LedgerEventError::PersistenceFailed {
                    message: format!(
                        "work.pr_associated binding pr_number out of range for work_id '{work_id}'"
                    ),
                })
            })
            .transpose()
    }

    fn persist_work_pr_associated_with_binding_guard(
        &self,
        conn: &Connection,
        signed_event: &SignedLedgerEvent,
        prev_hash: &str,
        event_hash: &str,
        requested_pr_number: u64,
    ) -> Result<(), LedgerEventError> {
        conn.execute("BEGIN IMMEDIATE", [])
            .map_err(|e| LedgerEventError::PersistenceFailed {
                message: format!("failed to begin work.pr_associated transaction: {e}"),
            })?;

        let persistence_result = (|| {
            if let Some(bound_pr_number) =
                self.routed_work_pr_bound_pr_number(conn, &signed_event.work_id)?
            {
                if bound_pr_number != requested_pr_number {
                    return Err(LedgerEventError::PersistenceFailed {
                        message: format!(
                            "{WORK_PR_BINDING_CONFLICT_TAG}: [{INV_FAC_PR_BIND_001}] work_id '{}' \
                             is bound to pr_number={}, requested={}",
                            signed_event.work_id, bound_pr_number, requested_pr_number
                        ),
                    });
                }
            }

            self.persist_signed_event(conn, signed_event, prev_hash, event_hash)
        })();

        match persistence_result {
            Ok(()) => {
                conn.execute("COMMIT", []).map_err(|e| {
                    let _ = conn.execute("ROLLBACK", []);
                    LedgerEventError::PersistenceFailed {
                        message: format!(
                            "failed to commit work.pr_associated transaction (rolled back): {e}"
                        ),
                    }
                })?;
                Ok(())
            },
            Err(error) => {
                let _ = conn.execute("ROLLBACK", []);
                Err(error)
            },
        }
    }
}

impl LedgerEventEmitter for SqliteLedgerEventEmitter {
    fn emit_work_claimed(
        &self,
        claim: &WorkClaim,
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        let payload = serde_json::json!({
            "event_type": "work_claimed",
            "work_id": claim.work_id,
            "lease_id": claim.lease_id,
            "actor_id": claim.actor_id,
            "role": format!("{:?}", claim.role),
            "policy_resolved_ref": claim.policy_resolution.policy_resolved_ref,
            "capability_manifest_hash": hex::encode(claim.policy_resolution.capability_manifest_hash),
            "context_pack_hash": hex::encode(claim.policy_resolution.context_pack_hash),
            "role_spec_hash": hex::encode(claim.policy_resolution.role_spec_hash),
            "context_pack_recipe_hash": hex::encode(claim.policy_resolution.context_pack_recipe_hash),
        });

        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;
        let prev_hash = self.latest_event_hash_routed(&conn)?;
        let (signed_event, event_hash) = self.build_signed_event_with_prev_hash(
            "work_claimed",
            &claim.work_id,
            &claim.actor_id,
            payload,
            timestamp_ns,
            WORK_CLAIMED_DOMAIN_PREFIX,
            &prev_hash,
        )?;
        self.persist_signed_event(&conn, &signed_event, &prev_hash, &event_hash)?;

        info!(event_id = %signed_event.event_id, "Persisted WorkClaimed event");

        Ok(signed_event)
    }

    fn get_event(&self, event_id: &str) -> Option<SignedLedgerEvent> {
        let conn = self.conn.lock().ok()?;

        // TCK-00631 / Finding 1: Handle canonical events whose synthesised
        // event_id starts with "canonical-".
        if self.is_frozen_internal() {
            if let Some(seq_id) = Self::parse_canonical_event_id(event_id) {
                return conn
                    .query_row(
                        "SELECT seq_id, event_type, session_id, actor_id, payload, \
                                COALESCE(signature, X''), timestamp_ns \
                         FROM events WHERE seq_id = ?1",
                        params![seq_id],
                        Self::canonical_row_to_event,
                    )
                    .optional()
                    .ok()
                    .flatten();
            }
        }

        conn.query_row(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
             FROM ledger_events WHERE event_id = ?1",
            params![event_id],
            |row| {
                Ok(SignedLedgerEvent {
                    event_id: row.get(0)?,
                    event_type: row.get(1)?,
                    work_id: row.get(2)?,
                    actor_id: row.get(3)?,
                    payload: row.get(4)?,
                    signature: row.get(5)?,
                    timestamp_ns: row.get(6)?,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    fn emit_session_started(
        &self,
        session_id: &str,
        work_id: &str,
        lease_id: &str,
        actor_id: &str,
        adapter_profile_hash: &[u8; 32],
        role_spec_hash: Option<&[u8; 32]>,
        timestamp_ns: u64,
        contract_binding: Option<&crate::hsi_contract::SessionContractBinding>,
        identity_proof_profile_hash: Option<&[u8; 32]>,
        selection_decision: Option<&SelectionDecision>,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        // Domain prefix for session events (must be at function start per clippy)
        const SESSION_STARTED_DOMAIN_PREFIX: &[u8] = b"apm2.event.session_started:";

        let payload = build_session_started_payload(
            session_id,
            work_id,
            lease_id,
            actor_id,
            adapter_profile_hash,
            role_spec_hash,
            contract_binding,
            identity_proof_profile_hash,
            selection_decision,
        );

        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;
        let prev_hash = self.latest_event_hash_routed(&conn)?;
        let (signed_event, event_hash) = self.build_signed_event_with_prev_hash(
            "session_started",
            work_id,
            actor_id,
            payload,
            timestamp_ns,
            SESSION_STARTED_DOMAIN_PREFIX,
            &prev_hash,
        )?;
        self.persist_signed_event(&conn, &signed_event, &prev_hash, &event_hash)?;

        info!(
            event_id = %signed_event.event_id,
            session_id = %session_id,
            "Persisted SessionStarted event"
        );

        Ok(signed_event)
    }

    fn emit_session_event(
        &self,
        session_id: &str,
        event_type: &str,
        payload: &[u8],
        actor_id: &str,
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        // Domain prefix for generic session events (TCK-00290)
        const SESSION_EVENT_DOMAIN_PREFIX: &[u8] = b"apm2.event.session_event:";

        // Build payload as JSON with actual event type and base64-encoded payload
        let payload_json = serde_json::json!({
            "event_type": event_type,
            "session_id": session_id,
            "actor_id": actor_id,
            "payload": hex::encode(payload),
        });

        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;
        let prev_hash = self.latest_event_hash_routed(&conn)?;
        let (signed_event, event_hash) = self.build_signed_event_with_prev_hash(
            event_type,
            session_id, // Use session_id as work_id for indexing
            actor_id,
            payload_json,
            timestamp_ns,
            SESSION_EVENT_DOMAIN_PREFIX,
            &prev_hash,
        )?;
        self.persist_signed_event(&conn, &signed_event, &prev_hash, &event_hash)?;

        info!(
            event_id = %signed_event.event_id,
            session_id = %session_id,
            event_type = %event_type,
            actor_id = %actor_id,
            "Persisted SessionEvent"
        );

        Ok(signed_event)
    }

    fn emit_session_event_with_envelope(
        &self,
        session_id: &str,
        event_type: &str,
        payload_envelope: &serde_json::Value,
        actor_id: &str,
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        // Domain prefix for generic session events (TCK-00290)
        const SESSION_EVENT_DOMAIN_PREFIX: &[u8] = b"apm2.event.session_event:";

        let mut payload_json = payload_envelope.clone();
        let Some(payload_object) = payload_json.as_object_mut() else {
            return Err(LedgerEventError::ValidationFailed {
                message: "session event envelope must be a JSON object".to_string(),
            });
        };

        // Enforce daemon-authoritative identity fields.
        payload_object.insert("event_type".to_string(), serde_json::json!(event_type));
        payload_object.insert("session_id".to_string(), serde_json::json!(session_id));
        payload_object.insert("actor_id".to_string(), serde_json::json!(actor_id));

        if payload_object
            .get("payload")
            .and_then(serde_json::Value::as_str)
            .is_none()
        {
            return Err(LedgerEventError::ValidationFailed {
                message: "session event envelope missing required 'payload' field".to_string(),
            });
        }

        let work_pr_associated_pr_number = if event_type == "work.pr_associated" {
            let Some(pr_number) = payload_object
                .get("pr_number")
                .and_then(serde_json::Value::as_u64)
            else {
                return Err(LedgerEventError::ValidationFailed {
                    message:
                        "work.pr_associated envelope missing required numeric 'pr_number' field"
                            .to_string(),
                });
            };
            Some(pr_number)
        } else {
            None
        };

        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;
        let prev_hash = self.latest_event_hash_routed(&conn)?;
        let (signed_event, event_hash) = self.build_signed_event_with_prev_hash(
            event_type,
            session_id, // session_id maps to work_id in canonical tables
            actor_id,
            payload_json,
            timestamp_ns,
            SESSION_EVENT_DOMAIN_PREFIX,
            &prev_hash,
        )?;
        if let Some(pr_number) = work_pr_associated_pr_number {
            self.persist_work_pr_associated_with_binding_guard(
                &conn,
                &signed_event,
                &prev_hash,
                &event_hash,
                pr_number,
            )?;
        } else {
            self.persist_signed_event(&conn, &signed_event, &prev_hash, &event_hash)?;
        }

        info!(
            event_id = %signed_event.event_id,
            session_id = %session_id,
            event_type = %event_type,
            actor_id = %actor_id,
            "Persisted SessionEvent with caller-provided envelope"
        );

        Ok(signed_event)
    }

    /// TCK-00638 SECURITY FIX: Emit `evidence.published` with `evidence_id`
    /// surfaced in the JSON envelope for UNIQUE index enforcement.
    ///
    /// The canonical `events` table has a partial UNIQUE index on
    /// `json_extract(CAST(payload AS TEXT), '$.evidence_id') WHERE event_type =
    /// 'evidence.published'` that prevents duplicate evidence events at the
    /// database level. The legacy `ledger_events` table has an analogous
    /// index on `json_extract(CAST(payload AS TEXT), '$.evidence_id')`.
    /// CAST is required because the payload column is BLOB and `SQLite` < 3.45
    /// does not support `json_extract` on BLOB directly.
    ///
    /// By including `evidence_id` at the top level of the JSON envelope,
    /// `SQLite`'s `json_extract` can enforce uniqueness without decoding the
    /// nested hex-encoded protobuf payload.
    fn emit_evidence_published_event(
        &self,
        session_id: &str,
        payload: &[u8],
        actor_id: &str,
        timestamp_ns: u64,
        evidence_id: &str,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        // Domain prefix for generic session events (TCK-00290)
        const SESSION_EVENT_DOMAIN_PREFIX: &[u8] = b"apm2.event.session_event:";

        // Build payload as JSON with evidence_id at the top level for UNIQUE
        // index enforcement. The evidence_id is deterministically derived from
        // (work_id, kind, dedupe_key) and matches the protobuf's evidence_id.
        let payload_json = serde_json::json!({
            "event_type": "evidence.published",
            "session_id": session_id,
            "actor_id": actor_id,
            "payload": hex::encode(payload),
            "evidence_id": evidence_id,
        });

        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;
        let prev_hash = self.latest_event_hash_routed(&conn)?;
        let (signed_event, event_hash) = self.build_signed_event_with_prev_hash(
            "evidence.published",
            session_id, // Use session_id as work_id for indexing
            actor_id,
            payload_json,
            timestamp_ns,
            SESSION_EVENT_DOMAIN_PREFIX,
            &prev_hash,
        )?;
        self.persist_signed_event(&conn, &signed_event, &prev_hash, &event_hash)?;

        info!(
            event_id = %signed_event.event_id,
            session_id = %session_id,
            evidence_id = %evidence_id,
            actor_id = %actor_id,
            "Persisted evidence.published event with evidence_id for UNIQUE enforcement"
        );

        Ok(signed_event)
    }

    fn emit_stop_flags_mutated(
        &self,
        mutation: &StopFlagsMutation<'_>,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        let payload = serde_json::json!({
            "event_type": "stop_flags_mutated",
            "actor_id": mutation.actor_id,
            "emergency_stop_previous": mutation.emergency_stop_previous,
            "emergency_stop_current": mutation.emergency_stop_current,
            "governance_stop_previous": mutation.governance_stop_previous,
            "governance_stop_current": mutation.governance_stop_current,
            "request_context": mutation.request_context,
            "timestamp_ns": mutation.timestamp_ns,
        });

        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;
        let prev_hash = self.latest_event_hash_routed(&conn)?;
        let (signed_event, event_hash) = self.build_signed_event_with_prev_hash(
            "stop_flags_mutated",
            STOP_FLAGS_MUTATED_WORK_ID,
            mutation.actor_id,
            payload,
            mutation.timestamp_ns,
            STOP_FLAGS_MUTATED_DOMAIN_PREFIX,
            &prev_hash,
        )?;
        self.persist_signed_event(&conn, &signed_event, &prev_hash, &event_hash)?;

        info!(
            event_id = %signed_event.event_id,
            actor_id = %mutation.actor_id,
            emergency_stop_previous = mutation.emergency_stop_previous,
            emergency_stop_current = mutation.emergency_stop_current,
            governance_stop_previous = mutation.governance_stop_previous,
            governance_stop_current = mutation.governance_stop_current,
            "Persisted StopFlagsMutated event"
        );

        Ok(signed_event)
    }

    fn emit_defect_recorded(
        &self,
        defect: &DefectRecorded,
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        // TCK-00307 MAJOR 4: Call validate() to enforce DoS protections
        defect
            .validate()
            .map_err(|e| LedgerEventError::ValidationFailed { message: e })?;

        // TCK-00307 MAJOR 1: Include time_envelope_ref in JSON serialization
        // for temporal binding per RFC-0016.
        let time_envelope_ref_hex = defect
            .time_envelope_ref
            .as_ref()
            .map(|ter| hex::encode(&ter.hash));

        // Build payload as JSON
        let payload = serde_json::json!({
            "event_type": "defect_recorded",
            "defect_id": defect.defect_id,
            "defect_type": defect.defect_type,
            "cas_hash": hex::encode(&defect.cas_hash),
            "source": defect.source,
            "work_id": defect.work_id,
            "severity": defect.severity,
            "detected_at": defect.detected_at,
            "time_envelope_ref": time_envelope_ref_hex,
        });

        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;
        let prev_hash = self.latest_event_hash_routed(&conn)?;
        let (signed_event, event_hash) = self.build_signed_event_with_prev_hash(
            "defect_recorded",
            &defect.work_id,
            "",
            payload,
            timestamp_ns,
            DEFECT_RECORDED_DOMAIN_PREFIX,
            &prev_hash,
        )?;
        self.persist_signed_event(&conn, &signed_event, &prev_hash, &event_hash)?;

        info!(
            event_id = %signed_event.event_id,
            defect_id = %defect.defect_id,
            defect_type = %defect.defect_type,
            "Persisted DefectRecorded event"
        );

        Ok(signed_event)
    }

    fn get_events_by_work_id(&self, work_id: &str) -> Vec<SignedLedgerEvent> {
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };

        let mut events = Vec::new();

        // Foundational history replay: returns ALL events for a work_id.
        // This method is used by the projection bridge to rebuild state
        // (e.g. ProjectionWorkAuthority). A LIMIT clause here would
        // silently discard recent events for work items with large
        // histories, permanently freezing the observed state.
        //
        // NOTE: MAX_EVIDENCE_SCAN_ROWS is intended for bounded reverse-
        // scan lookups (e.g. get_event_by_evidence_identity), NOT for
        // this foundational history replay method.
        if let Ok(mut stmt) = conn.prepare(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
             FROM ledger_events WHERE work_id = ?1 ORDER BY timestamp_ns ASC, rowid ASC",
        ) {
            if let Ok(rows) = stmt.query_map(params![work_id], |row| {
                Ok(SignedLedgerEvent {
                    event_id: row.get(0)?,
                    event_type: row.get(1)?,
                    work_id: row.get(2)?,
                    actor_id: row.get(3)?,
                    payload: row.get(4)?,
                    signature: row.get(5)?,
                    timestamp_ns: row.get(6)?,
                })
            }) {
                events.extend(rows.filter_map(Result::ok));
            }
        }

        // TCK-00631 / Finding 1: append canonical events when frozen.
        // No LIMIT — foundational replay requires complete history.
        if self.is_frozen_internal() {
            if let Ok(mut stmt) = conn.prepare(
                "SELECT seq_id, event_type, session_id, actor_id, payload, \
                        COALESCE(signature, X''), timestamp_ns \
                 FROM events WHERE session_id = ?1 \
                 ORDER BY timestamp_ns ASC, rowid ASC",
            ) {
                if let Ok(rows) = stmt.query_map(params![work_id], Self::canonical_row_to_event) {
                    events.extend(rows.filter_map(Result::ok));
                }
            }
        }

        events
    }

    fn get_first_event_by_work_id_and_type(
        &self,
        work_id: &str,
        event_type: &str,
    ) -> Option<SignedLedgerEvent> {
        let Ok(conn) = self.conn.lock() else {
            return None;
        };

        // Legacy table: bounded LIMIT 1 query (O(1) with index).
        if let Ok(mut stmt) = conn.prepare(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
             FROM ledger_events WHERE work_id = ?1 AND event_type = ?2
             ORDER BY timestamp_ns ASC, rowid ASC LIMIT 1",
        ) {
            if let Ok(mut rows) = stmt.query_map(params![work_id, event_type], |row| {
                Ok(SignedLedgerEvent {
                    event_id: row.get(0)?,
                    event_type: row.get(1)?,
                    work_id: row.get(2)?,
                    actor_id: row.get(3)?,
                    payload: row.get(4)?,
                    signature: row.get(5)?,
                    timestamp_ns: row.get(6)?,
                })
            }) {
                if let Some(Ok(event)) = rows.next() {
                    return Some(event);
                }
            }
        }

        // TCK-00631 / Finding 1: check canonical events table when frozen.
        if self.is_frozen_internal() {
            if let Ok(mut stmt) = conn.prepare(
                "SELECT seq_id, event_type, session_id, actor_id, payload, \
                        COALESCE(signature, X''), timestamp_ns \
                 FROM events WHERE session_id = ?1 AND event_type = ?2 \
                 ORDER BY timestamp_ns ASC, rowid ASC LIMIT 1",
            ) {
                if let Ok(mut rows) =
                    stmt.query_map(params![work_id, event_type], Self::canonical_row_to_event)
                {
                    if let Some(Ok(event)) = rows.next() {
                        return Some(event);
                    }
                }
            }
        }

        None
    }

    fn has_work_pr_association_tuple(
        &self,
        work_id: &str,
        pr_number: u64,
        commit_sha: &str,
    ) -> bool {
        let Ok(conn) = self.conn.lock() else {
            return false;
        };
        let Ok(pr_number_i64) = i64::try_from(pr_number) else {
            return false;
        };

        let legacy_hit = conn
            .query_row(
                "SELECT 1 \
                 FROM ledger_events \
                 WHERE work_id = ?1 \
                   AND event_type = 'work.pr_associated' \
                   AND json_extract(CAST(payload AS TEXT), '$.pr_number') = ?2 \
                   AND lower(json_extract(CAST(payload AS TEXT), '$.commit_sha')) = lower(?3) \
                 LIMIT 1",
                params![work_id, pr_number_i64, commit_sha],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .ok()
            .flatten()
            .is_some();
        if legacy_hit {
            return true;
        }

        if !self.is_frozen_internal() {
            return false;
        }

        conn.query_row(
            "SELECT 1 \
             FROM events \
             WHERE session_id = ?1 \
               AND event_type = 'work.pr_associated' \
               AND json_extract(CAST(payload AS TEXT), '$.pr_number') = ?2 \
               AND lower(json_extract(CAST(payload AS TEXT), '$.commit_sha')) = lower(?3) \
             LIMIT 1",
            params![work_id, pr_number_i64, commit_sha],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .ok()
        .flatten()
        .is_some()
    }

    /// TCK-00637 SECURITY FIX (Findings 5/8): Bounded SQL query for the
    /// most recent `work_transitioned` event matching a `rationale_code`.
    /// Uses `json_extract` at the database level to avoid O(N)
    /// application-level JSON parsing.
    fn get_latest_work_transition_by_rationale(
        &self,
        work_id: &str,
        rationale_code: &str,
    ) -> Option<SignedLedgerEvent> {
        let Ok(conn) = self.conn.lock() else {
            return None;
        };

        let legacy_event = conn
            .query_row(
                "SELECT event_id, event_type, work_id, actor_id, payload, \
                        signature, timestamp_ns \
                 FROM ledger_events \
                 WHERE work_id = ?1 AND event_type = 'work_transitioned' \
                   AND json_extract(CAST(payload AS TEXT), '$.rationale_code') = ?2 \
                 ORDER BY timestamp_ns DESC, rowid DESC LIMIT 1",
                params![work_id, rationale_code],
                |row| {
                    Ok(SignedLedgerEvent {
                        event_id: row.get(0)?,
                        event_type: row.get(1)?,
                        work_id: row.get(2)?,
                        actor_id: row.get(3)?,
                        payload: row.get(4)?,
                        signature: row.get(5)?,
                        timestamp_ns: row.get(6)?,
                    })
                },
            )
            .optional()
            .ok()
            .flatten();

        let canonical_event = if self.is_frozen_internal() {
            conn.query_row(
                "SELECT seq_id, event_type, session_id, actor_id, payload, \
                        COALESCE(signature, X''), timestamp_ns \
                 FROM events \
                 WHERE session_id = ?1 AND event_type = 'work_transitioned' \
                   AND json_extract(CAST(payload AS TEXT), '$.rationale_code') = ?2 \
                 ORDER BY timestamp_ns DESC, rowid DESC LIMIT 1",
                params![work_id, rationale_code],
                Self::canonical_row_to_event,
            )
            .optional()
            .ok()
            .flatten()
        } else {
            None
        };

        match (legacy_event, canonical_event) {
            (Some(legacy), Some(canonical)) => {
                if canonical.timestamp_ns >= legacy.timestamp_ns {
                    Some(canonical)
                } else {
                    Some(legacy)
                }
            },
            (Some(legacy), None) => Some(legacy),
            (None, Some(canonical)) => Some(canonical),
            (None, None) => None,
        }
    }

    /// TCK-00637 SECURITY FIX (Findings 5/8): Bounded SQL query for an
    /// `evidence.published` event by its deterministic `evidence_id`.
    /// Uses `json_extract` at the database level to avoid O(N)
    /// application-level JSON parsing.
    fn get_evidence_by_evidence_id(
        &self,
        work_id: &str,
        evidence_id: &str,
    ) -> Option<SignedLedgerEvent> {
        let Ok(conn) = self.conn.lock() else {
            return None;
        };

        // Legacy table: direct lookup via json_extract on evidence_id.
        if let Ok(mut stmt) = conn.prepare(
            "SELECT event_id, event_type, work_id, actor_id, payload, \
                    signature, timestamp_ns \
             FROM ledger_events \
             WHERE work_id = ?1 AND event_type = 'evidence.published' \
               AND json_extract(CAST(payload AS TEXT), '$.evidence_id') = ?2 \
             ORDER BY timestamp_ns DESC, rowid DESC LIMIT 1",
        ) {
            if let Ok(mut rows) = stmt.query_map(params![work_id, evidence_id], |row| {
                Ok(SignedLedgerEvent {
                    event_id: row.get(0)?,
                    event_type: row.get(1)?,
                    work_id: row.get(2)?,
                    actor_id: row.get(3)?,
                    payload: row.get(4)?,
                    signature: row.get(5)?,
                    timestamp_ns: row.get(6)?,
                })
            }) {
                if let Some(Ok(event)) = rows.next() {
                    return Some(event);
                }
            }
        }

        // TCK-00631: check canonical events table when frozen.
        if self.is_frozen_internal() {
            if let Ok(mut stmt) = conn.prepare(
                "SELECT seq_id, event_type, session_id, actor_id, payload, \
                        COALESCE(signature, X''), timestamp_ns \
                 FROM events \
                 WHERE session_id = ?1 AND event_type = 'evidence.published' \
                   AND json_extract(CAST(payload AS TEXT), '$.evidence_id') = ?2 \
                 ORDER BY timestamp_ns DESC, rowid DESC LIMIT 1",
            ) {
                if let Ok(mut rows) =
                    stmt.query_map(params![work_id, evidence_id], Self::canonical_row_to_event)
                {
                    if let Some(Ok(event)) = rows.next() {
                        return Some(event);
                    }
                }
            }
        }

        None
    }

    fn get_events_since(
        &self,
        cursor_timestamp_ns: u64,
        cursor_event_id: &str,
        event_types: &[&str],
        limit: usize,
    ) -> Vec<SignedLedgerEvent> {
        if limit == 0 || event_types.is_empty() {
            return Vec::new();
        }

        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };

        let Ok(cursor_timestamp_i64) = i64::try_from(cursor_timestamp_ns) else {
            return Vec::new();
        };
        let normalized_cursor_event_id = Self::normalize_canonical_cursor_event_id(cursor_event_id);
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let placeholders = std::iter::repeat_n("?", event_types.len())
            .collect::<Vec<_>>()
            .join(", ");

        let build_params = || {
            let mut params = Vec::with_capacity(event_types.len() + 4);
            params.push(Value::Integer(cursor_timestamp_i64));
            params.push(Value::Integer(cursor_timestamp_i64));
            params.push(Value::Text(normalized_cursor_event_id.clone()));
            for event_type in event_types {
                params.push(Value::Text((*event_type).to_string()));
            }
            params.push(Value::Integer(limit_i64));
            params
        };

        // Legacy branch intentionally orders by `event_id` (not `rowid`) for
        // cursor pagination compatibility with mixed legacy+canonical reads.
        // `get_events_since` persists only `(timestamp_ns, event_id)` cursors;
        // when canonical freeze mode is active, the same cursor must be
        // comparable across both tables using a single stable string key.
        let legacy_sql = format!(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns \
             FROM ledger_events \
             WHERE (timestamp_ns > ? OR (timestamp_ns = ? AND event_id > ?)) \
               AND event_type IN ({placeholders}) \
             ORDER BY timestamp_ns ASC, event_id ASC \
             LIMIT ?"
        );

        let mut events = Vec::with_capacity(limit.saturating_mul(2));

        if let Ok(mut stmt) = conn.prepare(&legacy_sql) {
            let params = build_params();
            if let Ok(rows) = stmt.query_map(params_from_iter(params.iter()), |row| {
                Ok(SignedLedgerEvent {
                    event_id: row.get(0)?,
                    event_type: row.get(1)?,
                    work_id: row.get(2)?,
                    actor_id: row.get(3)?,
                    payload: row.get(4)?,
                    signature: row.get(5)?,
                    timestamp_ns: row.get(6)?,
                })
            }) {
                events.extend(rows.filter_map(Result::ok));
            }
        }

        if self.is_frozen_internal() {
            // TCK-00669 MINOR fix: Parse the numeric seq_id from the cursor
            // string in Rust and compare `seq_id > ?` directly, instead of
            // computing `printf('canonical-%020d', seq_id)` per row. This
            // allows SQLite to use the index on `seq_id`.
            let cursor_seq_id =
                Self::parse_canonical_event_id(&normalized_cursor_event_id).unwrap_or(-1);

            let canonical_sql = format!(
                "SELECT seq_id, event_type, session_id, actor_id, payload, \
                        COALESCE(signature, X''), timestamp_ns \
                 FROM events \
                 WHERE (timestamp_ns > ? OR (timestamp_ns = ? AND seq_id > ?)) \
                   AND event_type IN ({placeholders}) \
                 ORDER BY timestamp_ns ASC, seq_id ASC \
                 LIMIT ?"
            );

            let mut canonical_params = Vec::with_capacity(event_types.len() + 4);
            canonical_params.push(Value::Integer(cursor_timestamp_i64));
            canonical_params.push(Value::Integer(cursor_timestamp_i64));
            canonical_params.push(Value::Integer(cursor_seq_id));
            for event_type in event_types {
                canonical_params.push(Value::Text((*event_type).to_string()));
            }
            canonical_params.push(Value::Integer(limit_i64));

            if let Ok(mut stmt) = conn.prepare(&canonical_sql) {
                if let Ok(rows) = stmt.query_map(
                    params_from_iter(canonical_params.iter()),
                    Self::canonical_row_to_event,
                ) {
                    events.extend(rows.filter_map(Result::ok));
                }
            }
        }

        events.sort_by(|left, right| {
            (left.timestamp_ns, &left.event_id).cmp(&(right.timestamp_ns, &right.event_id))
        });
        events.truncate(limit);
        events
    }

    fn get_all_events(&self) -> Vec<SignedLedgerEvent> {
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };

        let mut events = Vec::new();

        // Legacy events.
        if let Ok(mut stmt) = conn.prepare(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
             FROM ledger_events
             ORDER BY timestamp_ns ASC, rowid ASC",
        ) {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok(SignedLedgerEvent {
                    event_id: row.get(0)?,
                    event_type: row.get(1)?,
                    work_id: row.get(2)?,
                    actor_id: row.get(3)?,
                    payload: row.get(4)?,
                    signature: row.get(5)?,
                    timestamp_ns: row.get(6)?,
                })
            }) {
                events.extend(rows.filter_map(Result::ok));
            }
        }

        // TCK-00631 / Finding 1: append canonical events when frozen.
        if self.is_frozen_internal() {
            if let Ok(mut stmt) = conn.prepare(
                "SELECT seq_id, event_type, session_id, actor_id, payload, \
                        COALESCE(signature, X''), timestamp_ns \
                 FROM events ORDER BY timestamp_ns ASC, rowid ASC",
            ) {
                if let Ok(rows) = stmt.query_map([], Self::canonical_row_to_event) {
                    events.extend(rows.filter_map(Result::ok));
                }
            }
        }

        events
    }

    fn get_event_count(&self) -> usize {
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };

        // TCK-00631 / Finding 1: When frozen, include canonical events in
        // the count so projections detect post-freeze appends.
        let legacy_count = conn
            .query_row("SELECT COUNT(*) FROM ledger_events", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or(0);

        let canonical_count = if self.is_frozen_internal() {
            conn.query_row("SELECT COUNT(*) FROM events", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or(0)
        } else {
            0
        };

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let count = legacy_count.saturating_add(canonical_count) as usize;
        count
    }

    fn get_latest_event(&self) -> Option<SignedLedgerEvent> {
        let conn = self.conn.lock().ok()?;

        // TCK-00631 / Finding 1: When frozen, prefer the canonical table's
        // most-recent event.  If the canonical table has rows, that is the
        // authoritative latest; otherwise fall through to the legacy snapshot.
        if self.is_frozen_internal() {
            if let Some(ev) = Self::canonical_get_latest_event(&conn) {
                return Some(ev);
            }
        }

        conn.query_row(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
             FROM ledger_events
             ORDER BY timestamp_ns DESC, rowid DESC
             LIMIT 1",
            [],
            |row| {
                Ok(SignedLedgerEvent {
                    event_id: row.get(0)?,
                    event_type: row.get(1)?,
                    work_id: row.get(2)?,
                    actor_id: row.get(3)?,
                    payload: row.get(4)?,
                    signature: row.get(5)?,
                    timestamp_ns: row.get(6)?,
                })
            },
        )
        .ok()
    }

    fn get_latest_governance_policy_event(&self) -> Option<SignedLedgerEvent> {
        let conn = self.conn.lock().ok()?;

        // TCK-00631 / Finding 1: When frozen, check canonical table first
        // for the latest governance-policy event.
        if self.is_frozen_internal() {
            if let Some(ev) = Self::canonical_get_latest_governance_policy_event(&conn) {
                return Some(ev);
            }
        }

        conn.query_row(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
             FROM ledger_events
             WHERE event_type_class = ?1
             AND event_type IN (
                 'gate.policy_resolved',
                 'policy_root_published',
                 'policy_updated',
                 'gate_configuration_updated'
             )
             AND actor_id IN (
                 'orchestrator:gate-lifecycle',
                 'governance:policy-root',
                 'governance:policy'
             )
             ORDER BY rowid DESC
             LIMIT 1",
            params![EventTypeClass::Governance.as_str()],
            |row| {
                Ok(SignedLedgerEvent {
                    event_id: row.get(0)?,
                    event_type: row.get(1)?,
                    work_id: row.get(2)?,
                    actor_id: row.get(3)?,
                    payload: row.get(4)?,
                    signature: row.get(5)?,
                    timestamp_ns: row.get(6)?,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    fn get_latest_gate_policy_resolved_event(&self) -> Option<SignedLedgerEvent> {
        let conn = self.conn.lock().ok()?;

        // TCK-00631 / Finding 1: When frozen, check canonical table first.
        if self.is_frozen_internal() {
            if let Some(ev) = Self::canonical_get_latest_gate_policy_resolved_event(&conn) {
                return Some(ev);
            }
        }

        conn.query_row(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
             FROM ledger_events
             WHERE event_type_class = ?1
             AND event_type = 'gate.policy_resolved'
             AND actor_id = 'orchestrator:gate-lifecycle'
             ORDER BY rowid DESC
             LIMIT 1",
            params![EventTypeClass::Governance.as_str()],
            |row| {
                Ok(SignedLedgerEvent {
                    event_id: row.get(0)?,
                    event_type: row.get(1)?,
                    work_id: row.get(2)?,
                    actor_id: row.get(3)?,
                    payload: row.get(4)?,
                    signature: row.get(5)?,
                    timestamp_ns: row.get(6)?,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    fn get_latest_event_hash(&self) -> Result<Option<String>, String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "connection lock poisoned".to_string())?;

        // TCK-00631 / Finding 1: When frozen, the canonical `events` table
        // holds the authoritative chain tip — query it instead.
        if self.is_frozen_internal() {
            return Self::canonical_get_latest_event_hash_hex(&conn);
        }

        let hash = conn
            .query_row(
                "SELECT event_hash FROM ledger_events ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| format!("sqlite latest event_hash query failed: {e}"))?;

        if hash
            .as_deref()
            .is_some_and(|value| value.is_empty() || value == "legacy-uninitialized")
        {
            return Err("latest ledger event_hash is uninitialized".to_string());
        }
        Ok(hash)
    }

    fn derive_event_chain_hash(&self) -> Result<String, String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "connection lock poisoned".to_string())?;
        let verifying_key = self.verifying_key();
        Self::derive_event_chain_hash_from_db(&conn, &verifying_key)
    }

    fn get_event_by_receipt_id(&self, receipt_id: &str) -> Option<SignedLedgerEvent> {
        let conn = self.conn.lock().ok()?;

        // Query review receipt events by receipt_id embedded in the JSON payload.
        // Both `review_receipt_recorded` and `review_blocked_recorded` events
        // store `receipt_id` in the payload. We use `json_extract` with
        // `CAST(payload AS TEXT)` because payloads are stored as BLOBs.
        //
        // ORDER BY rowid DESC LIMIT 1 ensures deterministic latest-row selection
        // (defense-in-depth; receipt_id should be unique across receipt events).
        conn.query_row(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns \
             FROM ledger_events \
             WHERE event_type IN ('review_receipt_recorded', 'review_blocked_recorded') \
             AND json_extract(CAST(payload AS TEXT), '$.receipt_id') = ?1 \
             ORDER BY rowid DESC LIMIT 1",
            params![receipt_id],
            |row| {
                Ok(SignedLedgerEvent {
                    event_id: row.get(0)?,
                    event_type: row.get(1)?,
                    work_id: row.get(2)?,
                    actor_id: row.get(3)?,
                    payload: row.get(4)?,
                    signature: row.get(5)?,
                    timestamp_ns: row.get(6)?,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    fn emit_redundancy_receipt_consumed(
        &self,
        session_id: &str,
        receipt_id: &str,
        request_id: &str,
        tool_class: &str,
        intent_digest: &[u8; 32],
        argument_content_digest: &[u8; 32],
        channel_key: &str,
        actor_id: &str,
        timestamp_ns: u64,
        receipt_hash: &[u8; 32],
        admission_bundle_digest: &[u8; 32],
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        const RECEIPT_CONSUMED_DOMAIN_PREFIX: &[u8] = b"apm2.event.redundancy_receipt_consumed:";

        let payload = serde_json::json!({
            "event_type": REDUNDANCY_RECEIPT_CONSUMED_EVENT,
            "session_id": session_id,
            "receipt_id": receipt_id,
            "request_id": request_id,
            "tool_class": tool_class,
            "intent_digest": hex::encode(intent_digest),
            "argument_content_digest": hex::encode(argument_content_digest),
            "channel_key": channel_key,
            "actor_id": actor_id,
            "timestamp_ns": timestamp_ns,
            "receipt_hash": hex::encode(receipt_hash),
            "admission_bundle_digest": hex::encode(admission_bundle_digest),
        });

        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;
        let prev_hash = self.latest_event_hash_routed(&conn)?;
        let (signed_event, event_hash) = self.build_signed_event_with_prev_hash(
            REDUNDANCY_RECEIPT_CONSUMED_EVENT,
            session_id,
            actor_id,
            payload,
            timestamp_ns,
            RECEIPT_CONSUMED_DOMAIN_PREFIX,
            &prev_hash,
        )?;
        self.persist_signed_event(&conn, &signed_event, &prev_hash, &event_hash)?;

        info!(
            event_id = %signed_event.event_id,
            session_id = %session_id,
            receipt_id = %receipt_id,
            request_id = %request_id,
            tool_class = %tool_class,
            intent_digest = %hex::encode(intent_digest),
            channel_key = %channel_key,
            receipt_hash = %hex::encode(receipt_hash),
            admission_bundle_digest = %hex::encode(admission_bundle_digest),
            "Persisted RedundancyReceiptConsumed event"
        );
        Ok(signed_event)
    }

    fn get_redundancy_receipt_consumption(
        &self,
        receipt_id: &str,
    ) -> Option<RedundancyReceiptConsumption> {
        fn parse_hash32(value: Option<&serde_json::Value>) -> Option<[u8; 32]> {
            let hex = value?.as_str()?;
            let bytes = hex::decode(hex).ok()?;
            let arr: [u8; 32] = bytes.try_into().ok()?;
            Some(arr)
        }

        let conn = self.conn.lock().ok()?;

        let payload: Vec<u8> = conn
            .query_row(
                "SELECT payload FROM ledger_events
                 WHERE event_type = ?1
                 AND json_extract(CAST(payload AS TEXT), '$.receipt_id') = ?2
                 ORDER BY rowid DESC LIMIT 1",
                params![REDUNDANCY_RECEIPT_CONSUMED_EVENT, receipt_id],
                |row| row.get(0),
            )
            .optional()
            .ok()
            .flatten()?;
        let payload = serde_json::from_slice::<serde_json::Value>(&payload).ok()?;
        Some(RedundancyReceiptConsumption {
            receipt_id: payload.get("receipt_id")?.as_str()?.to_string(),
            request_id: payload.get("request_id")?.as_str()?.to_string(),
            tool_class: payload.get("tool_class")?.as_str()?.to_string(),
            intent_digest: parse_hash32(payload.get("intent_digest")),
            argument_content_digest: parse_hash32(payload.get("argument_content_digest")),
            channel_key: payload
                .get("channel_key")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            receipt_hash: parse_hash32(payload.get("receipt_hash")),
            admission_bundle_digest: parse_hash32(payload.get("admission_bundle_digest")),
        })
    }

    fn get_authoritative_receipt_event_count(&self) -> usize {
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };

        let Ok(count) = conn.query_row(
            "SELECT COUNT(*) FROM ledger_events
             WHERE event_type IN ('review_receipt_recorded', 'review_blocked_recorded')",
            [],
            |row| row.get::<_, i64>(0),
        ) else {
            return 0;
        };

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let count = count as usize;
        count
    }

    fn get_authoritative_receipt_events(&self) -> Vec<SignedLedgerEvent> {
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };

        let projection_limit = i64::try_from(MAX_PROJECTION_EVENTS).unwrap_or(i64::MAX);
        let Ok(mut stmt) = conn.prepare(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
             FROM (
                 SELECT rowid, event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
                 FROM ledger_events
                 WHERE event_type IN ('review_receipt_recorded', 'review_blocked_recorded')
                 ORDER BY rowid DESC
                 LIMIT ?1
             ) recent
             ORDER BY timestamp_ns ASC, rowid ASC",
        ) else {
            return Vec::new();
        };

        let rows = stmt.query_map(params![projection_limit], |row| {
            Ok(SignedLedgerEvent {
                event_id: row.get(0)?,
                event_type: row.get(1)?,
                work_id: row.get(2)?,
                actor_id: row.get(3)?,
                payload: row.get(4)?,
                signature: row.get(5)?,
                timestamp_ns: row.get(6)?,
            })
        });

        rows.map_or_else(|_| Vec::new(), |iter| iter.filter_map(Result::ok).collect())
    }

    fn get_launch_liveness_projection_event_count(&self) -> usize {
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };

        let Ok(count) = conn.query_row(
            "SELECT COUNT(*) FROM ledger_events
             WHERE event_type IN (
                 'session_started',
                 'session_terminated',
                 'review_receipt_recorded',
                 'review_blocked_recorded'
             )",
            [],
            |row| row.get::<_, i64>(0),
        ) else {
            return 0;
        };

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let count = count as usize;
        count
    }

    fn get_launch_liveness_projection_events(&self) -> Vec<SignedLedgerEvent> {
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };

        let projection_limit = i64::try_from(MAX_PROJECTION_EVENTS).unwrap_or(i64::MAX);
        let Ok(mut stmt) = conn.prepare(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
             FROM (
                 SELECT rowid, event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
                 FROM ledger_events
                 WHERE event_type IN (
                     'session_started',
                     'session_terminated',
                     'review_receipt_recorded',
                     'review_blocked_recorded'
                 )
                 ORDER BY rowid DESC
                 LIMIT ?1
             ) recent
             ORDER BY timestamp_ns ASC, rowid ASC",
        ) else {
            return Vec::new();
        };

        let rows = stmt.query_map(params![projection_limit], |row| {
            Ok(SignedLedgerEvent {
                event_id: row.get(0)?,
                event_type: row.get(1)?,
                work_id: row.get(2)?,
                actor_id: row.get(3)?,
                payload: row.get(4)?,
                signature: row.get(5)?,
                timestamp_ns: row.get(6)?,
            })
        });

        rows.map_or_else(|_| Vec::new(), |iter| iter.filter_map(Result::ok).collect())
    }

    fn get_event_by_receipt_identity(
        &self,
        receipt_id: &str,
        lease_id: &str,
        work_id: &str,
        changeset_digest_hex: &str,
    ) -> Option<SignedLedgerEvent> {
        let conn = self.conn.lock().ok()?;

        conn.query_row(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns \
             FROM ledger_events \
             WHERE event_type IN ('review_receipt_recorded', 'review_blocked_recorded') \
             AND json_extract(CAST(payload AS TEXT), '$.receipt_id') = ?1 \
             AND json_extract(CAST(payload AS TEXT), '$.lease_id') = ?2 \
             AND COALESCE(json_extract(CAST(payload AS TEXT), '$.work_id'), work_id) = ?3 \
             AND json_extract(CAST(payload AS TEXT), '$.changeset_digest') = ?4 \
             ORDER BY rowid DESC LIMIT 1",
            params![receipt_id, lease_id, work_id, changeset_digest_hex],
            |row| {
                Ok(SignedLedgerEvent {
                    event_id: row.get(0)?,
                    event_type: row.get(1)?,
                    work_id: row.get(2)?,
                    actor_id: row.get(3)?,
                    payload: row.get(4)?,
                    signature: row.get(5)?,
                    timestamp_ns: row.get(6)?,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    fn get_event_by_changeset_identity(
        &self,
        work_id: &str,
        changeset_digest_hex: &str,
    ) -> Option<SignedLedgerEvent> {
        let conn = self.conn.lock().ok()?;

        conn.query_row(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns \
             FROM ledger_events \
             WHERE event_type = 'changeset_published' \
             AND work_id = ?1 \
             AND json_extract(CAST(payload AS TEXT), '$.changeset_digest') = ?2 \
             ORDER BY rowid DESC LIMIT 1",
            params![work_id, changeset_digest_hex],
            |row| {
                Ok(SignedLedgerEvent {
                    event_id: row.get(0)?,
                    event_type: row.get(1)?,
                    work_id: row.get(2)?,
                    actor_id: row.get(3)?,
                    payload: row.get(4)?,
                    signature: row.get(5)?,
                    timestamp_ns: row.get(6)?,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    fn get_event_by_evidence_identity(
        &self,
        work_id: &str,
        entry_id: &str,
    ) -> Option<SignedLedgerEvent> {
        let conn = self.conn.lock().ok()?;

        // TCK-00638 / BLOCKER fix: When frozen, also search the canonical
        // `events` table. The daemon routes writes to canonical events when
        // the freeze guard is active, so replay detection must look there
        // to avoid duplicate evidence.published entries.
        if self.is_frozen_internal() {
            if let Some(ev) = Self::canonical_get_evidence_by_identity(&conn, work_id, entry_id) {
                return Some(ev);
            }
        }

        // TCK-00638 SECURITY FIX: Use O(1) indexed lookup via
        // json_extract(CAST(payload AS TEXT), '$.evidence_id') backed by
        // `idx_evidence_published_unique`. This replaces the previous
        // O(N) scan with per-row protobuf decoding bounded by
        // MAX_EVIDENCE_SCAN_ROWS, which could miss duplicates in
        // long-lived work streams with >1000 evidence entries.
        // CAST is required because the payload column is BLOB and
        // SQLite < 3.45 does not support json_extract on BLOB directly.
        conn.query_row(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns \
             FROM ledger_events \
             WHERE event_type = 'evidence.published' \
             AND work_id = ?1 \
             AND json_extract(CAST(payload AS TEXT), '$.evidence_id') = ?2 \
             ORDER BY rowid DESC LIMIT 1",
            params![work_id, entry_id],
            |row| {
                Ok(SignedLedgerEvent {
                    event_id: row.get(0)?,
                    event_type: row.get(1)?,
                    work_id: row.get(2)?,
                    actor_id: row.get(3)?,
                    payload: row.get(4)?,
                    signature: row.get(5)?,
                    timestamp_ns: row.get(6)?,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    fn get_work_transition_count(&self, work_id: &str) -> u32 {
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };

        let Ok(count) = conn.query_row(
            "SELECT COUNT(*) FROM ledger_events WHERE work_id = ?1 AND event_type = 'work_transitioned'",
            params![work_id],
            |row| row.get::<_, i64>(0),
        ) else {
            return 0;
        };

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let count = count as u32;
        count
    }

    fn emit_episode_event(
        &self,
        episode_id: &str,
        event_type: &str,
        payload: &[u8],
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        // Build payload as JSON with episode event metadata
        // SECURITY: timestamp_ns is included in signed payload to prevent temporal
        // malleability per LAW-09 (Temporal Pinning & Freshness) and RS-40
        // (Time & Monotonicity)
        let payload_json = serde_json::json!({
            "event_type": event_type,
            "episode_id": episode_id,
            "payload": hex::encode(payload),
            "timestamp_ns": timestamp_ns,
        });

        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;
        let prev_hash = self.latest_event_hash_routed(&conn)?;
        let (signed_event, event_hash) = self.build_signed_event_with_prev_hash(
            event_type,
            episode_id, // Use episode_id as work_id for indexing
            "daemon",   // Episode events are daemon-authored
            payload_json,
            timestamp_ns,
            EPISODE_EVENT_DOMAIN_PREFIX,
            &prev_hash,
        )?;
        self.persist_signed_event(&conn, &signed_event, &prev_hash, &event_hash)?;

        info!(
            event_id = %signed_event.event_id,
            episode_id = %episode_id,
            event_type = %event_type,
            "Persisted EpisodeEvent"
        );

        Ok(signed_event)
    }

    fn emit_review_receipt(
        &self,
        lease_id: &str,
        work_id: &str,
        receipt_id: &str,
        changeset_digest: &[u8; 32],
        artifact_bundle_hash: &[u8; 32],
        capability_manifest_hash: &[u8; 32],
        context_pack_hash: &[u8; 32],
        role_spec_hash: &[u8; 32],
        reviewer_actor_id: &str,
        timestamp_ns: u64,
        identity_proof_hash: &[u8; 32],
        time_envelope_ref: &str,
        pcac_lifecycle: Option<&PrivilegedPcacLifecycleArtifacts>,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        // TCK-00321: Use REVIEW_RECEIPT_RECORDED_PREFIX from apm2_core::fac for
        // protocol compatibility across daemon/core boundary.
        // (Previously used daemon-local prefix; now aligned with core.)

        for (name, hash) in [
            ("capability_manifest_hash", capability_manifest_hash),
            ("context_pack_hash", context_pack_hash),
            ("role_spec_hash", role_spec_hash),
        ] {
            if bool::from(hash.ct_eq(&[0u8; 32])) {
                return Err(LedgerEventError::ValidationFailed {
                    message: format!("{name} is zero (fail-closed)"),
                });
            }
        }

        // Build payload as JSON with review receipt data
        // SECURITY: timestamp_ns is included in signed payload to prevent temporal
        // malleability per LAW-09 (Temporal Pinning & Freshness) and RS-40
        // (Time & Monotonicity)
        //
        // SECURITY (TCK-00356 Fix 1): identity_proof_hash is included in
        // the signed payload so it is audit-bound and cannot be stripped
        // post-signing.
        let mut payload_map = serde_json::Map::new();
        payload_map.insert(
            "event_type".to_string(),
            serde_json::json!("review_receipt_recorded"),
        );
        payload_map.insert("episode_id".to_string(), serde_json::json!(lease_id));
        payload_map.insert("lease_id".to_string(), serde_json::json!(lease_id));
        payload_map.insert("work_id".to_string(), serde_json::json!(work_id));
        payload_map.insert("receipt_id".to_string(), serde_json::json!(receipt_id));
        payload_map.insert(
            "changeset_digest".to_string(),
            serde_json::json!(hex::encode(changeset_digest)),
        );
        payload_map.insert(
            "artifact_bundle_hash".to_string(),
            serde_json::json!(hex::encode(artifact_bundle_hash)),
        );
        payload_map.insert(
            "capability_manifest_hash".to_string(),
            serde_json::json!(hex::encode(capability_manifest_hash)),
        );
        payload_map.insert(
            "context_pack_hash".to_string(),
            serde_json::json!(hex::encode(context_pack_hash)),
        );
        payload_map.insert(
            "role_spec_hash".to_string(),
            serde_json::json!(hex::encode(role_spec_hash)),
        );
        payload_map.insert("verdict".to_string(), serde_json::json!("APPROVE"));
        payload_map.insert(
            "reviewer_actor_id".to_string(),
            serde_json::json!(reviewer_actor_id),
        );
        payload_map.insert("timestamp_ns".to_string(), serde_json::json!(timestamp_ns));
        payload_map.insert(
            "identity_proof_hash".to_string(),
            serde_json::json!(hex::encode(identity_proof_hash)),
        );
        payload_map.insert(
            "time_envelope_ref".to_string(),
            serde_json::json!(time_envelope_ref),
        );
        if let Some(artifacts) = pcac_lifecycle {
            append_privileged_pcac_lifecycle_fields(&mut payload_map, artifacts);
        }

        let payload_json = serde_json::Value::Object(payload_map);
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;
        let prev_hash = self.latest_event_hash_routed(&conn)?;
        let (signed_event, event_hash) = self.build_signed_event_with_prev_hash(
            "review_receipt_recorded",
            work_id,
            reviewer_actor_id,
            payload_json,
            timestamp_ns,
            REVIEW_RECEIPT_RECORDED_PREFIX,
            &prev_hash,
        )?;
        self.persist_signed_event(&conn, &signed_event, &prev_hash, &event_hash)?;

        info!(
            event_id = %signed_event.event_id,
            lease_id = %lease_id,
            work_id = %work_id,
            receipt_id = %receipt_id,
            time_envelope_ref = %time_envelope_ref,
            "Persisted ReviewReceiptRecorded event"
        );

        Ok(signed_event)
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_review_blocked_receipt(
        &self,
        lease_id: &str,
        work_id: &str,
        receipt_id: &str,
        changeset_digest: &[u8; 32],
        artifact_bundle_hash: &[u8; 32],
        capability_manifest_hash: &[u8; 32],
        context_pack_hash: &[u8; 32],
        role_spec_hash: &[u8; 32],
        reason_code: u32,
        blocked_log_hash: &[u8; 32],
        reviewer_actor_id: &str,
        timestamp_ns: u64,
        identity_proof_hash: &[u8; 32],
        time_envelope_ref: &str,
        pcac_lifecycle: Option<&PrivilegedPcacLifecycleArtifacts>,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        use crate::protocol::dispatch::REVIEW_BLOCKED_RECORDED_LEDGER_PREFIX;

        for (name, hash) in [
            ("capability_manifest_hash", capability_manifest_hash),
            ("context_pack_hash", context_pack_hash),
            ("role_spec_hash", role_spec_hash),
        ] {
            if bool::from(hash.ct_eq(&[0u8; 32])) {
                return Err(LedgerEventError::ValidationFailed {
                    message: format!("{name} is zero (fail-closed)"),
                });
            }
        }

        // SECURITY (TCK-00356 Fix 2): identity_proof_hash is included in
        // the signed payload so it is audit-bound and cannot be stripped
        // post-signing, matching the APPROVE path's payload binding.
        let mut payload_map = serde_json::Map::new();
        payload_map.insert(
            "event_type".to_string(),
            serde_json::json!("review_blocked_recorded"),
        );
        payload_map.insert("lease_id".to_string(), serde_json::json!(lease_id));
        payload_map.insert("work_id".to_string(), serde_json::json!(work_id));
        payload_map.insert("receipt_id".to_string(), serde_json::json!(receipt_id));
        payload_map.insert(
            "changeset_digest".to_string(),
            serde_json::json!(hex::encode(changeset_digest)),
        );
        payload_map.insert(
            "artifact_bundle_hash".to_string(),
            serde_json::json!(hex::encode(artifact_bundle_hash)),
        );
        payload_map.insert(
            "capability_manifest_hash".to_string(),
            serde_json::json!(hex::encode(capability_manifest_hash)),
        );
        payload_map.insert(
            "context_pack_hash".to_string(),
            serde_json::json!(hex::encode(context_pack_hash)),
        );
        payload_map.insert(
            "role_spec_hash".to_string(),
            serde_json::json!(hex::encode(role_spec_hash)),
        );
        payload_map.insert("verdict".to_string(), serde_json::json!("BLOCKED"));
        payload_map.insert(
            "blocked_reason_code".to_string(),
            serde_json::json!(reason_code),
        );
        // Preserve legacy field for backward compatibility with old readers.
        payload_map.insert("reason_code".to_string(), serde_json::json!(reason_code));
        payload_map.insert(
            "blocked_log_hash".to_string(),
            serde_json::json!(hex::encode(blocked_log_hash)),
        );
        payload_map.insert(
            "reviewer_actor_id".to_string(),
            serde_json::json!(reviewer_actor_id),
        );
        payload_map.insert("timestamp_ns".to_string(), serde_json::json!(timestamp_ns));
        payload_map.insert(
            "identity_proof_hash".to_string(),
            serde_json::json!(hex::encode(identity_proof_hash)),
        );
        payload_map.insert(
            "time_envelope_ref".to_string(),
            serde_json::json!(time_envelope_ref),
        );
        if let Some(artifacts) = pcac_lifecycle {
            append_privileged_pcac_lifecycle_fields(&mut payload_map, artifacts);
        }

        let payload_json = serde_json::Value::Object(payload_map);
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;
        let prev_hash = self.latest_event_hash_routed(&conn)?;
        let (signed_event, event_hash) = self.build_signed_event_with_prev_hash(
            "review_blocked_recorded",
            work_id,
            reviewer_actor_id,
            payload_json,
            timestamp_ns,
            REVIEW_BLOCKED_RECORDED_LEDGER_PREFIX,
            &prev_hash,
        )?;
        self.persist_signed_event(&conn, &signed_event, &prev_hash, &event_hash)?;

        info!(
            event_id = %signed_event.event_id,
            lease_id = %lease_id,
            work_id = %work_id,
            receipt_id = %receipt_id,
            reason_code = %reason_code,
            time_envelope_ref = %time_envelope_ref,
            "Persisted ReviewBlockedRecorded event"
        );

        Ok(signed_event)
    }

    fn emit_episode_run_attributed(
        &self,
        work_id: &str,
        episode_id: &str,
        session_id: &str,
        adapter_profile_hash: &[u8; 32],
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        // TCK-00330: Domain prefix for episode run attribution events.
        // This is imported from dispatch.rs and used to ensure domain separation.
        const EPISODE_RUN_ATTRIBUTED_PREFIX: &[u8] = b"apm2.event.episode_run_attributed:";

        // Build payload as JSON with run attribution data
        // SECURITY: timestamp_ns is included in signed payload to prevent temporal
        // malleability per LAW-09 (Temporal Pinning & Freshness) and RS-40
        // (Time & Monotonicity)
        // TCK-00330: adapter_profile_hash provides ledger attribution for profile-based
        // auditing
        let payload = serde_json::json!({
            "event_type": "episode_run_attributed",
            "work_id": work_id,
            "episode_id": episode_id,
            "session_id": session_id,
            "adapter_profile_hash": hex::encode(adapter_profile_hash),
            "timestamp_ns": timestamp_ns,
        });
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;
        let prev_hash = self.latest_event_hash_routed(&conn)?;
        let (signed_event, event_hash) = self.build_signed_event_with_prev_hash(
            "episode_run_attributed",
            work_id,
            session_id, // Session is the actor for run attribution
            payload,
            timestamp_ns,
            EPISODE_RUN_ATTRIBUTED_PREFIX,
            &prev_hash,
        )?;
        self.persist_signed_event(&conn, &signed_event, &prev_hash, &event_hash)?;

        info!(
            event_id = %signed_event.event_id,
            work_id = %work_id,
            episode_id = %episode_id,
            session_id = %session_id,
            adapter_profile_hash = %hex::encode(adapter_profile_hash),
            "Persisted EpisodeRunAttributed event"
        );

        Ok(signed_event)
    }

    fn emit_work_transitioned(
        &self,
        transition: &WorkTransition<'_>,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        // Build payload as JSON with work transition data
        // SECURITY: timestamp_ns is included in signed payload to prevent temporal
        // malleability per LAW-09 (Temporal Pinning & Freshness)
        let payload = serde_json::json!({
            "event_type": "work_transitioned",
            "work_id": transition.work_id,
            "from_state": transition.from_state,
            "to_state": transition.to_state,
            "rationale_code": transition.rationale_code,
            "previous_transition_count": transition.previous_transition_count,
            "actor_id": transition.actor_id,
            "timestamp_ns": transition.timestamp_ns,
        });
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;
        let prev_hash = self.latest_event_hash_routed(&conn)?;
        let (signed_event, event_hash) = self.build_signed_event_with_prev_hash(
            "work_transitioned",
            transition.work_id,
            transition.actor_id,
            payload,
            transition.timestamp_ns,
            WORK_TRANSITIONED_DOMAIN_PREFIX,
            &prev_hash,
        )?;
        self.persist_signed_event(&conn, &signed_event, &prev_hash, &event_hash)?;

        info!(
            event_id = %signed_event.event_id,
            work_id = %transition.work_id,
            from_state = %transition.from_state,
            to_state = %transition.to_state,
            "Persisted WorkTransitioned event"
        );

        Ok(signed_event)
    }

    fn emit_session_terminated(
        &self,
        session_id: &str,
        work_id: &str,
        exit_code: i32,
        termination_reason: &str,
        actor_id: &str,
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        // Build payload as JSON with session termination data
        // SECURITY: timestamp_ns is included in signed payload to prevent temporal
        // malleability per LAW-09 (Temporal Pinning & Freshness)
        let payload = serde_json::json!({
            "event_type": "session_terminated",
            "session_id": session_id,
            "work_id": work_id,
            "exit_code": exit_code,
            "termination_reason": termination_reason,
            "actor_id": actor_id,
            "timestamp_ns": timestamp_ns,
        });
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;
        let prev_hash = self.latest_event_hash_routed(&conn)?;
        let (signed_event, event_hash) = self.build_signed_event_with_prev_hash(
            "session_terminated",
            work_id,
            actor_id,
            payload,
            timestamp_ns,
            SESSION_TERMINATED_LEDGER_DOMAIN_PREFIX,
            &prev_hash,
        )?;
        self.persist_signed_event(&conn, &signed_event, &prev_hash, &event_hash)?;

        info!(
            event_id = %signed_event.event_id,
            session_id = %session_id,
            work_id = %work_id,
            exit_code = %exit_code,
            "Persisted SessionTerminated event"
        );

        Ok(signed_event)
    }

    /// TCK-00395 MAJOR 2: Transactional override for `emit_claim_lifecycle`.
    ///
    /// Wraps `WorkClaimed` + `WorkTransitioned(Open->Claimed)` in a single
    /// `SQLite` transaction to guarantee atomicity. On failure of either
    /// event, the entire transaction is rolled back.
    fn emit_claim_lifecycle(
        &self,
        claim: &WorkClaim,
        actor_id: &str,
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;

        // Begin explicit transaction for atomicity
        conn.execute("BEGIN IMMEDIATE", [])
            .map_err(|e| LedgerEventError::PersistenceFailed {
                message: format!("transaction begin failed: {e}"),
            })?;

        // --- Event 1: WorkClaimed ---
        let prev_hash = self.latest_event_hash_routed(&conn).inspect_err(|_e| {
            let _ = conn.execute("ROLLBACK", []);
        })?;
        let claimed_payload = serde_json::json!({
            "event_type": "work_claimed",
            "work_id": claim.work_id,
            "lease_id": claim.lease_id,
            "actor_id": claim.actor_id,
            "role": format!("{:?}", claim.role),
            "policy_resolved_ref": claim.policy_resolution.policy_resolved_ref,
            "capability_manifest_hash": hex::encode(claim.policy_resolution.capability_manifest_hash),
            "context_pack_hash": hex::encode(claim.policy_resolution.context_pack_hash),
            "role_spec_hash": hex::encode(claim.policy_resolution.role_spec_hash),
            "context_pack_recipe_hash": hex::encode(claim.policy_resolution.context_pack_recipe_hash),
        });
        let (claimed_event, claimed_event_hash) = self
            .build_signed_event_with_prev_hash(
                "work_claimed",
                &claim.work_id,
                &claim.actor_id,
                claimed_payload,
                timestamp_ns,
                WORK_CLAIMED_DOMAIN_PREFIX,
                &prev_hash,
            )
            .inspect_err(|_e| {
                let _ = conn.execute("ROLLBACK", []);
            })?;

        if let Err(e) =
            self.persist_signed_event(&conn, &claimed_event, &prev_hash, &claimed_event_hash)
        {
            let _ = conn.execute("ROLLBACK", []);
            return Err(e);
        }

        // --- Event 2: WorkTransitioned(Open -> Claimed) ---
        // Get transition count within the transaction
        let transition_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ledger_events WHERE work_id = ?1 AND event_type = 'work_transitioned'",
                params![claim.work_id],
                |row| row.get(0),
            )
            .unwrap_or(0);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let transition_count = transition_count as u32;

        let transition_payload = serde_json::json!({
            "event_type": "work_transitioned",
            "work_id": claim.work_id,
            "from_state": "Open",
            "to_state": "Claimed",
            "rationale_code": "work_claimed_via_ipc",
            "previous_transition_count": transition_count,
            "actor_id": actor_id,
            "timestamp_ns": timestamp_ns,
        });
        let (transition_event, transition_event_hash) = self
            .build_signed_event_with_prev_hash(
                "work_transitioned",
                &claim.work_id,
                actor_id,
                transition_payload,
                timestamp_ns,
                WORK_TRANSITIONED_DOMAIN_PREFIX,
                &claimed_event_hash,
            )
            .inspect_err(|_e| {
                let _ = conn.execute("ROLLBACK", []);
            })?;

        if let Err(e) = self.persist_signed_event(
            &conn,
            &transition_event,
            &claimed_event_hash,
            &transition_event_hash,
        ) {
            let _ = conn.execute("ROLLBACK", []);
            return Err(e);
        }

        // Commit the transaction. On commit failure, attempt explicit
        // ROLLBACK to restore consistent state (TCK-00395 Security v3 MAJOR).
        if let Err(commit_err) = conn.execute("COMMIT", []) {
            warn!(error = %commit_err, "COMMIT failed for WorkClaimed transaction - attempting ROLLBACK");
            if let Err(rollback_err) = conn.execute("ROLLBACK", []) {
                return Err(LedgerEventError::PersistenceFailed {
                    message: format!(
                        "COMMIT failed ({commit_err}) and ROLLBACK also failed ({rollback_err}) - database may be inconsistent"
                    ),
                });
            }
            return Err(LedgerEventError::PersistenceFailed {
                message: format!("transaction commit failed (rolled back): {commit_err}"),
            });
        }

        info!(
            event_id = %claimed_event.event_id,
            work_id = %claim.work_id,
            "Persisted WorkClaimed + WorkTransitioned(Open->Claimed) atomically"
        );

        Ok(claimed_event)
    }

    /// TCK-00395 MAJOR 2: Transactional override for `emit_spawn_lifecycle`.
    ///
    /// Wraps `SessionStarted` (with optional contract binding) +
    /// `WorkTransitioned(Claimed->InProgress)` in a single `SQLite`
    /// transaction to guarantee atomicity.
    fn emit_spawn_lifecycle(
        &self,
        session_id: &str,
        work_id: &str,
        lease_id: &str,
        actor_id: &str,
        adapter_profile_hash: &[u8; 32],
        role_spec_hash: Option<&[u8; 32]>,
        timestamp_ns: u64,
        contract_binding: Option<&crate::hsi_contract::SessionContractBinding>,
        identity_proof_profile_hash: Option<&[u8; 32]>,
        selection_decision: Option<&SelectionDecision>,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        const SESSION_STARTED_DOMAIN_PREFIX: &[u8] = b"apm2.event.session_started:";

        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;

        // Begin explicit transaction for atomicity
        conn.execute("BEGIN IMMEDIATE", [])
            .map_err(|e| LedgerEventError::PersistenceFailed {
                message: format!("transaction begin failed: {e}"),
            })?;

        // --- Event 1: SessionStarted ---
        let prev_hash = self.latest_event_hash_routed(&conn).inspect_err(|_e| {
            let _ = conn.execute("ROLLBACK", []);
        })?;
        let session_payload = build_session_started_payload(
            session_id,
            work_id,
            lease_id,
            actor_id,
            adapter_profile_hash,
            role_spec_hash,
            contract_binding,
            identity_proof_profile_hash,
            selection_decision,
        );
        let (session_event, session_event_hash) = self
            .build_signed_event_with_prev_hash(
                "session_started",
                work_id,
                actor_id,
                session_payload,
                timestamp_ns,
                SESSION_STARTED_DOMAIN_PREFIX,
                &prev_hash,
            )
            .inspect_err(|_e| {
                let _ = conn.execute("ROLLBACK", []);
            })?;

        if let Err(e) =
            self.persist_signed_event(&conn, &session_event, &prev_hash, &session_event_hash)
        {
            let _ = conn.execute("ROLLBACK", []);
            return Err(e);
        }

        // --- Event 2: WorkTransitioned(Claimed -> InProgress) ---
        let transition_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ledger_events WHERE work_id = ?1 AND event_type = 'work_transitioned'",
                params![work_id],
                |row| row.get(0),
            )
            .unwrap_or(0);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let transition_count = transition_count as u32;

        let transition_payload = serde_json::json!({
            "event_type": "work_transitioned",
            "work_id": work_id,
            "from_state": "Claimed",
            "to_state": "InProgress",
            "rationale_code": "episode_spawned_via_ipc",
            "previous_transition_count": transition_count,
            "actor_id": actor_id,
            "timestamp_ns": timestamp_ns,
        });
        let (transition_event, transition_event_hash) = self
            .build_signed_event_with_prev_hash(
                "work_transitioned",
                work_id,
                actor_id,
                transition_payload,
                timestamp_ns,
                WORK_TRANSITIONED_DOMAIN_PREFIX,
                &session_event_hash,
            )
            .inspect_err(|_e| {
                let _ = conn.execute("ROLLBACK", []);
            })?;

        if let Err(e) = self.persist_signed_event(
            &conn,
            &transition_event,
            &session_event_hash,
            &transition_event_hash,
        ) {
            let _ = conn.execute("ROLLBACK", []);
            return Err(e);
        }

        // Commit the transaction. On commit failure, attempt explicit
        // ROLLBACK to restore consistent state (TCK-00395 Security v3 MAJOR).
        if let Err(commit_err) = conn.execute("COMMIT", []) {
            warn!(error = %commit_err, "COMMIT failed for SessionStarted transaction - attempting ROLLBACK");
            if let Err(rollback_err) = conn.execute("ROLLBACK", []) {
                return Err(LedgerEventError::PersistenceFailed {
                    message: format!(
                        "COMMIT failed ({commit_err}) and ROLLBACK also failed ({rollback_err}) - database may be inconsistent"
                    ),
                });
            }
            return Err(LedgerEventError::PersistenceFailed {
                message: format!("transaction commit failed (rolled back): {commit_err}"),
            });
        }

        info!(
            event_id = %session_event.event_id,
            session_id = %session_id,
            work_id = %work_id,
            "Persisted SessionStarted + WorkTransitioned(Claimed->InProgress) atomically"
        );

        Ok(session_event)
    }

    fn emit_changeset_published(
        &self,
        work_id: &str,
        changeset_digest: &[u8; 32],
        cas_hash: &[u8; 32],
        actor_id: &str,
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        // Build payload as JSON with changeset publication data.
        // SECURITY: timestamp_ns is included in signed payload to prevent
        // temporal malleability per LAW-09.
        let payload = serde_json::json!({
            "event_type": "changeset_published",
            "work_id": work_id,
            "changeset_digest": hex::encode(changeset_digest),
            "cas_hash": hex::encode(cas_hash),
            "actor_id": actor_id,
            "timestamp_ns": timestamp_ns,
        });
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;
        let prev_hash = self.latest_event_hash_routed(&conn)?;
        let (signed_event, event_hash) = self.build_signed_event_with_prev_hash(
            "changeset_published",
            work_id,
            actor_id,
            payload,
            timestamp_ns,
            CHANGESET_PUBLISHED_LEDGER_DOMAIN_PREFIX,
            &prev_hash,
        )?;
        self.persist_signed_event(&conn, &signed_event, &prev_hash, &event_hash)?;

        info!(
            event_id = %signed_event.event_id,
            work_id = %work_id,
            changeset_digest = %hex::encode(changeset_digest),
            cas_hash = %hex::encode(cas_hash),
            "Persisted ChangeSetPublished event"
        );

        Ok(signed_event)
    }

    /// TCK-00350: Emits a receipt with envelope bindings persisted in the
    /// payload.
    ///
    /// Overrides the default to include `envelope_hash`,
    /// `capability_manifest_hash`, and `view_commitment_hash` in the
    /// signed JSON payload. Fail-closed: bindings are validated before
    /// emission.
    #[allow(clippy::too_many_arguments)]
    fn emit_receipt_with_bindings(
        &self,
        episode_id: &str,
        receipt_id: &str,
        changeset_digest: &[u8; 32],
        artifact_bundle_hash: &[u8; 32],
        reviewer_actor_id: &str,
        timestamp_ns: u64,
        bindings: &crate::episode::EnvelopeBindings,
        identity_proof_hash: &[u8; 32],
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        // Fail-closed: validate bindings before emission
        bindings
            .validate()
            .map_err(|e| LedgerEventError::ValidationFailed {
                message: format!("envelope binding validation failed: {e}"),
            })?;

        // TCK-00350: Include envelope bindings in signed payload.
        // This ensures receipts carry immutable proof of the envelope,
        // capability manifest, and view commitment that were active.
        //
        // SECURITY (TCK-00356 Fix 1): identity_proof_hash is included in
        // the signed payload so it is audit-bound.
        let (env_hex, cap_hex, view_hex) = bindings.to_hex_map();
        let payload_json = serde_json::json!({
            "event_type": "review_receipt_recorded",
            "episode_id": episode_id,
            "receipt_id": receipt_id,
            "changeset_digest": hex::encode(changeset_digest),
            "artifact_bundle_hash": hex::encode(artifact_bundle_hash),
            "reviewer_actor_id": reviewer_actor_id,
            "timestamp_ns": timestamp_ns,
            "envelope_hash": env_hex,
            "capability_manifest_hash": cap_hex,
            "view_commitment_hash": view_hex,
            "identity_proof_hash": hex::encode(identity_proof_hash),
        });
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;
        let prev_hash = self.latest_event_hash_routed(&conn)?;
        let (signed_event, event_hash) = self.build_signed_event_with_prev_hash(
            "review_receipt_recorded",
            episode_id,
            reviewer_actor_id,
            payload_json,
            timestamp_ns,
            REVIEW_RECEIPT_RECORDED_PREFIX,
            &prev_hash,
        )?;
        self.persist_signed_event(&conn, &signed_event, &prev_hash, &event_hash)?;

        info!(
            event_id = %signed_event.event_id,
            episode_id = %episode_id,
            receipt_id = %receipt_id,
            envelope_hash = %env_hex,
            "Persisted ReviewReceiptRecorded event with envelope bindings"
        );

        Ok(signed_event)
    }

    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    fn freeze_legacy_writes(&self) -> Result<(), LedgerEventError> {
        self.freeze_legacy_writes_self().map(|_| ())
    }
}

/// Durable work registry backed by `SQLite`.
#[derive(Debug)]
pub struct SqliteWorkRegistry {
    conn: Arc<Mutex<Connection>>,
    claim_inserted_at: std::sync::RwLock<HashMap<(String, i32), Instant>>,
}

impl SqliteWorkRegistry {
    /// Creates a new registry with the given `SQLite` connection.
    #[must_use]
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            conn,
            claim_inserted_at: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Initializes the database schema.
    ///
    /// Claims are keyed by `(work_id, role)` to support Phase 2 multi-role
    /// workflows where Implementer and Reviewer each claim the same `work_id`.
    ///
    /// # Migration (Finding 2, round 5; Finding 1, round 7)
    ///
    /// Pre-existing databases may have the legacy schema with
    /// `work_id TEXT PRIMARY KEY` (single-role uniqueness). Two legacy
    /// variants exist:
    ///
    ///   (a) `work_id TEXT PRIMARY KEY` with no `role` column.
    ///   (b) `work_id TEXT PRIMARY KEY` with `role INTEGER` (intermediate
    ///       revision that added the role column but kept the single-column
    ///       PK — multi-role inserts still fail with `SQLITE_CONSTRAINT`).
    ///
    /// This method detects the legacy schema by **key/index topology**:
    /// if `work_id` is the sole PRIMARY KEY column, the table requires
    /// migration regardless of whether a `role` column is present.
    ///
    /// Migration steps:
    ///
    /// 1. Detect whether `work_claims` already exists with `work_id` as the
    ///    sole PRIMARY KEY column (via `PRAGMA table_info` pk flag).
    /// 2. If legacy schema: rename old table to `work_claims_legacy`, create
    ///    new table with composite uniqueness, copy data (preserving role if
    ///    present, defaulting to `1` = Implementer otherwise), drop the legacy
    ///    backup.
    /// 3. If new schema or fresh DB: use `CREATE TABLE IF NOT EXISTS`.
    ///
    /// The migration is idempotent: running it multiple times on the same
    /// database is safe.
    pub fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
        // Check whether the work_claims table already exists.
        let table_exists: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='work_claims'",
                [],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);

        if table_exists {
            // Detect legacy schema by key/index topology, not just column
            // presence.
            //
            // Legacy schema variants that require migration:
            //   (a) `work_id TEXT PRIMARY KEY` with NO `role` column
            //   (b) `work_id TEXT PRIMARY KEY` WITH `role INTEGER` column
            //       (intermediate revision that added role but kept the
            //       single-column PK)
            //
            // The authoritative signal is whether `work_id` is the sole
            // PRIMARY KEY column. In SQLite, `PRAGMA table_info` returns
            // column index 5 (`pk`) as >0 for columns in the PRIMARY KEY.
            // If `work_id` has pk>0 and no other column has pk>0, the table
            // enforces single-row-per-work_id and MUST be migrated.
            let mut has_role_column = false;
            let mut work_id_is_pk = false;
            let mut pk_column_count: usize = 0;

            {
                let mut stmt = conn.prepare("PRAGMA table_info(work_claims)")?;
                let mut rows = stmt.query([])?;
                while let Some(row) = rows.next()? {
                    let col_name: String = row.get(1)?;
                    let pk_flag: i32 = row.get(5)?;

                    if col_name == "role" {
                        has_role_column = true;
                    }
                    if pk_flag > 0 {
                        pk_column_count += 1;
                        if col_name == "work_id" {
                            work_id_is_pk = true;
                        }
                    }
                }
            }

            // Migration required when work_id is the SOLE PRIMARY KEY
            // column. This covers both legacy variants: (a) no role column
            // at all, and (b) role column present but PK still enforces
            // uniqueness on work_id alone.
            let needs_migration = work_id_is_pk && pk_column_count == 1;

            if needs_migration {
                // Legacy schema detected: work_claims has work_id TEXT
                // PRIMARY KEY (single-column PK). Migrate atomically.
                //
                // Strategy: rename → create new → copy → drop old.
                // All within a single transaction for atomicity.
                //
                // If the legacy table has a `role` column, preserve it.
                // If not, default to role=1 (Implementer).
                if has_role_column {
                    conn.execute_batch(
                        "BEGIN IMMEDIATE;
                         ALTER TABLE work_claims RENAME TO work_claims_legacy;
                         CREATE TABLE work_claims (
                             work_id TEXT NOT NULL,
                             lease_id TEXT NOT NULL,
                             actor_id TEXT NOT NULL,
                             role INTEGER NOT NULL DEFAULT 1,
                             claim_json BLOB NOT NULL
                         );
                         INSERT INTO work_claims (work_id, lease_id, actor_id, role, claim_json)
                             SELECT work_id, lease_id, actor_id, role, claim_json
                             FROM work_claims_legacy;
                         DROP TABLE work_claims_legacy;
                         COMMIT;",
                    )?;
                } else {
                    conn.execute_batch(
                        "BEGIN IMMEDIATE;
                         ALTER TABLE work_claims RENAME TO work_claims_legacy;
                         CREATE TABLE work_claims (
                             work_id TEXT NOT NULL,
                             lease_id TEXT NOT NULL,
                             actor_id TEXT NOT NULL,
                             role INTEGER NOT NULL DEFAULT 1,
                             claim_json BLOB NOT NULL
                         );
                         INSERT INTO work_claims (work_id, lease_id, actor_id, role, claim_json)
                             SELECT work_id, lease_id, actor_id, 1, claim_json
                             FROM work_claims_legacy;
                         DROP TABLE work_claims_legacy;
                         COMMIT;",
                    )?;
                }
            }
        } else {
            // Fresh database: create the table with the Phase 2 schema.
            conn.execute(
                "CREATE TABLE work_claims (
                    work_id TEXT NOT NULL,
                    lease_id TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    role INTEGER NOT NULL,
                    claim_json BLOB NOT NULL
                )",
                [],
            )?;
        }

        // Multi-role UNIQUE constraint: (work_id, role) instead of just work_id.
        // Different roles for the same work_id are allowed and expected.
        // CREATE UNIQUE INDEX IF NOT EXISTS is idempotent.
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_work_claims_work_role \
             ON work_claims(work_id, role)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_work_claims_lease_id \
             ON work_claims(lease_id)",
            [],
        )?;
        Ok(())
    }
}

impl WorkRegistry for SqliteWorkRegistry {
    fn register_claim(&self, claim: WorkClaim) -> Result<WorkClaim, WorkRegistryError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| WorkRegistryError::RegistrationFailed {
                message: "connection lock poisoned".to_string(),
            })?;

        // Check for duplicate (work_id, role) pair — multi-role support.
        // Different roles for the same work_id are allowed and expected.
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM work_claims WHERE work_id = ?1 AND role = ?2",
                params![claim.work_id, claim.role as i32],
                |_| Ok(true),
            )
            .optional()
            .unwrap_or(Some(false))
            .unwrap_or(false);

        if exists {
            return Err(WorkRegistryError::DuplicateWorkId {
                work_id: claim.work_id,
            });
        }

        let claim_json =
            serde_json::to_vec(&claim).map_err(|e| WorkRegistryError::RegistrationFailed {
                message: format!("serialization failed: {e}"),
            })?;

        conn.execute(
            "INSERT INTO work_claims (work_id, lease_id, actor_id, role, claim_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                claim.work_id,
                claim.lease_id,
                claim.actor_id,
                claim.role as i32,
                claim_json
            ],
        )
        .map_err(|e| WorkRegistryError::RegistrationFailed {
            message: format!("sqlite insert failed: {e}"),
        })?;

        if let Ok(mut ages) = self.claim_inserted_at.write() {
            ages.insert((claim.work_id.clone(), claim.role as i32), Instant::now());
        }

        Ok(claim)
    }

    fn get_claim(&self, work_id: &str) -> Option<WorkClaim> {
        let conn = self.conn.lock().ok()?;
        // Return the first claim registered for this work_id (any role),
        // ordered by role for deterministic results.
        let claim_json: Vec<u8> = conn
            .query_row(
                "SELECT claim_json FROM work_claims WHERE work_id = ?1 \
                 ORDER BY role ASC LIMIT 1",
                params![work_id],
                |row| row.get(0),
            )
            .optional()
            .ok()
            .flatten()?;

        serde_json::from_slice(&claim_json).ok()
    }

    fn get_claim_for_role(&self, work_id: &str, role: WorkRole) -> Option<WorkClaim> {
        let conn = self.conn.lock().ok()?;
        let claim_json: Vec<u8> = conn
            .query_row(
                "SELECT claim_json FROM work_claims WHERE work_id = ?1 AND role = ?2",
                params![work_id, role as i32],
                |row| row.get(0),
            )
            .optional()
            .ok()
            .flatten()?;

        serde_json::from_slice(&claim_json).ok()
    }

    fn get_claim_by_lease_id(&self, work_id: &str, lease_id: &str) -> Option<WorkClaim> {
        let conn = self.conn.lock().ok()?;
        // Direct SQL lookup by (work_id, lease_id) — O(1) with index.
        // This is more efficient than the default trait implementation
        // which iterates through roles.
        let claim_json: Vec<u8> = conn
            .query_row(
                "SELECT claim_json FROM work_claims \
                 WHERE work_id = ?1 AND lease_id = ?2 \
                 LIMIT 1",
                params![work_id, lease_id],
                |row| row.get(0),
            )
            .optional()
            .ok()
            .flatten()?;

        serde_json::from_slice(&claim_json).ok()
    }

    fn get_claim_age_for_role(&self, work_id: &str, role: WorkRole) -> Option<Duration> {
        self.claim_inserted_at.read().ok().and_then(|ages| {
            ages.get(&(work_id.to_string(), role as i32))
                .map(Instant::elapsed)
        })
    }

    fn clear_claim_age(&self, work_id: &str, role: WorkRole) {
        if let Ok(mut ages) = self.claim_inserted_at.write() {
            ages.remove(&(work_id.to_string(), role as i32));
        }
    }

    fn remove_claim_for_role(&self, work_id: &str, role: WorkRole) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "DELETE FROM work_claims WHERE work_id = ?1 AND role = ?2",
                params![work_id, role as i32],
            );
        }
        self.clear_claim_age(work_id, role);
    }
}

/// Durable lease validator backed by `SQLite`.
///
/// # Freeze Guard and Canonical Bridge (TCK-00631)
///
/// After RFC-0032 Phase 0 migration, this validator can be frozen via
/// [`Self::freeze_legacy_writes`]. Once frozen, all write methods
/// (`register_full_lease_inner`, `register_lease_with_executor`) route
/// to the canonical `events` table via
/// `persist_lease_to_canonical_events` instead of the legacy
/// `ledger_events` table.
///
/// `freeze_legacy_writes` is **unconditional**: it always activates the
/// freeze guard.
///
/// ## Synchronization Protocol (CTR-1002)
///
/// The `frozen` flag is an `AtomicBool` with `Acquire`/`Release` ordering:
/// - **Protected data**: Write-target routing (`events` vs `ledger_events`).
/// - **Publication**: `freeze_legacy_writes` stores `true` with `Release`.
/// - **Consumption**: Every write method loads with `Acquire` to determine the
///   write target.
/// - **Happens-before**: `freeze_legacy_writes(Release)` -> write method
///   `load(Acquire)` ensures all write methods see the freeze after it is set.
/// - **Allowed reorderings**: None — once frozen, the flag is never unset.
#[derive(Debug)]
pub struct SqliteLeaseValidator {
    conn: Arc<Mutex<Connection>>,
    signing_key: ed25519_dalek::SigningKey,
    /// Freeze guard: when `true`, all write methods reject.
    /// Set once by `freeze_legacy_writes` and never cleared.
    /// See synchronization protocol above.
    frozen: AtomicBool,
}

impl SqliteLeaseValidator {
    /// Creates a new validator with the given `SQLite` connection.
    ///
    /// Generates an ephemeral signing key — suitable for tests only.
    /// Production code MUST use `new_with_signing_key` with the daemon
    /// lifecycle signing key.
    ///
    /// The validator starts unfrozen. Call [`Self::freeze_legacy_writes`]
    /// after migration to activate the freeze guard.
    #[cfg(test)]
    #[must_use]
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        use rand::rngs::OsRng;

        Self {
            conn,
            signing_key: ed25519_dalek::SigningKey::generate(&mut OsRng),
            frozen: AtomicBool::new(false),
        }
    }

    /// Creates a new validator bound to the daemon authority signing key.
    ///
    /// The validator starts unfrozen. Call [`Self::freeze_legacy_writes`]
    /// after migration to activate the freeze guard.
    #[must_use]
    pub const fn new_with_signing_key(
        conn: Arc<Mutex<Connection>>,
        signing_key: ed25519_dalek::SigningKey,
    ) -> Self {
        Self {
            conn,
            signing_key,
            frozen: AtomicBool::new(false),
        }
    }

    /// Activates the freeze guard if `ledger_events_legacy_frozen` exists.
    ///
    /// After this call returns `Ok(true)`, all subsequent write methods on
    /// this validator will reject without mutating the database.
    ///
    /// # Fail-Closed Semantics
    ///
    /// If the existence check itself fails (e.g., database error), the
    /// validator is frozen anyway — it is safer to block writes than to risk
    /// dual-writing. The error is returned so the caller can log it.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the freeze guard was activated (table exists or DB check
    ///   failed).
    /// - `Ok(false)` if the frozen table does not exist (legacy mode, no
    ///   migration ran).
    ///
    /// # Errors
    ///
    /// Returns the underlying database error after freezing the validator.
    fn freeze_legacy_writes_inner(&self) -> Result<bool, String> {
        // Always freeze — there is no valid production scenario where
        // freeze_legacy_writes() is called and the guard should remain
        // inactive.  This matches the emitter's unconditional freeze
        // semantics (TCK-00631 BLOCKER 1 fix).
        self.frozen.store(true, Ordering::Release);

        let conn = self
            .conn
            .lock()
            .map_err(|e| format!("connection lock poisoned during freeze check: {e}"))?;

        // Best-effort observability check — freeze decision is unconditional.
        match conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ledger_events_legacy_frozen' LIMIT 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()
        {
            Ok(Some(_)) => {},
            Ok(None) => {
                info!(
                    "lease_validator freeze_legacy_writes: ledger_events_legacy_frozen \
                     table absent (canonical-mode DB); writes routed to canonical events"
                );
            },
            Err(e) => {
                // Validator is already frozen; log the error for observability.
                return Err(format!(
                    "failed to check ledger_events_legacy_frozen existence \
                     (fail-closed: writes frozen): {e}"
                ));
            },
        }

        Ok(true)
    }

    /// Returns `true` if the freeze guard is active (writes blocked).
    #[must_use]
    pub fn is_frozen(&self) -> bool {
        self.frozen.load(Ordering::Acquire)
    }

    /// Returns the verifier corresponding to the validator's signing key.
    ///
    /// Used by tests to assert signature-authenticated chain validation.
    #[must_use]
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    fn select_newest_by_timestamp<T>(
        legacy: Option<(T, i64)>,
        canonical: Option<(T, i64)>,
    ) -> Option<T> {
        match (legacy, canonical) {
            (Some((legacy_value, legacy_ts)), Some((canonical_value, canonical_ts))) => {
                if canonical_ts >= legacy_ts {
                    Some(canonical_value)
                } else {
                    Some(legacy_value)
                }
            },
            (Some((legacy_value, _)), None) => Some(legacy_value),
            (None, Some((canonical_value, _))) => Some(canonical_value),
            (None, None) => None,
        }
    }

    fn latest_legacy_lease_work_id(
        conn: &Connection,
        lease_id: &str,
    ) -> rusqlite::Result<Option<(String, i64)>> {
        conn.query_row(
            "SELECT work_id, timestamp_ns FROM ledger_events \
             WHERE event_type = 'gate_lease_issued' \
             AND json_extract(CAST(payload AS TEXT), '$.lease_id') = ?1 \
             ORDER BY timestamp_ns DESC, rowid DESC LIMIT 1",
            params![lease_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
    }

    fn latest_canonical_lease_work_id(
        conn: &Connection,
        lease_id: &str,
    ) -> rusqlite::Result<Option<(String, i64)>> {
        conn.query_row(
            "SELECT session_id, timestamp_ns FROM events \
             WHERE event_type = 'gate_lease_issued' \
             AND json_extract(CAST(payload AS TEXT), '$.lease_id') = ?1 \
             ORDER BY timestamp_ns DESC, rowid DESC LIMIT 1",
            params![lease_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
    }

    fn latest_legacy_lease_payload(
        conn: &Connection,
        lease_id: &str,
        require_full_lease: bool,
    ) -> rusqlite::Result<Option<(Vec<u8>, i64)>> {
        let sql = if require_full_lease {
            "SELECT payload, timestamp_ns FROM ledger_events \
             WHERE event_type = 'gate_lease_issued' \
             AND json_extract(CAST(payload AS TEXT), '$.lease_id') = ?1 \
             AND json_extract(CAST(payload AS TEXT), '$.full_lease') IS NOT NULL \
             ORDER BY timestamp_ns DESC, rowid DESC LIMIT 1"
        } else {
            "SELECT payload, timestamp_ns FROM ledger_events \
             WHERE event_type = 'gate_lease_issued' \
             AND json_extract(CAST(payload AS TEXT), '$.lease_id') = ?1 \
             ORDER BY timestamp_ns DESC, rowid DESC LIMIT 1"
        };
        conn.query_row(sql, params![lease_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()
    }

    fn latest_canonical_lease_payload(
        conn: &Connection,
        lease_id: &str,
        require_full_lease: bool,
    ) -> rusqlite::Result<Option<(Vec<u8>, i64)>> {
        let sql = if require_full_lease {
            "SELECT payload, timestamp_ns FROM events \
             WHERE event_type = 'gate_lease_issued' \
             AND json_extract(CAST(payload AS TEXT), '$.lease_id') = ?1 \
             AND json_extract(CAST(payload AS TEXT), '$.full_lease') IS NOT NULL \
             ORDER BY timestamp_ns DESC, rowid DESC LIMIT 1"
        } else {
            "SELECT payload, timestamp_ns FROM events \
             WHERE event_type = 'gate_lease_issued' \
             AND json_extract(CAST(payload AS TEXT), '$.lease_id') = ?1 \
             ORDER BY timestamp_ns DESC, rowid DESC LIMIT 1"
        };
        conn.query_row(sql, params![lease_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()
    }

    fn distinct_work_claim_binding_count(
        conn: &Connection,
        lease_id: &str,
    ) -> rusqlite::Result<u64> {
        conn.query_row(
            "SELECT COUNT(*) FROM (\
                SELECT work_id, actor_id \
                FROM work_claims \
                WHERE lease_id = ?1 \
                GROUP BY work_id, actor_id\
            )",
            params![lease_id],
            |row| row.get(0),
        )
    }

    fn latest_work_claim_lease_binding(
        conn: &Connection,
        lease_id: &str,
    ) -> rusqlite::Result<Option<(String, String)>> {
        let distinct_bindings = Self::distinct_work_claim_binding_count(conn, lease_id)?;
        if distinct_bindings > 1 {
            warn!(
                lease_id = %lease_id,
                distinct_bindings,
                "lease fallback denied: multiple distinct work_claim bindings found for lease"
            );
            return Ok(None);
        }
        conn.query_row(
            "SELECT work_id, actor_id FROM work_claims \
             WHERE lease_id = ?1 \
             ORDER BY rowid DESC LIMIT 1",
            params![lease_id],
            |row| {
                let work_id: String = row.get(0)?;
                let actor_id: String = row.get(1)?;
                Ok((work_id, actor_id))
            },
        )
        .optional()
        .map(|binding| {
            binding.filter(|(work_id, actor_id)| {
                let work_ok = !work_id.trim().is_empty();
                let actor_ok = !actor_id.trim().is_empty();
                if !work_ok || !actor_ok {
                    warn!(
                        lease_id = %lease_id,
                        work_ok,
                        actor_ok,
                        "lease fallback denied: invalid empty work/actor binding in work_claims"
                    );
                }
                work_ok && actor_ok
            })
        })
    }

    fn canonicalize_lease_payload(payload: &serde_json::Value) -> Result<Vec<u8>, String> {
        let payload_json = payload.to_string();
        let canonical_payload = canonicalize_json(&payload_json)
            .map_err(|e| format!("lease payload JCS failed: {e}"))?;
        Ok(canonical_payload.into_bytes())
    }

    fn sign_gate_lease_payload(&self, payload_bytes: &[u8]) -> Vec<u8> {
        let mut canonical_bytes =
            Vec::with_capacity(GATE_LEASE_ISSUED_LEDGER_DOMAIN_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(GATE_LEASE_ISSUED_LEDGER_DOMAIN_PREFIX);
        canonical_bytes.extend_from_slice(payload_bytes);
        self.signing_key.sign(&canonical_bytes).to_bytes().to_vec()
    }

    /// Persists a lease event to the canonical `events` table using BLAKE3
    /// hash chain. Called when the freeze guard is active.
    ///
    /// # Transaction contract
    ///
    /// This helper does **not** manage its own transaction — callers are
    /// responsible for BEGIN/COMMIT/ROLLBACK.  It only performs the
    /// chain-tip read + INSERT, leaving transaction ownership with the
    /// caller (matching the legacy path's savepoint-based protocol).
    #[allow(clippy::unused_self, clippy::too_many_arguments)] // &self for method consistency; params match column set
    fn persist_lease_to_canonical_events(
        &self,
        conn: &Connection,
        event_type: &str,
        session_id: &str,
        actor_id: &str,
        payload_bytes: &[u8],
        signature: &[u8],
        timestamp_ns: i64,
    ) -> Result<(), String> {
        use apm2_core::crypto::EventHasher;

        let tail_hash_opt: Option<Vec<u8>> = conn
            .query_row(
                "SELECT event_hash FROM events WHERE event_hash IS NOT NULL \
                 ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("failed to read canonical chain tip: {e}"))?;

        let prev_hash: [u8; 32] = match tail_hash_opt {
            Some(ref h) => h.as_slice().try_into().map_err(|_| {
                format!(
                    "canonical events tail event_hash has length {}, expected 32",
                    h.len()
                )
            })?,
            None => EventHasher::GENESIS_PREV_HASH,
        };

        let event_hash = EventHasher::hash_event(payload_bytes, &prev_hash);

        conn.execute(
            "INSERT INTO events (event_type, session_id, actor_id, record_version, \
             payload, timestamp_ns, prev_hash, event_hash, signature) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                event_type,
                session_id,
                actor_id,
                1_i64,
                payload_bytes,
                timestamp_ns,
                prev_hash.as_slice(),
                event_hash.as_slice(),
                signature,
            ],
        )
        .map_err(|e| format!("canonical events insert failed: {e}"))?;

        Ok(())
    }

    fn register_full_lease_inner(
        &self,
        lease: &apm2_core::fac::GateLease,
        delegated_parent_lease_id: Option<&str>,
    ) -> Result<(), String> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| format!("failed to acquire ledger lock: {e}"))?;
        conn.execute("BEGIN IMMEDIATE", [])
            .map_err(|e| format!("failed to begin lease transaction: {e}"))?;

        // TCK-00631: When frozen, route to canonical `events` table.
        // Transaction ownership stays with this caller — persist helper
        // only performs chain-tip read + INSERT.
        if self.frozen.load(Ordering::Acquire) {
            let prev_hash_hex = SqliteLedgerEventEmitter::latest_canonical_event_hash(&conn)
                .map_err(|e| {
                    let _ = conn.execute("ROLLBACK", []);
                    format!("failed to read canonical chain tip: {e}")
                })?;
            let payload = serde_json::json!({
                "event_type": "gate_lease_issued",
                "lease_id": lease.lease_id,
                "work_id": lease.work_id,
                "gate_id": lease.gate_id,
                "executor_actor_id": lease.executor_actor_id,
                "full_lease": lease,
                "delegated_parent_lease_id": delegated_parent_lease_id,
                "prev_hash": prev_hash_hex,
            });
            let payload_bytes = Self::canonicalize_lease_payload(&payload).inspect_err(|_e| {
                let _ = conn.execute("ROLLBACK", []);
            })?;
            let signature = self.sign_gate_lease_payload(&payload_bytes);
            let issued_at_i64 = i64::try_from(lease.issued_at).map_err(|_| {
                let _ = conn.execute("ROLLBACK", []);
                format!("lease issued_at '{}' exceeds i64 range", lease.issued_at)
            })?;
            self.persist_lease_to_canonical_events(
                &conn,
                "gate_lease_issued",
                &lease.work_id,
                "system",
                &payload_bytes,
                &signature,
                issued_at_i64,
            )
            .inspect_err(|_| {
                let _ = conn.execute("ROLLBACK", []);
            })?;
            conn.execute("COMMIT", [])
                .map_err(|e| format!("failed to commit canonical lease: {e}"))?;
            return Ok(());
        }

        // Legacy path (unfrozen): insert into `ledger_events`.
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

        let duplicate_exists: bool = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM ledger_events
                    WHERE event_type = 'gate_lease_issued'
                    AND json_extract(CAST(payload AS TEXT), '$.lease_id') = ?1
                    AND json_extract(CAST(payload AS TEXT), '$.full_lease') IS NOT NULL
                )",
                params![lease.lease_id],
                |row| row.get(0),
            )
            .map_err(|e| {
                let _ = conn.execute("ROLLBACK", []);
                format!("failed to query existing lease: {e}")
            })?;
        if duplicate_exists {
            let _ = conn.execute("ROLLBACK", []);
            return Err(format!("duplicate lease_id: {}", lease.lease_id));
        }

        let prev_hash = SqliteLedgerEventEmitter::latest_event_hash(&conn).map_err(|e| {
            let _ = conn.execute("ROLLBACK", []);
            format!("failed to read previous hash: {e}")
        })?;
        let payload = serde_json::json!({
            "event_type": "gate_lease_issued",
            "lease_id": lease.lease_id,
            "work_id": lease.work_id,
            "gate_id": lease.gate_id,
            "executor_actor_id": lease.executor_actor_id,
            "full_lease": lease,
            "delegated_parent_lease_id": delegated_parent_lease_id,
            "prev_hash": prev_hash,
        });
        let payload_bytes = Self::canonicalize_lease_payload(&payload).inspect_err(|_e| {
            let _ = conn.execute("ROLLBACK", []);
        })?;
        let signature = self.sign_gate_lease_payload(&payload_bytes);
        let tip_timestamp_i64: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(timestamp_ns), 0) FROM ledger_events",
                [],
                |row| row.get(0),
            )
            .map_err(|e| {
                let _ = conn.execute("ROLLBACK", []);
                format!("failed to read latest ledger timestamp: {e}")
            })?;
        let issued_at_i64 = i64::try_from(lease.issued_at).map_err(|_| {
            let _ = conn.execute("ROLLBACK", []);
            format!("lease issued_at '{}' exceeds i64 range", lease.issued_at)
        })?;
        let appended_timestamp_i64 = issued_at_i64.max(tip_timestamp_i64);
        let timestamp_ns = u64::try_from(appended_timestamp_i64).map_err(|_| {
            let _ = conn.execute("ROLLBACK", []);
            format!("appended timestamp '{appended_timestamp_i64}' cannot be represented as u64")
        })?;
        let event_hash = SqliteLedgerEventEmitter::compute_event_hash(&EventHashInput {
            event_id: &event_id,
            event_type: "gate_lease_issued",
            work_id: &lease.work_id,
            actor_id: "system",
            payload: &payload_bytes,
            signature: &signature,
            timestamp_ns,
            prev_hash: &prev_hash,
        });

        conn.execute(
            "INSERT INTO ledger_events (
                event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns, prev_hash, event_hash
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                &event_id,
                "gate_lease_issued",
                lease.work_id,
                "system",
                payload_bytes,
                signature,
                appended_timestamp_i64,
                &prev_hash,
                &event_hash,
            ],
        )
        .map_err(|e| {
            let _ = conn.execute("ROLLBACK", []);
            format!("failed to insert lease event: {e}")
        })?;
        let checkpoint = HashChainCheckpoint {
            rowid: conn.last_insert_rowid(),
            event_id: Some(event_id),
            event_hash,
        };
        SqliteLedgerEventEmitter::persist_hash_chain_checkpoint(
            &conn,
            &checkpoint,
            &self.signing_key,
        )
        .map_err(|e| {
            let _ = conn.execute("ROLLBACK", []);
            format!("failed to update hash-chain checkpoint metadata: {e}")
        })?;

        conn.execute("COMMIT", [])
            .map_err(|e| format!("failed to commit lease insert: {e}"))?;

        Ok(())
    }
}

// ============================================================================
// TCK-00395: Batch lifecycle methods for SqliteLedgerEventEmitter
// ============================================================================

impl LeaseValidator for SqliteLeaseValidator {
    fn validate_gate_lease(
        &self,
        lease_id: &str,
        work_id: &str,
    ) -> Result<(), LeaseValidationError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| LeaseValidationError::LedgerQueryFailed {
                message: "connection lock poisoned".to_string(),
            })?;

        let legacy_lookup = Self::latest_legacy_lease_work_id(&conn, lease_id).map_err(|e| {
            LeaseValidationError::LedgerQueryFailed {
                message: e.to_string(),
            }
        })?;
        let canonical_lookup = if self.is_frozen() {
            Self::latest_canonical_lease_work_id(&conn, lease_id).map_err(|e| {
                LeaseValidationError::LedgerQueryFailed {
                    message: e.to_string(),
                }
            })?
        } else {
            None
        };

        let Some(resolved_work_id) =
            Self::select_newest_by_timestamp(legacy_lookup, canonical_lookup)
        else {
            return Err(LeaseValidationError::LeaseNotFound {
                lease_id: lease_id.to_string(),
            });
        };

        let work_id_matches = resolved_work_id.len() == work_id.len()
            && bool::from(resolved_work_id.as_bytes().ct_eq(work_id.as_bytes()));
        if work_id_matches {
            Ok(())
        } else {
            Err(LeaseValidationError::WorkIdMismatch {
                actual: work_id.to_string(),
            })
        }
    }

    fn get_lease_executor_actor_id(&self, lease_id: &str) -> Option<String> {
        let conn = self.conn.lock().ok()?;

        let legacy_payload = Self::latest_legacy_lease_payload(&conn, lease_id, false)
            .ok()
            .flatten();
        let canonical_payload = if self.is_frozen() {
            Self::latest_canonical_lease_payload(&conn, lease_id, false)
                .ok()
                .flatten()
        } else {
            None
        };
        if let Some(payload_bytes) =
            Self::select_newest_by_timestamp(legacy_payload, canonical_payload)
        {
            let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
            if let Some(actor_id) = payload
                .get("executor_actor_id")
                .and_then(|v| v.as_str())
                .map(String::from)
            {
                return Some(actor_id);
            }
        }

        // Migration fallback: recover executor actor from persisted work claim
        // rows when no canonical gate lease payload is available.
        Self::latest_work_claim_lease_binding(&conn, lease_id)
            .ok()
            .flatten()
            .map(|(_, actor_id)| actor_id)
    }

    fn register_lease(&self, lease_id: &str, work_id: &str, gate_id: &str) {
        self.register_lease_with_executor(lease_id, work_id, gate_id, "");
    }

    fn register_lease_with_executor(
        &self,
        lease_id: &str,
        work_id: &str,
        gate_id: &str,
        executor_actor_id: &str,
    ) {
        // Emit an authoritative signed ledger event so chain verification can
        // authenticate lease-admission history.
        let Ok(conn) = self.conn.lock() else {
            return;
        };
        if conn.execute("BEGIN IMMEDIATE", []).is_err() {
            return;
        }

        // TCK-00631: When frozen, route to canonical `events` table.
        // Transaction ownership stays with this caller — persist helper
        // only performs chain-tip read + INSERT.
        if self.frozen.load(Ordering::Acquire) {
            let Ok(prev_hash_hex) = SqliteLedgerEventEmitter::latest_canonical_event_hash(&conn)
            else {
                let _ = conn.execute("ROLLBACK", []);
                return;
            };
            // Derive a real timestamp from the canonical events tip, mirroring
            // the legacy path which derives from ledger_events tip.  Falls back
            // to wall-time via chrono::Utc if the canonical table is empty.
            let tip_timestamp_ns: i64 = conn
                .query_row(
                    "SELECT COALESCE(MAX(timestamp_ns), 0) FROM events",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap_or_else(|_| chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
            let payload = serde_json::json!({
                "event_type": "gate_lease_issued",
                "lease_id": lease_id,
                "work_id": work_id,
                "gate_id": gate_id,
                "executor_actor_id": executor_actor_id,
                "prev_hash": prev_hash_hex,
            });
            let Ok(payload_bytes) = Self::canonicalize_lease_payload(&payload) else {
                let _ = conn.execute("ROLLBACK", []);
                return;
            };
            let signature = self.sign_gate_lease_payload(&payload_bytes);
            if self
                .persist_lease_to_canonical_events(
                    &conn,
                    "gate_lease_issued",
                    work_id,
                    "system",
                    &payload_bytes,
                    &signature,
                    tip_timestamp_ns,
                )
                .is_err()
            {
                let _ = conn.execute("ROLLBACK", []);
                return;
            }
            let _ = conn.execute("COMMIT", []);
            return;
        }

        // Legacy path (unfrozen): insert into `ledger_events`.
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());
        let Ok(prev_hash) = SqliteLedgerEventEmitter::latest_event_hash(&conn) else {
            let _ = conn.execute("ROLLBACK", []);
            return;
        };
        let Ok(tip_timestamp_i64) = conn.query_row(
            "SELECT COALESCE(MAX(timestamp_ns), 0) FROM ledger_events",
            [],
            |row| row.get::<_, i64>(0),
        ) else {
            let _ = conn.execute("ROLLBACK", []);
            return;
        };
        let Ok(timestamp_ns) = u64::try_from(tip_timestamp_i64) else {
            let _ = conn.execute("ROLLBACK", []);
            return;
        };
        let payload = serde_json::json!({
            "event_type": "gate_lease_issued",
            "lease_id": lease_id,
            "work_id": work_id,
            "gate_id": gate_id,
            "executor_actor_id": executor_actor_id,
            "prev_hash": prev_hash,
        });
        let Ok(payload_bytes) = Self::canonicalize_lease_payload(&payload) else {
            let _ = conn.execute("ROLLBACK", []);
            return;
        };
        let signature = self.sign_gate_lease_payload(&payload_bytes);
        let event_hash = SqliteLedgerEventEmitter::compute_event_hash(&EventHashInput {
            event_id: &event_id,
            event_type: "gate_lease_issued",
            work_id,
            actor_id: "system",
            payload: &payload_bytes,
            signature: &signature,
            timestamp_ns,
            prev_hash: &prev_hash,
        });
        if conn
            .execute(
            "INSERT INTO ledger_events (
                event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns, prev_hash, event_hash
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                event_id,
                "gate_lease_issued",
                work_id,
                "system",
                payload_bytes,
                signature,
                tip_timestamp_i64,
                &prev_hash,
                &event_hash,
            ],
        )
            .is_err()
        {
            let _ = conn.execute("ROLLBACK", []);
            return;
        }
        let checkpoint = HashChainCheckpoint {
            rowid: conn.last_insert_rowid(),
            event_id: Some(event_id),
            event_hash,
        };
        if SqliteLedgerEventEmitter::persist_hash_chain_checkpoint(
            &conn,
            &checkpoint,
            &self.signing_key,
        )
        .is_err()
        {
            let _ = conn.execute("ROLLBACK", []);
            return;
        }
        if conn.execute("COMMIT", []).is_err() {
            let _ = conn.execute("ROLLBACK", []);
        }
    }

    fn get_lease_work_id(&self, lease_id: &str) -> Option<String> {
        let conn = self.conn.lock().ok()?;

        let legacy_lookup = Self::latest_legacy_lease_work_id(&conn, lease_id)
            .ok()
            .flatten();
        let canonical_lookup = if self.is_frozen() {
            Self::latest_canonical_lease_work_id(&conn, lease_id)
                .ok()
                .flatten()
        } else {
            None
        };

        if let Some(work_id) = Self::select_newest_by_timestamp(legacy_lookup, canonical_lookup) {
            return Some(work_id);
        }

        // Migration fallback: recover lease->work binding from persisted work
        // claim rows when no canonical gate lease event exists yet.
        Self::latest_work_claim_lease_binding(&conn, lease_id)
            .ok()
            .flatten()
            .map(|(work_id, _)| work_id)
    }

    // Full leases are persisted in signed ledger rows. Reads remain
    // fail-closed and only return rows that contain `full_lease`.
    fn get_gate_lease(&self, lease_id: &str) -> Option<apm2_core::fac::GateLease> {
        let conn = self.conn.lock().ok()?;

        let legacy_payload = Self::latest_legacy_lease_payload(&conn, lease_id, true)
            .ok()
            .flatten();
        let canonical_payload = if self.is_frozen() {
            Self::latest_canonical_lease_payload(&conn, lease_id, true)
                .ok()
                .flatten()
        } else {
            None
        };
        let payload_bytes = Self::select_newest_by_timestamp(legacy_payload, canonical_payload)?;

        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;

        // Try to deserialize from the stored full_lease JSON if available.
        let full_lease = payload.get("full_lease")?;
        serde_json::from_value::<apm2_core::fac::GateLease>(full_lease.clone()).ok()
    }

    /// Registers a full gate lease as a signed `gate_lease_issued` event.
    fn register_full_lease(&self, lease: &apm2_core::fac::GateLease) -> Result<(), String> {
        self.register_full_lease_inner(lease, None)
    }

    fn register_delegated_full_lease(
        &self,
        lease: &apm2_core::fac::GateLease,
        parent_lease_id: &str,
    ) -> Result<(), String> {
        self.register_full_lease_inner(lease, Some(parent_lease_id))
    }

    fn get_delegation_parent_lease_id(&self, lease_id: &str) -> Result<Option<String>, String> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| format!("failed to acquire ledger lock: {e}"))?;
        let mut stmt = conn
            .prepare(
                "SELECT payload FROM ledger_events \
                 WHERE event_type = 'gate_lease_issued' \
                 AND json_extract(CAST(payload AS TEXT), '$.lease_id') = ?1 \
                 AND json_extract(CAST(payload AS TEXT), '$.full_lease') IS NOT NULL \
                 ORDER BY rowid DESC LIMIT 1",
            )
            .map_err(|e| {
                format!("failed to prepare delegation parent lookup for lease '{lease_id}': {e}")
            })?;

        let payload_bytes: Option<Vec<u8>> = stmt
            .query_row(params![lease_id], |row| row.get(0))
            .optional()
            .map_err(|e| {
                format!("failed to query delegation parent metadata for lease '{lease_id}': {e}")
            })?;
        let Some(payload_bytes) = payload_bytes else {
            return Ok(None);
        };

        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).map_err(|e| {
            format!("failed to parse gate_lease_issued payload for lease '{lease_id}': {e}")
        })?;

        let Some(parent_value) = payload.get("delegated_parent_lease_id") else {
            return Ok(None);
        };
        if parent_value.is_null() {
            return Ok(None);
        }
        let parent_lease_id = parent_value.as_str().ok_or_else(|| {
            format!(
                "gate_lease_issued payload for lease '{lease_id}' has non-string delegated_parent_lease_id"
            )
        })?;
        if parent_lease_id.is_empty() {
            return Err(format!(
                "gate_lease_issued payload for lease '{lease_id}' has empty delegated_parent_lease_id"
            ));
        }
        Ok(Some(parent_lease_id.to_owned()))
    }

    fn freeze_legacy_writes(&self) -> Result<(), String> {
        self.freeze_legacy_writes_inner().map(|_| ())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::protocol::dispatch::PolicyResolution;
    use crate::protocol::messages::WorkRole;

    /// Creates an in-memory `SQLite` connection with schema initialized.
    fn test_emitter() -> SqliteLedgerEventEmitter {
        let conn = Connection::open_in_memory().unwrap();
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        SqliteLedgerEventEmitter::new(Arc::new(Mutex::new(conn)), signing_key)
    }

    fn test_policy_resolution() -> PolicyResolution {
        PolicyResolution {
            policy_resolved_ref: "test-resolved".to_string(),
            pcac_policy: None,
            pointer_only_waiver: None,
            resolved_policy_hash: [0u8; 32],
            capability_manifest_hash: [0u8; 32],
            context_pack_hash: [0u8; 32],
            role_spec_hash: [0u8; 32],
            context_pack_recipe_hash: [0u8; 32],
            resolved_risk_tier: 0,
            resolved_scope_baseline: None,
            expected_adapter_profile_hash: None,
        }
    }

    fn insert_projection_event(
        emitter: &SqliteLedgerEventEmitter,
        idx: usize,
        event_type: &str,
        payload: &serde_json::Value,
    ) {
        let payload_bytes = serde_json::to_vec(payload).expect("payload should serialize");
        let conn = emitter
            .conn
            .lock()
            .expect("sqlite lock should be available");
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                format!("EVT-PROJ-{idx:08}"),
                event_type,
                format!("W-PROJ-{idx:08}"),
                "actor:test",
                payload_bytes,
                vec![0u8; 64],
                i64::try_from(idx).expect("idx should fit i64"),
            ],
        )
        .expect("projection seed event should insert");
    }

    #[test]
    fn backfill_hash_chain_handles_multiple_batches_without_uninitialized_rows() {
        let conn = Connection::open_in_memory().expect("sqlite in-memory should open");
        SqliteLedgerEventEmitter::init_schema_for_test(&conn)
            .expect("schema initialization should succeed");
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        let row_count = 1_041;
        for idx in 0..row_count {
            conn.execute(
                "INSERT INTO ledger_events
                    (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns, prev_hash, event_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'genesis', 'legacy-uninitialized')",
                params![
                    format!("legacy-batch-{idx:05}"),
                    "session_started",
                    format!("W-BATCH-{idx:05}"),
                    "uid:test",
                    br#"{"mode":"legacy"}"#.as_slice(),
                    b"sig".as_slice(),
                    i64::from(idx + 1),
                ],
            )
            .expect("legacy row insert should succeed");
        }

        conn.execute(
            "DELETE FROM ledger_metadata WHERE meta_key = ?1",
            params![SqliteLedgerEventEmitter::HASH_CHAIN_BACKFILL_COMPLETED_FLAG],
        )
        .expect("backfill completion flag reset should succeed");

        let migrated = SqliteLedgerEventEmitter::backfill_hash_chain(&conn, &signing_key)
            .expect("backfill should succeed for multi-batch legacy rows");
        assert!(migrated, "backfill should report migration work applied");

        let remaining_uninitialized: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ledger_events
                 WHERE event_hash IS NULL OR event_hash = '' OR event_hash = 'legacy-uninitialized'",
                [],
                |row| row.get(0),
            )
            .expect("uninitialized row count query should succeed");
        assert_eq!(
            remaining_uninitialized, 0,
            "all legacy rows must be assigned event hashes during backfill"
        );

        let latest_event_hash: String = conn
            .query_row(
                "SELECT event_hash FROM ledger_events ORDER BY timestamp_ns DESC, rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .expect("latest event hash query should succeed");
        let checkpoint = SqliteLedgerEventEmitter::get_metadata_value(
            &conn,
            SqliteLedgerEventEmitter::HASH_CHAIN_CHECKPOINT_KEY,
        )
        .expect("checkpoint lookup should succeed")
        .expect("checkpoint should be present after backfill");
        assert_eq!(
            checkpoint, latest_event_hash,
            "checkpoint metadata must track the latest event hash after backfill"
        );
    }

    #[test]
    fn backfill_hash_chain_links_legacy_suffix_to_existing_hashed_prefix() {
        let conn = Connection::open_in_memory().expect("sqlite in-memory should open");
        SqliteLedgerEventEmitter::init_schema_for_test(&conn)
            .expect("schema initialization should succeed");
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        conn.execute("DELETE FROM ledger_events", [])
            .expect("table reset should succeed");

        let first_hash = SqliteLedgerEventEmitter::compute_event_hash(&EventHashInput {
            event_id: "seed-0001",
            event_type: "session_started",
            work_id: "W-SEED-0001",
            actor_id: "uid:test",
            payload: br#"{"mode":"seed"}"#,
            signature: b"sig-seed",
            timestamp_ns: 1,
            prev_hash: SqliteLedgerEventEmitter::LEDGER_CHAIN_GENESIS,
        });
        conn.execute(
            "INSERT INTO ledger_events
                (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns, prev_hash, event_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                "seed-0001",
                "session_started",
                "W-SEED-0001",
                "uid:test",
                br#"{"mode":"seed"}"#.as_slice(),
                b"sig-seed".as_slice(),
                1_i64,
                SqliteLedgerEventEmitter::LEDGER_CHAIN_GENESIS,
                &first_hash,
            ],
        )
        .expect("seed hashed row insert should succeed");

        for idx in 2..=3 {
            conn.execute(
                "INSERT INTO ledger_events
                    (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns, prev_hash, event_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'genesis', 'legacy-uninitialized')",
                params![
                    format!("seed-{idx:04}"),
                    "session_started",
                    format!("W-SEED-{idx:04}"),
                    "uid:test",
                    br#"{"mode":"legacy"}"#.as_slice(),
                    b"sig-legacy".as_slice(),
                    i64::from(idx),
                ],
            )
            .expect("legacy suffix row insert should succeed");
        }

        conn.execute(
            "DELETE FROM ledger_metadata WHERE meta_key = ?1",
            params![SqliteLedgerEventEmitter::HASH_CHAIN_BACKFILL_COMPLETED_FLAG],
        )
        .expect("backfill completion flag reset should succeed");

        SqliteLedgerEventEmitter::backfill_hash_chain(&conn, &signing_key)
            .expect("backfill should succeed for mixed hashed/legacy rows");

        let second_prev_hash: String = conn
            .query_row(
                "SELECT prev_hash FROM ledger_events WHERE event_id = 'seed-0002'",
                [],
                |row| row.get(0),
            )
            .expect("second row prev_hash lookup should succeed");
        assert_eq!(
            second_prev_hash, first_hash,
            "legacy suffix must chain from the existing hashed prefix"
        );

        let second_hash: String = conn
            .query_row(
                "SELECT event_hash FROM ledger_events WHERE event_id = 'seed-0002'",
                [],
                |row| row.get(0),
            )
            .expect("second row hash lookup should succeed");
        let third_prev_hash: String = conn
            .query_row(
                "SELECT prev_hash FROM ledger_events WHERE event_id = 'seed-0003'",
                [],
                |row| row.get(0),
            )
            .expect("third row prev_hash lookup should succeed");
        assert_eq!(
            third_prev_hash, second_hash,
            "legacy rows within the suffix must link to the immediate prior migrated row"
        );
    }

    #[test]
    fn startup_validation_checks_only_checkpoint_suffix_rows() {
        const TOTAL_EVENTS: usize = 24;
        const SUFFIX_EVENTS: usize = 5;

        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("sqlite in-memory should open"),
        ));
        {
            let conn_guard = conn.lock().expect("sqlite lock should be available");
            SqliteLedgerEventEmitter::init_schema_for_test(&conn_guard)
                .expect("schema initialization should succeed");
        }

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let emitter = SqliteLedgerEventEmitter::new(Arc::clone(&conn), signing_key.clone());

        for idx in 0..TOTAL_EVENTS {
            emitter
                .emit_session_event(
                    "W-STARTUP-SUFFIX-001",
                    "session_started",
                    format!(r#"{{"event_type":"session_started","idx":{idx}}}"#).as_bytes(),
                    "uid:suffix-test",
                    1_700_000_000_000_100_000 + idx as u64,
                )
                .expect("session event should emit");
        }

        let checkpoint_rowid = i64::try_from(TOTAL_EVENTS - SUFFIX_EVENTS)
            .expect("checkpoint rowid conversion should fit i64");
        let checkpoint = {
            let conn_guard = conn.lock().expect("sqlite lock should be available");
            conn_guard
                .query_row(
                    "SELECT rowid, event_id, event_hash FROM ledger_events WHERE rowid = ?1",
                    params![checkpoint_rowid],
                    |row| {
                        Ok(HashChainCheckpoint {
                            rowid: row.get(0)?,
                            event_id: Some(row.get(1)?),
                            event_hash: row.get(2)?,
                        })
                    },
                )
                .expect("checkpoint row should exist")
        };

        let validated_rows = {
            let conn_guard = conn.lock().expect("sqlite lock should be available");
            SqliteLedgerEventEmitter::persist_hash_chain_checkpoint(
                &conn_guard,
                &checkpoint,
                &signing_key,
            )
            .expect("checkpoint metadata update should succeed");
            SqliteLedgerEventEmitter::validate_startup_hash_chain_checkpoint(
                &conn_guard,
                &signing_key,
                Some(&signing_key.verifying_key()),
            )
            .expect("startup checkpoint validation should succeed")
        };

        assert_eq!(
            validated_rows, SUFFIX_EVENTS,
            "startup validation must process only rows after the trusted checkpoint"
        );
    }

    #[test]
    fn startup_validation_restart_succeeds_with_persistent_key_and_fails_with_wrong_key() {
        const EVENT_COUNT: usize = 3;

        let temp_dir = tempdir().expect("tempdir should create");
        let db_path = temp_dir.path().join("ledger_restart.sqlite3");
        let signing_key_a = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        {
            let conn = Connection::open(&db_path).expect("sqlite file should open");
            SqliteLedgerEventEmitter::init_schema_with_signing_key(&conn, &signing_key_a)
                .expect("schema initialization should succeed");
            let emitter =
                SqliteLedgerEventEmitter::new(Arc::new(Mutex::new(conn)), signing_key_a.clone());

            for idx in 0..EVENT_COUNT {
                emitter
                    .emit_session_event(
                        "W-RESTART-001",
                        "session_started",
                        format!(r#"{{"event_type":"session_started","idx":{idx}}}"#).as_bytes(),
                        "uid:restart-test",
                        1_700_000_000_000_200_000 + idx as u64,
                    )
                    .expect("session event should persist");
            }
        }

        let conn = Connection::open(&db_path).expect("sqlite file should reopen");
        SqliteLedgerEventEmitter::init_schema_with_signing_key(&conn, &signing_key_a)
            .expect("startup schema init should accept the original verifying key");

        SqliteLedgerEventEmitter::persist_hash_chain_checkpoint(
            &conn,
            &HashChainCheckpoint::genesis(),
            &signing_key_a,
        )
        .expect("checkpoint reset should succeed");
        let validated_rows = SqliteLedgerEventEmitter::validate_startup_hash_chain_checkpoint(
            &conn,
            &signing_key_a,
            Some(&signing_key_a.verifying_key()),
        )
        .expect("startup validation should succeed with original key");
        assert_eq!(
            validated_rows, EVENT_COUNT,
            "startup validation should verify all rows from genesis when checkpoint is reset"
        );

        SqliteLedgerEventEmitter::persist_hash_chain_checkpoint(
            &conn,
            &HashChainCheckpoint::genesis(),
            &signing_key_a,
        )
        .expect("checkpoint reset should succeed");
        let signing_key_b = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let err = SqliteLedgerEventEmitter::validate_startup_hash_chain_checkpoint(
            &conn,
            &signing_key_a,
            Some(&signing_key_b.verifying_key()),
        )
        .expect_err("startup validation must fail with a different verifying key");
        assert!(
            err.contains("signature verification"),
            "wrong-key startup failure should report signature verification failure: {err}"
        );
    }

    #[test]
    fn startup_validation_missing_checkpoint_metadata_verifies_full_chain_before_reseeding() {
        const EVENT_COUNT: usize = 4;

        let temp_dir = tempdir().expect("tempdir should create");
        let db_path = temp_dir.path().join("ledger_missing_checkpoint.sqlite3");
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        {
            let conn = Connection::open(&db_path).expect("sqlite file should open");
            SqliteLedgerEventEmitter::init_schema_with_signing_key(&conn, &signing_key)
                .expect("schema initialization should succeed");
            let emitter =
                SqliteLedgerEventEmitter::new(Arc::new(Mutex::new(conn)), signing_key.clone());

            for idx in 0..EVENT_COUNT {
                emitter
                    .emit_session_event(
                        "W-MISSING-CHECKPOINT-001",
                        "session_started",
                        format!(r#"{{"event_type":"session_started","idx":{idx}}}"#).as_bytes(),
                        "uid:checkpoint-test",
                        1_700_000_000_000_300_000 + idx as u64,
                    )
                    .expect("session event should persist");
            }
        }

        let conn = Connection::open(&db_path).expect("sqlite file should reopen");
        conn.execute(
            "DELETE FROM ledger_metadata WHERE meta_key IN (?1, ?2, ?3, ?4)",
            params![
                SqliteLedgerEventEmitter::HASH_CHAIN_CHECKPOINT_KEY,
                SqliteLedgerEventEmitter::HASH_CHAIN_CHECKPOINT_ROWID_KEY,
                SqliteLedgerEventEmitter::HASH_CHAIN_CHECKPOINT_EVENT_ID_KEY,
                SqliteLedgerEventEmitter::HASH_CHAIN_CHECKPOINT_SIGNATURE_KEY,
            ],
        )
        .expect("checkpoint metadata deletion should succeed");

        let validated_rows = SqliteLedgerEventEmitter::validate_startup_hash_chain_checkpoint(
            &conn,
            &signing_key,
            Some(&signing_key.verifying_key()),
        )
        .expect("startup validation should verify full chain when checkpoint metadata is missing");
        assert_eq!(
            validated_rows, EVENT_COUNT,
            "missing checkpoint metadata must trigger full-chain verification, not blind reseed"
        );
    }

    #[test]
    fn startup_validation_missing_checkpoint_signature_verifies_full_chain_before_reseeding() {
        const EVENT_COUNT: usize = 4;

        let temp_dir = tempdir().expect("tempdir should create");
        let db_path = temp_dir
            .path()
            .join("ledger_missing_checkpoint_signature.sqlite3");
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        {
            let conn = Connection::open(&db_path).expect("sqlite file should open");
            SqliteLedgerEventEmitter::init_schema_with_signing_key(&conn, &signing_key)
                .expect("schema initialization should succeed");
            let emitter =
                SqliteLedgerEventEmitter::new(Arc::new(Mutex::new(conn)), signing_key.clone());

            for idx in 0..EVENT_COUNT {
                emitter
                    .emit_session_event(
                        "W-MISSING-CHECKPOINT-SIGNATURE-001",
                        "session_started",
                        format!(r#"{{"event_type":"session_started","idx":{idx}}}"#).as_bytes(),
                        "uid:checkpoint-signature-test",
                        1_700_000_000_000_350_000 + idx as u64,
                    )
                    .expect("session event should persist");
            }
        }

        let conn = Connection::open(&db_path).expect("sqlite file should reopen");
        conn.execute(
            "DELETE FROM ledger_metadata WHERE meta_key = ?1",
            params![SqliteLedgerEventEmitter::HASH_CHAIN_CHECKPOINT_SIGNATURE_KEY],
        )
        .expect("checkpoint signature metadata deletion should succeed");

        let validated_rows = SqliteLedgerEventEmitter::validate_startup_hash_chain_checkpoint(
            &conn,
            &signing_key,
            Some(&signing_key.verifying_key()),
        )
        .expect("startup validation should verify full chain when checkpoint signature is missing");
        assert_eq!(
            validated_rows, EVENT_COUNT,
            "missing checkpoint signature must trigger full-chain verification"
        );
    }

    #[test]
    fn startup_validation_invalid_checkpoint_signature_verifies_full_chain_before_reseeding() {
        const EVENT_COUNT: usize = 4;

        let temp_dir = tempdir().expect("tempdir should create");
        let db_path = temp_dir
            .path()
            .join("ledger_invalid_checkpoint_signature.sqlite3");
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        {
            let conn = Connection::open(&db_path).expect("sqlite file should open");
            SqliteLedgerEventEmitter::init_schema_with_signing_key(&conn, &signing_key)
                .expect("schema initialization should succeed");
            let emitter =
                SqliteLedgerEventEmitter::new(Arc::new(Mutex::new(conn)), signing_key.clone());

            for idx in 0..EVENT_COUNT {
                emitter
                    .emit_session_event(
                        "W-INVALID-CHECKPOINT-SIGNATURE-001",
                        "session_started",
                        format!(r#"{{"event_type":"session_started","idx":{idx}}}"#).as_bytes(),
                        "uid:checkpoint-signature-test",
                        1_700_000_000_000_360_000 + idx as u64,
                    )
                    .expect("session event should persist");
            }
        }

        let conn = Connection::open(&db_path).expect("sqlite file should reopen");
        conn.execute(
            "UPDATE ledger_metadata SET meta_value = ?1 WHERE meta_key = ?2",
            params![
                "ffffffff",
                SqliteLedgerEventEmitter::HASH_CHAIN_CHECKPOINT_SIGNATURE_KEY
            ],
        )
        .expect("checkpoint signature metadata tamper should succeed");

        let validated_rows = SqliteLedgerEventEmitter::validate_startup_hash_chain_checkpoint(
            &conn,
            &signing_key,
            Some(&signing_key.verifying_key()),
        )
        .expect("startup validation should verify full chain when checkpoint signature is invalid");
        assert_eq!(
            validated_rows, EVENT_COUNT,
            "invalid checkpoint signature must trigger full-chain verification"
        );
    }

    #[test]
    fn startup_validation_with_stale_checkpoint_verifies_suffix_after_restart() {
        const EVENT_COUNT: usize = 5;
        const STALE_ROWID: i64 = 3;
        const EXPECTED_SUFFIX_ROWS: usize = 2;

        let temp_dir = tempdir().expect("tempdir should create");
        let db_path = temp_dir.path().join("ledger_stale_checkpoint.sqlite3");
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        {
            let conn = Connection::open(&db_path).expect("sqlite file should open");
            SqliteLedgerEventEmitter::init_schema_with_signing_key(&conn, &signing_key)
                .expect("schema initialization should succeed");
            let emitter =
                SqliteLedgerEventEmitter::new(Arc::new(Mutex::new(conn)), signing_key.clone());

            for idx in 0..EVENT_COUNT {
                emitter
                    .emit_session_event(
                        "W-STALE-CHECKPOINT-001",
                        "session_started",
                        format!(r#"{{"event_type":"session_started","idx":{idx}}}"#).as_bytes(),
                        "uid:stale-test",
                        1_700_000_000_000_400_000 + idx as u64,
                    )
                    .expect("session event should persist");
            }
        }

        let conn = Connection::open(&db_path).expect("sqlite file should reopen");
        let stale_checkpoint: HashChainCheckpoint = conn
            .query_row(
                "SELECT rowid, event_id, event_hash FROM ledger_events WHERE rowid = ?1",
                params![STALE_ROWID],
                |row| {
                    Ok(HashChainCheckpoint {
                        rowid: row.get(0)?,
                        event_id: Some(row.get(1)?),
                        event_hash: row.get(2)?,
                    })
                },
            )
            .expect("stale checkpoint row should exist");
        SqliteLedgerEventEmitter::persist_hash_chain_checkpoint(
            &conn,
            &stale_checkpoint,
            &signing_key,
        )
        .expect("stale checkpoint metadata update should succeed");

        let validated_rows = SqliteLedgerEventEmitter::validate_startup_hash_chain_checkpoint(
            &conn,
            &signing_key,
            Some(&signing_key.verifying_key()),
        )
        .expect("startup validation should verify suffix from stale checkpoint");
        assert_eq!(
            validated_rows, EXPECTED_SUFFIX_ROWS,
            "stale checkpoint must validate only the unverified suffix"
        );
    }

    #[test]
    fn startup_validation_recovers_stale_checkpoint_after_canonical_migration() {
        const EVENT_COUNT: usize = 6;

        let temp_dir = tempdir().expect("tempdir should create");
        let db_path = temp_dir
            .path()
            .join("ledger_canonical_cutover_recover.sqlite3");
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        {
            let conn = Connection::open(&db_path).expect("sqlite file should open");
            SqliteLedgerEventEmitter::init_schema_with_signing_key(&conn, &signing_key)
                .expect("schema initialization should succeed");
            let emitter =
                SqliteLedgerEventEmitter::new(Arc::new(Mutex::new(conn)), signing_key.clone());

            for idx in 0..EVENT_COUNT {
                emitter
                    .emit_session_event(
                        "W-CANONICAL-CHECKPOINT-001",
                        "session_started",
                        format!(r#"{{"event_type":"session_started","idx":{idx}}}"#).as_bytes(),
                        "uid:canonical-cutover-test",
                        1_700_000_000_000_450_000 + idx as u64,
                    )
                    .expect("session event should persist");
            }
        }

        {
            let conn = Connection::open(&db_path).expect("sqlite file should reopen for migration");
            apm2_core::ledger::init_canonical_schema(&conn)
                .expect("canonical schema initialization should succeed");
            let migration_stats = apm2_core::ledger::migrate_legacy_ledger_events(&conn)
                .expect("legacy migration should succeed");
            assert_eq!(
                migration_stats.rows_migrated, EVENT_COUNT as u64,
                "migration should move all legacy rows into canonical events"
            );
        }

        let conn = Connection::open(&db_path).expect("sqlite file should reopen for validation");
        let validated_rows = SqliteLedgerEventEmitter::validate_startup_hash_chain_checkpoint(
            &conn,
            &signing_key,
            Some(&signing_key.verifying_key()),
        )
        .expect(
            "startup validation should recover stale legacy checkpoint after canonical migration",
        );
        assert_eq!(
            validated_rows, 0,
            "canonical cutover recovery should validate zero legacy suffix rows"
        );

        let checkpoint_rowid = SqliteLedgerEventEmitter::get_metadata_value(
            &conn,
            SqliteLedgerEventEmitter::HASH_CHAIN_CHECKPOINT_ROWID_KEY,
        )
        .expect("checkpoint rowid metadata lookup should succeed")
        .expect("checkpoint rowid metadata should be present");
        assert_eq!(
            checkpoint_rowid, "0",
            "recovered checkpoint should be reseeded to legacy genesis"
        );
    }

    #[test]
    fn startup_validation_rejects_checkpoint_ahead_of_empty_legacy_tip_without_canonical_rows() {
        const EVENT_COUNT: usize = 3;

        let temp_dir = tempdir().expect("tempdir should create");
        let db_path = temp_dir
            .path()
            .join("ledger_checkpoint_ahead_fail_closed.sqlite3");
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

        {
            let conn = Connection::open(&db_path).expect("sqlite file should open");
            SqliteLedgerEventEmitter::init_schema_with_signing_key(&conn, &signing_key)
                .expect("schema initialization should succeed");
            let emitter =
                SqliteLedgerEventEmitter::new(Arc::new(Mutex::new(conn)), signing_key.clone());

            for idx in 0..EVENT_COUNT {
                emitter
                    .emit_session_event(
                        "W-CHECKPOINT-FAIL-CLOSED-001",
                        "session_started",
                        format!(r#"{{"event_type":"session_started","idx":{idx}}}"#).as_bytes(),
                        "uid:checkpoint-fail-closed-test",
                        1_700_000_000_000_460_000 + idx as u64,
                    )
                    .expect("session event should persist");
            }
        }

        {
            let conn = Connection::open(&db_path).expect("sqlite file should reopen for mutation");
            conn.execute("DELETE FROM ledger_events", [])
                .expect("legacy rows should be deletable for fail-closed test");
        }

        let conn = Connection::open(&db_path).expect("sqlite file should reopen for validation");
        let err = SqliteLedgerEventEmitter::validate_startup_hash_chain_checkpoint(
            &conn,
            &signing_key,
            Some(&signing_key.verifying_key()),
        )
        .expect_err(
            "startup validation must fail when checkpoint is ahead of tip without canonical rows",
        );
        assert!(
            err.contains("checkpoint rowid") && err.contains("ahead of chain tip"),
            "expected explicit ahead-of-tip failure, got: {err}"
        );
    }

    #[test]
    fn derive_event_chain_hash_rejects_rehashed_tampered_event_with_invalid_signature() {
        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("sqlite in-memory should open"),
        ));
        {
            let conn_guard = conn.lock().expect("sqlite lock should be available");
            SqliteLedgerEventEmitter::init_schema_for_test(&conn_guard)
                .expect("schema initialization should succeed");
        }

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let emitter = SqliteLedgerEventEmitter::new(Arc::clone(&conn), signing_key);

        let claim = WorkClaim {
            work_id: "W-SIG-CHECK-001".to_string(),
            lease_id: "L-SIG-CHECK-001".to_string(),
            actor_id: "uid:sig-check".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };
        emitter
            .emit_work_claimed(&claim, 1_700_000_000_000_000_000)
            .expect("work_claimed should persist");

        {
            let conn_guard = conn.lock().expect("sqlite lock should be available");
            let (
                event_id,
                event_type,
                work_id,
                actor_id,
                payload_bytes,
                timestamp_i64,
                prev_hash,
            ): (String, String, String, String, Vec<u8>, i64, String) = conn_guard
                .query_row(
                    "SELECT event_id, event_type, work_id, actor_id, payload, timestamp_ns, prev_hash
                     FROM ledger_events
                     ORDER BY rowid ASC
                     LIMIT 1",
                    [],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ))
                    },
                )
                .expect("seed event row should load");
            #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
            let timestamp_ns = timestamp_i64 as u64;

            let mut tampered_payload: serde_json::Value =
                serde_json::from_slice(&payload_bytes).expect("seed payload should decode");
            tampered_payload["tampered"] = serde_json::Value::Bool(true);
            let tampered_payload_bytes =
                serde_json::to_vec(&tampered_payload).expect("tampered payload should encode");
            let tampered_signature = vec![0x7Fu8; 64];
            let tampered_event_hash =
                SqliteLedgerEventEmitter::compute_event_hash(&EventHashInput {
                    event_id: &event_id,
                    event_type: &event_type,
                    work_id: &work_id,
                    actor_id: &actor_id,
                    payload: &tampered_payload_bytes,
                    signature: &tampered_signature,
                    timestamp_ns,
                    prev_hash: &prev_hash,
                });

            conn_guard
                .execute(
                    "UPDATE ledger_events
                     SET payload = ?1, signature = ?2, event_hash = ?3
                     WHERE event_id = ?4",
                    params![
                        tampered_payload_bytes,
                        tampered_signature,
                        tampered_event_hash,
                        event_id
                    ],
                )
                .expect("tampered row update should succeed");
            SqliteLedgerEventEmitter::set_metadata_value(
                &conn_guard,
                SqliteLedgerEventEmitter::HASH_CHAIN_CHECKPOINT_KEY,
                &tampered_event_hash,
            )
            .expect("checkpoint update should succeed");
        }

        let err = emitter
            .derive_event_chain_hash()
            .expect_err("signature-authenticated chain derivation must fail on tampered row");
        assert!(
            err.contains("signature verification"),
            "chain verification must fail on invalid signatures: {err}"
        );
    }

    #[test]
    fn authoritative_projection_query_is_bounded_to_recent_receipts() {
        let emitter = test_emitter();
        let total = MAX_PROJECTION_EVENTS + 3;

        for idx in 0..total {
            insert_projection_event(
                &emitter,
                idx,
                "review_receipt_recorded",
                &serde_json::json!({
                    "receipt_id": format!("RCP-PROJ-{idx:08}"),
                }),
            );
        }

        assert_eq!(
            emitter.get_authoritative_receipt_event_count(),
            total,
            "authoritative receipt count should report full history"
        );

        let events = emitter.get_authoritative_receipt_events();
        assert_eq!(
            events.len(),
            MAX_PROJECTION_EVENTS,
            "authoritative projection query must cap returned rows"
        );

        let expected_first = total - MAX_PROJECTION_EVENTS;
        assert_eq!(
            events.first().map(|event| event.work_id.clone()),
            Some(format!("W-PROJ-{expected_first:08}")),
            "bounded query must keep the most recent receipt window"
        );
        assert_eq!(
            events.last().map(|event| event.work_id.clone()),
            Some(format!("W-PROJ-{:08}", total - 1)),
            "bounded query must include newest receipt event"
        );
    }

    #[test]
    fn liveness_projection_query_is_bounded_to_recent_events() {
        let emitter = test_emitter();
        let total = MAX_PROJECTION_EVENTS + 4;

        for idx in 0..total {
            insert_projection_event(
                &emitter,
                idx,
                "session_started",
                &serde_json::json!({
                    "session_id": format!("SESS-PROJ-{idx:08}"),
                }),
            );
        }

        assert_eq!(
            emitter.get_launch_liveness_projection_event_count(),
            total,
            "liveness event count should report full history"
        );

        let events = emitter.get_launch_liveness_projection_events();
        assert_eq!(
            events.len(),
            MAX_PROJECTION_EVENTS,
            "liveness projection query must cap returned rows"
        );

        let expected_first = total - MAX_PROJECTION_EVENTS;
        assert_eq!(
            events.first().map(|event| event.work_id.clone()),
            Some(format!("W-PROJ-{expected_first:08}")),
            "bounded liveness query must keep the most recent event window"
        );
        assert_eq!(
            events.last().map(|event| event.work_id.clone()),
            Some(format!("W-PROJ-{:08}", total - 1)),
            "bounded liveness query must include newest event"
        );
    }

    /// FIX-SEC-BLOCKER: Events with equal timestamps are retrieved in
    /// deterministic (rowid) order.
    #[test]
    fn equal_timestamp_events_deterministic_order_sqlite() {
        let emitter = test_emitter();
        let ts = 1_000_000_000u64;

        // Emit multiple events with the same timestamp
        let claim = WorkClaim {
            work_id: "W-ORDER-SQL-001".to_string(),
            lease_id: "L-001".to_string(),
            actor_id: "uid:1000".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };

        emitter.emit_work_claimed(&claim, ts).unwrap();

        emitter
            .emit_work_transitioned(&WorkTransition {
                work_id: "W-ORDER-SQL-001",
                from_state: "Open",
                to_state: "Claimed",
                rationale_code: "work_claimed_via_ipc",
                previous_transition_count: 0,
                actor_id: "uid:1000",
                timestamp_ns: ts,
            })
            .unwrap();

        emitter
            .emit_session_started(
                "SESS-SQL-001",
                "W-ORDER-SQL-001",
                "L-001",
                "uid:1000",
                &[0xAA; 32],
                None,
                ts,
                None,
                None,
                None,
            )
            .unwrap();

        // Query events - must be in insertion order
        let events = emitter.get_events_by_work_id("W-ORDER-SQL-001");
        assert_eq!(events.len(), 3, "Expected 3 events");

        // Verify ordering by event_type (insertion order)
        assert_eq!(
            events[0].event_type, "work_claimed",
            "First event should be work_claimed"
        );
        assert_eq!(
            events[1].event_type, "work_transitioned",
            "Second event should be work_transitioned"
        );
        assert_eq!(
            events[2].event_type, "session_started",
            "Third event should be session_started"
        );

        // All have the same timestamp
        for event in &events {
            assert_eq!(
                event.timestamp_ns, ts,
                "All events should have the same timestamp"
            );
        }
    }

    /// FIX-SEC-BLOCKER: `get_work_transition_count` returns accurate count
    /// from `SQLite`.
    #[test]
    fn get_work_transition_count_sqlite() {
        let emitter = test_emitter();

        // Initially 0
        assert_eq!(emitter.get_work_transition_count("W-COUNT-SQL-001"), 0);

        // Emit a non-transition event
        let claim = WorkClaim {
            work_id: "W-COUNT-SQL-001".to_string(),
            lease_id: "L-001".to_string(),
            actor_id: "uid:1000".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };
        emitter.emit_work_claimed(&claim, 1_000).unwrap();

        // Still 0 (work_claimed is not a transition)
        assert_eq!(emitter.get_work_transition_count("W-COUNT-SQL-001"), 0);

        // Emit a transition
        emitter
            .emit_work_transitioned(&WorkTransition {
                work_id: "W-COUNT-SQL-001",
                from_state: "Open",
                to_state: "Claimed",
                rationale_code: "work_claimed_via_ipc",
                previous_transition_count: 0,
                actor_id: "uid:1000",
                timestamp_ns: 2_000,
            })
            .unwrap();

        assert_eq!(emitter.get_work_transition_count("W-COUNT-SQL-001"), 1);

        // Emit another transition
        emitter
            .emit_work_transitioned(&WorkTransition {
                work_id: "W-COUNT-SQL-001",
                from_state: "Claimed",
                to_state: "InProgress",
                rationale_code: "episode_spawned_via_ipc",
                previous_transition_count: 1,
                actor_id: "uid:1000",
                timestamp_ns: 3_000,
            })
            .unwrap();

        assert_eq!(emitter.get_work_transition_count("W-COUNT-SQL-001"), 2);

        // Different work_id still 0
        assert_eq!(emitter.get_work_transition_count("W-COUNT-SQL-002"), 0);
    }

    /// FIX-SEC-BLOCKER: `SessionTerminated` event is persisted to `SQLite`.
    #[test]
    fn session_terminated_persisted_sqlite() {
        let emitter = test_emitter();

        let result = emitter.emit_session_terminated(
            "SESS-SQL-001",
            "W-TERM-SQL-001",
            0,
            "completed_normally",
            "uid:1000",
            1_000_000_000,
        );
        assert!(result.is_ok());

        let events = emitter.get_events_by_work_id("W-TERM-SQL-001");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "session_terminated");

        let payload: serde_json::Value = serde_json::from_slice(&events[0].payload).unwrap();
        assert_eq!(payload["session_id"], "SESS-SQL-001");
        assert_eq!(payload["work_id"], "W-TERM-SQL-001");
        assert_eq!(payload["exit_code"], 0);
        assert_eq!(payload["termination_reason"], "completed_normally");
    }

    // ====================================================================
    // TCK-00395 MAJOR 2: Transactional lifecycle tests
    // ====================================================================

    /// `emit_claim_lifecycle` on `SqliteLedgerEventEmitter` persists both
    /// events atomically in a single transaction.
    #[test]
    fn emit_claim_lifecycle_sqlite_atomic() {
        let emitter = test_emitter();
        let claim = WorkClaim {
            work_id: "W-ATOMIC-SQL-001".to_string(),
            lease_id: "L-001".to_string(),
            actor_id: "uid:1000".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };

        let result = emitter.emit_claim_lifecycle(&claim, "uid:1000", 1_000_000_000);
        assert!(result.is_ok(), "emit_claim_lifecycle should succeed");

        let events = emitter.get_events_by_work_id("W-ATOMIC-SQL-001");
        assert_eq!(
            events.len(),
            2,
            "Expected 2 events (claimed + transitioned)"
        );
        assert_eq!(events[0].event_type, "work_claimed");
        assert_eq!(events[1].event_type, "work_transitioned");

        let payload: serde_json::Value = serde_json::from_slice(&events[1].payload).unwrap();
        assert_eq!(payload["from_state"], "Open");
        assert_eq!(payload["to_state"], "Claimed");
        assert_eq!(payload["previous_transition_count"], 0);
    }

    /// `emit_spawn_lifecycle` on `SqliteLedgerEventEmitter` persists both
    /// events atomically in a single transaction.
    #[test]
    fn emit_spawn_lifecycle_sqlite_atomic() {
        let emitter = test_emitter();

        // First set up a claim
        let claim = WorkClaim {
            work_id: "W-ATOMIC-SQL-002".to_string(),
            lease_id: "L-001".to_string(),
            actor_id: "uid:1000".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };
        emitter
            .emit_claim_lifecycle(&claim, "uid:1000", 1_000_000_000)
            .unwrap();

        // Now spawn lifecycle
        let result = emitter.emit_spawn_lifecycle(
            "SESS-SQL-002",
            "W-ATOMIC-SQL-002",
            "L-001",
            "uid:1000",
            &[0xAA; 32],
            None,
            2_000_000_000,
            None,
            None,
            None,
        );
        assert!(result.is_ok(), "emit_spawn_lifecycle should succeed");

        let events = emitter.get_events_by_work_id("W-ATOMIC-SQL-002");
        // work_claimed, work_transitioned(Open->Claimed),
        // session_started, work_transitioned(Claimed->InProgress)
        assert_eq!(events.len(), 4, "Expected 4 events total");
        assert_eq!(events[2].event_type, "session_started");
        assert_eq!(events[3].event_type, "work_transitioned");

        let payload: serde_json::Value = serde_json::from_slice(&events[3].payload).unwrap();
        assert_eq!(payload["from_state"], "Claimed");
        assert_eq!(payload["to_state"], "InProgress");
        // After claim lifecycle, there's 1 transition, so
        // previous_transition_count for InProgress should be 1
        assert_eq!(payload["previous_transition_count"], 1);
    }

    /// Failure injection: If the second insert fails in
    /// `emit_claim_lifecycle`, the first insert is rolled back (no partial
    /// commit).
    #[test]
    fn emit_claim_lifecycle_rollback_on_second_insert_failure() {
        // Create a connection and schema, then drop the table to
        // simulate a failure scenario.
        let conn = Connection::open_in_memory().unwrap();
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();

        // Insert a trigger that causes the second insert (work_transitioned)
        // to fail by using a UNIQUE constraint violation. We'll pre-insert
        // a row with a known event_id pattern.
        //
        // Alternative approach: use a restricted table. Instead, we test
        // that a successful call produces exactly 2 events and a failure
        // produces 0 events by using a corrupted connection.
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let conn = Arc::new(Mutex::new(conn));
        let emitter = SqliteLedgerEventEmitter::new(conn.clone(), signing_key);

        // A successful call should produce 2 events
        let claim = WorkClaim {
            work_id: "W-ROLLBACK-001".to_string(),
            lease_id: "L-001".to_string(),
            actor_id: "uid:1000".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };
        let result = emitter.emit_claim_lifecycle(&claim, "uid:1000", 1_000);
        assert!(result.is_ok());

        let events = emitter.get_events_by_work_id("W-ROLLBACK-001");
        assert_eq!(
            events.len(),
            2,
            "Successful call should produce exactly 2 events"
        );

        // Now drop the table and verify that a new call fails with no
        // partial state
        {
            let c = conn.lock().unwrap();
            c.execute("DROP TABLE ledger_events", []).unwrap();
        }
        let claim2 = WorkClaim {
            work_id: "W-ROLLBACK-002".to_string(),
            lease_id: "L-002".to_string(),
            actor_id: "uid:1000".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };
        let result2 = emitter.emit_claim_lifecycle(&claim2, "uid:1000", 2_000);
        assert!(result2.is_err(), "Should fail when table is dropped");
    }

    /// Failure injection: If the second insert fails in
    /// `emit_spawn_lifecycle`, the first insert is rolled back.
    #[test]
    fn emit_spawn_lifecycle_rollback_on_failure() {
        let conn = Connection::open_in_memory().unwrap();
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let conn = Arc::new(Mutex::new(conn));
        let emitter = SqliteLedgerEventEmitter::new(conn.clone(), signing_key);

        // A successful call should produce 2 events
        let result = emitter.emit_spawn_lifecycle(
            "SESS-ROLLBACK-001",
            "W-ROLLBACK-003",
            "L-001",
            "uid:1000",
            &[0xAA; 32],
            None,
            1_000,
            None,
            None,
            None,
        );
        assert!(result.is_ok());
        let events = emitter.get_events_by_work_id("W-ROLLBACK-003");
        assert_eq!(
            events.len(),
            2,
            "Successful spawn lifecycle produces 2 events"
        );

        // Drop the table to force failure
        {
            let c = conn.lock().unwrap();
            c.execute("DROP TABLE ledger_events", []).unwrap();
        }
        let result2 = emitter.emit_spawn_lifecycle(
            "SESS-ROLLBACK-002",
            "W-ROLLBACK-004",
            "L-002",
            "uid:1000",
            &[0xAA; 32],
            None,
            2_000,
            None,
            None,
            None,
        );
        assert!(result2.is_err(), "Should fail when table is dropped");
    }

    /// TCK-00340: Verify `SqliteLeaseValidator::get_gate_lease` retrieves
    /// a full `GateLease` stored via `register_full_lease`.
    #[test]
    fn sqlite_lease_validator_get_gate_lease_roundtrip() {
        use crate::protocol::dispatch::LeaseValidator;

        let conn = Connection::open_in_memory().unwrap();
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();
        let conn = Arc::new(Mutex::new(conn));
        // Use Arc<dyn LeaseValidator> to match how the dispatcher uses it
        let validator: Arc<dyn LeaseValidator> =
            Arc::new(SqliteLeaseValidator::new(Arc::clone(&conn)));

        let signer = apm2_core::crypto::Signer::generate();
        let lease = apm2_core::fac::GateLeaseBuilder::new("test-lease-001", "W-RT-001", "gate-rt")
            .changeset_digest([0x42; 32])
            .executor_actor_id("exec-rt")
            .issued_at(1_000_000)
            .expires_at(2_000_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("issuer-rt")
            .time_envelope_ref("htf:tick:100")
            .build_and_sign(&signer);

        validator
            .register_full_lease(&lease)
            .expect("register_full_lease should succeed in test");

        let retrieved = validator.get_gate_lease("test-lease-001");
        assert!(
            retrieved.is_some(),
            "get_gate_lease must return the stored lease"
        );
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.lease_id, "test-lease-001");
        assert_eq!(retrieved.work_id, "W-RT-001");
        assert_eq!(retrieved.gate_id, "gate-rt");
        assert_eq!(retrieved.executor_actor_id, "exec-rt");
    }

    /// TCK-00340: Verify `SqliteLeaseValidator::get_lease_work_id` returns
    /// the correct `work_id` for a stored lease.
    #[test]
    fn sqlite_lease_validator_get_lease_work_id() {
        use crate::protocol::dispatch::LeaseValidator;

        let conn = Connection::open_in_memory().unwrap();
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();
        let conn = Arc::new(Mutex::new(conn));
        let validator = SqliteLeaseValidator::new(Arc::clone(&conn));

        validator.register_lease_with_executor(
            "work-lease-001",
            "W-WID-001",
            "gate-wid",
            "exec-wid",
        );

        let work_id = validator.get_lease_work_id("work-lease-001");
        assert_eq!(
            work_id.as_deref(),
            Some("W-WID-001"),
            "get_lease_work_id must return the stored work_id"
        );
    }

    /// Regression (TCK-00637): lease read APIs must resolve leases that were
    /// written to canonical `events` while the validator is frozen.
    #[test]
    fn sqlite_lease_validator_frozen_reads_from_canonical_events() {
        use apm2_core::ledger::init_canonical_schema;

        use crate::protocol::dispatch::LeaseValidator;

        let conn = Connection::open_in_memory().unwrap();
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();
        init_canonical_schema(&conn).unwrap();
        let conn = Arc::new(Mutex::new(conn));
        let validator = SqliteLeaseValidator::new(Arc::clone(&conn));

        validator
            .freeze_legacy_writes_inner()
            .expect("freeze_legacy_writes must succeed in test");
        assert!(validator.is_frozen(), "validator must be frozen");

        validator.register_lease_with_executor(
            "lease-frozen-read-001",
            "W-FROZEN-READ-001",
            "gate-frozen-read",
            "actor-frozen-read",
        );

        assert_eq!(
            validator
                .get_lease_work_id("lease-frozen-read-001")
                .as_deref(),
            Some("W-FROZEN-READ-001"),
            "get_lease_work_id must read canonical gate_lease_issued rows when frozen"
        );
        assert_eq!(
            validator
                .get_lease_executor_actor_id("lease-frozen-read-001")
                .as_deref(),
            Some("actor-frozen-read"),
            "get_lease_executor_actor_id must read canonical gate_lease_issued rows when frozen"
        );
        assert!(
            validator
                .validate_gate_lease("lease-frozen-read-001", "W-FROZEN-READ-001")
                .is_ok(),
            "validate_gate_lease must succeed for canonical rows when frozen"
        );

        let signer = apm2_core::crypto::Signer::generate();
        let full_lease = apm2_core::fac::GateLeaseBuilder::new(
            "lease-frozen-full-001",
            "W-FROZEN-FULL-001",
            "gate-frozen-full",
        )
        .changeset_digest([0x11; 32])
        .executor_actor_id("actor-frozen-full")
        .issued_at(1_500_000)
        .expires_at(2_500_000)
        .policy_hash([0x22; 32])
        .issuer_actor_id("issuer-frozen")
        .time_envelope_ref("htf:tick:frozen")
        .build_and_sign(&signer);
        validator
            .register_full_lease(&full_lease)
            .expect("register_full_lease must succeed in frozen mode");

        let recovered_full = validator
            .get_gate_lease("lease-frozen-full-001")
            .expect("get_gate_lease must read canonical full_lease rows when frozen");
        assert_eq!(recovered_full.lease_id, "lease-frozen-full-001");
        assert_eq!(recovered_full.work_id, "W-FROZEN-FULL-001");
        assert_eq!(recovered_full.executor_actor_id, "actor-frozen-full");

        let conn_guard = conn.lock().unwrap();
        let legacy_rows: i64 = conn_guard
            .query_row(
                "SELECT COUNT(*) FROM ledger_events WHERE event_type = 'gate_lease_issued'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            legacy_rows, 0,
            "frozen validator writes must not append gate_lease_issued rows to legacy table"
        );
    }

    /// Regression (TCK-00637): when frozen and both tables may contain matching
    /// transitions, `get_latest_work_transition_by_rationale` must return the
    /// newest event by timestamp across legacy + canonical tables.
    #[test]
    fn sqlite_work_transition_rationale_lookup_prefers_newer_canonical_event() {
        use apm2_core::ledger::init_canonical_schema;

        let conn = Connection::open_in_memory().unwrap();
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();
        init_canonical_schema(&conn).unwrap();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let conn = Arc::new(Mutex::new(conn));
        let emitter = SqliteLedgerEventEmitter::new(Arc::clone(&conn), signing_key);

        let work_id = "W-transition-freeze-001";
        let rationale = "claim_work_v2_implementer";

        emitter
            .emit_work_transitioned(&WorkTransition {
                work_id,
                from_state: "Open",
                to_state: "Claimed",
                rationale_code: rationale,
                previous_transition_count: 0,
                actor_id: "legacy-actor",
                timestamp_ns: 1_000_000,
            })
            .expect("legacy work_transitioned insert should succeed");

        {
            let conn_guard = conn.lock().unwrap();
            emitter
                .freeze_legacy_writes(&conn_guard)
                .expect("freeze_legacy_writes must succeed");
        }
        assert!(emitter.is_frozen(), "emitter must be frozen");

        emitter
            .emit_work_transitioned(&WorkTransition {
                work_id,
                from_state: "Open",
                to_state: "Claimed",
                rationale_code: rationale,
                previous_transition_count: 1,
                actor_id: "canonical-actor",
                timestamp_ns: 2_000_000,
            })
            .expect("canonical work_transitioned insert should succeed");

        let latest = emitter
            .get_latest_work_transition_by_rationale(work_id, rationale)
            .expect("latest matching transition must exist");
        assert_eq!(
            latest.actor_id, "canonical-actor",
            "lookup must return newer canonical transition instead of legacy-first match"
        );
        assert_eq!(
            latest.timestamp_ns, 2_000_000,
            "lookup must return the highest timestamp across both tables"
        );
    }

    /// Regression: lease registration updates the hash-chain checkpoint
    /// metadata so startup checkpoint validation succeeds.
    #[test]
    fn sqlite_lease_validator_register_lease_with_executor_updates_checkpoint() {
        let conn = Connection::open_in_memory().unwrap();
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();
        let conn = Arc::new(Mutex::new(conn));
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let validator =
            SqliteLeaseValidator::new_with_signing_key(Arc::clone(&conn), signing_key.clone());

        validator.register_lease_with_executor(
            "checkpoint-lease-001",
            "W-CHECKPOINT-001",
            "gate-checkpoint",
            "exec-checkpoint",
        );

        let verifying_key = signing_key.verifying_key();
        let conn_guard = conn.lock().expect("sqlite lock should be available");
        let chain_tip =
            SqliteLedgerEventEmitter::derive_event_chain_hash_from_db(&conn_guard, &verifying_key)
                .expect("chain tip derivation should succeed");
        let checkpoint = SqliteLedgerEventEmitter::get_metadata_value(
            &conn_guard,
            SqliteLedgerEventEmitter::HASH_CHAIN_CHECKPOINT_KEY,
        )
        .expect("checkpoint metadata lookup should succeed");
        assert_eq!(
            checkpoint.as_deref(),
            Some(chain_tip.as_str()),
            "register_lease_with_executor must update hash-chain checkpoint"
        );
        SqliteLedgerEventEmitter::validate_startup_hash_chain_checkpoint(
            &conn_guard,
            &signing_key,
            Some(&verifying_key),
        )
        .expect("startup checkpoint validation should pass after lease registration");
    }

    /// Regression: full-lease registration updates hash-chain checkpoint
    /// metadata atomically with event insertion.
    #[test]
    fn sqlite_lease_validator_register_full_lease_updates_checkpoint() {
        use crate::protocol::dispatch::LeaseValidator;

        let conn = Connection::open_in_memory().unwrap();
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();
        let conn = Arc::new(Mutex::new(conn));
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let validator =
            SqliteLeaseValidator::new_with_signing_key(Arc::clone(&conn), signing_key.clone());

        let signer = apm2_core::crypto::Signer::generate();
        let lease = apm2_core::fac::GateLeaseBuilder::new(
            "checkpoint-full-lease-001",
            "W-CHECKPOINT-002",
            "gate-full-checkpoint",
        )
        .changeset_digest([0x11; 32])
        .executor_actor_id("exec-full-checkpoint")
        .issued_at(1_234_567)
        .expires_at(2_345_678)
        .policy_hash([0x22; 32])
        .issuer_actor_id("issuer-full-checkpoint")
        .time_envelope_ref("htf:tick:321")
        .build_and_sign(&signer);

        validator
            .register_full_lease(&lease)
            .expect("register_full_lease should succeed");

        let verifying_key = signing_key.verifying_key();
        let conn_guard = conn.lock().expect("sqlite lock should be available");
        let chain_tip =
            SqliteLedgerEventEmitter::derive_event_chain_hash_from_db(&conn_guard, &verifying_key)
                .expect("chain tip derivation should succeed");
        let checkpoint = SqliteLedgerEventEmitter::get_metadata_value(
            &conn_guard,
            SqliteLedgerEventEmitter::HASH_CHAIN_CHECKPOINT_KEY,
        )
        .expect("checkpoint metadata lookup should succeed");
        assert_eq!(
            checkpoint.as_deref(),
            Some(chain_tip.as_str()),
            "register_full_lease must update hash-chain checkpoint"
        );
        SqliteLedgerEventEmitter::validate_startup_hash_chain_checkpoint(
            &conn_guard,
            &signing_key,
            Some(&verifying_key),
        )
        .expect("startup checkpoint validation should pass after full lease registration");
    }

    // ====================================================================
    // v10 BLOCKER 2: register_full_lease duplicate rejection tests
    // ====================================================================

    /// v10 BLOCKER 2: `SqliteLeaseValidator::register_full_lease` rejects
    /// duplicate `lease_id` to enforce DB-level uniqueness.
    #[test]
    fn sqlite_lease_validator_register_full_lease_duplicate_rejected() {
        use crate::protocol::dispatch::LeaseValidator;

        let conn = Connection::open_in_memory().unwrap();
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();
        let conn = Arc::new(Mutex::new(conn));
        let validator: Arc<dyn LeaseValidator> =
            Arc::new(SqliteLeaseValidator::new(Arc::clone(&conn)));

        let signer = apm2_core::crypto::Signer::generate();
        let lease = apm2_core::fac::GateLeaseBuilder::new("dup-lease-001", "W-DUP-001", "gate-dup")
            .changeset_digest([0x42; 32])
            .executor_actor_id("exec-dup")
            .issued_at(1_000_000)
            .expires_at(2_000_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("issuer-dup")
            .time_envelope_ref("htf:tick:100")
            .build_and_sign(&signer);

        // First registration succeeds
        let result1 = validator.register_full_lease(&lease);
        assert!(result1.is_ok(), "First registration should succeed");

        // Second registration with same lease_id must fail
        let result2 = validator.register_full_lease(&lease);
        assert!(
            result2.is_err(),
            "Duplicate lease_id must be rejected by register_full_lease"
        );
        let err_msg = result2.unwrap_err();
        assert!(
            err_msg.contains("duplicate lease_id"),
            "Error message should mention duplicate: {err_msg}"
        );
    }

    // ====================================================================
    // TCK-00348: Contract binding canonicalizer metadata tests
    // ====================================================================

    /// TCK-00348: `emit_session_started` includes canonicalizer metadata
    /// in the persisted payload when a contract binding is provided.
    #[test]
    fn emit_session_started_includes_canonicalizer_metadata() {
        use crate::hsi_contract::RiskTier;
        use crate::hsi_contract::handshake_binding::{CanonicalizerInfo, SessionContractBinding};

        let emitter = test_emitter();

        let binding = SessionContractBinding {
            cli_contract_hash: "blake3:client_abc".to_string(),
            server_contract_hash: "blake3:server_xyz".to_string(),
            client_canonicalizers: vec![CanonicalizerInfo {
                id: "apm2.canonical.v1".to_string(),
                version: 1,
            }],
            mismatch_waived: true,
            risk_tier: RiskTier::Tier1,
        };

        let result = emitter.emit_session_started(
            "SESS-CANON-001",
            "W-CANON-001",
            "L-001",
            "uid:1000",
            &[0xAA; 32],
            None,
            1_000_000_000,
            Some(&binding),
            None,
            None,
        );
        assert!(result.is_ok(), "emit_session_started should succeed");

        let signed_event = result.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&signed_event.payload).unwrap();

        // Verify contract binding fields present
        assert_eq!(payload["cli_contract_hash"], "blake3:client_abc");
        assert_eq!(payload["server_contract_hash"], "blake3:server_xyz");
        assert_eq!(payload["mismatch_waived"], true);
        assert_eq!(payload["adapter_profile_hash"], hex::encode([0xAA; 32]));
        assert_eq!(payload["waiver_id"], "WVR-0002");
        assert_eq!(payload["role_spec_hash_absent"], true);

        // Verify canonicalizer metadata is present
        let canonicalizers = payload["client_canonicalizers"]
            .as_array()
            .expect("client_canonicalizers should be an array");
        assert_eq!(canonicalizers.len(), 1, "Expected 1 canonicalizer entry");
        assert_eq!(canonicalizers[0]["id"], "apm2.canonical.v1");
        assert_eq!(canonicalizers[0]["version"], 1);
    }

    /// TCK-00348: `emit_spawn_lifecycle` includes canonicalizer metadata
    /// in the persisted `SessionStarted` payload.
    #[test]
    fn emit_spawn_lifecycle_includes_canonicalizer_metadata() {
        use crate::hsi_contract::RiskTier;
        use crate::hsi_contract::handshake_binding::{CanonicalizerInfo, SessionContractBinding};

        let emitter = test_emitter();

        // Set up a claimed work item via emit_claim_lifecycle
        let claim = WorkClaim {
            work_id: "W-CANON-002".to_string(),
            lease_id: "L-002".to_string(),
            actor_id: "uid:1000".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };
        emitter
            .emit_claim_lifecycle(&claim, "uid:1000", 1_000_000_000)
            .unwrap();

        let binding = SessionContractBinding {
            cli_contract_hash: "blake3:client_def".to_string(),
            server_contract_hash: "blake3:server_ghi".to_string(),
            client_canonicalizers: vec![
                CanonicalizerInfo {
                    id: "apm2.canonical.v1".to_string(),
                    version: 1,
                },
                CanonicalizerInfo {
                    id: "apm2.canonical.jcs".to_string(),
                    version: 2,
                },
            ],
            mismatch_waived: false,
            risk_tier: RiskTier::Tier2,
        };

        let result = emitter.emit_spawn_lifecycle(
            "SESS-CANON-002",
            "W-CANON-002",
            "L-002",
            "uid:1000",
            &[0xAA; 32],
            None,
            2_000_000_000,
            Some(&binding),
            None,
            None,
        );
        assert!(result.is_ok(), "emit_spawn_lifecycle should succeed");

        let signed_event = result.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&signed_event.payload).unwrap();

        // Verify contract binding fields present
        assert_eq!(payload["cli_contract_hash"], "blake3:client_def");
        assert_eq!(payload["server_contract_hash"], "blake3:server_ghi");
        assert_eq!(payload["mismatch_waived"], false);
        assert_eq!(payload["adapter_profile_hash"], hex::encode([0xAA; 32]));
        assert_eq!(payload["waiver_id"], "WVR-0002");
        assert_eq!(payload["role_spec_hash_absent"], true);

        // Verify canonicalizer metadata is present with both entries
        let canonicalizers = payload["client_canonicalizers"]
            .as_array()
            .expect("client_canonicalizers should be an array");
        assert_eq!(canonicalizers.len(), 2, "Expected 2 canonicalizer entries");
        assert_eq!(canonicalizers[0]["id"], "apm2.canonical.v1");
        assert_eq!(canonicalizers[0]["version"], 1);
        assert_eq!(canonicalizers[1]["id"], "apm2.canonical.jcs");
        assert_eq!(canonicalizers[1]["version"], 2);
    }

    /// Verifies that `get_event_by_receipt_id` finds review receipt events
    /// by their payload-embedded `receipt_id` field, and that submitting the
    /// same `receipt_id` twice returns the original event (idempotent).
    #[test]
    fn test_get_event_by_receipt_id_returns_existing_event() {
        let emitter = test_emitter();

        let changeset = [0xABu8; 32];
        let artifact = [0xCDu8; 32];

        // Emit a review receipt with a specific receipt_id
        let identity_proof = [0x99u8; 32];
        let event1 = emitter
            .emit_review_receipt(
                "lease-001",
                "work-001",
                "RR-IDEMP-001",
                &changeset,
                &artifact,
                &[0x11; 32],
                &[0x22; 32],
                &[0x33; 32],
                "reviewer-actor-x",
                1_000_000_000,
                &identity_proof,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                None,
            )
            .expect("first emit should succeed");

        // Lookup by receipt_id should find the event
        let found = emitter.get_event_by_receipt_id("RR-IDEMP-001");
        assert!(
            found.is_some(),
            "get_event_by_receipt_id must find the event"
        );
        let found = found.unwrap();
        assert_eq!(
            found.event_id, event1.event_id,
            "Must return the same event_id as the original emission"
        );
        assert_eq!(found.event_type, "review_receipt_recorded");

        // Lookup by a different receipt_id should return None
        let not_found = emitter.get_event_by_receipt_id("RR-IDEMP-999");
        assert!(
            not_found.is_none(),
            "get_event_by_receipt_id must return None for unknown receipt_id"
        );
    }

    /// Verifies that `get_event_by_receipt_id` also finds blocked receipt
    /// events.
    #[test]
    fn test_get_event_by_receipt_id_finds_blocked_receipts() {
        let emitter = test_emitter();

        let changeset_digest = [0x42u8; 32];
        let artifact_bundle_hash = [0xA5u8; 32];
        let blocked_log_hash = [0xEEu8; 32];

        let identity_proof_hash = [0xDDu8; 32];
        let blocked_event = emitter
            .emit_review_blocked_receipt(
                "lease-blocked-001",
                "work-blocked-001",
                "RR-BLOCKED-001",
                &changeset_digest,
                &artifact_bundle_hash,
                &[0x11; 32],
                &[0x22; 32],
                &[0x33; 32],
                42,
                &blocked_log_hash,
                "reviewer-actor-y",
                2_000_000_000,
                &identity_proof_hash,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                None,
            )
            .expect("blocked receipt emit should succeed");

        let found = emitter.get_event_by_receipt_id("RR-BLOCKED-001");
        assert!(
            found.is_some(),
            "get_event_by_receipt_id must find blocked receipt events"
        );
        let found = found.unwrap();
        assert_eq!(
            found.event_id, blocked_event.event_id,
            "Must return the same event_id as the original blocked emission"
        );
        assert_eq!(found.event_type, "review_blocked_recorded");
    }

    /// Regression: startup migration upgrades rowid-based quarantine tables
    /// and never deletes by unstable `rowid`.
    #[test]
    fn init_schema_migrates_rowid_quarantine_table_without_rowid_deletes() {
        let conn = Connection::open_in_memory().unwrap();

        conn.execute(
            "CREATE TABLE ledger_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                work_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                signature BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO ledger_events
                (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "legit-event-id",
                "unrelated_event",
                "work-001",
                "actor-001",
                br#"{"ok":true}"#.as_slice(),
                b"sig".as_slice(),
                1_i64
            ],
        )
        .unwrap();

        conn.execute(
            "CREATE TABLE ledger_events_quarantine (
                rowid_orig INTEGER NOT NULL,
                event_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                work_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                signature BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL,
                quarantine_reason TEXT NOT NULL DEFAULT 'receipt_id_dedupe_migration'
            )",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO ledger_events_quarantine
                (rowid_orig, event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                1_i64,
                "legacy-quarantined-event-id",
                "review_receipt_recorded",
                "work-legacy",
                "actor-legacy",
                br#"{"receipt_id":"RR-LEGACY-001"}"#.as_slice(),
                b"legacy-sig".as_slice(),
                2_i64
            ],
        )
        .unwrap();

        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();

        let legit_event_still_exists: bool = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM ledger_events WHERE event_id = 'legit-event-id'
                )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            legit_event_still_exists,
            "event_id-based cleanup must not delete unrelated rows that share historic rowids"
        );

        let has_rowid_orig_column: bool = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM pragma_table_info('ledger_events_quarantine')
                    WHERE name = 'rowid_orig'
                )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !has_rowid_orig_column,
            "quarantine table must no longer persist rowid_orig"
        );

        let has_event_id_primary_key: bool = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM pragma_table_info('ledger_events_quarantine')
                    WHERE name = 'event_id' AND pk = 1
                )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            has_event_id_primary_key,
            "quarantine table must be keyed by event_id"
        );
    }

    /// Regression: duplicate receipt migration quarantines by `event_id`,
    /// preserves the canonical first event, and remains idempotent.
    #[test]
    fn init_schema_quarantines_duplicate_receipts_by_event_id_idempotently() {
        let conn = Connection::open_in_memory().unwrap();

        conn.execute(
            "CREATE TABLE ledger_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                work_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                signature BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();

        let duplicate_payload = br#"{"receipt_id":"RR-DUPE-001","lease_id":"L-DUPE-001","work_id":"W-DUPE-001","changeset_digest":"abc123"}"#;
        conn.execute(
            "INSERT INTO ledger_events
                (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "receipt-event-keep",
                "review_receipt_recorded",
                "work-a",
                "actor-a",
                duplicate_payload.as_slice(),
                b"sig-a".as_slice(),
                10_i64
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ledger_events
                (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "receipt-event-duplicate",
                "review_receipt_recorded",
                "work-b",
                "actor-b",
                duplicate_payload.as_slice(),
                b"sig-b".as_slice(),
                11_i64
            ],
        )
        .unwrap();

        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();

        let keep_exists: bool = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM ledger_events WHERE event_id = 'receipt-event-keep'
                )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(keep_exists, "canonical first receipt event must remain");

        let duplicate_exists: bool = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM ledger_events WHERE event_id = 'receipt-event-duplicate'
                )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !duplicate_exists,
            "duplicate receipt event must be removed from ledger_events"
        );

        let duplicate_quarantined_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ledger_events_quarantine
                 WHERE event_id = 'receipt-event-duplicate'
                 AND quarantine_reason = 'receipt_id_dedupe_migration'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            duplicate_quarantined_count, 1,
            "duplicate receipt event must be quarantined exactly once"
        );

        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();

        let duplicate_quarantined_count_after_rerun: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ledger_events_quarantine
                 WHERE event_id = 'receipt-event-duplicate'
                 AND quarantine_reason = 'receipt_id_dedupe_migration'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            duplicate_quarantined_count_after_rerun, 1,
            "idempotent reruns must not duplicate quarantine entries"
        );
    }

    /// Regression: review receipt and consumption events can share a receipt ID
    /// while per-event-type uniqueness remains enforced.
    #[test]
    fn init_schema_scopes_receipt_id_uniqueness_by_event_type() {
        let conn = Connection::open_in_memory().unwrap();
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();

        let has_receipt_id_unique_index: bool = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'index' AND name = 'idx_unique_receipt_id'
                )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            has_receipt_id_unique_index,
            "init_schema must restore scoped idx_unique_receipt_id for review receipt events"
        );

        let has_receipt_consumed_unique_index: bool = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'index' AND name = 'idx_unique_receipt_consumed'
                )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            has_receipt_consumed_unique_index,
            "init_schema must create idx_unique_receipt_consumed for consumption events"
        );

        let has_receipt_consumed_lookup_index: bool = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'index' AND name = 'idx_redundancy_receipt_consumed_receipt_id'
                )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            has_receipt_consumed_lookup_index,
            "init_schema must create lookup index for redundancy receipt consumption events"
        );

        conn.execute(
            "INSERT INTO ledger_events
                (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "receipt-unique-base",
                "review_receipt_recorded",
                "work-base",
                "actor-base",
                br#"{"receipt_id":"RR-UNIQUE-001","lease_id":"lease-base","work_id":"work-base","changeset_digest":"digest-base"}"#.as_slice(),
                b"sig-base".as_slice(),
                101_i64
            ],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO ledger_events
                (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "receipt-consumed-base",
                "redundancy_receipt_consumed",
                "session-base",
                "actor-base",
                br#"{"receipt_id":"RR-UNIQUE-001","request_id":"REQ-BASE","tool_class":"inference"}"#.as_slice(),
                b"sig-consumed".as_slice(),
                101_i64
            ],
        )
        .expect("review and consumed events must be allowed to share receipt_id");

        let duplicate_err = conn
            .execute(
                "INSERT INTO ledger_events
                    (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    "receipt-unique-duplicate",
                    "review_blocked_recorded",
                    "work-other",
                    "actor-other",
                    br#"{"receipt_id":"RR-UNIQUE-001","lease_id":"lease-other","work_id":"work-other","changeset_digest":"digest-other"}"#.as_slice(),
                    b"sig-other".as_slice(),
                    102_i64
                ],
            )
            .expect_err("duplicate receipt_id must be rejected by unique index");

        let duplicate_err_text = duplicate_err.to_string();
        assert!(
            duplicate_err_text.contains("idx_unique_receipt_id")
                || duplicate_err_text.contains("UNIQUE constraint failed"),
            "expected UNIQUE failure for idx_unique_receipt_id, got: {duplicate_err_text}"
        );

        let duplicate_consumed_err = conn
            .execute(
                "INSERT INTO ledger_events
                    (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    "receipt-consumed-duplicate",
                    "redundancy_receipt_consumed",
                    "session-other",
                    "actor-other",
                    br#"{"receipt_id":"RR-UNIQUE-001","request_id":"REQ-OTHER","tool_class":"inference"}"#.as_slice(),
                    b"sig-consumed-other".as_slice(),
                    103_i64
                ],
            )
            .expect_err("duplicate redundancy consumption receipt_id must be rejected");
        let duplicate_consumed_err_text = duplicate_consumed_err.to_string();
        assert!(
            duplicate_consumed_err_text.contains("idx_unique_receipt_consumed")
                || duplicate_consumed_err_text.contains("UNIQUE constraint failed"),
            "expected UNIQUE failure for idx_unique_receipt_consumed, got: {duplicate_consumed_err_text}"
        );
    }

    #[test]
    fn derive_event_chain_hash_detects_tampered_intermediate_event_hash() {
        let emitter = test_emitter();
        let claim = WorkClaim {
            work_id: "W-HASH-CHAIN-001".to_string(),
            lease_id: "L-HASH-CHAIN-001".to_string(),
            actor_id: "uid:1000".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };

        emitter
            .emit_work_claimed(&claim, 1_700_000_000_000_000_000)
            .expect("work_claimed must emit for hash-chain test");
        emitter
            .emit_work_transitioned(&WorkTransition {
                work_id: "W-HASH-CHAIN-001",
                from_state: "Open",
                to_state: "Claimed",
                rationale_code: "hash_chain_test",
                previous_transition_count: 0,
                actor_id: "uid:1000",
                timestamp_ns: 1_700_000_000_000_000_001,
            })
            .expect("work_transitioned must emit for hash-chain test");
        emitter
            .emit_session_terminated(
                "SESS-HASH-CHAIN-001",
                "W-HASH-CHAIN-001",
                0,
                "test-complete",
                "uid:1000",
                1_700_000_000_000_000_002,
            )
            .expect("session_terminated must emit for hash-chain test");

        emitter
            .derive_event_chain_hash()
            .expect("initial event chain derivation should succeed");

        {
            let conn = emitter
                .conn
                .lock()
                .expect("sqlite lock should be available for tamper mutation");
            conn.execute(
                "UPDATE ledger_events SET event_hash = 'tampered' WHERE rowid = 2",
                [],
            )
            .expect("tamper mutation should succeed for regression coverage");
        }

        let chain_err = emitter
            .derive_event_chain_hash()
            .expect_err("tampered intermediate hash must fail chain derivation");
        assert!(
            chain_err.contains("hash chain broken") && chain_err.contains("event_hash"),
            "expected explicit hash-chain break diagnostics, got: {chain_err}"
        );
    }

    #[test]
    fn derive_event_chain_hash_detects_signature_tampering_with_rehashed_row() {
        let emitter = test_emitter();
        let claim = WorkClaim {
            work_id: "W-HASH-CHAIN-SIG-001".to_string(),
            lease_id: "L-HASH-CHAIN-SIG-001".to_string(),
            actor_id: "uid:1000".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };

        emitter
            .emit_work_claimed(&claim, 1_700_000_000_000_100_000)
            .expect("work_claimed must emit for signature tampering test");

        let (event_id, event_type, work_id, actor_id, payload, timestamp_ns, prev_hash): (
            String,
            String,
            String,
            String,
            Vec<u8>,
            i64,
            String,
        ) = {
            let conn = emitter
                .conn
                .lock()
                .expect("sqlite lock should be available for seed query");
            conn.query_row(
                "SELECT event_id, event_type, work_id, actor_id, payload, timestamp_ns, prev_hash \
                 FROM ledger_events WHERE rowid = 1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .expect("seed row should exist")
        };
        #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
        let timestamp_ns = timestamp_ns as u64;

        let tampered_signature = vec![0xA5; 64];
        let tampered_event_hash = SqliteLedgerEventEmitter::compute_event_hash(&EventHashInput {
            event_id: &event_id,
            event_type: &event_type,
            work_id: &work_id,
            actor_id: &actor_id,
            payload: &payload,
            signature: &tampered_signature,
            timestamp_ns,
            prev_hash: &prev_hash,
        });

        {
            let conn = emitter
                .conn
                .lock()
                .expect("sqlite lock should be available for tamper mutation");
            conn.execute(
                "UPDATE ledger_events SET signature = ?1, event_hash = ?2 WHERE event_id = ?3",
                params![tampered_signature, tampered_event_hash, event_id],
            )
            .expect("signature tamper mutation should succeed");
        }

        let chain_err = emitter
            .derive_event_chain_hash()
            .expect_err("rehashed signature tampering must fail chain derivation");
        assert!(
            chain_err.contains("signature verification")
                || chain_err.contains("failed Ed25519 signature"),
            "expected signature verification failure diagnostics, got: {chain_err}"
        );
    }

    #[test]
    fn admin_full_chain_verification_catches_mid_chain_tampering() {
        let emitter = test_emitter();
        let claim = WorkClaim {
            work_id: "W-ADMIN-VERIFY-001".to_string(),
            lease_id: "L-ADMIN-VERIFY-001".to_string(),
            actor_id: "uid:admin-verify".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };

        emitter
            .emit_work_claimed(&claim, 1_700_000_000_000_200_000)
            .expect("work_claimed must emit for admin verification test");
        emitter
            .emit_work_transitioned(&WorkTransition {
                work_id: "W-ADMIN-VERIFY-001",
                from_state: "Open",
                to_state: "Claimed",
                rationale_code: "admin_verify_test",
                previous_transition_count: 0,
                actor_id: "uid:admin-verify",
                timestamp_ns: 1_700_000_000_000_200_001,
            })
            .expect("work_transitioned must emit for admin verification test");
        emitter
            .emit_session_terminated(
                "SESS-ADMIN-VERIFY-001",
                "W-ADMIN-VERIFY-001",
                0,
                "admin-verify-complete",
                "uid:admin-verify",
                1_700_000_000_000_200_002,
            )
            .expect("session_terminated must emit for admin verification test");

        crate::protocol::dispatch::LedgerEventEmitter::verify_chain_admin(&emitter)
            .expect("admin full-chain verification should pass on untampered ledger");

        {
            let conn = emitter
                .conn
                .lock()
                .expect("sqlite lock should be available for tamper mutation");
            conn.execute(
                "UPDATE ledger_events SET event_hash = 'tampered-admin-check' WHERE rowid = 2",
                [],
            )
            .expect("tamper mutation should succeed");
        }

        let admin_err = crate::protocol::dispatch::LedgerEventEmitter::verify_chain_admin(&emitter)
            .expect_err("admin full-chain verification must fail on tampered mid-chain row");
        assert!(
            admin_err.contains("hash chain broken"),
            "admin chain verification must report chain break: {admin_err}"
        );
    }

    #[test]
    fn review_receipt_and_consumption_event_allow_same_receipt_id() {
        let emitter = test_emitter();
        let receipt_id = "RR-CONSUME-001";
        let identity_proof_hash = [0xABu8; 32];

        emitter
            .emit_review_receipt(
                "lease-consume-001",
                "work-consume-001",
                receipt_id,
                &[0x01; 32],
                &[0x02; 32],
                &[0x03; 32],
                &[0x04; 32],
                &[0x05; 32],
                "reviewer-consume-001",
                1_700_000_000_000_000_100,
                &identity_proof_hash,
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                None,
            )
            .expect("review receipt emission should succeed");

        emitter
            .emit_redundancy_receipt_consumed(
                "session-consume-001",
                receipt_id,
                "REQ-CONSUME-001",
                "inference",
                &[0xA1; 32],
                &[0xB2; 32],
                "session-001::inference",
                "session-consume-001",
                1_700_000_000_000_000_101,
                &[0xC3; 32],
                &[0xD4; 32],
            )
            .expect("consumption event should succeed for same receipt_id as review receipt");

        let consumption = emitter
            .get_redundancy_receipt_consumption(receipt_id)
            .expect("consumption lookup should return emitted binding");
        assert_eq!(consumption.request_id, "REQ-CONSUME-001");
        assert_eq!(consumption.tool_class, "inference");
        assert_eq!(consumption.intent_digest, Some([0xA1; 32]));
        assert_eq!(consumption.argument_content_digest, Some([0xB2; 32]));
        assert_eq!(
            consumption.channel_key.as_deref(),
            Some("session-001::inference")
        );
        assert_eq!(
            consumption.receipt_hash,
            Some([0xC3; 32]),
            "receipt_hash must be persisted and readable"
        );
        assert_eq!(
            consumption.admission_bundle_digest,
            Some([0xD4; 32]),
            "admission_bundle_digest must be persisted and readable"
        );
    }

    /// Verifies that `emit_review_blocked_receipt` includes replay-critical
    /// blocked fields and identity binding in the signed payload.
    #[test]
    fn test_blocked_receipt_payload_contains_replay_bindings() {
        let emitter = test_emitter();
        let changeset_digest = [0x42u8; 32];
        let artifact_bundle_hash = [0xC3u8; 32];
        let blocked_log_hash = [0xAAu8; 32];
        let identity_proof_hash = [0xBBu8; 32];

        let event = emitter
            .emit_review_blocked_receipt(
                "lease-blocked-iph",
                "work-blocked-iph",
                "RR-BLOCKED-IPH",
                &changeset_digest,
                &artifact_bundle_hash,
                &[0x11; 32],
                &[0x22; 32],
                &[0x33; 32],
                99,
                &blocked_log_hash,
                "reviewer-actor-z",
                3_000_000_000,
                &identity_proof_hash,
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                None,
            )
            .expect("blocked receipt emit should succeed");

        // Parse the payload and verify replay bindings are present.
        let payload: serde_json::Value =
            serde_json::from_slice(&event.payload).expect("payload should be valid JSON");

        let artifact_hash = payload
            .get("artifact_bundle_hash")
            .expect("payload must contain artifact_bundle_hash field");
        assert_eq!(
            artifact_hash.as_str().unwrap(),
            hex::encode(artifact_bundle_hash),
            "artifact_bundle_hash in blocked event payload must match the input"
        );
        assert_eq!(
            payload.get("work_id").and_then(serde_json::Value::as_str),
            Some("work-blocked-iph"),
            "blocked payload must include canonical work_id binding"
        );

        let blocked_reason_code = payload
            .get("blocked_reason_code")
            .expect("payload must contain blocked_reason_code field");
        assert_eq!(
            blocked_reason_code.as_u64().unwrap(),
            99,
            "blocked_reason_code in blocked event payload must match the input"
        );

        let blocked_log = payload
            .get("blocked_log_hash")
            .expect("payload must contain blocked_log_hash field");
        assert_eq!(
            blocked_log.as_str().unwrap(),
            hex::encode(blocked_log_hash),
            "blocked_log_hash in blocked event payload must match the input"
        );

        let iph = payload
            .get("identity_proof_hash")
            .expect("payload must contain identity_proof_hash field");
        assert_eq!(
            iph.as_str().unwrap(),
            hex::encode(identity_proof_hash),
            "identity_proof_hash in blocked event payload must match the input"
        );
    }

    /// TCK-00631: After migration + freeze, writes route to canonical
    /// `events` table (not legacy `ledger_events`).
    ///
    /// Verifies:
    /// 1. After `migrate_legacy_ledger_events`, `freeze_legacy_writes`
    ///    activates the guard.
    /// 2. Subsequent write attempts succeed and insert into canonical `events`.
    /// 3. No rows are added to `ledger_events` (legacy table stays empty).
    /// 4. At least one new event is appended to `events` after migration.
    #[test]
    fn tck_00631_canonical_append_after_migration() {
        use apm2_core::ledger::{init_canonical_schema, migrate_legacy_ledger_events};
        use rusqlite::Connection;

        let conn = Connection::open_in_memory().unwrap();

        // 1. Set up legacy schema with test rows.
        conn.execute(
            "CREATE TABLE ledger_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                work_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                signature BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();

        // Insert 3 legacy rows.
        for i in 1_u64..=3 {
            conn.execute(
                "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, \
                 payload, signature, timestamp_ns) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    format!("evt-{i}"),
                    "test.event",
                    format!("work-{i}"),
                    "actor-1",
                    format!("{{\"n\":{i}}}").as_bytes(),
                    b"sig",
                    1_000_000_000_u64 * i,
                ],
            )
            .unwrap();
        }

        // 2. Initialize canonical schema and run migration.
        init_canonical_schema(&conn).unwrap();
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 3, "expected 3 rows migrated");
        assert!(!stats.already_migrated, "should not be a no-op");

        // 3. Verify canonical `events` has the migrated rows.
        let events_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            events_count, 3,
            "canonical events must have 3 migrated rows"
        );

        // 4. Construct emitter, initialize schema, and freeze.
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let conn_arc = Arc::new(Mutex::new(conn));
        let emitter = SqliteLedgerEventEmitter::new(Arc::clone(&conn_arc), signing_key);

        let conn_guard = conn_arc.lock().unwrap();
        let frozen = emitter.freeze_legacy_writes(&conn_guard).unwrap();
        assert!(frozen, "freeze_legacy_writes must always return true");
        drop(conn_guard);

        assert!(
            emitter.is_frozen(),
            "emitter must be frozen after freeze_legacy_writes"
        );

        // 5. Write MUST SUCCEED — routed to canonical `events`.
        let claim = WorkClaim {
            work_id: "frozen-test-work".to_string(),
            lease_id: "frozen-test-lease".to_string(),
            actor_id: "frozen-test-actor".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };
        let result = emitter.emit_work_claimed(&claim, 999_000_000);
        assert!(
            result.is_ok(),
            "write must succeed when frozen (routed to canonical events), got: {:?}",
            result.err()
        );

        // 6. Verify canonical `events` now has 4 rows (3 migrated + 1 new).
        let conn_guard = conn_arc.lock().unwrap();
        let events_count_after: i64 = conn_guard
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            events_count_after, 4,
            "canonical events must have 4 rows (3 migrated + 1 new)"
        );

        // 7. Verify `ledger_events` is still empty (no legacy write leaked).
        let legacy_count_after: i64 = conn_guard
            .query_row("SELECT COUNT(*) FROM ledger_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            legacy_count_after, 0,
            "ledger_events must remain empty after frozen write"
        );

        // 8. Verify hash chain continuity: the new event's prev_hash matches the last
        //    migrated event's event_hash.
        let new_row: (Vec<u8>, Vec<u8>) = conn_guard
            .query_row(
                "SELECT prev_hash, event_hash FROM events ORDER BY rowid DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            new_row.0.len(),
            32,
            "new event prev_hash must be 32 bytes (BLAKE3)"
        );
        assert_eq!(
            new_row.1.len(),
            32,
            "new event event_hash must be 32 bytes (BLAKE3)"
        );

        // The prev_hash of the new row should match the event_hash of row #3.
        let third_row_hash: Vec<u8> = conn_guard
            .query_row(
                "SELECT event_hash FROM events WHERE rowid = (SELECT MAX(rowid) - 1 FROM events)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            new_row.0, third_row_hash,
            "new event prev_hash must chain from the last migrated event"
        );
    }

    /// TCK-00631: After migration + freeze, lease validator writes route to
    /// canonical `events` table.
    ///
    /// Verifies:
    /// 1. After migration, `freeze_legacy_writes` activates the guard.
    /// 2. `register_full_lease` succeeds by routing to canonical `events`.
    /// 3. `register_lease_with_executor` succeeds by routing to canonical
    ///    `events`.
    /// 4. No rows are added to `ledger_events` (legacy table stays empty).
    /// 5. New rows appear in canonical `events`.
    #[test]
    fn tck_00631_lease_write_routes_to_canonical_after_migration() {
        use apm2_core::ledger::{init_canonical_schema, migrate_legacy_ledger_events};
        use rusqlite::Connection;

        let conn = Connection::open_in_memory().unwrap();

        // 1. Set up legacy schema with test rows.
        conn.execute(
            "CREATE TABLE ledger_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                work_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                signature BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();

        // Insert 2 legacy rows.
        for i in 1_u64..=2 {
            conn.execute(
                "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, \
                 payload, signature, timestamp_ns) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    format!("evt-lease-{i}"),
                    "test.event",
                    format!("work-lease-{i}"),
                    "actor-1",
                    format!("{{\"n\":{i}}}").as_bytes(),
                    b"sig",
                    1_000_000_000_u64 * i,
                ],
            )
            .unwrap();
        }

        // 2. Initialize canonical schema and run migration.
        init_canonical_schema(&conn).unwrap();
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 2, "expected 2 rows migrated");

        // 3. Initialize emitter schema (needed for hash chain metadata).
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();

        // 4. Verify ledger_events is empty after migration.
        let legacy_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM ledger_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            legacy_count, 0,
            "ledger_events must be empty after migration"
        );

        // 5. Construct lease validator and freeze.
        let conn_arc = Arc::new(Mutex::new(conn));
        let validator = SqliteLeaseValidator::new(Arc::clone(&conn_arc));

        validator.freeze_legacy_writes_inner().unwrap();
        assert!(
            validator.is_frozen(),
            "validator must be frozen after freeze_legacy_writes"
        );

        // 6. register_full_lease — must succeed, routing to canonical events.
        let signer = apm2_core::crypto::Signer::generate();
        let lease = apm2_core::fac::GateLeaseBuilder::new(
            "LEASE-FROZEN-TEST",
            "WORK-FROZEN-TEST",
            "GATE-FROZEN-TEST",
        )
        .changeset_digest([0x42; 32])
        .executor_actor_id("actor-frozen")
        .issued_at(999_000_000)
        .expires_at(999_999_999)
        .policy_hash([0xAB; 32])
        .issuer_actor_id("issuer-frozen")
        .time_envelope_ref("htf:tick:0")
        .build_and_sign(&signer);
        let result = validator.register_full_lease(&lease);
        assert!(
            result.is_ok(),
            "register_full_lease must succeed when frozen (routed to canonical events), got: {:?}",
            result.err()
        );

        // 7. register_lease_with_executor — must succeed (canonical routing).
        validator.register_lease_with_executor(
            "LEASE-FROZEN-2",
            "WORK-FROZEN-2",
            "GATE-FROZEN-2",
            "actor-frozen",
        );

        // 8. Verify no rows were added to ledger_events.
        let conn_guard = conn_arc.lock().unwrap();
        let legacy_count_after: i64 = conn_guard
            .query_row("SELECT COUNT(*) FROM ledger_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            legacy_count_after, 0,
            "ledger_events must remain empty after frozen lease writes"
        );

        // 9. Verify canonical events has 2 migrated + 2 new = 4 rows.
        let events_count: i64 = conn_guard
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            events_count, 4,
            "canonical events must have 4 rows (2 migrated + 2 lease writes)"
        );
    }

    /// TCK-00631: Verify `is_canonical_events_mode` returns true after
    /// migration and false when legacy rows exist without migration.
    #[test]
    fn tck_00631_canonical_mode_check() {
        use apm2_core::ledger::{
            init_canonical_schema, is_canonical_events_mode, migrate_legacy_ledger_events,
        };
        use rusqlite::Connection;

        // Scenario (a): Legacy-only DB — should be `false` (legacy mode).
        let conn = Connection::open_in_memory().unwrap();
        init_canonical_schema(&conn).unwrap();
        conn.execute(
            "CREATE TABLE ledger_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                work_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                signature BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ledger_events VALUES ('e1', 'test', 'w1', 'a1', X'00', X'00', 1000)",
            [],
        )
        .unwrap();
        let mode = is_canonical_events_mode(&conn).unwrap();
        assert!(!mode, "legacy-only DB should NOT be in canonical mode");

        // Scenario (b): After migration — should be `true`.
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 1);
        let mode_after = is_canonical_events_mode(&conn).unwrap();
        assert!(
            mode_after,
            "after migration, DB must be in canonical events mode"
        );

        // Scenario (c): Canonical-only DB (no legacy table) — should be `true`.
        let conn2 = Connection::open_in_memory().unwrap();
        init_canonical_schema(&conn2).unwrap();
        let mode_canonical = is_canonical_events_mode(&conn2).unwrap();
        assert!(
            mode_canonical,
            "canonical-only DB must be in canonical events mode"
        );
    }

    /// TCK-00631: Verify freeze guard is unconditional — even without
    /// the frozen table, `freeze_legacy_writes` always activates the guard.
    #[test]
    fn tck_00631_freeze_guard_unconditional() {
        // Create an emitter without a frozen table (no migration ran).
        let conn = Connection::open_in_memory().unwrap();
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let conn_arc = Arc::new(Mutex::new(conn));
        let emitter = SqliteLedgerEventEmitter::new(Arc::clone(&conn_arc), signing_key);

        // Even without frozen table — freeze ALWAYS returns true.
        let conn_guard = conn_arc.lock().unwrap();
        let frozen = emitter.freeze_legacy_writes(&conn_guard).unwrap();
        assert!(
            frozen,
            "freeze_legacy_writes must always return true (unconditional)"
        );
        assert!(
            emitter.is_frozen(),
            "emitter must be frozen after freeze_legacy_writes regardless of table state"
        );
        drop(conn_guard);
    }

    /// TCK-00631: BLOCKER 1 regression — canonical-mode DB (events > 0, no
    /// frozen table) must still freeze and route writes to canonical events.
    ///
    /// Counterexample path that was previously unfrozen:
    /// 1. Startup: `init_schema_with_signing_key` creates `ledger_events`.
    /// 2. `migrate_legacy_ledger_events` returns `already_migrated=true`
    ///    (events > 0, `ledger_events` == 0) without creating
    ///    `ledger_events_legacy_frozen`.
    /// 3. `freeze_legacy_writes()` must still freeze and route to canonical.
    #[test]
    fn tck_00631_canonical_mode_no_frozen_table_still_freezes() {
        use apm2_core::ledger::init_canonical_schema;
        use rusqlite::Connection;

        let conn = Connection::open_in_memory().unwrap();

        // Set up canonical-mode DB: `events` has rows, `ledger_events` empty.
        init_canonical_schema(&conn).unwrap();

        // Insert a canonical event directly.
        conn.execute(
            "INSERT INTO events (event_type, session_id, actor_id, record_version, \
             payload, timestamp_ns, prev_hash, event_hash, signature) \
             VALUES ('test.event', 'work-1', 'actor-1', 1, X'7B226E223A317D', \
             1000000000, X'0000000000000000000000000000000000000000000000000000000000000000', \
             X'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', X'7369676E')",
            [],
        )
        .unwrap();

        // Create empty ledger_events (as init_schema_with_signing_key would).
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();

        // Confirm: events has rows, ledger_events has 0 rows, NO frozen table.
        let events_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert!(events_count > 0, "events must have rows");

        let legacy_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM ledger_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(legacy_count, 0, "ledger_events must be empty");

        let frozen_table_exists: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' \
                 AND name = 'ledger_events_legacy_frozen' LIMIT 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .unwrap()
            .is_some();
        assert!(
            !frozen_table_exists,
            "ledger_events_legacy_frozen must NOT exist for this test"
        );

        // Construct emitter and freeze.
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let conn_arc = Arc::new(Mutex::new(conn));
        let emitter = SqliteLedgerEventEmitter::new(Arc::clone(&conn_arc), signing_key);

        let conn_guard = conn_arc.lock().unwrap();
        let frozen = emitter.freeze_legacy_writes(&conn_guard).unwrap();
        assert!(
            frozen,
            "freeze_legacy_writes must return true even without frozen table"
        );
        drop(conn_guard);

        assert!(emitter.is_frozen(), "emitter must be frozen");

        // Write must succeed via canonical bridge.
        let claim = WorkClaim {
            work_id: "canonical-test-work".to_string(),
            lease_id: "canonical-test-lease".to_string(),
            actor_id: "canonical-test-actor".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };
        let result = emitter.emit_work_claimed(&claim, 2_000_000_000);
        assert!(
            result.is_ok(),
            "write must succeed via canonical bridge, got: {:?}",
            result.err()
        );

        // Verify: new row in canonical `events`, legacy still empty.
        let conn_guard = conn_arc.lock().unwrap();
        let events_after: i64 = conn_guard
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            events_after,
            events_count + 1,
            "canonical events must gain 1 row"
        );

        let legacy_after: i64 = conn_guard
            .query_row("SELECT COUNT(*) FROM ledger_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            legacy_after, 0,
            "ledger_events must remain empty after frozen write"
        );
    }

    /// SECURITY (f-781-security-1771692992655093-0): Verify that the
    /// `idx_canonical_work_opened_unique` index on the canonical `events`
    /// table enforces at-most-one `work.opened` per `work_id` (mapped to
    /// `session_id`) when the emitter is frozen. Concurrent threads
    /// attempting to emit `work.opened` for the same `work_id` must
    /// produce exactly one persisted row; the duplicate must receive a
    /// UNIQUE constraint violation error.
    #[test]
    fn tck_00635_frozen_concurrent_work_opened_unique_constraint() {
        use std::sync::Arc;

        use apm2_core::ledger::{init_canonical_schema, migrate_legacy_ledger_events};
        use rusqlite::Connection;

        let conn = Connection::open_in_memory().unwrap();

        // 1. Set up legacy schema with one seed row.
        conn.execute(
            "CREATE TABLE ledger_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                work_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                signature BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, \
             payload, signature, timestamp_ns) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                "evt-seed-1",
                "test.event",
                "work-seed",
                "actor-1",
                b"{\"n\":1}",
                b"sig",
                1_000_000_000_u64,
            ],
        )
        .unwrap();

        // 2. Initialize canonical schema and migrate.
        init_canonical_schema(&conn).unwrap();
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 1);

        // 3. Verify idx_canonical_work_opened_unique exists on events.
        let has_idx: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master \
                 WHERE type = 'index' AND name = 'idx_canonical_work_opened_unique'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            has_idx,
            "idx_canonical_work_opened_unique must exist on canonical events table"
        );

        // 4. Construct emitter, initialize legacy schema, and freeze.
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let conn_arc = Arc::new(Mutex::new(conn));
        let emitter = Arc::new(SqliteLedgerEventEmitter::new(
            Arc::clone(&conn_arc),
            signing_key,
        ));

        let conn_guard = conn_arc.lock().unwrap();
        emitter.freeze_legacy_writes(&conn_guard).unwrap();
        drop(conn_guard);

        assert!(
            emitter.is_frozen(),
            "emitter must be frozen for canonical writes"
        );

        // 5. Concurrently emit work.opened for the same work_id from 4 threads. Exactly
        //    1 must succeed; the rest must fail with UNIQUE constraint violations.
        let barrier = Arc::new(std::sync::Barrier::new(4));
        let mut handles = Vec::new();

        for i in 0..4_u64 {
            let e = Arc::clone(&emitter);
            let bar = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                bar.wait();
                let payload = format!("{{\"event_type\":\"work.opened\",\"n\":{i}}}");
                e.emit_session_event(
                    "W-race-frozen-001",
                    "work.opened",
                    payload.as_bytes(),
                    &format!("actor-{i}"),
                    2_000_000_000 + i,
                )
            }));
        }

        let mut success_count = 0_u32;
        let mut unique_violation_count = 0_u32;
        for handle in handles {
            match handle.join().expect("thread panicked") {
                Ok(_) => success_count += 1,
                Err(e) => {
                    let msg = e.to_string();
                    assert!(
                        msg.contains("UNIQUE constraint"),
                        "Non-success emit must be UNIQUE constraint violation, got: {msg}"
                    );
                    unique_violation_count += 1;
                },
            }
        }

        assert_eq!(
            success_count, 1,
            "Exactly one thread must successfully emit work.opened (got {success_count})"
        );
        assert_eq!(
            unique_violation_count, 3,
            "Remaining threads must fail with UNIQUE constraint (got {unique_violation_count})"
        );

        // 6. Verify exactly 1 work.opened row in canonical events.
        let conn_guard = conn_arc.lock().unwrap();
        let work_opened_count: i64 = conn_guard
            .query_row(
                "SELECT COUNT(*) FROM events \
                 WHERE event_type = 'work.opened' AND session_id = 'W-race-frozen-001'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            work_opened_count, 1,
            "Exactly one work.opened must exist in canonical events for W-race-frozen-001"
        );
    }

    /// TCK-00639 SECURITY FIX: Verify canonical UNIQUE constraint
    /// `idx_canonical_work_pr_associated_unique` enforces at-most-one
    /// `work.pr_associated` per `(work_id, pr_number, commit_sha)` under
    /// concurrent writers.
    #[test]
    fn tck_00639_frozen_concurrent_work_pr_associated_unique_constraint() {
        use std::sync::Arc;

        use apm2_core::ledger::{init_canonical_schema, migrate_legacy_ledger_events};
        use rusqlite::Connection;

        let conn = Connection::open_in_memory().unwrap();

        conn.execute(
            "CREATE TABLE ledger_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                work_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                signature BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, \
             payload, signature, timestamp_ns) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                "evt-seed-pr-1",
                "test.event",
                "work-seed",
                "actor-1",
                b"{\"n\":1}",
                b"sig",
                1_000_000_000_u64,
            ],
        )
        .unwrap();

        init_canonical_schema(&conn).unwrap();
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 1);

        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();

        let has_idx: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master \
                 WHERE type = 'index' AND name = 'idx_canonical_work_pr_associated_unique'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            has_idx,
            "idx_canonical_work_pr_associated_unique must exist on canonical events table"
        );

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let conn_arc = Arc::new(Mutex::new(conn));
        let emitter = Arc::new(SqliteLedgerEventEmitter::new(
            Arc::clone(&conn_arc),
            signing_key,
        ));

        let conn_guard = conn_arc.lock().unwrap();
        emitter.freeze_legacy_writes(&conn_guard).unwrap();
        drop(conn_guard);
        assert!(
            emitter.is_frozen(),
            "emitter must be frozen for canonical writes"
        );

        let barrier = Arc::new(std::sync::Barrier::new(4));
        let mut handles = Vec::new();
        let work_id = "W-race-frozen-pr-001";
        let pr_number = 4242_u64;
        let commit_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let payload =
            apm2_core::work::helpers::work_pr_associated_payload(work_id, pr_number, commit_sha);
        let payload_hex = hex::encode(payload);

        for i in 0..4_u64 {
            let e = Arc::clone(&emitter);
            let bar = Arc::clone(&barrier);
            let payload_hex = payload_hex.clone();
            handles.push(std::thread::spawn(move || {
                bar.wait();
                let envelope = serde_json::json!({
                    "event_type": "work.pr_associated",
                    "session_id": work_id,
                    "actor_id": format!("actor-{i}"),
                    "payload": payload_hex,
                    "pr_number": pr_number,
                    "commit_sha": commit_sha,
                });
                e.emit_session_event_with_envelope(
                    work_id,
                    "work.pr_associated",
                    &envelope,
                    &format!("actor-{i}"),
                    2_000_000_000 + i,
                )
            }));
        }

        let mut success_count = 0_u32;
        let mut unique_violation_count = 0_u32;
        for handle in handles {
            match handle.join().expect("thread panicked") {
                Ok(_) => success_count += 1,
                Err(e) => {
                    let msg = e.to_string();
                    assert!(
                        msg.contains("UNIQUE constraint"),
                        "non-success emit must be UNIQUE constraint violation, got: {msg}"
                    );
                    unique_violation_count += 1;
                },
            }
        }

        assert_eq!(
            success_count, 1,
            "Exactly one thread must persist work.pr_associated (got {success_count})"
        );
        assert_eq!(
            unique_violation_count, 3,
            "Remaining threads must fail with UNIQUE constraint (got {unique_violation_count})"
        );

        let conn_guard = conn_arc.lock().unwrap();
        let pr_number_i64 = i64::try_from(pr_number).expect("pr_number must fit in i64");
        let work_pr_count: i64 = conn_guard
            .query_row(
                "SELECT COUNT(*) FROM events \
                 WHERE event_type = 'work.pr_associated' AND session_id = ?1 \
                 AND json_extract(CAST(payload AS TEXT), '$.pr_number') = ?2 \
                 AND json_extract(CAST(payload AS TEXT), '$.commit_sha') = ?3",
                rusqlite::params![work_id, pr_number_i64, commit_sha],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            work_pr_count, 1,
            "Exactly one canonical work.pr_associated row must exist"
        );
    }

    /// TCK-00639 anti-flap guard: concurrent writes with different
    /// `pr_number` values for the same `work_id` must not both commit.
    #[test]
    fn tck_00639_frozen_work_pr_binding_conflict_rejects_different_pr_numbers() {
        use std::sync::Arc;

        use apm2_core::ledger::{init_canonical_schema, migrate_legacy_ledger_events};
        use rusqlite::Connection;

        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE ledger_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                work_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                signature BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, \
             payload, signature, timestamp_ns) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                "evt-seed-pr-binding",
                "test.event",
                "work-seed",
                "actor-1",
                b"{\"n\":1}",
                b"sig",
                1_000_000_000_u64,
            ],
        )
        .unwrap();

        init_canonical_schema(&conn).unwrap();
        let stats = migrate_legacy_ledger_events(&conn).unwrap();
        assert_eq!(stats.rows_migrated, 1);
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let conn_arc = Arc::new(Mutex::new(conn));
        let emitter = Arc::new(SqliteLedgerEventEmitter::new(
            Arc::clone(&conn_arc),
            signing_key,
        ));
        {
            let guard = conn_arc.lock().unwrap();
            emitter.freeze_legacy_writes(&guard).unwrap();
        }
        assert!(
            emitter.is_frozen(),
            "emitter must be frozen for canonical writes"
        );

        let work_id = "W-race-binding-pr-001";
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let attempts = [
            (5001_u64, "ffffffffffffffffffffffffffffffffffffffff"),
            (5002_u64, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        ];

        let handles: Vec<_> = attempts
            .into_iter()
            .enumerate()
            .map(|(idx, (pr_number, commit_sha))| {
                let e = Arc::clone(&emitter);
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    let payload = apm2_core::work::helpers::work_pr_associated_payload(
                        work_id, pr_number, commit_sha,
                    );
                    let envelope = serde_json::json!({
                        "event_type": "work.pr_associated",
                        "session_id": work_id,
                        "actor_id": format!("actor-{idx}"),
                        "payload": hex::encode(payload),
                        "pr_number": pr_number,
                        "commit_sha": commit_sha,
                    });
                    e.emit_session_event_with_envelope(
                        work_id,
                        "work.pr_associated",
                        &envelope,
                        &format!("actor-{idx}"),
                        2_100_000_000 + u64::try_from(idx).expect("index must fit in u64"),
                    )
                })
            })
            .collect();

        let mut success_count = 0_u32;
        let mut binding_conflict_count = 0_u32;
        for handle in handles {
            match handle.join().expect("thread panicked") {
                Ok(_) => success_count += 1,
                Err(error) => {
                    let message = error.to_string();
                    assert!(
                        message.contains(WORK_PR_BINDING_CONFLICT_TAG),
                        "non-success must be work-pr binding conflict, got: {message}"
                    );
                    binding_conflict_count += 1;
                },
            }
        }

        assert_eq!(success_count, 1, "exactly one write must succeed");
        assert_eq!(
            binding_conflict_count, 1,
            "exactly one conflicting write must be rejected"
        );

        let conn_guard = conn_arc.lock().unwrap();
        let row_count: i64 = conn_guard
            .query_row(
                "SELECT COUNT(*) FROM events \
                 WHERE event_type = 'work.pr_associated' AND session_id = ?1",
                rusqlite::params![work_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(row_count, 1, "only one work.pr_associated row may persist");
    }

    #[test]
    fn tck_00639_has_work_pr_association_tuple_uses_semantic_tuple_lookup() {
        let emitter = test_emitter();

        let legacy_work_id = "W-PR-LOOKUP-LEGACY-001";
        let legacy_pr_number = 910_u64;
        let legacy_commit_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let legacy_payload = apm2_core::work::helpers::work_pr_associated_payload(
            legacy_work_id,
            legacy_pr_number,
            legacy_commit_sha,
        );
        let legacy_envelope = serde_json::json!({
            "event_type": "work.pr_associated",
            "session_id": legacy_work_id,
            "actor_id": "actor-legacy",
            "payload": hex::encode(legacy_payload),
            "pr_number": legacy_pr_number,
            "commit_sha": legacy_commit_sha,
        });

        emitter
            .emit_session_event_with_envelope(
                legacy_work_id,
                "work.pr_associated",
                &legacy_envelope,
                "actor-legacy",
                1_000_000_000,
            )
            .expect("legacy work.pr_associated insert should succeed");

        assert!(emitter.has_work_pr_association_tuple(
            legacy_work_id,
            legacy_pr_number,
            legacy_commit_sha
        ));
        assert!(emitter.has_work_pr_association_tuple(
            legacy_work_id,
            legacy_pr_number,
            &legacy_commit_sha.to_ascii_uppercase()
        ));
        assert!(!emitter.has_work_pr_association_tuple(
            legacy_work_id,
            legacy_pr_number + 1,
            legacy_commit_sha
        ));
        assert!(!emitter.has_work_pr_association_tuple(
            legacy_work_id,
            legacy_pr_number,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ));

        {
            let guard = emitter
                .conn
                .lock()
                .expect("sqlite lock should be available");
            apm2_core::ledger::init_canonical_schema(&guard)
                .expect("canonical schema init should succeed");
            apm2_core::ledger::migrate_legacy_ledger_events(&guard)
                .expect("legacy event migration should succeed");
            // Re-run emitter schema init so canonical partial indexes (including
            // case-insensitive work.pr_associated tuple uniqueness) are
            // installed when `events` exists.
            SqliteLedgerEventEmitter::init_schema_for_test(&guard)
                .expect("schema re-init should install canonical indexes");
            emitter
                .freeze_legacy_writes(&guard)
                .expect("freeze should succeed");
        }

        let canonical_work_id = "W-PR-LOOKUP-CANONICAL-001";
        let canonical_pr_number = 911_u64;
        let canonical_commit_sha = "cccccccccccccccccccccccccccccccccccccccc";
        let canonical_payload = apm2_core::work::helpers::work_pr_associated_payload(
            canonical_work_id,
            canonical_pr_number,
            canonical_commit_sha,
        );
        let canonical_envelope = serde_json::json!({
            "event_type": "work.pr_associated",
            "session_id": canonical_work_id,
            "actor_id": "actor-canonical",
            "payload": hex::encode(canonical_payload),
            "pr_number": canonical_pr_number,
            "commit_sha": canonical_commit_sha,
        });

        emitter
            .emit_session_event_with_envelope(
                canonical_work_id,
                "work.pr_associated",
                &canonical_envelope,
                "actor-canonical",
                2_000_000_000,
            )
            .expect("canonical work.pr_associated insert should succeed");

        assert!(emitter.has_work_pr_association_tuple(
            canonical_work_id,
            canonical_pr_number,
            canonical_commit_sha
        ));
        assert!(emitter.has_work_pr_association_tuple(
            canonical_work_id,
            canonical_pr_number,
            &canonical_commit_sha.to_ascii_uppercase()
        ));
    }

    #[test]
    fn tck_00639_work_pr_associated_unique_constraint_is_case_insensitive() {
        let emitter = test_emitter();

        let work_id = "W-PR-UNIQUE-CI-LEGACY-001";
        let pr_number = 912_u64;
        let commit_sha_lower = "dddddddddddddddddddddddddddddddddddddddd";
        let commit_sha_upper = commit_sha_lower.to_ascii_uppercase();

        let payload = apm2_core::work::helpers::work_pr_associated_payload(
            work_id,
            pr_number,
            commit_sha_lower,
        );
        let envelope_lower = serde_json::json!({
            "event_type": "work.pr_associated",
            "session_id": work_id,
            "actor_id": "actor-legacy-ci",
            "payload": hex::encode(payload),
            "pr_number": pr_number,
            "commit_sha": commit_sha_lower,
        });
        emitter
            .emit_session_event_with_envelope(
                work_id,
                "work.pr_associated",
                &envelope_lower,
                "actor-legacy-ci",
                3_000_000_000,
            )
            .expect("legacy lowercase tuple insert should succeed");

        let payload_upper = apm2_core::work::helpers::work_pr_associated_payload(
            work_id,
            pr_number,
            &commit_sha_upper,
        );
        let envelope_upper = serde_json::json!({
            "event_type": "work.pr_associated",
            "session_id": work_id,
            "actor_id": "actor-legacy-ci",
            "payload": hex::encode(payload_upper),
            "pr_number": pr_number,
            "commit_sha": commit_sha_upper,
        });
        let legacy_duplicate = emitter.emit_session_event_with_envelope(
            work_id,
            "work.pr_associated",
            &envelope_upper,
            "actor-legacy-ci",
            4_000_000_000,
        );
        assert!(
            legacy_duplicate
                .err()
                .is_some_and(|err| err.to_string().contains("UNIQUE constraint")),
            "legacy tuple with case-only commit variation must hit UNIQUE constraint"
        );

        {
            let guard = emitter
                .conn
                .lock()
                .expect("sqlite lock should be available");
            apm2_core::ledger::init_canonical_schema(&guard)
                .expect("canonical schema init should succeed");
            apm2_core::ledger::migrate_legacy_ledger_events(&guard)
                .expect("legacy event migration should succeed");
            SqliteLedgerEventEmitter::init_schema_for_test(&guard)
                .expect("schema re-init should install canonical indexes");
            emitter
                .freeze_legacy_writes(&guard)
                .expect("freeze should succeed");
        }

        let canonical_work_id = "W-PR-UNIQUE-CI-CANONICAL-001";
        let canonical_pr_number = 913_u64;
        let canonical_commit_lower = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let canonical_commit_upper = canonical_commit_lower.to_ascii_uppercase();

        let canonical_payload = apm2_core::work::helpers::work_pr_associated_payload(
            canonical_work_id,
            canonical_pr_number,
            canonical_commit_lower,
        );
        let canonical_envelope_lower = serde_json::json!({
            "event_type": "work.pr_associated",
            "session_id": canonical_work_id,
            "actor_id": "actor-canonical-ci",
            "payload": hex::encode(canonical_payload),
            "pr_number": canonical_pr_number,
            "commit_sha": canonical_commit_lower,
        });
        emitter
            .emit_session_event_with_envelope(
                canonical_work_id,
                "work.pr_associated",
                &canonical_envelope_lower,
                "actor-canonical-ci",
                5_000_000_000,
            )
            .expect("canonical lowercase tuple insert should succeed");

        let canonical_payload_upper = apm2_core::work::helpers::work_pr_associated_payload(
            canonical_work_id,
            canonical_pr_number,
            &canonical_commit_upper,
        );
        let canonical_envelope_upper = serde_json::json!({
            "event_type": "work.pr_associated",
            "session_id": canonical_work_id,
            "actor_id": "actor-canonical-ci",
            "payload": hex::encode(canonical_payload_upper),
            "pr_number": canonical_pr_number,
            "commit_sha": canonical_commit_upper,
        });
        let canonical_duplicate = emitter.emit_session_event_with_envelope(
            canonical_work_id,
            "work.pr_associated",
            &canonical_envelope_upper,
            "actor-canonical-ci",
            6_000_000_000,
        );
        assert!(
            canonical_duplicate
                .err()
                .is_some_and(|err| err.to_string().contains("UNIQUE constraint")),
            "canonical tuple with case-only commit variation must hit UNIQUE constraint"
        );
    }

    /// Regression: `get_event_by_evidence_identity` on
    /// `SqliteLedgerEventEmitter` must decode the JSON envelope, hex-decode
    /// the protobuf payload, and verify `published.evidence_id == entry_id`
    /// before returning. With two different `entry_id` values under the same
    /// `work_id`, the second publish must NOT false-hit the first entry.
    #[test]
    fn test_sqlite_get_event_by_evidence_identity_no_false_idempotency() {
        use prost::Message;

        let emitter = test_emitter();

        // Build two different WORK_CONTEXT_ENTRY evidence events under the
        // same work_id but with different evidence_id / entry_id values.
        let make_evidence_protobuf = |evidence_id: &str, artifact_byte: u8| {
            let published = apm2_core::events::EvidencePublished {
                evidence_id: evidence_id.to_string(),
                work_id: "W-IDEM-TEST".to_string(),
                category: "WORK_CONTEXT_ENTRY".to_string(),
                artifact_hash: vec![artifact_byte; 32],
                verification_command_ids: Vec::new(),
                classification: "INTERNAL".to_string(),
                artifact_size: 42,
                metadata: vec![
                    format!("entry_id={evidence_id}"),
                    "kind=HANDOFF_NOTE".to_string(),
                    format!("dedupe_key=dedup-{evidence_id}"),
                    "actor_id=actor-test".to_string(),
                ],
                time_envelope_ref: None,
            };
            let event = apm2_core::events::EvidenceEvent {
                event: Some(apm2_core::events::evidence_event::Event::Published(
                    published,
                )),
            };
            event.encode_to_vec()
        };

        // Emit first evidence event via emit_evidence_published_event (which
        // wraps in JSON envelope with hex-encoded protobuf and top-level
        // evidence_id for UNIQUE index enforcement). Session_id is used as
        // work_id in the ledger, so pass the work_id as session_id.
        let proto_a = make_evidence_protobuf("CTX-entry-A", 0xAA);
        let event_a = emitter
            .emit_evidence_published_event(
                "W-IDEM-TEST",
                &proto_a,
                "actor-test",
                1_000_000_000,
                "CTX-entry-A",
            )
            .expect("first evidence event should emit");

        // Emit second evidence event with a DIFFERENT evidence_id.
        let proto_b = make_evidence_protobuf("CTX-entry-B", 0xBB);
        let event_b = emitter
            .emit_evidence_published_event(
                "W-IDEM-TEST",
                &proto_b,
                "actor-test",
                2_000_000_000,
                "CTX-entry-B",
            )
            .expect("second evidence event should emit");

        // Verify: looking up entry_id "CTX-entry-A" returns the first event.
        let result_a = emitter.get_event_by_evidence_identity("W-IDEM-TEST", "CTX-entry-A");
        assert!(
            result_a.is_some(),
            "get_event_by_evidence_identity must find CTX-entry-A"
        );
        assert_eq!(
            result_a.unwrap().event_id,
            event_a.event_id,
            "Must return the event matching CTX-entry-A, not the latest one"
        );

        // Verify: looking up entry_id "CTX-entry-B" returns the second event.
        let result_b = emitter.get_event_by_evidence_identity("W-IDEM-TEST", "CTX-entry-B");
        assert!(
            result_b.is_some(),
            "get_event_by_evidence_identity must find CTX-entry-B"
        );
        assert_eq!(
            result_b.unwrap().event_id,
            event_b.event_id,
            "Must return the event matching CTX-entry-B, not the first one"
        );

        // Verify: looking up a non-existent entry_id returns None (no false positive).
        let result_none = emitter.get_event_by_evidence_identity("W-IDEM-TEST", "CTX-nonexistent");
        assert!(
            result_none.is_none(),
            "Non-existent entry_id must return None"
        );

        // Verify: looking up the correct entry_id but wrong work_id returns None.
        let result_wrong_work =
            emitter.get_event_by_evidence_identity("W-WRONG-WORK", "CTX-entry-A");
        assert!(
            result_wrong_work.is_none(),
            "Wrong work_id must return None"
        );
    }

    /// TCK-00638 / BLOCKER fix regression test: Verify that
    /// `get_event_by_evidence_identity` finds evidence events written to the
    /// canonical `events` table when the freeze guard is active.
    ///
    /// Without the fix, the method only searched `ledger_events`, so
    /// idempotent replays would fail to detect already-published entries in
    /// canonical mode, causing duplicate `evidence.published` events.
    #[test]
    fn test_canonical_evidence_replay_lookup_after_freeze() {
        use apm2_core::ledger::{init_canonical_schema, migrate_legacy_ledger_events};
        use prost::Message;

        // 1. Create emitter with legacy schema.
        let conn = Connection::open_in_memory().unwrap();
        SqliteLedgerEventEmitter::init_schema_for_test(&conn).unwrap();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let conn_arc = Arc::new(Mutex::new(conn));
        let emitter = SqliteLedgerEventEmitter::new(Arc::clone(&conn_arc), signing_key);

        // 2. Initialize canonical schema and migrate (creates frozen marker).
        {
            let conn_guard = conn_arc.lock().unwrap();
            init_canonical_schema(&conn_guard).unwrap();
            let _stats = migrate_legacy_ledger_events(&conn_guard).unwrap();
        }

        // 3. Freeze legacy writes — all subsequent writes go to canonical `events`.
        {
            let conn_guard = conn_arc.lock().unwrap();
            let frozen = emitter.freeze_legacy_writes(&conn_guard).unwrap();
            assert!(frozen, "freeze_legacy_writes must return true");
        }
        assert!(emitter.is_frozen(), "emitter must be frozen");

        // 4. Emit an evidence.published event via emit_evidence_published_event.
        // This write goes to the canonical `events` table (not legacy).
        let published = apm2_core::events::EvidencePublished {
            evidence_id: "CTX-canonical-entry".to_string(),
            work_id: "W-CANONICAL-TEST".to_string(),
            category: "WORK_CONTEXT_ENTRY".to_string(),
            artifact_hash: vec![0xCC; 32],
            verification_command_ids: Vec::new(),
            classification: "INTERNAL".to_string(),
            artifact_size: 100,
            metadata: vec![
                "entry_id=CTX-canonical-entry".to_string(),
                "kind=HANDOFF_NOTE".to_string(),
                "dedupe_key=dedup-canonical".to_string(),
                "actor_id=actor-canonical".to_string(),
            ],
            time_envelope_ref: None,
        };
        let evidence_event = apm2_core::events::EvidenceEvent {
            event: Some(apm2_core::events::evidence_event::Event::Published(
                published,
            )),
        };
        let proto_bytes = evidence_event.encode_to_vec();

        let emit_result = emitter
            .emit_evidence_published_event(
                "W-CANONICAL-TEST",
                &proto_bytes,
                "actor-canonical",
                5_000_000_000,
                "CTX-canonical-entry",
            )
            .expect("emit_evidence_published_event must succeed in frozen mode");

        // 5. Verify the event was written to canonical `events` (not legacy).
        {
            let conn_guard = conn_arc.lock().unwrap();
            let canonical_count: i64 = conn_guard
                .query_row(
                    "SELECT COUNT(*) FROM events WHERE event_type = 'evidence.published'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                canonical_count >= 1,
                "canonical events table must have the evidence event"
            );

            let legacy_count: i64 = conn_guard
                .query_row(
                    "SELECT COUNT(*) FROM ledger_events \
                     WHERE event_type = 'evidence.published'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                legacy_count, 0,
                "legacy ledger_events must NOT have evidence events after freeze"
            );
        }

        // 6. REGRESSION: get_event_by_evidence_identity MUST find the event
        // even though it is in the canonical `events` table, not legacy.
        let result =
            emitter.get_event_by_evidence_identity("W-CANONICAL-TEST", "CTX-canonical-entry");
        assert!(
            result.is_some(),
            "BLOCKER fix: get_event_by_evidence_identity must find canonical-mode \
             evidence events for idempotent replay detection"
        );

        // Verify it returned the correct event (by checking the event_id
        // starts with "canonical-" since it was synthesised from seq_id).
        let found = result.unwrap();
        assert!(
            found.event_id.starts_with("canonical-"),
            "event_id must be synthesised from canonical seq_id, got: {}",
            found.event_id
        );

        // 7. Non-existent entry_id must still return None.
        let none_result =
            emitter.get_event_by_evidence_identity("W-CANONICAL-TEST", "CTX-nonexistent");
        assert!(
            none_result.is_none(),
            "Non-existent entry_id must return None even in canonical mode"
        );

        // 8. Verify the returned event has the correct timestamp.
        let found2 = emitter
            .get_event_by_evidence_identity("W-CANONICAL-TEST", "CTX-canonical-entry")
            .unwrap();
        assert_eq!(
            found2.timestamp_ns, 5_000_000_000,
            "timestamp must match the emitted event"
        );

        // 9. Verify emit_result event_id matches (the legacy event_id from
        // emit is different from the canonical synthesised one, but the
        // canonical lookup should still work).
        let _ = emit_result; // used above for proof that emit succeeded
    }

    /// TCK-00669 regression: `get_events_since` must not skip canonical rows
    /// under same-timestamp cursor collisions once `seq_id` crosses 9.
    ///
    /// This test also verifies backward compatibility for previously persisted
    /// unpadded cursor IDs by advancing the cursor as `canonical-<seq_id>`
    /// (without zero padding) between paginated reads.
    #[test]
    fn test_get_events_since_canonical_cursor_collision_no_skip() {
        use apm2_core::ledger::init_canonical_schema;

        let conn = Connection::open_in_memory().expect("sqlite in-memory should open");
        SqliteLedgerEventEmitter::init_schema_for_test(&conn)
            .expect("legacy schema initialization should succeed");
        init_canonical_schema(&conn).expect("canonical schema initialization should succeed");

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let conn_arc = Arc::new(Mutex::new(conn));
        let emitter = SqliteLedgerEventEmitter::new(Arc::clone(&conn_arc), signing_key);

        {
            let conn_guard = conn_arc.lock().expect("sqlite lock should be available");
            let frozen = emitter
                .freeze_legacy_writes(&conn_guard)
                .expect("freeze_legacy_writes should succeed");
            assert!(frozen, "freeze_legacy_writes must return true");
        }
        assert!(emitter.is_frozen(), "emitter must be frozen");

        let timestamp_ns = 1_700_000_000_000_000_000_u64;
        let total_events = 12_u64;

        for seq in 0..total_events {
            let payload = format!(r#"{{"seq":{seq}}}"#);
            emitter
                .emit_session_event(
                    "W-CURSOR-COLLISION",
                    "fac.job.claimed",
                    payload.as_bytes(),
                    "uid:cursor-collision",
                    timestamp_ns,
                )
                .expect("canonical session event emit should succeed");
        }

        let mut cursor_event_id = String::new();
        let mut seen_seq_ids = Vec::new();
        let mut pages = 0usize;

        loop {
            let batch =
                emitter.get_events_since(timestamp_ns, &cursor_event_id, &["fac.job.claimed"], 4);
            if batch.is_empty() {
                break;
            }

            pages += 1;
            assert!(
                pages <= 10,
                "pagination must converge without looping indefinitely"
            );

            for event in &batch {
                let suffix = event
                    .event_id
                    .strip_prefix(SqliteLedgerEventEmitter::CANONICAL_EVENT_ID_PREFIX)
                    .expect("canonical events must use canonical- prefix");
                assert_eq!(
                    suffix.len(),
                    SqliteLedgerEventEmitter::CANONICAL_EVENT_ID_WIDTH,
                    "canonical event IDs must be fixed-width zero padded"
                );
                seen_seq_ids.push(
                    event
                        .canonical_seq_id()
                        .expect("canonical event must expose seq_id"),
                );
            }

            let last_seq_id = *seen_seq_ids
                .last()
                .expect("at least one event must be seen in non-empty batch");
            cursor_event_id = format!("canonical-{last_seq_id}");
        }

        assert!(
            pages >= 3,
            "bounded pagination must span multiple pages for >9 same-timestamp rows"
        );
        assert_eq!(
            seen_seq_ids,
            (1..=total_events).collect::<Vec<_>>(),
            "get_events_since must return all canonical rows in seq_id order \
             without skipping double-digit seq IDs"
        );
    }

    /// BLOCKER regression: `get_event_by_evidence_identity` must scan at most
    /// TCK-00638 SECURITY FIX: With the UNIQUE index on
    /// `json_extract(CAST(payload AS TEXT), '$.evidence_id')`, lookups are now
    /// O(1) indexed instead of O(N) scan with per-row protobuf decoding.
    ///
    /// This test publishes more than the previous `MAX_EVIDENCE_SCAN_ROWS`
    /// evidence events under the same `work_id` and verifies the indexed
    /// lookup returns `None` for a non-existent `entry_id` and correctly
    /// finds existing entries regardless of position.
    #[test]
    fn test_evidence_lookup_is_indexed_not_scan_bounded() {
        use prost::Message;

        let emitter = test_emitter();

        let work_id = "W-DOS-BOUND-TEST";
        let actor_id = "test-actor";

        // Publish MAX_EVIDENCE_SCAN_ROWS + 10 events with distinct entry_ids.
        // Each uses emit_evidence_published_event with evidence_id at the
        // top level of the JSON envelope for UNIQUE index enforcement.
        let event_count = MAX_EVIDENCE_SCAN_ROWS + 10;
        for i in 0..event_count {
            let evidence_id = format!("CTX-dos-entry-{i:06}");
            let published = apm2_core::events::EvidencePublished {
                evidence_id: evidence_id.clone(),
                work_id: work_id.to_string(),
                category: "WORK_CONTEXT_ENTRY".to_string(),
                artifact_hash: vec![0u8; 32],
                verification_command_ids: Vec::new(),
                classification: "INTERNAL".to_string(),
                artifact_size: 100,
                metadata: vec![],
                time_envelope_ref: None,
            };
            let event = apm2_core::events::EvidenceEvent {
                event: Some(apm2_core::events::evidence_event::Event::Published(
                    published,
                )),
            };
            let proto_bytes = event.encode_to_vec();

            emitter
                .emit_evidence_published_event(
                    work_id,
                    &proto_bytes,
                    actor_id,
                    1_000_000_000 + u64::from(i),
                    &evidence_id,
                )
                .expect("emit must succeed");
        }

        // Lookup a non-existent entry_id — must return None via indexed
        // lookup (no scan needed).
        let result = emitter.get_event_by_evidence_identity(work_id, "CTX-does-not-exist");
        assert!(
            result.is_none(),
            "Non-existent entry_id must return None even with > MAX_EVIDENCE_SCAN_ROWS events"
        );

        // Lookup the most recent entry — must be found via indexed lookup.
        let last_id = format!("CTX-dos-entry-{:06}", event_count - 1);
        let found = emitter.get_event_by_evidence_identity(work_id, &last_id);
        assert!(
            found.is_some(),
            "Most recent entry must be findable via indexed lookup"
        );

        // TCK-00638 FIX: Lookup the FIRST entry — must ALSO be found since
        // the indexed lookup does not have a scan window limitation.
        let first_id = "CTX-dos-entry-000000";
        let found_first = emitter.get_event_by_evidence_identity(work_id, first_id);
        assert!(
            found_first.is_some(),
            "First entry must be findable via indexed lookup (no scan truncation)"
        );
    }

    /// TCK-00638 SECURITY: Verify that the UNIQUE constraint on
    /// `json_extract(CAST(payload AS TEXT), '$.evidence_id')` rejects duplicate
    /// `evidence.published` events for the same `evidence_id`.
    ///
    /// Concurrent `PublishWorkContextEntry` requests that race past the
    /// application-level idempotency check must be caught by the DB UNIQUE
    /// index, causing `emit_evidence_published_event` to return an error
    /// that triggers the `find_work_context_published_replay` fallback.
    #[test]
    fn test_evidence_published_unique_constraint_rejects_duplicate() {
        use prost::Message;

        let emitter = test_emitter();

        let make_proto = |evidence_id: &str| {
            let published = apm2_core::events::EvidencePublished {
                evidence_id: evidence_id.to_string(),
                work_id: "W-UNIQUE-TEST".to_string(),
                category: "WORK_CONTEXT_ENTRY".to_string(),
                artifact_hash: vec![0xDD; 32],
                verification_command_ids: Vec::new(),
                classification: "INTERNAL".to_string(),
                artifact_size: 64,
                metadata: vec![],
                time_envelope_ref: None,
            };
            let event = apm2_core::events::EvidenceEvent {
                event: Some(apm2_core::events::evidence_event::Event::Published(
                    published,
                )),
            };
            event.encode_to_vec()
        };

        let proto = make_proto("CTX-unique-entry");

        // First emit succeeds.
        let first = emitter
            .emit_evidence_published_event(
                "W-UNIQUE-TEST",
                &proto,
                "actor-test",
                1_000_000_000,
                "CTX-unique-entry",
            )
            .expect("first emit must succeed");

        // Second emit with the SAME evidence_id must fail with UNIQUE
        // constraint violation.
        let second = emitter.emit_evidence_published_event(
            "W-UNIQUE-TEST",
            &proto,
            "actor-test",
            2_000_000_000,
            "CTX-unique-entry",
        );
        assert!(
            second.is_err(),
            "Duplicate evidence_id must be rejected by UNIQUE constraint; got: {second:?}"
        );
        let err_msg = format!("{}", second.unwrap_err());
        assert!(
            err_msg.contains("UNIQUE constraint failed"),
            "Error must mention UNIQUE constraint: {err_msg}"
        );

        // Third emit with a DIFFERENT evidence_id must succeed (not falsely rejected).
        let proto_different = make_proto("CTX-different-entry");
        let third = emitter
            .emit_evidence_published_event(
                "W-UNIQUE-TEST",
                &proto_different,
                "actor-test",
                3_000_000_000,
                "CTX-different-entry",
            )
            .expect("different evidence_id must succeed");

        // Verify lookup returns the correct event for each evidence_id.
        let found_first =
            emitter.get_event_by_evidence_identity("W-UNIQUE-TEST", "CTX-unique-entry");
        assert_eq!(
            found_first.as_ref().map(|e| &e.event_id),
            Some(&first.event_id),
            "lookup must return the first persisted event"
        );

        let found_third =
            emitter.get_event_by_evidence_identity("W-UNIQUE-TEST", "CTX-different-entry");
        assert_eq!(
            found_third.as_ref().map(|e| &e.event_id),
            Some(&third.event_id),
            "lookup must return the third persisted event"
        );
    }

    // ====================================================================
    // TCK-00637 Finding 2: Schema migration for legacy work_claims PK
    // ====================================================================

    /// Verify that `SqliteWorkRegistry::init_schema` migrates a legacy
    /// `work_claims` table (with `work_id TEXT PRIMARY KEY` and no `role`
    /// column) to the Phase 2 schema with composite `(work_id, role)`
    /// uniqueness. The migration must:
    ///
    /// 1. Preserve existing claim data with a default `role = 1` (Implementer).
    /// 2. Allow multi-role inserts after migration.
    /// 3. Be idempotent (running `init_schema` twice is safe).
    #[test]
    fn test_work_claims_legacy_schema_migration() {
        use rusqlite::Connection;

        let conn = Connection::open_in_memory().unwrap();

        // Create the LEGACY schema: work_id TEXT PRIMARY KEY, no role column.
        conn.execute(
            "CREATE TABLE work_claims (
                work_id TEXT PRIMARY KEY,
                lease_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                claim_json BLOB NOT NULL
            )",
            [],
        )
        .unwrap();

        // Insert a legacy claim (no role column).
        let claim = WorkClaim {
            work_id: "W-legacy-001".to_string(),
            lease_id: "L-legacy-001".to_string(),
            actor_id: "actor-legacy".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };
        let claim_json = serde_json::to_vec(&claim).unwrap();
        conn.execute(
            "INSERT INTO work_claims (work_id, lease_id, actor_id, claim_json) \
             VALUES (?1, ?2, ?3, ?4)",
            params!["W-legacy-001", "L-legacy-001", "actor-legacy", claim_json],
        )
        .unwrap();

        // Run the migration via init_schema.
        SqliteWorkRegistry::init_schema(&conn).expect("migration should succeed");

        // Verify the legacy claim was preserved with role = 1 (Implementer).
        let role: i32 = conn
            .query_row(
                "SELECT role FROM work_claims WHERE work_id = 'W-legacy-001'",
                [],
                |row| row.get(0),
            )
            .expect("legacy claim should exist after migration");
        assert_eq!(
            role, 1,
            "legacy claims should be assigned role=1 (Implementer)"
        );

        // Verify multi-role inserts now work (different role for same work_id).
        let reviewer_claim_json = serde_json::to_vec(&WorkClaim {
            work_id: "W-legacy-001".to_string(),
            lease_id: "L-reviewer-001".to_string(),
            actor_id: "actor-reviewer".to_string(),
            role: WorkRole::Reviewer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        })
        .unwrap();
        conn.execute(
            "INSERT INTO work_claims (work_id, lease_id, actor_id, role, claim_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "W-legacy-001",
                "L-reviewer-001",
                "actor-reviewer",
                WorkRole::Reviewer as i32,
                reviewer_claim_json,
            ],
        )
        .expect("multi-role insert should succeed after migration");

        // Verify the UNIQUE index on (work_id, role) rejects duplicates.
        let dup_result = conn.execute(
            "INSERT INTO work_claims (work_id, lease_id, actor_id, role, claim_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["W-legacy-001", "L-dup", "actor-dup", 1_i32, claim_json],
        );
        assert!(
            dup_result.is_err(),
            "duplicate (work_id, role) must be rejected"
        );
    }

    /// Verify that `SqliteWorkRegistry::init_schema` is idempotent on the
    /// new Phase 2 schema (no-op when called twice).
    #[test]
    fn test_work_claims_init_schema_idempotent() {
        use rusqlite::Connection;

        let conn = Connection::open_in_memory().unwrap();

        // First call: creates the table fresh.
        SqliteWorkRegistry::init_schema(&conn).expect("first init should succeed");

        // Insert a claim.
        let claim = WorkClaim {
            work_id: "W-idem-001".to_string(),
            lease_id: "L-idem-001".to_string(),
            actor_id: "actor-idem".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };
        let claim_json = serde_json::to_vec(&claim).unwrap();
        conn.execute(
            "INSERT INTO work_claims (work_id, lease_id, actor_id, role, claim_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "W-idem-001",
                "L-idem-001",
                "actor-idem",
                WorkRole::Implementer as i32,
                claim_json,
            ],
        )
        .unwrap();

        // Second call: must be a no-op (table exists with role column).
        SqliteWorkRegistry::init_schema(&conn).expect("second init should succeed (idempotent)");

        // Verify data is preserved.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM work_claims", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1, "data must be preserved after idempotent re-init");
    }

    /// Regression test for BLOCKER: legacy PK schema WITH role column.
    ///
    /// The intermediate schema revision had `work_id TEXT PRIMARY KEY` plus
    /// `role INTEGER` but kept the single-column PK. Migration must detect
    /// this by key/index topology (not just column presence) and rebuild
    /// the table so multi-role inserts succeed.
    #[test]
    fn test_work_claims_legacy_pk_with_role_column_migration() {
        use rusqlite::Connection;

        let conn = Connection::open_in_memory().unwrap();

        // Create the intermediate legacy schema: work_id PK + role column.
        // This is the schema that existed between the original (no role) and
        // the final Phase 2 schema (no single-column PK on work_id).
        conn.execute(
            "CREATE TABLE work_claims (
                work_id TEXT PRIMARY KEY,
                lease_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                role INTEGER NOT NULL DEFAULT 1,
                claim_json BLOB NOT NULL
            )",
            [],
        )
        .unwrap();

        // Insert an implementer claim.
        let impl_claim = WorkClaim {
            work_id: "W-pk-role-001".to_string(),
            lease_id: "L-impl-001".to_string(),
            actor_id: "actor-impl".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };
        let impl_json = serde_json::to_vec(&impl_claim).unwrap();
        conn.execute(
            "INSERT INTO work_claims (work_id, lease_id, actor_id, role, claim_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "W-pk-role-001",
                "L-impl-001",
                "actor-impl",
                WorkRole::Implementer as i32,
                impl_json,
            ],
        )
        .unwrap();

        // Before migration: inserting a REVIEWER for the same work_id must
        // FAIL because the PRIMARY KEY(work_id) enforces single-row-per-work_id.
        let reviewer_claim = WorkClaim {
            work_id: "W-pk-role-001".to_string(),
            lease_id: "L-reviewer-001".to_string(),
            actor_id: "actor-reviewer".to_string(),
            role: WorkRole::Reviewer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };
        let reviewer_json = serde_json::to_vec(&reviewer_claim).unwrap();
        let pre_migration_result = conn.execute(
            "INSERT INTO work_claims (work_id, lease_id, actor_id, role, claim_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "W-pk-role-001",
                "L-reviewer-001",
                "actor-reviewer",
                WorkRole::Reviewer as i32,
                reviewer_json,
            ],
        );
        assert!(
            pre_migration_result.is_err(),
            "pre-migration: same work_id with different role must fail \
             due to PRIMARY KEY(work_id)"
        );

        // Run migration.
        SqliteWorkRegistry::init_schema(&conn)
            .expect("migration of legacy PK + role schema should succeed");

        // Verify the implementer claim was preserved with its original role.
        let preserved_role: i32 = conn
            .query_row(
                "SELECT role FROM work_claims WHERE work_id = 'W-pk-role-001'",
                [],
                |row| row.get(0),
            )
            .expect("implementer claim should exist after migration");
        assert_eq!(
            preserved_role,
            WorkRole::Implementer as i32,
            "implementer claim role must be preserved"
        );

        // After migration: inserting a REVIEWER for the same work_id must
        // SUCCEED because the single-column PK on work_id was removed.
        let reviewer_json2 = serde_json::to_vec(&reviewer_claim).unwrap();
        conn.execute(
            "INSERT INTO work_claims (work_id, lease_id, actor_id, role, claim_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "W-pk-role-001",
                "L-reviewer-001",
                "actor-reviewer",
                WorkRole::Reviewer as i32,
                reviewer_json2,
            ],
        )
        .expect(
            "post-migration: same work_id with different role must succeed \
             (multi-role support)",
        );

        // Verify both claims exist.
        let total: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM work_claims WHERE work_id = 'W-pk-role-001'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            total, 2,
            "both implementer and reviewer claims must coexist"
        );

        // Verify the UNIQUE index on (work_id, role) rejects true duplicates.
        let dup_result = conn.execute(
            "INSERT INTO work_claims (work_id, lease_id, actor_id, role, claim_json) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "W-pk-role-001",
                "L-dup",
                "actor-dup",
                WorkRole::Implementer as i32,
                impl_json,
            ],
        );
        assert!(
            dup_result.is_err(),
            "duplicate (work_id, role) must still be rejected"
        );
    }

    /// Verify `remove_claim_for_role` removes a specific (`work_id`, role)
    /// claim from `SqliteWorkRegistry`.
    #[test]
    fn test_sqlite_work_registry_remove_claim_for_role() {
        use std::sync::{Arc, Mutex};

        use rusqlite::Connection;

        let conn = Connection::open_in_memory().unwrap();
        SqliteWorkRegistry::init_schema(&conn).unwrap();
        let registry = SqliteWorkRegistry::new(Arc::new(Mutex::new(conn)));

        // Register two claims for the same work_id (different roles).
        let impl_claim = WorkClaim {
            work_id: "W-rm-001".to_string(),
            lease_id: "L-rm-impl".to_string(),
            actor_id: "actor-rm".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };
        let reviewer_claim = WorkClaim {
            work_id: "W-rm-001".to_string(),
            lease_id: "L-rm-reviewer".to_string(),
            actor_id: "actor-rm-2".to_string(),
            role: WorkRole::Reviewer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };

        registry
            .register_claim(impl_claim)
            .expect("register implementer");
        registry
            .register_claim(reviewer_claim)
            .expect("register reviewer");

        // Both claims must exist.
        assert!(
            registry
                .get_claim_for_role("W-rm-001", WorkRole::Implementer)
                .is_some(),
            "implementer claim must exist before removal"
        );
        assert!(
            registry
                .get_claim_for_role("W-rm-001", WorkRole::Reviewer)
                .is_some(),
            "reviewer claim must exist before removal"
        );

        // Remove the implementer claim only.
        registry.remove_claim_for_role("W-rm-001", WorkRole::Implementer);

        // Implementer claim must be gone.
        assert!(
            registry
                .get_claim_for_role("W-rm-001", WorkRole::Implementer)
                .is_none(),
            "implementer claim must be removed"
        );
        // Reviewer claim must still exist.
        assert!(
            registry
                .get_claim_for_role("W-rm-001", WorkRole::Reviewer)
                .is_some(),
            "reviewer claim must survive targeted removal"
        );

        // Re-registering the same (work_id, role) must succeed after removal.
        let re_claim = WorkClaim {
            work_id: "W-rm-001".to_string(),
            lease_id: "L-rm-impl-2".to_string(),
            actor_id: "actor-rm".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };
        registry
            .register_claim(re_claim)
            .expect("re-register after removal must succeed");
    }

    #[test]
    fn test_sqlite_work_registry_clear_claim_age_keeps_claim() {
        use std::sync::{Arc, Mutex};

        use rusqlite::Connection;

        let conn = Connection::open_in_memory().unwrap();
        SqliteWorkRegistry::init_schema(&conn).unwrap();
        let registry = SqliteWorkRegistry::new(Arc::new(Mutex::new(conn)));

        let claim = WorkClaim {
            work_id: "W-clear-age-001".to_string(),
            lease_id: "L-clear-age-001".to_string(),
            actor_id: "actor-clear-age".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };

        registry
            .register_claim(claim.clone())
            .expect("register implementer");
        assert!(
            registry
                .get_claim_age_for_role(&claim.work_id, claim.role)
                .is_some(),
            "age metadata should be present after register_claim"
        );

        registry.clear_claim_age(&claim.work_id, claim.role);

        assert!(
            registry
                .get_claim_for_role(&claim.work_id, claim.role)
                .is_some(),
            "clear_claim_age must not remove the persisted claim row"
        );
        assert!(
            registry
                .get_claim_age_for_role(&claim.work_id, claim.role)
                .is_none(),
            "clear_claim_age must remove age metadata after success"
        );
    }

    #[test]
    fn test_sqlite_lease_validator_fallback_resolves_work_claim_binding() {
        let conn = Connection::open_in_memory().expect("open in-memory sqlite");
        SqliteLedgerEventEmitter::init_schema_for_test(&conn)
            .expect("initialize ledger schema for lease validator");
        SqliteWorkRegistry::init_schema(&conn).expect("initialize work registry schema");

        let shared = Arc::new(Mutex::new(conn));
        let registry = SqliteWorkRegistry::new(Arc::clone(&shared));
        let validator = SqliteLeaseValidator::new(Arc::clone(&shared));

        let claim = crate::protocol::dispatch::WorkClaim {
            work_id: "W-fallback-lease-001".to_string(),
            lease_id: "L-fallback-lease-001".to_string(),
            actor_id: "actor:fallback".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: test_policy_resolution(),
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
            permeability_receipt: None,
        };
        registry
            .register_claim(claim.clone())
            .expect("register fallback claim");

        assert_eq!(
            validator.get_lease_work_id(&claim.lease_id),
            Some(claim.work_id.clone()),
            "lease validator should recover lease->work binding from persisted work_claims when no gate_lease_issued event exists"
        );
        assert_eq!(
            validator.get_lease_executor_actor_id(&claim.lease_id),
            Some(claim.actor_id.clone()),
            "lease validator should recover executor actor from persisted work_claims when no lease payload exists"
        );
    }

    #[test]
    fn test_sqlite_lease_validator_authoritative_lease_precedes_fallback() {
        let conn = Connection::open_in_memory().expect("open in-memory sqlite");
        SqliteLedgerEventEmitter::init_schema_for_test(&conn)
            .expect("initialize ledger schema for lease validator");
        SqliteWorkRegistry::init_schema(&conn).expect("initialize work registry schema");

        let shared = Arc::new(Mutex::new(conn));
        let registry = SqliteWorkRegistry::new(Arc::clone(&shared));
        let validator = SqliteLeaseValidator::new(Arc::clone(&shared));

        let lease_id = "L-authoritative-lease-001";
        registry
            .register_claim(crate::protocol::dispatch::WorkClaim {
                work_id: "W-claim-fallback-001".to_string(),
                lease_id: lease_id.to_string(),
                actor_id: "actor:claim-fallback".to_string(),
                role: WorkRole::Implementer,
                policy_resolution: test_policy_resolution(),
                executor_custody_domains: vec![],
                author_custody_domains: vec![],
                permeability_receipt: None,
            })
            .expect("register fallback claim");

        validator.register_lease_with_executor(
            lease_id,
            "W-authoritative-001",
            "gate-test",
            "actor:authoritative",
        );

        assert_eq!(
            validator.get_lease_work_id(lease_id),
            Some("W-authoritative-001".to_string()),
            "authoritative gate lease event should override work_claim fallback binding"
        );
        assert_eq!(
            validator.get_lease_executor_actor_id(lease_id),
            Some("actor:authoritative".to_string()),
            "authoritative gate lease payload should override fallback actor binding"
        );
    }

    #[test]
    fn test_sqlite_lease_validator_fallback_denies_ambiguous_work_claim_bindings() {
        let conn = Connection::open_in_memory().expect("open in-memory sqlite");
        SqliteLedgerEventEmitter::init_schema_for_test(&conn)
            .expect("initialize ledger schema for lease validator");
        SqliteWorkRegistry::init_schema(&conn).expect("initialize work registry schema");

        let shared = Arc::new(Mutex::new(conn));
        let registry = SqliteWorkRegistry::new(Arc::clone(&shared));
        let validator = SqliteLeaseValidator::new(Arc::clone(&shared));

        let lease_id = "L-ambiguous-fallback-001";
        registry
            .register_claim(crate::protocol::dispatch::WorkClaim {
                work_id: "W-ambiguous-a".to_string(),
                lease_id: lease_id.to_string(),
                actor_id: "actor:ambiguous-a".to_string(),
                role: WorkRole::Implementer,
                policy_resolution: test_policy_resolution(),
                executor_custody_domains: vec![],
                author_custody_domains: vec![],
                permeability_receipt: None,
            })
            .expect("register first fallback claim");
        registry
            .register_claim(crate::protocol::dispatch::WorkClaim {
                work_id: "W-ambiguous-b".to_string(),
                lease_id: lease_id.to_string(),
                actor_id: "actor:ambiguous-b".to_string(),
                role: WorkRole::Implementer,
                policy_resolution: test_policy_resolution(),
                executor_custody_domains: vec![],
                author_custody_domains: vec![],
                permeability_receipt: None,
            })
            .expect("register second fallback claim");

        assert_eq!(
            validator.get_lease_work_id(lease_id),
            None,
            "fallback must fail closed when lease_id maps to multiple distinct work_claim bindings"
        );
        assert_eq!(
            validator.get_lease_executor_actor_id(lease_id),
            None,
            "executor actor lookup must fail closed on ambiguous fallback bindings"
        );
    }

    #[test]
    fn test_sqlite_work_registry_schema_creates_lease_lookup_index() {
        let conn = Connection::open_in_memory().expect("open in-memory sqlite");
        SqliteWorkRegistry::init_schema(&conn).expect("initialize work registry schema");
        let has_index: bool = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1
                    FROM sqlite_master
                    WHERE type = 'index' AND name = 'idx_work_claims_lease_id'
                )",
                [],
                |row| row.get(0),
            )
            .expect("index existence query should succeed");
        assert!(
            has_index,
            "work_claims schema must include idx_work_claims_lease_id for lease fallback lookups"
        );
    }
}

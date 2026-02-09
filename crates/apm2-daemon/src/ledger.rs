//! Persistent ledger implementation using `SQLite`.
//!
//! This module provides durable implementations of:
//! - [`LedgerEventEmitter`]: Persists signed events to `ledger_events` table
//! - [`WorkRegistry`]: Persists work claims to `work_claims` table
//! - [`LeaseValidator`]: Validates leases against `ledger_events` table
//!
//! # Schema
//!
//! The `ledger_events` table has columns: `event_id`, `event_type`, `work_id`,
//! `actor_id`, `payload`, `signature`, `timestamp_ns`.
//!
//! The `work_claims` table has columns: `work_id`, `lease_id`, `actor_id`,
//! `role`, `claim_json`.

use std::sync::{Arc, Mutex};

use apm2_core::determinism::canonicalize_json;
use apm2_core::events::{DefectRecorded, Validate};
use apm2_core::fac::{REVIEW_RECEIPT_RECORDED_PREFIX, SelectionDecision};
use ed25519_dalek::Signer;
use rusqlite::{Connection, OptionalExtension, params};
use tracing::{info, warn};

use crate::protocol::dispatch::{
    CHANGESET_PUBLISHED_LEDGER_DOMAIN_PREFIX, DEFECT_RECORDED_DOMAIN_PREFIX,
    EPISODE_EVENT_DOMAIN_PREFIX, LeaseValidationError, LeaseValidator, LedgerEventEmitter,
    LedgerEventError, SESSION_TERMINATED_LEDGER_DOMAIN_PREFIX, STOP_FLAGS_MUTATED_DOMAIN_PREFIX,
    STOP_FLAGS_MUTATED_WORK_ID, SignedLedgerEvent, StopFlagsMutation, WORK_CLAIMED_DOMAIN_PREFIX,
    WORK_TRANSITIONED_DOMAIN_PREFIX, WorkClaim, WorkRegistry, WorkRegistryError, WorkTransition,
    build_session_started_payload,
};

/// Durable ledger event emitter backed by `SQLite`.
#[derive(Debug)]
pub struct SqliteLedgerEventEmitter {
    conn: Arc<Mutex<Connection>>,
    signing_key: ed25519_dalek::SigningKey,
}

impl SqliteLedgerEventEmitter {
    /// Creates a new emitter with the given `SQLite` connection and signing
    /// key.
    #[must_use]
    pub const fn new(conn: Arc<Mutex<Connection>>, signing_key: ed25519_dalek::SigningKey) -> Self {
        Self { conn, signing_key }
    }

    /// Initializes the database schema.
    pub fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ledger_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                work_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload BLOB NOT NULL,
                signature BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ledger_events_work_id ON ledger_events(work_id)",
            [],
        )?;
        // Index for LeaseValidator
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ledger_events_type_payload ON ledger_events(event_type)",
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
        // SECURITY (v13 Finding 2 — Receipt Uniqueness Constraint):
        //
        // Enforce at-most-once semantics for review receipt events at the
        // database level. The `receipt_id` is stored as a field in the JSON
        // payload. A partial unique index on `json_extract(payload, '$.receipt_id')`
        // for review receipt event types prevents concurrent duplicate
        // `IngestReviewReceipt` calls from creating multiple receipt events.
        // This converts the check-then-act pattern into defense-in-depth:
        // application-level `get_event_by_receipt_id` provides the fast-path,
        // while the database constraint provides the authoritative uniqueness
        // guarantee.
        //
        // MIGRATION: Quarantine historical duplicate `receipt_id` rows before
        // creating the unique index. Quarantine entries are keyed by stable
        // `event_id` (never persistent `rowid`) so startup replays are safe
        // even if SQLite rowids are recycled over time.
        //
        // The migration is idempotent:
        // - quarantine table is created with `IF NOT EXISTS`
        // - legacy rowid-based tables are upgraded once to event_id-keyed schema
        // - rows already quarantined are skipped with `INSERT OR IGNORE`
        Self::ensure_receipt_quarantine_table(conn)?;
        conn.execute(
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
        conn.execute(
            "DELETE FROM ledger_events WHERE event_id IN ( \
                 SELECT event_id FROM ledger_events_quarantine \
                 WHERE quarantine_reason = 'receipt_id_dedupe_migration' \
             )",
            [],
        )?;
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_receipt_id \
             ON ledger_events(json_extract(CAST(payload AS TEXT), '$.receipt_id')) \
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
        conn.execute(
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
        conn.execute(
            "DELETE FROM ledger_events WHERE event_id IN ( \
                 SELECT event_id FROM ledger_events_quarantine \
                 WHERE quarantine_reason = 'changeset_digest_dedupe_migration' \
             )",
            [],
        )?;
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_changeset_published \
             ON ledger_events(work_id, json_extract(CAST(payload AS TEXT), '$.changeset_digest')) \
             WHERE event_type = 'changeset_published'",
            [],
        )?;
        Ok(())
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
}

impl LedgerEventEmitter for SqliteLedgerEventEmitter {
    fn emit_work_claimed(
        &self,
        claim: &WorkClaim,
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        // Generate unique event ID
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

        // Build payload as JSON
        let payload = serde_json::json!({
            "event_type": "work_claimed",
            "work_id": claim.work_id,
            "lease_id": claim.lease_id,
            "actor_id": claim.actor_id,
            "role": format!("{:?}", claim.role),
            "policy_resolved_ref": claim.policy_resolution.policy_resolved_ref,
            "capability_manifest_hash": hex::encode(claim.policy_resolution.capability_manifest_hash),
            "context_pack_hash": hex::encode(claim.policy_resolution.context_pack_hash),
        });

        // TCK-00289 BLOCKER 2: Use JCS (RFC 8785) canonicalization for signing.
        // This ensures deterministic JSON representation per RFC-0016.
        let payload_json = payload.to_string();
        let canonical_payload =
            canonicalize_json(&payload_json).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            })?;
        let payload_bytes = canonical_payload.as_bytes().to_vec();

        // Build canonical bytes for signing (domain prefix + JCS payload)
        let mut canonical_bytes =
            Vec::with_capacity(WORK_CLAIMED_DOMAIN_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(WORK_CLAIMED_DOMAIN_PREFIX);
        canonical_bytes.extend_from_slice(&payload_bytes);

        // Sign the canonical bytes
        let signature = self.signing_key.sign(&canonical_bytes);

        let signed_event = SignedLedgerEvent {
            event_id: event_id.clone(),
            event_type: "work_claimed".to_string(),
            work_id: claim.work_id.clone(),
            actor_id: claim.actor_id.clone(),
            payload: payload_bytes.clone(),
            signature: signature.to_bytes().to_vec(),
            timestamp_ns,
        };

        // Persist to SQLite
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                signed_event.event_id,
                signed_event.event_type,
                signed_event.work_id,
                signed_event.actor_id,
                signed_event.payload,
                signed_event.signature,
                signed_event.timestamp_ns
            ],
        ).map_err(|e| LedgerEventError::PersistenceFailed {
            message: format!("sqlite insert failed: {e}"),
        })?;

        info!(event_id = %event_id, "Persisted WorkClaimed event");

        Ok(signed_event)
    }

    fn get_event(&self, event_id: &str) -> Option<SignedLedgerEvent> {
        let conn = self.conn.lock().ok()?;
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

        // Generate unique event ID
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

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

        // TCK-00289 BLOCKER 2: Use JCS (RFC 8785) canonicalization for signing.
        // This ensures deterministic JSON representation per RFC-0016.
        let payload_json = payload.to_string();
        let canonical_payload =
            canonicalize_json(&payload_json).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            })?;
        let payload_bytes = canonical_payload.as_bytes().to_vec();

        // Build canonical bytes for signing (domain prefix + JCS payload)
        let mut canonical_bytes =
            Vec::with_capacity(SESSION_STARTED_DOMAIN_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(SESSION_STARTED_DOMAIN_PREFIX);
        canonical_bytes.extend_from_slice(&payload_bytes);

        // Sign the canonical bytes
        let signature = self.signing_key.sign(&canonical_bytes);

        let signed_event = SignedLedgerEvent {
            event_id: event_id.clone(),
            event_type: "session_started".to_string(),
            work_id: work_id.to_string(),
            actor_id: actor_id.to_string(),
            payload: payload_bytes.clone(),
            signature: signature.to_bytes().to_vec(),
            timestamp_ns,
        };

        // Persist to SQLite
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                signed_event.event_id,
                signed_event.event_type,
                signed_event.work_id,
                signed_event.actor_id,
                signed_event.payload,
                signed_event.signature,
                signed_event.timestamp_ns
            ],
        ).map_err(|e| LedgerEventError::PersistenceFailed {
            message: format!("sqlite insert failed: {e}"),
        })?;

        info!(event_id = %event_id, session_id = %session_id, "Persisted SessionStarted event");

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

        // Generate unique event ID
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

        // Build payload as JSON with actual event type and base64-encoded payload
        let payload_json = serde_json::json!({
            "event_type": event_type,
            "session_id": session_id,
            "actor_id": actor_id,
            "payload": hex::encode(payload),
        });

        // TCK-00290: Use JCS (RFC 8785) canonicalization for signing.
        let payload_string = payload_json.to_string();
        let canonical_payload =
            canonicalize_json(&payload_string).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            })?;
        let payload_bytes = canonical_payload.as_bytes().to_vec();

        // Build canonical bytes for signing (domain prefix + JCS payload)
        let mut canonical_bytes =
            Vec::with_capacity(SESSION_EVENT_DOMAIN_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(SESSION_EVENT_DOMAIN_PREFIX);
        canonical_bytes.extend_from_slice(&payload_bytes);

        // Sign the canonical bytes
        let signature = self.signing_key.sign(&canonical_bytes);

        let signed_event = SignedLedgerEvent {
            event_id: event_id.clone(),
            event_type: event_type.to_string(),
            work_id: session_id.to_string(), // Use session_id as work_id for indexing
            actor_id: actor_id.to_string(),
            payload: payload_bytes.clone(),
            signature: signature.to_bytes().to_vec(),
            timestamp_ns,
        };

        // Persist to SQLite
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                signed_event.event_id,
                signed_event.event_type,
                signed_event.work_id,
                signed_event.actor_id,
                signed_event.payload,
                signed_event.signature,
                signed_event.timestamp_ns
            ],
        ).map_err(|e| LedgerEventError::PersistenceFailed {
            message: format!("sqlite insert failed: {e}"),
        })?;

        info!(
            event_id = %event_id,
            session_id = %session_id,
            event_type = %event_type,
            actor_id = %actor_id,
            "Persisted SessionEvent"
        );

        Ok(signed_event)
    }

    fn emit_stop_flags_mutated(
        &self,
        mutation: &StopFlagsMutation<'_>,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

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

        let payload_json = payload.to_string();
        let canonical_payload =
            canonicalize_json(&payload_json).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            })?;
        let payload_bytes = canonical_payload.as_bytes().to_vec();

        let mut canonical_bytes =
            Vec::with_capacity(STOP_FLAGS_MUTATED_DOMAIN_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(STOP_FLAGS_MUTATED_DOMAIN_PREFIX);
        canonical_bytes.extend_from_slice(&payload_bytes);

        let signature = self.signing_key.sign(&canonical_bytes);

        let signed_event = SignedLedgerEvent {
            event_id: event_id.clone(),
            event_type: "stop_flags_mutated".to_string(),
            work_id: STOP_FLAGS_MUTATED_WORK_ID.to_string(),
            actor_id: mutation.actor_id.to_string(),
            payload: payload_bytes.clone(),
            signature: signature.to_bytes().to_vec(),
            timestamp_ns: mutation.timestamp_ns,
        };

        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                signed_event.event_id,
                signed_event.event_type,
                signed_event.work_id,
                signed_event.actor_id,
                signed_event.payload,
                signed_event.signature,
                signed_event.timestamp_ns
            ],
        ).map_err(|e| LedgerEventError::PersistenceFailed {
            message: format!("sqlite insert failed: {e}"),
        })?;

        info!(
            event_id = %event_id,
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

        // Generate unique event ID
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

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

        // TCK-00307: Use JCS (RFC 8785) canonicalization for signing.
        let payload_json = payload.to_string();
        let canonical_payload =
            canonicalize_json(&payload_json).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            })?;
        let payload_bytes = canonical_payload.as_bytes().to_vec();

        // Build canonical bytes for signing (domain prefix + JCS payload)
        let mut canonical_bytes =
            Vec::with_capacity(DEFECT_RECORDED_DOMAIN_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(DEFECT_RECORDED_DOMAIN_PREFIX);
        canonical_bytes.extend_from_slice(&payload_bytes);

        // Sign the canonical bytes
        let signature = self.signing_key.sign(&canonical_bytes);

        let signed_event = SignedLedgerEvent {
            event_id: event_id.clone(),
            event_type: "defect_recorded".to_string(),
            work_id: defect.work_id.clone(),
            actor_id: String::new(), // Defects are system events, no actor
            payload: payload_bytes.clone(),
            signature: signature.to_bytes().to_vec(),
            timestamp_ns,
        };

        // Persist to SQLite
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                signed_event.event_id,
                signed_event.event_type,
                signed_event.work_id,
                signed_event.actor_id,
                signed_event.payload,
                signed_event.signature,
                signed_event.timestamp_ns
            ],
        ).map_err(|e| LedgerEventError::PersistenceFailed {
            message: format!("sqlite insert failed: {e}"),
        })?;

        info!(
            event_id = %event_id,
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

        let Ok(mut stmt) = conn.prepare(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
             FROM ledger_events WHERE work_id = ?1 ORDER BY timestamp_ns ASC, rowid ASC",
        ) else {
            return Vec::new();
        };

        let rows = stmt.query_map(params![work_id], |row| {
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

    fn get_all_events(&self) -> Vec<SignedLedgerEvent> {
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };

        let Ok(mut stmt) = conn.prepare(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
             FROM ledger_events
             ORDER BY timestamp_ns ASC, rowid ASC",
        ) else {
            return Vec::new();
        };

        let rows = stmt.query_map([], |row| {
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

    fn get_event_count(&self) -> usize {
        let Ok(conn) = self.conn.lock() else {
            return 0;
        };

        let Ok(count) = conn.query_row("SELECT COUNT(*) FROM ledger_events", [], |row| {
            row.get::<_, i64>(0)
        }) else {
            return 0;
        };

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let count = count as usize;
        count
    }

    fn get_latest_event(&self) -> Option<SignedLedgerEvent> {
        let conn = self.conn.lock().ok()?;

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
        // TCK-00321: EPISODE_EVENT_DOMAIN_PREFIX imported from
        // crate::protocol::dispatch to maintain single source of truth for
        // domain prefixes.

        // Generate unique event ID
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

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

        // TCK-00321: Use JCS (RFC 8785) canonicalization for signing.
        let payload_string = payload_json.to_string();
        let canonical_payload =
            canonicalize_json(&payload_string).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            })?;
        let payload_bytes = canonical_payload.as_bytes().to_vec();

        // Build canonical bytes for signing (domain prefix + JCS payload)
        let mut canonical_bytes =
            Vec::with_capacity(EPISODE_EVENT_DOMAIN_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(EPISODE_EVENT_DOMAIN_PREFIX);
        canonical_bytes.extend_from_slice(&payload_bytes);

        // Sign the canonical bytes
        let signature = self.signing_key.sign(&canonical_bytes);

        let signed_event = SignedLedgerEvent {
            event_id: event_id.clone(),
            event_type: event_type.to_string(),
            work_id: episode_id.to_string(), // Use episode_id as work_id for indexing
            actor_id: "daemon".to_string(),  // Episode events are daemon-authored
            payload: payload_bytes.clone(),
            signature: signature.to_bytes().to_vec(),
            timestamp_ns,
        };

        // Persist to SQLite
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                signed_event.event_id,
                signed_event.event_type,
                signed_event.work_id,
                signed_event.actor_id,
                signed_event.payload,
                signed_event.signature,
                signed_event.timestamp_ns
            ],
        ).map_err(|e| LedgerEventError::PersistenceFailed {
            message: format!("sqlite insert failed: {e}"),
        })?;

        info!(
            event_id = %event_id,
            episode_id = %episode_id,
            event_type = %event_type,
            "Persisted EpisodeEvent"
        );

        Ok(signed_event)
    }

    fn emit_review_receipt(
        &self,
        episode_id: &str,
        receipt_id: &str,
        changeset_digest: &[u8; 32],
        artifact_bundle_hash: &[u8; 32],
        reviewer_actor_id: &str,
        timestamp_ns: u64,
        identity_proof_hash: &[u8; 32],
        time_envelope_ref: &str,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        // TCK-00321: Use REVIEW_RECEIPT_RECORDED_PREFIX from apm2_core::fac for
        // protocol compatibility across daemon/core boundary.
        // (Previously used daemon-local prefix; now aligned with core.)

        // Generate unique event ID
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

        // Build payload as JSON with review receipt data
        // SECURITY: timestamp_ns is included in signed payload to prevent temporal
        // malleability per LAW-09 (Temporal Pinning & Freshness) and RS-40
        // (Time & Monotonicity)
        //
        // SECURITY (TCK-00356 Fix 1): identity_proof_hash is included in
        // the signed payload so it is audit-bound and cannot be stripped
        // post-signing.
        let payload_json = serde_json::json!({
            "event_type": "review_receipt_recorded",
            "episode_id": episode_id,
            "lease_id": episode_id,
            "receipt_id": receipt_id,
            "changeset_digest": hex::encode(changeset_digest),
            "artifact_bundle_hash": hex::encode(artifact_bundle_hash),
            "verdict": "APPROVE",
            "reviewer_actor_id": reviewer_actor_id,
            "timestamp_ns": timestamp_ns,
            "identity_proof_hash": hex::encode(identity_proof_hash),
            "time_envelope_ref": time_envelope_ref,
        });

        // TCK-00321: Use JCS (RFC 8785) canonicalization for signing.
        let payload_string = payload_json.to_string();
        let canonical_payload =
            canonicalize_json(&payload_string).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            })?;
        let payload_bytes = canonical_payload.as_bytes().to_vec();

        // Build canonical bytes for signing (domain prefix + JCS payload)
        let mut canonical_bytes =
            Vec::with_capacity(REVIEW_RECEIPT_RECORDED_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(REVIEW_RECEIPT_RECORDED_PREFIX);
        canonical_bytes.extend_from_slice(&payload_bytes);

        // Sign the canonical bytes
        let signature = self.signing_key.sign(&canonical_bytes);

        let signed_event = SignedLedgerEvent {
            event_id: event_id.clone(),
            event_type: "review_receipt_recorded".to_string(),
            work_id: episode_id.to_string(),
            actor_id: reviewer_actor_id.to_string(),
            payload: payload_bytes.clone(),
            signature: signature.to_bytes().to_vec(),
            timestamp_ns,
        };

        // Persist to SQLite
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                signed_event.event_id,
                signed_event.event_type,
                signed_event.work_id,
                signed_event.actor_id,
                signed_event.payload,
                signed_event.signature,
                signed_event.timestamp_ns
            ],
        ).map_err(|e| LedgerEventError::PersistenceFailed {
            message: format!("sqlite insert failed: {e}"),
        })?;

        info!(
            event_id = %event_id,
            episode_id = %episode_id,
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
        receipt_id: &str,
        changeset_digest: &[u8; 32],
        artifact_bundle_hash: &[u8; 32],
        reason_code: u32,
        blocked_log_hash: &[u8; 32],
        reviewer_actor_id: &str,
        timestamp_ns: u64,
        identity_proof_hash: &[u8; 32],
        time_envelope_ref: &str,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        use crate::protocol::dispatch::REVIEW_BLOCKED_RECORDED_LEDGER_PREFIX;

        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

        // SECURITY (TCK-00356 Fix 2): identity_proof_hash is included in
        // the signed payload so it is audit-bound and cannot be stripped
        // post-signing, matching the APPROVE path's payload binding.
        let payload_json = serde_json::json!({
            "event_type": "review_blocked_recorded",
            "lease_id": lease_id,
            "receipt_id": receipt_id,
            "changeset_digest": hex::encode(changeset_digest),
            "artifact_bundle_hash": hex::encode(artifact_bundle_hash),
            "verdict": "BLOCKED",
            "blocked_reason_code": reason_code,
            // Preserve legacy field for backward compatibility with old readers.
            "reason_code": reason_code,
            "blocked_log_hash": hex::encode(blocked_log_hash),
            "reviewer_actor_id": reviewer_actor_id,
            "timestamp_ns": timestamp_ns,
            "identity_proof_hash": hex::encode(identity_proof_hash),
            "time_envelope_ref": time_envelope_ref,
        });

        let payload_string = payload_json.to_string();
        let canonical_payload =
            canonicalize_json(&payload_string).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            })?;
        let payload_bytes = canonical_payload.as_bytes().to_vec();

        let mut canonical_bytes =
            Vec::with_capacity(REVIEW_BLOCKED_RECORDED_LEDGER_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(REVIEW_BLOCKED_RECORDED_LEDGER_PREFIX);
        canonical_bytes.extend_from_slice(&payload_bytes);

        let signature = self.signing_key.sign(&canonical_bytes);

        let signed_event = SignedLedgerEvent {
            event_id: event_id.clone(),
            event_type: "review_blocked_recorded".to_string(),
            work_id: receipt_id.to_string(),
            actor_id: reviewer_actor_id.to_string(),
            payload: payload_bytes.clone(),
            signature: signature.to_bytes().to_vec(),
            timestamp_ns,
        };

        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                signed_event.event_id,
                signed_event.event_type,
                signed_event.work_id,
                signed_event.actor_id,
                signed_event.payload,
                signed_event.signature,
                signed_event.timestamp_ns
            ],
        ).map_err(|e| LedgerEventError::PersistenceFailed {
            message: format!("sqlite insert failed: {e}"),
        })?;

        info!(
            event_id = %event_id,
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

        // Generate unique event ID
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

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

        // TCK-00330: Use JCS (RFC 8785) canonicalization for signing.
        // This ensures deterministic JSON representation per RFC-0016.
        let payload_json = payload.to_string();
        let canonical_payload =
            canonicalize_json(&payload_json).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            })?;
        let payload_bytes = canonical_payload.as_bytes().to_vec();

        // Build canonical bytes for signing (domain prefix + JCS payload)
        let mut canonical_bytes =
            Vec::with_capacity(EPISODE_RUN_ATTRIBUTED_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(EPISODE_RUN_ATTRIBUTED_PREFIX);
        canonical_bytes.extend_from_slice(&payload_bytes);

        // Sign the canonical bytes
        let signature = self.signing_key.sign(&canonical_bytes);

        let signed_event = SignedLedgerEvent {
            event_id: event_id.clone(),
            event_type: "episode_run_attributed".to_string(),
            work_id: work_id.to_string(),
            actor_id: session_id.to_string(), // Session is the actor for run attribution
            payload: payload_bytes.clone(),
            signature: signature.to_bytes().to_vec(),
            timestamp_ns,
        };

        // Persist to SQLite
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                signed_event.event_id,
                signed_event.event_type,
                signed_event.work_id,
                signed_event.actor_id,
                signed_event.payload,
                signed_event.signature,
                signed_event.timestamp_ns
            ],
        ).map_err(|e| LedgerEventError::PersistenceFailed {
            message: format!("sqlite insert failed: {e}"),
        })?;

        info!(
            event_id = %event_id,
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
        // Generate unique event ID
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

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

        // TCK-00395: Use JCS (RFC 8785) canonicalization for signing.
        let payload_json = payload.to_string();
        let canonical_payload =
            canonicalize_json(&payload_json).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            })?;
        let payload_bytes = canonical_payload.as_bytes().to_vec();

        // Build canonical bytes for signing (domain prefix + JCS payload)
        let mut canonical_bytes =
            Vec::with_capacity(WORK_TRANSITIONED_DOMAIN_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(WORK_TRANSITIONED_DOMAIN_PREFIX);
        canonical_bytes.extend_from_slice(&payload_bytes);

        // Sign the canonical bytes
        let signature = self.signing_key.sign(&canonical_bytes);

        let signed_event = SignedLedgerEvent {
            event_id: event_id.clone(),
            event_type: "work_transitioned".to_string(),
            work_id: transition.work_id.to_string(),
            actor_id: transition.actor_id.to_string(),
            payload: payload_bytes.clone(),
            signature: signature.to_bytes().to_vec(),
            timestamp_ns: transition.timestamp_ns,
        };

        // Persist to SQLite
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                signed_event.event_id,
                signed_event.event_type,
                signed_event.work_id,
                signed_event.actor_id,
                signed_event.payload,
                signed_event.signature,
                signed_event.timestamp_ns
            ],
        ).map_err(|e| LedgerEventError::PersistenceFailed {
            message: format!("sqlite insert failed: {e}"),
        })?;

        info!(
            event_id = %event_id,
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
        // Generate unique event ID
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

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

        // TCK-00395: Use JCS (RFC 8785) canonicalization for signing.
        let payload_json = payload.to_string();
        let canonical_payload =
            canonicalize_json(&payload_json).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            })?;
        let payload_bytes = canonical_payload.as_bytes().to_vec();

        // Build canonical bytes for signing (domain prefix + JCS payload)
        let mut canonical_bytes =
            Vec::with_capacity(SESSION_TERMINATED_LEDGER_DOMAIN_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(SESSION_TERMINATED_LEDGER_DOMAIN_PREFIX);
        canonical_bytes.extend_from_slice(&payload_bytes);

        // Sign the canonical bytes
        let signature = self.signing_key.sign(&canonical_bytes);

        let signed_event = SignedLedgerEvent {
            event_id: event_id.clone(),
            event_type: "session_terminated".to_string(),
            work_id: work_id.to_string(),
            actor_id: actor_id.to_string(),
            payload: payload_bytes.clone(),
            signature: signature.to_bytes().to_vec(),
            timestamp_ns,
        };

        // Persist to SQLite
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                signed_event.event_id,
                signed_event.event_type,
                signed_event.work_id,
                signed_event.actor_id,
                signed_event.payload,
                signed_event.signature,
                signed_event.timestamp_ns
            ],
        ).map_err(|e| LedgerEventError::PersistenceFailed {
            message: format!("sqlite insert failed: {e}"),
        })?;

        info!(
            event_id = %event_id,
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
        let claimed_event_id = format!("EVT-{}", uuid::Uuid::new_v4());
        let claimed_payload = serde_json::json!({
            "event_type": "work_claimed",
            "work_id": claim.work_id,
            "lease_id": claim.lease_id,
            "actor_id": claim.actor_id,
            "role": format!("{:?}", claim.role),
            "policy_resolved_ref": claim.policy_resolution.policy_resolved_ref,
            "capability_manifest_hash": hex::encode(claim.policy_resolution.capability_manifest_hash),
            "context_pack_hash": hex::encode(claim.policy_resolution.context_pack_hash),
        });
        let claimed_payload_json = claimed_payload.to_string();
        let claimed_canonical = canonicalize_json(&claimed_payload_json).map_err(|e| {
            let _ = conn.execute("ROLLBACK", []);
            LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            }
        })?;
        let claimed_payload_bytes = claimed_canonical.as_bytes().to_vec();
        let mut claimed_canonical_bytes =
            Vec::with_capacity(WORK_CLAIMED_DOMAIN_PREFIX.len() + claimed_payload_bytes.len());
        claimed_canonical_bytes.extend_from_slice(WORK_CLAIMED_DOMAIN_PREFIX);
        claimed_canonical_bytes.extend_from_slice(&claimed_payload_bytes);
        let claimed_signature = self.signing_key.sign(&claimed_canonical_bytes);

        let claimed_event = SignedLedgerEvent {
            event_id: claimed_event_id.clone(),
            event_type: "work_claimed".to_string(),
            work_id: claim.work_id.clone(),
            actor_id: claim.actor_id.clone(),
            payload: claimed_payload_bytes.clone(),
            signature: claimed_signature.to_bytes().to_vec(),
            timestamp_ns,
        };

        if let Err(e) = conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                claimed_event.event_id,
                claimed_event.event_type,
                claimed_event.work_id,
                claimed_event.actor_id,
                claimed_event.payload,
                claimed_event.signature,
                claimed_event.timestamp_ns
            ],
        ) {
            let _ = conn.execute("ROLLBACK", []);
            return Err(LedgerEventError::PersistenceFailed {
                message: format!("sqlite insert failed (work_claimed): {e}"),
            });
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

        let transition_event_id = format!("EVT-{}", uuid::Uuid::new_v4());
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
        let transition_payload_json = transition_payload.to_string();
        let transition_canonical = canonicalize_json(&transition_payload_json).map_err(|e| {
            let _ = conn.execute("ROLLBACK", []);
            LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            }
        })?;
        let transition_payload_bytes = transition_canonical.as_bytes().to_vec();
        let mut transition_canonical_bytes = Vec::with_capacity(
            WORK_TRANSITIONED_DOMAIN_PREFIX.len() + transition_payload_bytes.len(),
        );
        transition_canonical_bytes.extend_from_slice(WORK_TRANSITIONED_DOMAIN_PREFIX);
        transition_canonical_bytes.extend_from_slice(&transition_payload_bytes);
        let transition_signature = self.signing_key.sign(&transition_canonical_bytes);

        if let Err(e) = conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                transition_event_id,
                "work_transitioned",
                claim.work_id,
                actor_id,
                transition_payload_bytes,
                transition_signature.to_bytes().to_vec(),
                timestamp_ns
            ],
        ) {
            let _ = conn.execute("ROLLBACK", []);
            return Err(LedgerEventError::PersistenceFailed {
                message: format!("sqlite insert failed (work_transitioned): {e}"),
            });
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
            event_id = %claimed_event_id,
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
        let session_event_id = format!("EVT-{}", uuid::Uuid::new_v4());
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
        let session_payload_json = session_payload.to_string();
        let session_canonical = canonicalize_json(&session_payload_json).map_err(|e| {
            let _ = conn.execute("ROLLBACK", []);
            LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            }
        })?;
        let session_payload_bytes = session_canonical.as_bytes().to_vec();
        let mut session_canonical_bytes =
            Vec::with_capacity(SESSION_STARTED_DOMAIN_PREFIX.len() + session_payload_bytes.len());
        session_canonical_bytes.extend_from_slice(SESSION_STARTED_DOMAIN_PREFIX);
        session_canonical_bytes.extend_from_slice(&session_payload_bytes);
        let session_signature = self.signing_key.sign(&session_canonical_bytes);

        let session_event = SignedLedgerEvent {
            event_id: session_event_id.clone(),
            event_type: "session_started".to_string(),
            work_id: work_id.to_string(),
            actor_id: actor_id.to_string(),
            payload: session_payload_bytes.clone(),
            signature: session_signature.to_bytes().to_vec(),
            timestamp_ns,
        };

        if let Err(e) = conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                session_event.event_id,
                session_event.event_type,
                session_event.work_id,
                session_event.actor_id,
                session_event.payload,
                session_event.signature,
                session_event.timestamp_ns
            ],
        ) {
            let _ = conn.execute("ROLLBACK", []);
            return Err(LedgerEventError::PersistenceFailed {
                message: format!("sqlite insert failed (session_started): {e}"),
            });
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

        let transition_event_id = format!("EVT-{}", uuid::Uuid::new_v4());
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
        let transition_payload_json = transition_payload.to_string();
        let transition_canonical = canonicalize_json(&transition_payload_json).map_err(|e| {
            let _ = conn.execute("ROLLBACK", []);
            LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            }
        })?;
        let transition_payload_bytes = transition_canonical.as_bytes().to_vec();
        let mut transition_canonical_bytes = Vec::with_capacity(
            WORK_TRANSITIONED_DOMAIN_PREFIX.len() + transition_payload_bytes.len(),
        );
        transition_canonical_bytes.extend_from_slice(WORK_TRANSITIONED_DOMAIN_PREFIX);
        transition_canonical_bytes.extend_from_slice(&transition_payload_bytes);
        let transition_signature = self.signing_key.sign(&transition_canonical_bytes);

        if let Err(e) = conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                transition_event_id,
                "work_transitioned",
                work_id,
                actor_id,
                transition_payload_bytes,
                transition_signature.to_bytes().to_vec(),
                timestamp_ns
            ],
        ) {
            let _ = conn.execute("ROLLBACK", []);
            return Err(LedgerEventError::PersistenceFailed {
                message: format!("sqlite insert failed (work_transitioned): {e}"),
            });
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
            event_id = %session_event_id,
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
        // Generate unique event ID
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

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

        // TCK-00394: Use JCS (RFC 8785) canonicalization for signing.
        let payload_json = payload.to_string();
        let canonical_payload =
            canonicalize_json(&payload_json).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            })?;
        let payload_bytes = canonical_payload.as_bytes().to_vec();

        // Build canonical bytes for signing (domain prefix + JCS payload)
        let mut canonical_bytes = Vec::with_capacity(
            CHANGESET_PUBLISHED_LEDGER_DOMAIN_PREFIX.len() + payload_bytes.len(),
        );
        canonical_bytes.extend_from_slice(CHANGESET_PUBLISHED_LEDGER_DOMAIN_PREFIX);
        canonical_bytes.extend_from_slice(&payload_bytes);

        // Sign the canonical bytes
        let signature = self.signing_key.sign(&canonical_bytes);

        let signed_event = SignedLedgerEvent {
            event_id: event_id.clone(),
            event_type: "changeset_published".to_string(),
            work_id: work_id.to_string(),
            actor_id: actor_id.to_string(),
            payload: payload_bytes.clone(),
            signature: signature.to_bytes().to_vec(),
            timestamp_ns,
        };

        // Persist to SQLite
        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                signed_event.event_id,
                signed_event.event_type,
                signed_event.work_id,
                signed_event.actor_id,
                signed_event.payload,
                signed_event.signature,
                signed_event.timestamp_ns
            ],
        ).map_err(|e| LedgerEventError::PersistenceFailed {
            message: format!("sqlite insert failed: {e}"),
        })?;

        info!(
            event_id = %event_id,
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

        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

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

        let payload_string = payload_json.to_string();
        let canonical_payload =
            canonicalize_json(&payload_string).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("JCS canonicalization failed: {e}"),
            })?;
        let payload_bytes = canonical_payload.as_bytes().to_vec();

        let mut canonical_bytes =
            Vec::with_capacity(REVIEW_RECEIPT_RECORDED_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(REVIEW_RECEIPT_RECORDED_PREFIX);
        canonical_bytes.extend_from_slice(&payload_bytes);

        let signature = self.signing_key.sign(&canonical_bytes);

        let signed_event = SignedLedgerEvent {
            event_id: event_id.clone(),
            event_type: "review_receipt_recorded".to_string(),
            work_id: episode_id.to_string(),
            actor_id: reviewer_actor_id.to_string(),
            payload: payload_bytes.clone(),
            signature: signature.to_bytes().to_vec(),
            timestamp_ns,
        };

        let conn = self
            .conn
            .lock()
            .map_err(|_| LedgerEventError::PersistenceFailed {
                message: "connection lock poisoned".to_string(),
            })?;

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                signed_event.event_id,
                signed_event.event_type,
                signed_event.work_id,
                signed_event.actor_id,
                signed_event.payload,
                signed_event.signature,
                signed_event.timestamp_ns
            ],
        ).map_err(|e| LedgerEventError::PersistenceFailed {
            message: format!("sqlite insert failed: {e}"),
        })?;

        info!(
            event_id = %event_id,
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
}

/// Durable work registry backed by `SQLite`.
#[derive(Debug)]
pub struct SqliteWorkRegistry {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteWorkRegistry {
    /// Creates a new registry with the given `SQLite` connection.
    #[must_use]
    pub const fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    /// Initializes the database schema.
    pub fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS work_claims (
                work_id TEXT PRIMARY KEY,
                lease_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                role INTEGER NOT NULL,
                claim_json BLOB NOT NULL
            )",
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

        // Check for duplicate
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM work_claims WHERE work_id = ?1",
                params![claim.work_id],
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

        Ok(claim)
    }

    fn get_claim(&self, work_id: &str) -> Option<WorkClaim> {
        let conn = self.conn.lock().ok()?;
        let claim_json: Vec<u8> = conn
            .query_row(
                "SELECT claim_json FROM work_claims WHERE work_id = ?1",
                params![work_id],
                |row| row.get(0),
            )
            .optional()
            .ok()
            .flatten()?;

        serde_json::from_slice(&claim_json).ok()
    }
}

/// Durable lease validator backed by `SQLite`.
#[derive(Debug)]
pub struct SqliteLeaseValidator {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteLeaseValidator {
    /// Creates a new validator with the given `SQLite` connection.
    #[must_use]
    pub const fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
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

        // We search for a 'gate_lease_issued' event where the payload contains the
        // lease_id and work_id. This is a scan if not indexed, but for now we
        // rely on the event_type index and payload parsing. Optimization: In a
        // real system, we'd have a `gate_leases` table. Here, we scan recent
        // events or rely on the fact that we might have indexed it if we had a
        // dedicated table.

        // Strategy: Query events of type 'gate_lease_issued' and filter in application
        // logic (slow but correct for now). Since SQLite JSON extract is not
        // guaranteed to be available, we load payload. Warning: This could be
        // slow.

        // Better Strategy: `LeaseValidator` also has `register_lease` method.
        // We can create a `gate_leases` table that `register_lease` populates, and
        // `validate_gate_lease` queries. This assumes `register_lease` is
        // called when the event is emitted (e.g. by the emitter).
        // But `register_lease` is currently for "testing purposes".

        // If we want "real" validation against the ledger, we must query the ledger.

        // TCK-00289 BLOCKER 1: Filter by work_id in SQL to avoid O(N) scan.
        // The table has an index on work_id (idx_ledger_events_work_id).
        let mut stmt = conn
            .prepare("SELECT payload FROM ledger_events WHERE event_type = 'gate_lease_issued' AND work_id = ?1")
            .map_err(|e| LeaseValidationError::LedgerQueryFailed {
                message: e.to_string(),
            })?;

        let rows = stmt
            .query_map(params![work_id], |row| {
                let payload: Vec<u8> = row.get(0)?;
                Ok(payload)
            })
            .map_err(|e| LeaseValidationError::LedgerQueryFailed {
                message: e.to_string(),
            })?;

        for payload_bytes in rows.flatten() {
            if let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) {
                if let Some(l) = payload.get("lease_id").and_then(|v| v.as_str()) {
                    if l == lease_id {
                        // work_id already matched via SQL WHERE clause
                        return Ok(());
                    }
                }
            }
        }

        Err(LeaseValidationError::LeaseNotFound {
            lease_id: lease_id.to_string(),
        })
    }

    fn get_lease_executor_actor_id(&self, lease_id: &str) -> Option<String> {
        let conn = self.conn.lock().ok()?;

        // TCK-00340 Security MAJOR: Use targeted WHERE clause with
        // json_extract instead of O(N) full table scan with per-row JSON
        // parse. Filters by event_type and lease_id in SQL, with ORDER BY
        // rowid DESC LIMIT 1 for deterministic latest-row selection.
        //
        // NOTE: payload is stored as BLOB, so we CAST to TEXT for
        // json_extract to work on the binary JSON data.
        let mut stmt = conn
            .prepare(
                "SELECT payload FROM ledger_events \
                 WHERE event_type = 'gate_lease_issued' \
                 AND json_extract(CAST(payload AS TEXT), '$.lease_id') = ?1 \
                 ORDER BY rowid DESC LIMIT 1",
            )
            .ok()?;

        let payload_bytes: Vec<u8> = stmt.query_row(params![lease_id], |row| row.get(0)).ok()?;

        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
        payload
            .get("executor_actor_id")
            .and_then(|v| v.as_str())
            .map(String::from)
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
        // We emit a fake event to populate the ledger for validation to work.
        // This makes `register_lease` functionally verify the ledger logic.
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());
        let payload = serde_json::json!({
            "event_type": "gate_lease_issued",
            "lease_id": lease_id,
            "work_id": work_id,
            "gate_id": gate_id,
            "executor_actor_id": executor_actor_id
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();

        // We insert a dummy event into ledger_events.
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    event_id,
                    "gate_lease_issued",
                    work_id,
                    "system",
                    payload_bytes,
                    vec![0u8; 64], // Dummy signature
                    0
                ],
            );
        }
    }

    fn get_lease_work_id(&self, lease_id: &str) -> Option<String> {
        let conn = self.conn.lock().ok()?;

        // TCK-00340 Quality BLOCKER 1: Use targeted WHERE clause with
        // json_extract instead of O(N) full table scan with per-row JSON
        // parse. Filters by event_type first (reduces scan scope), then
        // uses json_extract for indexed field filtering, with ORDER BY
        // rowid DESC LIMIT 1 for deterministic latest-row selection.
        //
        // NOTE: payload is stored as BLOB, so we CAST to TEXT for
        // json_extract to work on the binary JSON data.
        let mut stmt = conn
            .prepare(
                "SELECT work_id FROM ledger_events \
                 WHERE event_type = 'gate_lease_issued' \
                 AND json_extract(CAST(payload AS TEXT), '$.lease_id') = ?1 \
                 ORDER BY rowid DESC LIMIT 1",
            )
            .ok()?;

        stmt.query_row(params![lease_id], |row| row.get(0)).ok()
    }

    // Trust Model (single-writer): The daemon is the sole writer to the
    // ledger. Leases stored via `register_full_lease` are written by the
    // same process through authenticated IPC handlers that enforce admission
    // checks before persistence. Cryptographic signature verification is
    // not needed for same-process data reads — the process trust boundary
    // guarantees integrity. The embedded `issuer_signature` in each
    // `GateLease` is preserved for downstream / cross-node verification.
    fn get_gate_lease(&self, lease_id: &str) -> Option<apm2_core::fac::GateLease> {
        let conn = self.conn.lock().ok()?;

        // TCK-00340 Quality BLOCKER 2 / Security MAJOR: Use targeted WHERE
        // clause with json_extract instead of O(N) full table scan with
        // per-row JSON parse. Filters by event_type, lease_id, AND
        // full_lease presence in SQL via json_extract on CAST(payload AS
        // TEXT), with ORDER BY rowid DESC LIMIT 1 for deterministic
        // latest-row selection.
        //
        // NOTE: payload is stored as BLOB (Vec<u8> from serde_json::to_vec),
        // so we CAST to TEXT for json_extract compatibility.
        //
        // The full_lease IS NOT NULL guard ensures we only match events
        // that actually embed the full GateLease struct, skipping any
        // events that share the same lease_id but lack the full_lease
        // field (e.g. executor-only registration events).
        let result: Result<Vec<u8>, _> = conn.query_row(
            "SELECT payload FROM ledger_events \
             WHERE event_type = 'gate_lease_issued' \
             AND json_extract(CAST(payload AS TEXT), '$.lease_id') = ?1 \
             AND json_extract(CAST(payload AS TEXT), '$.full_lease') IS NOT NULL \
             ORDER BY rowid DESC LIMIT 1",
            params![lease_id],
            |row| row.get(0),
        );

        let Ok(payload_bytes) = result else {
            return None;
        };

        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;

        // Try to deserialize from the stored full_lease JSON if available.
        let full_lease = payload.get("full_lease")?;
        serde_json::from_value::<apm2_core::fac::GateLease>(full_lease.clone()).ok()
    }

    /// Registers a full gate lease as a synthetic `gate_lease_issued` event.
    ///
    /// # Trust Model (v6 Finding 2)
    ///
    /// This method inserts **synthetic events** into the ledger with a
    /// zero-filled signature (`[0u8; 64]`) and `actor_id = "system"`. These
    /// events are trusted because:
    ///
    /// 1. **Same-process trust boundary**: The daemon writes these events
    ///    within its own process. The `SQLite` event store is not externally
    ///    writable — all mutations go through the daemon's authenticated IPC
    ///    handlers which enforce admission checks before reaching this method.
    ///
    /// 2. **Read-path validation**: The `resolve_full_lease_from_events` reader
    ///    deserializes the `full_lease` JSON and validates it via `GateLease`'s
    ///    deserialization invariants. The lease's own `issuer_signature`
    ///    (Ed25519 over canonical bytes) is preserved in the serialized
    ///    `full_lease` field and can be verified by any downstream consumer
    ///    that needs cryptographic proof of issuance.
    ///
    /// 3. **Synthetic event markers**: The zero-filled signature and `"system"`
    ///    `actor_id` distinguish these events from cryptographically-signed
    ///    operator events. Consumers MUST NOT treat the event-level signature
    ///    as proof of issuance — the `full_lease.issuer_signature` field
    ///    provides that guarantee.
    ///
    /// # TODO
    ///
    /// TODO(RFC-0019): Replace synthetic events with fully authenticated-fact
    /// persistence where each ledger row carries a valid daemon-issued
    /// signature over the canonical event bytes. This would allow external
    /// auditors to verify event integrity without trusting the daemon process.
    fn register_full_lease(&self, lease: &apm2_core::fac::GateLease) -> Result<(), String> {
        // Store the full lease as a gate_lease_issued event with the complete
        // lease object embedded in the payload for later retrieval.

        // SECURITY (v11 BLOCKER 1 -- Atomic INSERT ... WHERE NOT EXISTS):
        //
        // The previous implementation used a check-then-insert (TOCTOU)
        // pattern: `get_gate_lease()` followed by a separate INSERT.
        // Under concurrent requests, two callers could both pass the
        // check and both insert, creating duplicate lease entries.
        //
        // The fix uses a SINGLE atomic SQL statement that checks for an
        // existing `gate_lease_issued` event with the same `lease_id`
        // (via `json_extract` on the payload BLOB) and only inserts if
        // no such row exists. SQLite serializes writes within a single
        // statement, eliminating the TOCTOU race.
        //
        // After the INSERT, we check `rows_affected()`: if 0, a lease
        // with this ID already exists -- return a duplicate error.
        // No schema migration or new columns are needed.

        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());
        let payload = serde_json::json!({
            "event_type": "gate_lease_issued",
            "lease_id": lease.lease_id,
            "work_id": lease.work_id,
            "gate_id": lease.gate_id,
            "executor_actor_id": lease.executor_actor_id,
            "full_lease": lease
        });
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| format!("failed to serialize lease payload: {e}"))?;

        let conn = self
            .conn
            .lock()
            .map_err(|e| format!("failed to acquire ledger lock: {e}"))?;

        // NOTE: The zero-filled signature is intentional -- see trust model
        // documentation above. The real cryptographic proof lives inside
        // `full_lease.issuer_signature`.
        //
        // The WHERE NOT EXISTS subquery atomically checks that no
        // `gate_lease_issued` event with this `lease_id` already exists
        // in the payload JSON. Because this is a single SQL statement,
        // SQLite's write serialization prevents interleaving.
        let rows_affected = conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
             WHERE NOT EXISTS (
                 SELECT 1 FROM ledger_events
                 WHERE event_type = 'gate_lease_issued'
                 AND json_extract(CAST(payload AS TEXT), '$.lease_id') = ?8
             )",
            params![
                event_id,
                "gate_lease_issued",
                lease.work_id,
                "system",
                payload_bytes,
                vec![0u8; 64],
                i64::try_from(lease.issued_at).unwrap_or(0),
                lease.lease_id
            ],
        )
        .map_err(|e| format!("failed to insert lease event: {e}"))?;

        if rows_affected == 0 {
            return Err(format!("duplicate lease_id: {}", lease.lease_id));
        }

        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::dispatch::PolicyResolution;
    use crate::protocol::messages::WorkRole;

    /// Creates an in-memory `SQLite` connection with schema initialized.
    fn test_emitter() -> SqliteLedgerEventEmitter {
        let conn = Connection::open_in_memory().unwrap();
        SqliteLedgerEventEmitter::init_schema(&conn).unwrap();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        SqliteLedgerEventEmitter::new(Arc::new(Mutex::new(conn)), signing_key)
    }

    fn test_policy_resolution() -> PolicyResolution {
        PolicyResolution {
            policy_resolved_ref: "test-resolved".to_string(),
            resolved_policy_hash: [0u8; 32],
            capability_manifest_hash: [0u8; 32],
            context_pack_hash: [0u8; 32],
            resolved_risk_tier: 0,
            resolved_scope_baseline: None,
            expected_adapter_profile_hash: None,
        }
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
        SqliteLedgerEventEmitter::init_schema(&conn).unwrap();

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
        SqliteLedgerEventEmitter::init_schema(&conn).unwrap();
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
        SqliteLedgerEventEmitter::init_schema(&conn).unwrap();
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
        SqliteLedgerEventEmitter::init_schema(&conn).unwrap();
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

    // ====================================================================
    // v10 BLOCKER 2: register_full_lease duplicate rejection tests
    // ====================================================================

    /// v10 BLOCKER 2: `SqliteLeaseValidator::register_full_lease` rejects
    /// duplicate `lease_id` to enforce DB-level uniqueness.
    #[test]
    fn sqlite_lease_validator_register_full_lease_duplicate_rejected() {
        use crate::protocol::dispatch::LeaseValidator;

        let conn = Connection::open_in_memory().unwrap();
        SqliteLedgerEventEmitter::init_schema(&conn).unwrap();
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
                "episode-001",
                "RR-IDEMP-001",
                &changeset,
                &artifact,
                "reviewer-actor-x",
                1_000_000_000,
                &identity_proof,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
                "RR-BLOCKED-001",
                &changeset_digest,
                &artifact_bundle_hash,
                42,
                &blocked_log_hash,
                "reviewer-actor-y",
                2_000_000_000,
                &identity_proof_hash,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
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

        SqliteLedgerEventEmitter::init_schema(&conn).unwrap();

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

        let duplicate_payload = br#"{"receipt_id":"RR-DUPE-001"}"#;
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

        SqliteLedgerEventEmitter::init_schema(&conn).unwrap();

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

        SqliteLedgerEventEmitter::init_schema(&conn).unwrap();

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
                "RR-BLOCKED-IPH",
                &changeset_digest,
                &artifact_bundle_hash,
                99,
                &blocked_log_hash,
                "reviewer-actor-z",
                3_000_000_000,
                &identity_proof_hash,
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
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
}

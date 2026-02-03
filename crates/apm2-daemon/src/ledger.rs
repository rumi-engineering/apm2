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

use ed25519_dalek::Signer;
use rusqlite::{Connection, OptionalExtension, params};
use tracing::info;

use crate::protocol::dispatch::{
    LeaseValidationError, LeaseValidator, LedgerEventEmitter, LedgerEventError, SignedLedgerEvent,
    WORK_CLAIMED_DOMAIN_PREFIX, WorkClaim, WorkRegistry, WorkRegistryError,
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
        Ok(())
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

        // Build canonical payload (deterministic JSON)
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

        let payload_bytes =
            serde_json::to_vec(&payload).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("payload serialization failed: {e}"),
            })?;

        // Build canonical bytes for signing (domain prefix + payload)
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

    fn get_events_by_work_id(&self, work_id: &str) -> Vec<SignedLedgerEvent> {
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };

        let Ok(mut stmt) = conn.prepare(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
             FROM ledger_events WHERE work_id = ?1 ORDER BY timestamp_ns ASC",
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

        let mut stmt = conn
            .prepare("SELECT payload FROM ledger_events WHERE event_type = 'gate_lease_issued'")
            .map_err(|e| LeaseValidationError::LedgerQueryFailed {
                message: e.to_string(),
            })?;

        let rows = stmt
            .query_map([], |row| {
                let payload: Vec<u8> = row.get(0)?;
                Ok(payload)
            })
            .map_err(|e| LeaseValidationError::LedgerQueryFailed {
                message: e.to_string(),
            })?;

        for payload_bytes in rows.flatten() {
            if let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) {
                if let (Some(l), Some(w)) = (
                    payload.get("lease_id").and_then(|v| v.as_str()),
                    payload.get("work_id").and_then(|v| v.as_str()),
                ) {
                    if l == lease_id {
                        if w == work_id {
                            return Ok(());
                        }
                        return Err(LeaseValidationError::WorkIdMismatch {
                            actual: work_id.to_string(),
                        });
                    }
                }
            }
        }

        Err(LeaseValidationError::LeaseNotFound {
            lease_id: lease_id.to_string(),
        })
    }

    fn register_lease(&self, lease_id: &str, work_id: &str, gate_id: &str) {
        // We emit a fake event to populate the ledger for validation to work.
        // This makes `register_lease` functionally verify the ledger logic.
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());
        let payload = serde_json::json!({
            "event_type": "gate_lease_issued",
            "lease_id": lease_id,
            "work_id": work_id,
            "gate_id": gate_id
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
}

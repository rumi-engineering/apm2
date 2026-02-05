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
use ed25519_dalek::Signer;
use rusqlite::{Connection, OptionalExtension, params};
use tracing::info;

use crate::protocol::dispatch::{
    DEFECT_RECORDED_DOMAIN_PREFIX, LeaseValidationError, LeaseValidator, LedgerEventEmitter,
    LedgerEventError, SignedLedgerEvent, WORK_CLAIMED_DOMAIN_PREFIX, WorkClaim, WorkRegistry,
    WorkRegistryError,
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
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        // Domain prefix for session events (must be at function start per clippy)
        const SESSION_STARTED_DOMAIN_PREFIX: &[u8] = b"apm2.event.session_started:";

        // Generate unique event ID
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

        // Build payload as JSON
        let payload = serde_json::json!({
            "event_type": "session_started",
            "session_id": session_id,
            "work_id": work_id,
            "lease_id": lease_id,
            "actor_id": actor_id,
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

    fn emit_episode_event(
        &self,
        episode_id: &str,
        event_type: &str,
        payload: &[u8],
        timestamp_ns: u64,
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        // Domain prefix for episode events (TCK-00321)
        const EPISODE_EVENT_DOMAIN_PREFIX: &[u8] = b"apm2.event.episode:";

        // Generate unique event ID
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

        // Build payload as JSON with episode event metadata
        // SECURITY: timestamp_ns is included in signed payload to prevent temporal malleability
        // per LAW-09 (Temporal Pinning & Freshness) and RS-40 (Time & Monotonicity)
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
    ) -> Result<SignedLedgerEvent, LedgerEventError> {
        // Domain prefix for review receipt events (TCK-00321)
        const REVIEW_RECEIPT_DOMAIN_PREFIX: &[u8] = b"apm2.event.review_receipt:";

        // Generate unique event ID
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

        // Build payload as JSON with review receipt data
        // SECURITY: timestamp_ns is included in signed payload to prevent temporal malleability
        // per LAW-09 (Temporal Pinning & Freshness) and RS-40 (Time & Monotonicity)
        let payload_json = serde_json::json!({
            "event_type": "review_receipt_recorded",
            "episode_id": episode_id,
            "receipt_id": receipt_id,
            "changeset_digest": hex::encode(changeset_digest),
            "artifact_bundle_hash": hex::encode(artifact_bundle_hash),
            "reviewer_actor_id": reviewer_actor_id,
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
            Vec::with_capacity(REVIEW_RECEIPT_DOMAIN_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(REVIEW_RECEIPT_DOMAIN_PREFIX);
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
            "Persisted ReviewReceiptRecorded event"
        );

        Ok(signed_event)
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

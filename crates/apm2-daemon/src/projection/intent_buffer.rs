// AGENT-AUTHORED (TCK-00504)
//! Projection intent schema and durable buffer for economics-gated admission.
//!
//! This module implements the [`IntentBuffer`] — a SQLite-backed durable buffer
//! for projection intents that supports economics-gated admission decisions.
//!
//! # Tables
//!
//! - **`projection_intents`**: Records each projection intent with its
//!   admission verdict (pending/admitted/denied), evaluation tick, and deny
//!   reason.
//! - **`deferred_replay_backlog`**: Bounded queue of deferred replay work items
//!   awaiting convergence after sink recovery, hard-capped at
//!   [`MAX_BACKLOG_ITEMS`].
//!
//! # Security Model
//!
//! - **Fail-closed eviction**: When the deferred replay backlog reaches
//!   capacity, the oldest entries are evicted and recorded as denied with an
//!   eviction reason. No intent is ever silently dropped.
//! - **Idempotent insert**: Duplicate `(work_id, changeset_digest)` pairs are
//!   handled via `INSERT OR IGNORE` — the existing row is preserved.
//! - **Bounded backlog**: [`MAX_BACKLOG_ITEMS`] (65536) prevents unbounded
//!   growth.
//! - **Deterministic ordering**: All queries use `ORDER BY rowid` for
//!   deterministic row selection.
//!
//! # Concurrency
//!
//! The [`IntentBuffer`] API is **synchronous** and performs blocking `SQLite`
//! I/O. Since `apm2-daemon` is an async application, callers **must not**
//! invoke these methods directly on a tokio worker thread. Instead, wrap calls
//! in [`tokio::task::spawn_blocking`] (or an equivalent offloading mechanism)
//! to avoid stalling the async executor.
//!
//! # Migration Safety
//!
//! The schema uses `CREATE TABLE IF NOT EXISTS` and does **not** alter existing
//! `projection_receipts` or `comment_receipts` tables. Backwards-compatible by
//! construction.

use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

// =============================================================================
// Constants
// =============================================================================

/// Hard cap on deferred replay backlog items.
///
/// When this limit is reached, the oldest entries are evicted with a deny
/// receipt. This prevents unbounded memory/disk growth from sink outages.
pub const MAX_BACKLOG_ITEMS: usize = 65_536;

/// Maximum length for string fields to prevent denial-of-service via oversized
/// input. Matches the module-wide convention.
const MAX_FIELD_LENGTH: usize = 1024;

// =============================================================================
// Error Types
// =============================================================================

/// Errors from [`IntentBuffer`] operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IntentBufferError {
    /// Database operation failed.
    #[error("database error: {0}")]
    Database(String),

    /// Mutex was poisoned.
    #[error("mutex poisoned: {0}")]
    MutexPoisoned(String),

    /// A required field exceeds the maximum allowed length.
    #[error("field {field} exceeds max length: {actual} > {max}")]
    FieldTooLong {
        /// Name of the field that exceeded the limit.
        field: &'static str,
        /// Actual length of the string.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// A required field is missing or empty.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Backlog capacity exhausted — eviction was performed.
    ///
    /// This is an informational error returned when an insert into
    /// `deferred_replay_backlog` triggered eviction of older entries.
    /// The new entry **was** inserted; this signals to the caller that
    /// eviction occurred and deny receipts should be emitted.
    #[error("backlog capacity exhausted: evicted {evicted_count} entries")]
    BacklogEviction {
        /// Number of entries evicted.
        evicted_count: usize,
        /// Intent IDs of evicted entries.
        evicted_intent_ids: Vec<String>,
    },
}

// =============================================================================
// Intent Verdict
// =============================================================================

/// Admission verdict for a projection intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentVerdict {
    /// Intent is pending evaluation.
    Pending,
    /// Intent was admitted for projection.
    Admitted,
    /// Intent was denied (with reason stored separately).
    Denied,
}

impl IntentVerdict {
    /// Returns the canonical string representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Admitted => "admitted",
            Self::Denied => "denied",
        }
    }

    /// Parses from canonical string. Returns `None` for unrecognized values
    /// (fail-closed: unknown verdict is not silently accepted).
    #[must_use]
    pub fn from_str_checked(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "admitted" => Some(Self::Admitted),
            "denied" => Some(Self::Denied),
            _ => None,
        }
    }
}

impl std::fmt::Display for IntentVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// ProjectionIntent
// =============================================================================

/// A projection intent record retrieved from the buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionIntent {
    /// Unique identifier for this intent (UUID).
    pub intent_id: String,
    /// Work item identifier.
    pub work_id: String,
    /// Changeset digest binding (32 bytes, hex-encoded in DB).
    pub changeset_digest: [u8; 32],
    /// Ledger head at time of intent creation (32 bytes).
    pub ledger_head: [u8; 32],
    /// Current projected status label.
    pub projected_status: String,
    /// Evaluation tick (monotonic, from HTF).
    pub eval_tick: u64,
    /// Admission verdict.
    pub verdict: IntentVerdict,
    /// Deny reason (empty string if not denied).
    pub deny_reason: String,
    /// Creation timestamp (nanoseconds since epoch, from HTF).
    pub created_at: u64,
    /// Admission timestamp (nanoseconds since epoch, 0 if not admitted).
    pub admitted_at: u64,
}

/// Lifecycle artifact references persisted on admitted projection intents.
///
/// These fields bind projection-side effects to the PCAC lifecycle tuple
/// evaluated immediately before effect execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntentLifecycleArtifacts {
    /// AJC identifier from the lifecycle gate output.
    pub ajc_id: [u8; 32],
    /// Intent digest consumed before projection effect execution.
    pub intent_digest: [u8; 32],
    /// Effect selector digest from the consume record.
    pub consume_selector_digest: [u8; 32],
    /// Tick at which consume succeeded.
    pub consume_tick: u64,
    /// HTF envelope reference at consume time.
    pub time_envelope_ref: [u8; 32],
}

// =============================================================================
// DeferredReplayEntry
// =============================================================================

/// A deferred replay backlog entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredReplayEntry {
    /// Intent ID linking to the `projection_intents` table.
    pub intent_id: String,
    /// Work item identifier.
    pub work_id: String,
    /// Backlog digest (32 bytes).
    pub backlog_digest: [u8; 32],
    /// Replay horizon tick (monotonic boundary for replay window).
    pub replay_horizon_tick: u64,
    /// Replay timestamp (nanoseconds since epoch, 0 if not yet replayed).
    pub replayed_at: u64,
    /// Whether replay has converged.
    pub converged: bool,
}

// =============================================================================
// Schema SQL
// =============================================================================

/// Schema SQL for intent buffer tables.
///
/// Uses `CREATE TABLE IF NOT EXISTS` to be backwards-compatible with existing
/// databases that already have `projection_receipts` and `comment_receipts`.
/// Those tables are **not** altered.
const INTENT_BUFFER_SCHEMA_SQL: &str = r"
    CREATE TABLE IF NOT EXISTS projection_intents (
        intent_id TEXT PRIMARY KEY,
        work_id TEXT NOT NULL,
        changeset_digest BLOB NOT NULL,
        ledger_head BLOB NOT NULL,
        projected_status TEXT NOT NULL,
        eval_tick INTEGER NOT NULL,
        verdict TEXT NOT NULL DEFAULT 'pending',
        deny_reason TEXT NOT NULL DEFAULT '',
        lifecycle_ajc_id BLOB NULL,
        lifecycle_intent_digest BLOB NULL,
        lifecycle_consume_selector_digest BLOB NULL,
        lifecycle_consume_tick INTEGER NULL,
        lifecycle_time_envelope_ref BLOB NULL,
        created_at INTEGER NOT NULL,
        admitted_at INTEGER NOT NULL DEFAULT 0,
        UNIQUE(work_id, changeset_digest)
    );

    CREATE INDEX IF NOT EXISTS idx_intents_work_id
        ON projection_intents(work_id);
    CREATE INDEX IF NOT EXISTS idx_intents_verdict
        ON projection_intents(verdict);
    CREATE INDEX IF NOT EXISTS idx_intents_eval_tick
        ON projection_intents(eval_tick);
    CREATE INDEX IF NOT EXISTS idx_intents_created_at
        ON projection_intents(created_at);

    CREATE TABLE IF NOT EXISTS deferred_replay_backlog (
        intent_id TEXT PRIMARY KEY,
        work_id TEXT NOT NULL,
        backlog_digest BLOB NOT NULL,
        replay_horizon_tick INTEGER NOT NULL,
        replayed_at INTEGER NOT NULL DEFAULT 0,
        converged INTEGER NOT NULL DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_backlog_work_id
        ON deferred_replay_backlog(work_id);
    CREATE INDEX IF NOT EXISTS idx_backlog_converged
        ON deferred_replay_backlog(converged);
    CREATE INDEX IF NOT EXISTS idx_backlog_replay_horizon
        ON deferred_replay_backlog(replay_horizon_tick);
";

// =============================================================================
// IntentBuffer
// =============================================================================

/// Durable buffer for projection intents and deferred replay backlog.
///
/// # Synchronization Protocol
///
/// The inner `Connection` is protected by `Arc<Mutex<Connection>>`. All
/// database operations acquire the mutex for the duration of their
/// transaction. The mutex is never held across async suspension points
/// (this struct has no async methods).
///
/// # Invariants
///
/// - [INV-IB01] `deferred_replay_backlog` never exceeds [`MAX_BACKLOG_ITEMS`].
///   When the cap is reached, oldest entries (by rowid) are evicted and
///   recorded as denied.
/// - [INV-IB02] Duplicate `(work_id, changeset_digest)` inserts into
///   `projection_intents` are idempotent — the existing row is preserved.
/// - [INV-IB03] Evicted backlog entries are returned to the caller for deny
///   receipt emission; they are never silently dropped.
/// - [INV-IB04] All queries use `ORDER BY rowid` for deterministic ordering.
pub struct IntentBuffer {
    /// `SQLite` connection, protected by mutex.
    /// Synchronization protocol: acquire lock, execute SQL, release lock.
    /// No lock held across method boundaries.
    conn: Arc<Mutex<Connection>>,
}

impl IntentBuffer {
    /// Creates a new `IntentBuffer` with the given `SQLite` connection.
    ///
    /// Initializes the schema (migration-safe: uses `IF NOT EXISTS`).
    ///
    /// # Errors
    ///
    /// Returns [`IntentBufferError::Database`] if schema initialization fails.
    /// Returns [`IntentBufferError::MutexPoisoned`] if the mutex is poisoned.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Result<Self, IntentBufferError> {
        {
            let guard = conn
                .lock()
                .map_err(|e| IntentBufferError::MutexPoisoned(format!("{e}")))?;
            guard
                .execute_batch(INTENT_BUFFER_SCHEMA_SQL)
                .map_err(|e| IntentBufferError::Database(format!("schema init failed: {e}")))?;
            Self::ensure_projection_intent_lifecycle_columns(&guard)?;
        }
        Ok(Self { conn })
    }

    /// Creates an in-memory `IntentBuffer` for testing.
    ///
    /// # Errors
    ///
    /// Returns [`IntentBufferError::Database`] if `SQLite` initialization
    /// fails.
    #[cfg(test)]
    pub fn in_memory() -> Result<Self, IntentBufferError> {
        let conn =
            Connection::open_in_memory().map_err(|e| IntentBufferError::Database(e.to_string()))?;
        let conn = Arc::new(Mutex::new(conn));
        Self::new(conn)
    }

    fn ensure_projection_intent_lifecycle_columns(
        conn: &Connection,
    ) -> Result<(), IntentBufferError> {
        const COLUMNS: [(&str, &str); 5] = [
            ("lifecycle_ajc_id", "BLOB NULL"),
            ("lifecycle_intent_digest", "BLOB NULL"),
            ("lifecycle_consume_selector_digest", "BLOB NULL"),
            ("lifecycle_consume_tick", "INTEGER NULL"),
            ("lifecycle_time_envelope_ref", "BLOB NULL"),
        ];

        for (column, definition) in COLUMNS {
            if !Self::projection_intent_column_exists(conn, column)? {
                let sql =
                    format!("ALTER TABLE projection_intents ADD COLUMN {column} {definition}");
                conn.execute(&sql, []).map_err(|e| {
                    IntentBufferError::Database(format!(
                        "failed to add projection_intents.{column}: {e}"
                    ))
                })?;
            }
        }

        Ok(())
    }

    fn projection_intent_column_exists(
        conn: &Connection,
        column: &str,
    ) -> Result<bool, IntentBufferError> {
        let mut stmt = conn
            .prepare("PRAGMA table_info(projection_intents)")
            .map_err(|e| IntentBufferError::Database(format!("table_info failed: {e}")))?;
        let mut rows = stmt
            .query([])
            .map_err(|e| IntentBufferError::Database(format!("table_info query failed: {e}")))?;

        while let Some(row) = rows
            .next()
            .map_err(|e| IntentBufferError::Database(format!("table_info row failed: {e}")))?
        {
            let name: String = row.get(1).map_err(|e| {
                IntentBufferError::Database(format!("table_info parse failed: {e}"))
            })?;
            if name == column {
                return Ok(true);
            }
        }

        Ok(false)
    }

    // =========================================================================
    // Insert
    // =========================================================================

    /// Inserts a new projection intent into the buffer.
    ///
    /// Idempotent: if `(work_id, changeset_digest)` already exists, the
    /// existing row is preserved and `Ok(false)` is returned.
    ///
    /// # Arguments
    ///
    /// * `intent_id` — Unique intent identifier (UUID).
    /// * `work_id` — Work item identifier.
    /// * `changeset_digest` — 32-byte changeset binding.
    /// * `ledger_head` — 32-byte ledger head at intent creation.
    /// * `projected_status` — Initial projected status label.
    /// * `eval_tick` — Evaluation tick from HTF.
    /// * `created_at` — Creation timestamp (nanoseconds, from HTF).
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if a new row was inserted.
    /// - `Ok(false)` if the row already existed (idempotent no-op).
    ///
    /// # Errors
    ///
    /// Returns [`IntentBufferError::FieldTooLong`] if string fields exceed
    /// bounds. Returns [`IntentBufferError::MissingField`] if required
    /// fields are empty.
    #[allow(clippy::too_many_arguments, clippy::cast_possible_wrap)]
    pub fn insert(
        &self,
        intent_id: &str,
        work_id: &str,
        changeset_digest: &[u8; 32],
        ledger_head: &[u8; 32],
        projected_status: &str,
        eval_tick: u64,
        created_at: u64,
    ) -> Result<bool, IntentBufferError> {
        // Validate inputs before acquiring lock
        validate_field("intent_id", intent_id)?;
        validate_field("work_id", work_id)?;
        validate_field("projected_status", projected_status)?;

        let guard = self.lock()?;
        let rows = guard
            .execute(
                "INSERT OR IGNORE INTO projection_intents
                 (intent_id, work_id, changeset_digest, ledger_head,
                  projected_status, eval_tick, verdict, deny_reason,
                  created_at, admitted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', '', ?7, 0)",
                params![
                    intent_id,
                    work_id,
                    changeset_digest.as_slice(),
                    ledger_head.as_slice(),
                    projected_status,
                    eval_tick as i64,
                    created_at as i64,
                ],
            )
            .map_err(|e| IntentBufferError::Database(format!("insert failed: {e}")))?;

        Ok(rows > 0)
    }

    // =========================================================================
    // Admit
    // =========================================================================

    /// Marks an intent as admitted.
    ///
    /// # Arguments
    ///
    /// * `intent_id` — The intent to admit.
    /// * `admitted_at` — Admission timestamp (nanoseconds, from HTF).
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the intent was found and updated.
    /// - `Ok(false)` if the intent was not found or already had a non-pending
    ///   verdict.
    ///
    /// # Errors
    ///
    /// Returns [`IntentBufferError::Database`] on SQL failure.
    #[allow(clippy::cast_possible_wrap)]
    pub fn admit(&self, intent_id: &str, admitted_at: u64) -> Result<bool, IntentBufferError> {
        validate_field("intent_id", intent_id)?;

        let guard = self.lock()?;
        // Only admit pending intents — check admission state BEFORE mutation.
        let rows = guard
            .execute(
                "UPDATE projection_intents
                 SET verdict = 'admitted', admitted_at = ?1
                 WHERE intent_id = ?2 AND verdict = 'pending'",
                params![admitted_at as i64, intent_id],
            )
            .map_err(|e| IntentBufferError::Database(format!("admit failed: {e}")))?;

        Ok(rows > 0)
    }

    /// Persists lifecycle artifact references on an existing intent.
    ///
    /// This is used by the projection worker to bind admitted intents to the
    /// lifecycle gate outputs evaluated immediately before effect execution.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the intent was found and updated.
    /// - `Ok(false)` if no intent row matched `intent_id`.
    ///
    /// # Errors
    ///
    /// Returns [`IntentBufferError::Database`] on SQL failure.
    #[allow(clippy::cast_possible_wrap)]
    pub fn attach_lifecycle_artifacts(
        &self,
        intent_id: &str,
        artifacts: &IntentLifecycleArtifacts,
    ) -> Result<bool, IntentBufferError> {
        validate_field("intent_id", intent_id)?;

        let guard = self.lock()?;
        let rows = guard
            .execute(
                "UPDATE projection_intents
                 SET lifecycle_ajc_id = ?1,
                     lifecycle_intent_digest = ?2,
                     lifecycle_consume_selector_digest = ?3,
                     lifecycle_consume_tick = ?4,
                     lifecycle_time_envelope_ref = ?5
                 WHERE intent_id = ?6",
                params![
                    artifacts.ajc_id.as_slice(),
                    artifacts.intent_digest.as_slice(),
                    artifacts.consume_selector_digest.as_slice(),
                    artifacts.consume_tick as i64,
                    artifacts.time_envelope_ref.as_slice(),
                    intent_id,
                ],
            )
            .map_err(|e| {
                IntentBufferError::Database(format!("attach_lifecycle_artifacts failed: {e}"))
            })?;

        Ok(rows > 0)
    }

    /// Retrieves lifecycle artifacts persisted on a pending intent.
    ///
    /// This is used during retry: if a previous attempt completed the
    /// lifecycle gate (`join -> revalidate -> consume`) and persisted
    /// artifacts but then failed during projection, the caller can
    /// retrieve the existing artifacts and skip the lifecycle gate on
    /// retry (avoiding `AlreadyConsumed` denial).
    ///
    /// # Returns
    ///
    /// - `Ok(Some(artifacts))` if the intent exists, is pending, and has all
    ///   five lifecycle columns non-NULL.
    /// - `Ok(None)` if the intent does not exist, is not pending, or has NULL
    ///   lifecycle columns.
    ///
    /// # Errors
    ///
    /// Returns [`IntentBufferError::Database`] on SQL failure.
    #[allow(clippy::cast_sign_loss)]
    pub fn get_lifecycle_artifacts(
        &self,
        intent_id: &str,
    ) -> Result<Option<IntentLifecycleArtifacts>, IntentBufferError> {
        validate_field("intent_id", intent_id)?;

        let guard = self.lock()?;
        let result = guard
            .query_row(
                "SELECT lifecycle_ajc_id,
                        lifecycle_intent_digest,
                        lifecycle_consume_selector_digest,
                        lifecycle_consume_tick,
                        lifecycle_time_envelope_ref
                 FROM projection_intents
                 WHERE intent_id = ?1
                   AND verdict = 'pending'
                   AND lifecycle_ajc_id IS NOT NULL
                   AND lifecycle_intent_digest IS NOT NULL
                   AND lifecycle_consume_selector_digest IS NOT NULL
                   AND lifecycle_consume_tick IS NOT NULL
                   AND lifecycle_time_envelope_ref IS NOT NULL",
                params![intent_id],
                |row| {
                    let ajc_blob: Vec<u8> = row.get(0)?;
                    let intent_blob: Vec<u8> = row.get(1)?;
                    let selector_blob: Vec<u8> = row.get(2)?;
                    let tick: i64 = row.get(3)?;
                    let envelope_blob: Vec<u8> = row.get(4)?;
                    Ok((ajc_blob, intent_blob, selector_blob, tick, envelope_blob))
                },
            )
            .optional()
            .map_err(|e| {
                IntentBufferError::Database(format!("get_lifecycle_artifacts failed: {e}"))
            })?;

        let Some((ajc_blob, intent_blob, selector_blob, tick, envelope_blob)) = result else {
            return Ok(None);
        };

        // Validate blob lengths — corrupt data must not produce zero-fills.
        let ajc_id: [u8; 32] = ajc_blob.as_slice().try_into().map_err(|_| {
            IntentBufferError::Database(format!(
                "lifecycle_ajc_id: expected 32 bytes, got {}",
                ajc_blob.len()
            ))
        })?;
        let intent_digest: [u8; 32] = intent_blob.as_slice().try_into().map_err(|_| {
            IntentBufferError::Database(format!(
                "lifecycle_intent_digest: expected 32 bytes, got {}",
                intent_blob.len()
            ))
        })?;
        let consume_selector_digest: [u8; 32] =
            selector_blob.as_slice().try_into().map_err(|_| {
                IntentBufferError::Database(format!(
                    "lifecycle_consume_selector_digest: expected 32 bytes, got {}",
                    selector_blob.len()
                ))
            })?;
        let time_envelope_ref: [u8; 32] = envelope_blob.as_slice().try_into().map_err(|_| {
            IntentBufferError::Database(format!(
                "lifecycle_time_envelope_ref: expected 32 bytes, got {}",
                envelope_blob.len()
            ))
        })?;

        Ok(Some(IntentLifecycleArtifacts {
            ajc_id,
            intent_digest,
            consume_selector_digest,
            consume_tick: tick as u64,
            time_envelope_ref,
        }))
    }

    // =========================================================================
    // Deny
    // =========================================================================

    /// Marks an intent as denied with a reason.
    ///
    /// # Arguments
    ///
    /// * `intent_id` — The intent to deny.
    /// * `reason` — Human/machine-readable deny reason.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the intent was found and updated.
    /// - `Ok(false)` if the intent was not found or already had a non-pending
    ///   verdict.
    ///
    /// # Errors
    ///
    /// Returns [`IntentBufferError::Database`] on SQL failure.
    pub fn deny(&self, intent_id: &str, reason: &str) -> Result<bool, IntentBufferError> {
        validate_field("intent_id", intent_id)?;
        validate_field("deny_reason", reason)?;

        let guard = self.lock()?;
        // Only deny pending intents — check admission state BEFORE mutation.
        let rows = guard
            .execute(
                "UPDATE projection_intents
                 SET verdict = 'denied', deny_reason = ?1
                 WHERE intent_id = ?2 AND verdict = 'pending'",
                params![reason, intent_id],
            )
            .map_err(|e| IntentBufferError::Database(format!("deny failed: {e}")))?;

        Ok(rows > 0)
    }

    // =========================================================================
    // Query
    // =========================================================================

    /// Retrieves a single intent by ID.
    ///
    /// # Errors
    ///
    /// Returns [`IntentBufferError::Database`] on SQL failure.
    pub fn get_intent(
        &self,
        intent_id: &str,
    ) -> Result<Option<ProjectionIntent>, IntentBufferError> {
        validate_field("intent_id", intent_id)?;
        let guard = self.lock()?;
        let result = guard
            .query_row(
                "SELECT intent_id, work_id, changeset_digest, ledger_head,
                        projected_status, eval_tick, verdict, deny_reason,
                        created_at, admitted_at
                 FROM projection_intents
                 WHERE intent_id = ?1",
                params![intent_id],
                row_to_intent,
            )
            .optional()
            .map_err(|e| IntentBufferError::Database(format!("get_intent failed: {e}")))?;

        Ok(result)
    }

    /// Queries intents by verdict, ordered by rowid (deterministic).
    ///
    /// Returns at most `limit` results.
    ///
    /// # Errors
    ///
    /// Returns [`IntentBufferError::Database`] on SQL failure.
    #[allow(clippy::cast_possible_wrap)]
    pub fn query_by_verdict(
        &self,
        verdict: IntentVerdict,
        limit: usize,
    ) -> Result<Vec<ProjectionIntent>, IntentBufferError> {
        let guard = self.lock()?;
        let mut stmt = guard
            .prepare(
                "SELECT intent_id, work_id, changeset_digest, ledger_head,
                        projected_status, eval_tick, verdict, deny_reason,
                        created_at, admitted_at
                 FROM projection_intents
                 WHERE verdict = ?1
                 ORDER BY rowid ASC
                 LIMIT ?2",
            )
            .map_err(|e| IntentBufferError::Database(format!("prepare failed: {e}")))?;

        let rows = stmt
            .query_map(params![verdict.as_str(), limit as i64], row_to_intent)
            .map_err(|e| IntentBufferError::Database(format!("query failed: {e}")))?;

        let mut results = Vec::new();
        for row in rows {
            let intent =
                row.map_err(|e| IntentBufferError::Database(format!("row parse failed: {e}")))?;
            results.push(intent);
        }

        Ok(results)
    }

    /// Returns the total count of intents.
    ///
    /// # Errors
    ///
    /// Returns [`IntentBufferError::Database`] on SQL failure.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    pub fn intent_count(&self) -> Result<usize, IntentBufferError> {
        let guard = self.lock()?;
        let count: i64 = guard
            .query_row("SELECT COUNT(*) FROM projection_intents", [], |row| {
                row.get(0)
            })
            .map_err(|e| IntentBufferError::Database(format!("count failed: {e}")))?;

        Ok(count as usize)
    }

    // =========================================================================
    // Deferred Replay Backlog
    // =========================================================================

    /// Inserts an entry into the deferred replay backlog.
    ///
    /// If the backlog is at [`MAX_BACKLOG_ITEMS`], the oldest entries are
    /// evicted first. Evicted entries are returned via
    /// [`IntentBufferError::BacklogEviction`] so the caller can emit deny
    /// receipts. The new entry **is** inserted even when eviction occurs.
    ///
    /// Idempotent: if `intent_id` already exists, the existing row is
    /// preserved and `Ok(false)` is returned.
    ///
    /// # Arguments
    ///
    /// * `intent_id` — Links to `projection_intents.intent_id`.
    /// * `work_id` — Work item identifier.
    /// * `backlog_digest` — 32-byte backlog digest.
    /// * `replay_horizon_tick` — Replay horizon boundary tick.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if a new row was inserted without eviction.
    /// - `Ok(false)` if the row already existed (idempotent).
    /// - `Err(BacklogEviction { .. })` if eviction occurred (new row **was**
    ///   inserted; the error carries evicted IDs for deny receipt emission).
    ///
    /// # Errors
    ///
    /// Returns [`IntentBufferError::BacklogEviction`] when eviction occurs.
    /// Returns [`IntentBufferError::Database`] on SQL failure.
    #[allow(clippy::cast_possible_wrap)]
    pub fn insert_backlog(
        &self,
        intent_id: &str,
        work_id: &str,
        backlog_digest: &[u8; 32],
        replay_horizon_tick: u64,
    ) -> Result<bool, IntentBufferError> {
        validate_field("intent_id", intent_id)?;
        validate_field("work_id", work_id)?;

        let mut guard = self.lock_mut()?;

        // Check for existing entry (idempotent insert).
        let exists: bool = guard
            .query_row(
                "SELECT 1 FROM deferred_replay_backlog WHERE intent_id = ?1",
                params![intent_id],
                |_| Ok(true),
            )
            .optional()
            .map_err(|e| IntentBufferError::Database(format!("exists check failed: {e}")))?
            .unwrap_or(false);

        if exists {
            return Ok(false);
        }

        // Wrap eviction + insertion in a transaction so that if the INSERT
        // fails, eviction is rolled back and INV-IB03 is upheld (evicted IDs
        // are only returned when the whole operation commits).
        let tx = guard
            .transaction()
            .map_err(|e| IntentBufferError::Database(format!("begin transaction failed: {e}")))?;

        // Check capacity and evict if needed (inside the transaction).
        let evicted = Self::evict_if_needed_in_tx(&tx)?;

        // Insert the new entry.
        tx.execute(
            "INSERT INTO deferred_replay_backlog
                 (intent_id, work_id, backlog_digest, replay_horizon_tick,
                  replayed_at, converged)
                 VALUES (?1, ?2, ?3, ?4, 0, 0)",
            params![
                intent_id,
                work_id,
                backlog_digest.as_slice(),
                replay_horizon_tick as i64,
            ],
        )
        .map_err(|e| IntentBufferError::Database(format!("insert_backlog failed: {e}")))?;

        // Commit the transaction — eviction + insert succeed or fail together.
        tx.commit()
            .map_err(|e| IntentBufferError::Database(format!("commit failed: {e}")))?;

        if !evicted.is_empty() {
            return Err(IntentBufferError::BacklogEviction {
                evicted_count: evicted.len(),
                evicted_intent_ids: evicted,
            });
        }

        Ok(true)
    }

    /// Marks a backlog entry as replayed.
    ///
    /// # Arguments
    ///
    /// * `intent_id` — The backlog entry to mark.
    /// * `replayed_at` — Replay timestamp (nanoseconds, from HTF).
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the entry was found and updated.
    /// - `Ok(false)` if not found.
    ///
    /// # Errors
    ///
    /// Returns [`IntentBufferError::Database`] on SQL failure.
    #[allow(clippy::cast_possible_wrap)]
    pub fn mark_replayed(
        &self,
        intent_id: &str,
        replayed_at: u64,
    ) -> Result<bool, IntentBufferError> {
        validate_field("intent_id", intent_id)?;
        let guard = self.lock()?;
        let rows = guard
            .execute(
                "UPDATE deferred_replay_backlog
                 SET replayed_at = ?1
                 WHERE intent_id = ?2 AND replayed_at = 0",
                params![replayed_at as i64, intent_id],
            )
            .map_err(|e| IntentBufferError::Database(format!("mark_replayed failed: {e}")))?;

        Ok(rows > 0)
    }

    /// Marks a backlog entry as converged.
    ///
    /// # Arguments
    ///
    /// * `intent_id` — The backlog entry to mark.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the entry was found and updated.
    /// - `Ok(false)` if not found.
    ///
    /// # Errors
    ///
    /// Returns [`IntentBufferError::Database`] on SQL failure.
    pub fn mark_converged(&self, intent_id: &str) -> Result<bool, IntentBufferError> {
        validate_field("intent_id", intent_id)?;
        let guard = self.lock()?;
        let rows = guard
            .execute(
                "UPDATE deferred_replay_backlog
                 SET converged = 1
                 WHERE intent_id = ?1 AND converged = 0",
                params![intent_id],
            )
            .map_err(|e| IntentBufferError::Database(format!("mark_converged failed: {e}")))?;

        Ok(rows > 0)
    }

    /// Retrieves a single backlog entry by intent ID.
    ///
    /// # Errors
    ///
    /// Returns [`IntentBufferError::Database`] on SQL failure.
    pub fn get_backlog_entry(
        &self,
        intent_id: &str,
    ) -> Result<Option<DeferredReplayEntry>, IntentBufferError> {
        validate_field("intent_id", intent_id)?;
        let guard = self.lock()?;
        let result = guard
            .query_row(
                "SELECT intent_id, work_id, backlog_digest,
                        replay_horizon_tick, replayed_at, converged
                 FROM deferred_replay_backlog
                 WHERE intent_id = ?1",
                params![intent_id],
                row_to_backlog_entry,
            )
            .optional()
            .map_err(|e| IntentBufferError::Database(format!("get_backlog failed: {e}")))?;

        Ok(result)
    }

    /// Queries non-converged backlog entries, ordered by rowid (deterministic).
    ///
    /// Returns at most `limit` results.
    ///
    /// # Errors
    ///
    /// Returns [`IntentBufferError::Database`] on SQL failure.
    #[allow(clippy::cast_possible_wrap)]
    pub fn query_pending_backlog(
        &self,
        limit: usize,
    ) -> Result<Vec<DeferredReplayEntry>, IntentBufferError> {
        let guard = self.lock()?;
        let mut stmt = guard
            .prepare(
                "SELECT intent_id, work_id, backlog_digest,
                        replay_horizon_tick, replayed_at, converged
                 FROM deferred_replay_backlog
                 WHERE converged = 0
                 ORDER BY rowid ASC
                 LIMIT ?1",
            )
            .map_err(|e| IntentBufferError::Database(format!("prepare failed: {e}")))?;

        let rows = stmt
            .query_map(params![limit as i64], row_to_backlog_entry)
            .map_err(|e| IntentBufferError::Database(format!("query failed: {e}")))?;

        let mut results = Vec::new();
        for row in rows {
            let entry =
                row.map_err(|e| IntentBufferError::Database(format!("row parse failed: {e}")))?;
            results.push(entry);
        }

        Ok(results)
    }

    /// Returns the total count of backlog entries.
    ///
    /// # Errors
    ///
    /// Returns [`IntentBufferError::Database`] on SQL failure.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    pub fn backlog_count(&self) -> Result<usize, IntentBufferError> {
        let guard = self.lock()?;
        let count: i64 = guard
            .query_row("SELECT COUNT(*) FROM deferred_replay_backlog", [], |row| {
                row.get(0)
            })
            .map_err(|e| IntentBufferError::Database(format!("count failed: {e}")))?;

        Ok(count as usize)
    }

    // =========================================================================
    // Eviction
    // =========================================================================

    /// Explicitly evicts the oldest backlog entries to bring count to the
    /// specified target. Returns the intent IDs of evicted entries.
    ///
    /// This is the public eviction API for callers that need to proactively
    /// trim the backlog. For capacity-enforcement during insert, use
    /// [`insert_backlog`](Self::insert_backlog) which handles eviction
    /// automatically.
    ///
    /// # Arguments
    ///
    /// * `target_count` — Desired maximum backlog size after eviction.
    ///
    /// # Errors
    ///
    /// Returns [`IntentBufferError::Database`] on SQL failure.
    pub fn evict_to_target(&self, target_count: usize) -> Result<Vec<String>, IntentBufferError> {
        let guard = self.lock()?;
        self.evict_to_target_locked(&guard, target_count)
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /// Acquires the mutex lock (immutable guard).
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, IntentBufferError> {
        self.conn
            .lock()
            .map_err(|e| IntentBufferError::MutexPoisoned(format!("{e}")))
    }

    /// Acquires the mutex lock (mutable guard, required for transactions).
    fn lock_mut(&self) -> Result<std::sync::MutexGuard<'_, Connection>, IntentBufferError> {
        self.conn
            .lock()
            .map_err(|e| IntentBufferError::MutexPoisoned(format!("{e}")))
    }

    /// Evicts oldest entries if backlog is at or above [`MAX_BACKLOG_ITEMS`],
    /// executing within the provided transaction. Returns evicted intent IDs.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn evict_if_needed_in_tx(
        tx: &rusqlite::Transaction<'_>,
    ) -> Result<Vec<String>, IntentBufferError> {
        let count: i64 = tx
            .query_row("SELECT COUNT(*) FROM deferred_replay_backlog", [], |row| {
                row.get(0)
            })
            .map_err(|e| IntentBufferError::Database(format!("count failed: {e}")))?;

        if (count as usize) < MAX_BACKLOG_ITEMS {
            return Ok(Vec::new());
        }

        // Evict 1 entry to make room for the new insert.
        Self::evict_to_target_on(tx, MAX_BACKLOG_ITEMS - 1)
    }

    /// Evicts oldest entries (by rowid) to bring count to `target_count`.
    /// Returns the intent IDs of evicted entries.
    ///
    /// Works on any type that dereferences to [`Connection`] (bare connection,
    /// transaction, etc.).
    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap
    )]
    fn evict_to_target_on(
        conn: &Connection,
        target_count: usize,
    ) -> Result<Vec<String>, IntentBufferError> {
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM deferred_replay_backlog", [], |row| {
                row.get(0)
            })
            .map_err(|e| IntentBufferError::Database(format!("count failed: {e}")))?;

        let current = count as usize;
        if current <= target_count {
            return Ok(Vec::new());
        }

        let to_evict = current - target_count;

        // Select oldest entries by rowid for deterministic eviction.
        let mut stmt = conn
            .prepare(
                "SELECT intent_id FROM deferred_replay_backlog
                 ORDER BY rowid ASC
                 LIMIT ?1",
            )
            .map_err(|e| IntentBufferError::Database(format!("prepare evict failed: {e}")))?;

        let evicted_ids: Vec<String> = stmt
            .query_map(params![to_evict as i64], |row| row.get(0))
            .map_err(|e| IntentBufferError::Database(format!("evict query failed: {e}")))?
            .collect::<Result<Vec<String>, _>>()
            .map_err(|e| IntentBufferError::Database(format!("evict collect failed: {e}")))?;

        // Delete evicted entries.
        for id in &evicted_ids {
            conn.execute(
                "DELETE FROM deferred_replay_backlog WHERE intent_id = ?1",
                params![id],
            )
            .map_err(|e| IntentBufferError::Database(format!("evict delete failed: {e}")))?;
        }

        // Also deny the corresponding intents so the audit trail is complete.
        for id in &evicted_ids {
            conn.execute(
                "UPDATE projection_intents
                 SET verdict = 'denied', deny_reason = 'backlog_capacity_eviction'
                 WHERE intent_id = ?1 AND verdict = 'pending'",
                params![id],
            )
            .map_err(|e| IntentBufferError::Database(format!("evict deny failed: {e}")))?;
        }

        Ok(evicted_ids)
    }

    /// Evicts oldest entries (by rowid) to bring count to `target_count`.
    /// Instance method wrapper for the public API.
    #[allow(clippy::unused_self)]
    fn evict_to_target_locked(
        &self,
        conn: &Connection,
        target_count: usize,
    ) -> Result<Vec<String>, IntentBufferError> {
        Self::evict_to_target_on(conn, target_count)
    }
}

// =============================================================================
// Row Parsing Helpers
// =============================================================================

/// Parses a `projection_intents` row into a [`ProjectionIntent`].
#[allow(clippy::cast_sign_loss)]
fn row_to_intent(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProjectionIntent> {
    let changeset_blob: Vec<u8> = row.get(2)?;
    let ledger_blob: Vec<u8> = row.get(3)?;

    let changeset_digest: [u8; 32] = changeset_blob.as_slice().try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Blob,
            format!(
                "changeset_digest: expected 32 bytes, got {}",
                changeset_blob.len()
            )
            .into(),
        )
    })?;
    let ledger_head: [u8; 32] = ledger_blob.as_slice().try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Blob,
            format!("ledger_head: expected 32 bytes, got {}", ledger_blob.len()).into(),
        )
    })?;

    let verdict_str: String = row.get(6)?;
    let verdict = IntentVerdict::from_str_checked(&verdict_str).unwrap_or(IntentVerdict::Denied); // Fail-closed: unknown verdict -> denied

    let eval_tick: i64 = row.get(5)?;
    let created_at: i64 = row.get(8)?;
    let admitted_at: i64 = row.get(9)?;

    Ok(ProjectionIntent {
        intent_id: row.get(0)?,
        work_id: row.get(1)?,
        changeset_digest,
        ledger_head,
        projected_status: row.get(4)?,
        eval_tick: eval_tick as u64,
        verdict,
        deny_reason: row.get(7)?,
        created_at: created_at as u64,
        admitted_at: admitted_at as u64,
    })
}

/// Parses a `deferred_replay_backlog` row into a [`DeferredReplayEntry`].
#[allow(clippy::cast_sign_loss)]
fn row_to_backlog_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeferredReplayEntry> {
    let backlog_blob: Vec<u8> = row.get(2)?;
    let backlog_digest: [u8; 32] = backlog_blob.as_slice().try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Blob,
            format!(
                "backlog_digest: expected 32 bytes, got {}",
                backlog_blob.len()
            )
            .into(),
        )
    })?;

    let replay_horizon_tick: i64 = row.get(3)?;
    let replayed_at: i64 = row.get(4)?;
    let converged: i64 = row.get(5)?;

    Ok(DeferredReplayEntry {
        intent_id: row.get(0)?,
        work_id: row.get(1)?,
        backlog_digest,
        replay_horizon_tick: replay_horizon_tick as u64,
        replayed_at: replayed_at as u64,
        converged: converged != 0,
    })
}

// =============================================================================
// Validation Helpers
// =============================================================================

/// Validates a string field: non-empty and within length bounds.
const fn validate_field(name: &'static str, value: &str) -> Result<(), IntentBufferError> {
    if value.is_empty() {
        return Err(IntentBufferError::MissingField(name));
    }
    if value.len() > MAX_FIELD_LENGTH {
        return Err(IntentBufferError::FieldTooLong {
            field: name,
            actual: value.len(),
            max: MAX_FIELD_LENGTH,
        });
    }
    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    // =========================================================================
    // Helpers
    // =========================================================================

    fn make_buffer() -> IntentBuffer {
        IntentBuffer::in_memory().expect("in-memory buffer")
    }

    fn make_digest(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    // =========================================================================
    // Intent Insert Tests
    // =========================================================================

    #[test]
    fn test_insert_and_retrieve() {
        let buf = make_buffer();
        let inserted = buf
            .insert(
                "intent-001",
                "work-001",
                &make_digest(0x42),
                &make_digest(0xAB),
                "pending",
                100,
                1_000_000,
            )
            .expect("insert");
        assert!(inserted, "first insert should return true");

        let intent = buf
            .get_intent("intent-001")
            .expect("get")
            .expect("should exist");
        assert_eq!(intent.intent_id, "intent-001");
        assert_eq!(intent.work_id, "work-001");
        assert_eq!(intent.changeset_digest, make_digest(0x42));
        assert_eq!(intent.ledger_head, make_digest(0xAB));
        assert_eq!(intent.projected_status, "pending");
        assert_eq!(intent.eval_tick, 100);
        assert_eq!(intent.verdict, IntentVerdict::Pending);
        assert_eq!(intent.deny_reason, "");
        assert_eq!(intent.created_at, 1_000_000);
        assert_eq!(intent.admitted_at, 0);
    }

    #[test]
    fn test_idempotent_insert_same_work_id_changeset() {
        let buf = make_buffer();

        // First insert
        let first = buf
            .insert(
                "intent-001",
                "work-001",
                &make_digest(0x42),
                &make_digest(0xAB),
                "pending",
                100,
                1_000_000,
            )
            .expect("first insert");
        assert!(first);

        // Second insert with same (work_id, changeset_digest) but different intent_id
        let second = buf
            .insert(
                "intent-002",
                "work-001",
                &make_digest(0x42),
                &make_digest(0xCC),
                "pending",
                200,
                2_000_000,
            )
            .expect("second insert");
        assert!(!second, "idempotent insert should return false");

        // Original row should be preserved
        let intent = buf
            .get_intent("intent-001")
            .expect("get")
            .expect("should exist");
        assert_eq!(intent.eval_tick, 100, "original row preserved");

        // The second intent_id should NOT exist
        let missing = buf.get_intent("intent-002").expect("get");
        assert!(missing.is_none(), "duplicate should not create new row");

        // Count should be exactly 1
        assert_eq!(buf.intent_count().expect("count"), 1);
    }

    #[test]
    fn test_insert_different_changeset_creates_new_row() {
        let buf = make_buffer();

        buf.insert(
            "intent-001",
            "work-001",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        )
        .expect("insert 1");

        buf.insert(
            "intent-002",
            "work-001",
            &make_digest(0x43), // Different changeset
            &make_digest(0xAB),
            "pending",
            200,
            2_000_000,
        )
        .expect("insert 2");

        assert_eq!(buf.intent_count().expect("count"), 2);
    }

    // =========================================================================
    // Admit / Deny Tests
    // =========================================================================

    #[test]
    fn test_admit_intent() {
        let buf = make_buffer();
        buf.insert(
            "intent-001",
            "work-001",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        )
        .expect("insert");

        let admitted = buf.admit("intent-001", 2_000_000).expect("admit");
        assert!(admitted);

        let intent = buf.get_intent("intent-001").expect("get").expect("exists");
        assert_eq!(intent.verdict, IntentVerdict::Admitted);
        assert_eq!(intent.admitted_at, 2_000_000);
    }

    #[test]
    fn test_admit_nonexistent_intent() {
        let buf = make_buffer();
        let admitted = buf.admit("nonexistent", 2_000_000).expect("admit");
        assert!(!admitted);
    }

    #[test]
    fn test_admit_already_denied_intent_fails() {
        let buf = make_buffer();
        buf.insert(
            "intent-001",
            "work-001",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        )
        .expect("insert");

        // Deny first
        buf.deny("intent-001", "policy violation").expect("deny");

        // Admitting a denied intent should fail (no-op)
        let admitted = buf.admit("intent-001", 2_000_000).expect("admit");
        assert!(!admitted, "should not admit a denied intent");

        // Verdict should still be denied
        let intent = buf.get_intent("intent-001").expect("get").expect("exists");
        assert_eq!(intent.verdict, IntentVerdict::Denied);
    }

    #[test]
    fn test_deny_intent() {
        let buf = make_buffer();
        buf.insert(
            "intent-001",
            "work-001",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        )
        .expect("insert");

        let denied = buf.deny("intent-001", "rate_limited").expect("deny");
        assert!(denied);

        let intent = buf.get_intent("intent-001").expect("get").expect("exists");
        assert_eq!(intent.verdict, IntentVerdict::Denied);
        assert_eq!(intent.deny_reason, "rate_limited");
    }

    #[test]
    fn test_deny_nonexistent_intent() {
        let buf = make_buffer();
        let denied = buf.deny("nonexistent", "no reason").expect("deny");
        assert!(!denied);
    }

    #[test]
    fn test_deny_already_admitted_intent_fails() {
        let buf = make_buffer();
        buf.insert(
            "intent-001",
            "work-001",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        )
        .expect("insert");

        buf.admit("intent-001", 2_000_000).expect("admit");

        // Denying an admitted intent should fail (no-op)
        let denied = buf.deny("intent-001", "too late").expect("deny");
        assert!(!denied, "should not deny an admitted intent");

        let intent = buf.get_intent("intent-001").expect("get").expect("exists");
        assert_eq!(intent.verdict, IntentVerdict::Admitted);
    }

    // =========================================================================
    // Query Tests
    // =========================================================================

    #[test]
    fn test_query_by_verdict() {
        let buf = make_buffer();

        // Insert 3 intents
        for i in 0u32..3 {
            buf.insert(
                &format!("intent-{i:03}"),
                &format!("work-{i:03}"),
                &make_digest(i as u8),
                &make_digest(0xAB),
                "pending",
                100 + u64::from(i),
                1_000_000,
            )
            .expect("insert");
        }

        // Admit one, deny one, leave one pending
        buf.admit("intent-000", 2_000_000).expect("admit");
        buf.deny("intent-001", "test deny").expect("deny");

        let pending = buf
            .query_by_verdict(IntentVerdict::Pending, 100)
            .expect("query");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].intent_id, "intent-002");

        let admitted = buf
            .query_by_verdict(IntentVerdict::Admitted, 100)
            .expect("query");
        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].intent_id, "intent-000");

        let denied = buf
            .query_by_verdict(IntentVerdict::Denied, 100)
            .expect("query");
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].intent_id, "intent-001");
    }

    #[test]
    fn test_query_by_verdict_respects_limit() {
        let buf = make_buffer();

        for i in 0u32..10 {
            buf.insert(
                &format!("intent-{i:03}"),
                &format!("work-{i:03}"),
                &make_digest(i as u8),
                &make_digest(0xAB),
                "pending",
                u64::from(i),
                1_000_000,
            )
            .expect("insert");
        }

        let results = buf
            .query_by_verdict(IntentVerdict::Pending, 3)
            .expect("query");
        assert_eq!(results.len(), 3);
    }

    // =========================================================================
    // Backlog Tests
    // =========================================================================

    #[test]
    fn test_backlog_insert_and_retrieve() {
        let buf = make_buffer();

        // Must insert intent first (for audit trail completeness)
        buf.insert(
            "intent-001",
            "work-001",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        )
        .expect("insert intent");

        let inserted = buf
            .insert_backlog("intent-001", "work-001", &make_digest(0xDD), 500)
            .expect("insert backlog");
        assert!(inserted);

        let entry = buf
            .get_backlog_entry("intent-001")
            .expect("get")
            .expect("exists");
        assert_eq!(entry.intent_id, "intent-001");
        assert_eq!(entry.work_id, "work-001");
        assert_eq!(entry.backlog_digest, make_digest(0xDD));
        assert_eq!(entry.replay_horizon_tick, 500);
        assert_eq!(entry.replayed_at, 0);
        assert!(!entry.converged);
    }

    #[test]
    fn test_backlog_idempotent_insert() {
        let buf = make_buffer();

        buf.insert(
            "intent-001",
            "work-001",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        )
        .expect("insert intent");

        let first = buf
            .insert_backlog("intent-001", "work-001", &make_digest(0xDD), 500)
            .expect("first");
        assert!(first);

        let second = buf
            .insert_backlog("intent-001", "work-001", &make_digest(0xEE), 600)
            .expect("second");
        assert!(!second, "idempotent insert should return false");

        // Original entry preserved
        let entry = buf
            .get_backlog_entry("intent-001")
            .expect("get")
            .expect("exists");
        assert_eq!(entry.replay_horizon_tick, 500, "original preserved");

        assert_eq!(buf.backlog_count().expect("count"), 1);
    }

    #[test]
    fn test_backlog_mark_replayed_and_converged() {
        let buf = make_buffer();

        buf.insert(
            "intent-001",
            "work-001",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        )
        .expect("insert intent");

        buf.insert_backlog("intent-001", "work-001", &make_digest(0xDD), 500)
            .expect("insert backlog");

        // Mark replayed
        let replayed = buf.mark_replayed("intent-001", 3_000_000).expect("replay");
        assert!(replayed);

        let entry = buf
            .get_backlog_entry("intent-001")
            .expect("get")
            .expect("exists");
        assert_eq!(entry.replayed_at, 3_000_000);
        assert!(!entry.converged);

        // Mark converged
        let converged = buf.mark_converged("intent-001").expect("converge");
        assert!(converged);

        let entry = buf
            .get_backlog_entry("intent-001")
            .expect("get")
            .expect("exists");
        assert!(entry.converged);

        // Double converge is no-op
        let again = buf.mark_converged("intent-001").expect("converge again");
        assert!(!again, "already converged");
    }

    #[test]
    fn test_query_pending_backlog() {
        let buf = make_buffer();

        for i in 0u8..5 {
            let id = format!("intent-{i:03}");
            let wid = format!("work-{i:03}");
            buf.insert(
                &id,
                &wid,
                &make_digest(i),
                &make_digest(0xAB),
                "pending",
                u64::from(i),
                1_000_000,
            )
            .expect("insert intent");
            buf.insert_backlog(&id, &wid, &make_digest(i + 100), u64::from(i) * 10)
                .expect("insert backlog");
        }

        // Mark two as converged
        buf.mark_converged("intent-000").expect("converge");
        buf.mark_converged("intent-001").expect("converge");

        let pending = buf.query_pending_backlog(100).expect("query");
        assert_eq!(pending.len(), 3);
        assert_eq!(pending[0].intent_id, "intent-002");
        assert_eq!(pending[1].intent_id, "intent-003");
        assert_eq!(pending[2].intent_id, "intent-004");
    }

    // =========================================================================
    // Capacity and Eviction Tests
    // =========================================================================

    #[test]
    fn test_backlog_at_max_minus_one_allows_insert() {
        let buf = make_buffer();

        // Fill to MAX - 1 = 65535
        fill_backlog(&buf, MAX_BACKLOG_ITEMS - 1);

        assert_eq!(buf.backlog_count().expect("count"), MAX_BACKLOG_ITEMS - 1);

        // One more insert should succeed without eviction
        let id = format!("intent-{:06}", MAX_BACKLOG_ITEMS - 1);
        let wid = format!("work-{:06}", MAX_BACKLOG_ITEMS - 1);
        buf.insert(
            &id,
            &wid,
            &make_digest(0xFF),
            &make_digest(0xAB),
            "pending",
            999_999,
            1_000_000,
        )
        .expect("insert intent");

        let result = buf.insert_backlog(&id, &wid, &make_digest(0xFF), 999_999);
        assert!(result.is_ok(), "should insert without eviction");
        assert!(result.unwrap(), "should actually insert");

        assert_eq!(buf.backlog_count().expect("count"), MAX_BACKLOG_ITEMS);
    }

    #[test]
    fn test_backlog_at_max_triggers_eviction() {
        let buf = make_buffer();

        // Fill to exactly MAX = 65536
        fill_backlog(&buf, MAX_BACKLOG_ITEMS);
        assert_eq!(buf.backlog_count().expect("count"), MAX_BACKLOG_ITEMS);

        // Next insert should trigger eviction
        let n = MAX_BACKLOG_ITEMS;
        let id = format!("intent-{n:06}");
        let wid = format!("work-{n:06}");
        buf.insert(
            &id,
            &wid,
            &make_digest(0xFE),
            &make_digest(0xAB),
            "pending",
            999_999,
            1_000_000,
        )
        .expect("insert intent");

        let result = buf.insert_backlog(&id, &wid, &make_digest(0xFE), 999_999);
        match result {
            Err(IntentBufferError::BacklogEviction {
                evicted_count,
                evicted_intent_ids,
            }) => {
                assert_eq!(evicted_count, 1, "should evict exactly 1 entry");
                assert_eq!(evicted_intent_ids.len(), 1);
                // The oldest entry (intent-000000) should be evicted
                assert_eq!(evicted_intent_ids[0], "intent-000000");
            },
            other => panic!("expected BacklogEviction, got: {other:?}"),
        }

        // Count should still be MAX (evicted 1, inserted 1)
        assert_eq!(buf.backlog_count().expect("count"), MAX_BACKLOG_ITEMS);

        // The new entry should exist
        let entry = buf.get_backlog_entry(&id).expect("get").expect("exists");
        assert_eq!(entry.intent_id, id);

        // The evicted entry should not exist
        let evicted = buf.get_backlog_entry("intent-000000").expect("get");
        assert!(evicted.is_none(), "evicted entry should be gone");

        // The evicted intent should be denied
        let intent = buf
            .get_intent("intent-000000")
            .expect("get")
            .expect("exists");
        assert_eq!(intent.verdict, IntentVerdict::Denied);
        assert_eq!(intent.deny_reason, "backlog_capacity_eviction");
    }

    #[test]
    fn test_explicit_evict_to_target() {
        let buf = make_buffer();
        fill_backlog(&buf, 100);
        assert_eq!(buf.backlog_count().expect("count"), 100);

        let evicted = buf.evict_to_target(90).expect("evict");
        assert_eq!(evicted.len(), 10);
        assert_eq!(buf.backlog_count().expect("count"), 90);

        // Verify evicted IDs are the oldest (deterministic by rowid)
        for (i, id) in evicted.iter().enumerate() {
            assert_eq!(*id, format!("intent-{i:06}"));
        }
    }

    #[test]
    fn test_evict_to_target_already_below() {
        let buf = make_buffer();
        fill_backlog(&buf, 10);

        let evicted = buf.evict_to_target(100).expect("evict");
        assert!(evicted.is_empty(), "nothing to evict");
        assert_eq!(buf.backlog_count().expect("count"), 10);
    }

    // =========================================================================
    // Input Validation Tests
    // =========================================================================

    #[test]
    fn test_insert_rejects_empty_intent_id() {
        let buf = make_buffer();
        let result = buf.insert(
            "",
            "work-001",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        );
        assert!(matches!(
            result,
            Err(IntentBufferError::MissingField("intent_id"))
        ));
    }

    #[test]
    fn test_insert_rejects_empty_work_id() {
        let buf = make_buffer();
        let result = buf.insert(
            "intent-001",
            "",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        );
        assert!(matches!(
            result,
            Err(IntentBufferError::MissingField("work_id"))
        ));
    }

    #[test]
    fn test_insert_rejects_oversized_field() {
        let buf = make_buffer();
        let long = "x".repeat(MAX_FIELD_LENGTH + 1);
        let result = buf.insert(
            &long,
            "work-001",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        );
        assert!(matches!(
            result,
            Err(IntentBufferError::FieldTooLong {
                field: "intent_id",
                ..
            })
        ));
    }

    // =========================================================================
    // Verdict Display Tests
    // =========================================================================

    #[test]
    fn test_intent_verdict_display() {
        assert_eq!(IntentVerdict::Pending.to_string(), "pending");
        assert_eq!(IntentVerdict::Admitted.to_string(), "admitted");
        assert_eq!(IntentVerdict::Denied.to_string(), "denied");
    }

    #[test]
    fn test_intent_verdict_roundtrip() {
        for verdict in &[
            IntentVerdict::Pending,
            IntentVerdict::Admitted,
            IntentVerdict::Denied,
        ] {
            let s = verdict.as_str();
            let parsed = IntentVerdict::from_str_checked(s);
            assert_eq!(parsed, Some(*verdict));
        }
    }

    #[test]
    fn test_intent_verdict_unknown_fails_closed() {
        let parsed = IntentVerdict::from_str_checked("unknown_value");
        assert_eq!(
            parsed, None,
            "unknown verdict must not be silently accepted"
        );
    }

    // =========================================================================
    // Migration Safety Tests
    // =========================================================================

    #[test]
    fn test_migration_does_not_alter_existing_tables() {
        let conn = Connection::open_in_memory().expect("open");

        // Create existing tables that must not be altered
        conn.execute_batch(
            r"
            CREATE TABLE projection_receipts (
                id INTEGER PRIMARY KEY,
                work_id TEXT NOT NULL
            );
            CREATE TABLE comment_receipts (
                receipt_id TEXT PRIMARY KEY,
                work_id TEXT NOT NULL
            );

            INSERT INTO projection_receipts (id, work_id) VALUES (1, 'existing-work');
            INSERT INTO comment_receipts (receipt_id, work_id) VALUES ('r-001', 'existing-work');
            ",
        )
        .expect("create existing tables");

        // Now create the IntentBuffer — this runs our migration
        let conn = Arc::new(Mutex::new(conn));
        let _buf = IntentBuffer::new(conn.clone()).expect("buffer creation");

        // Verify existing tables are untouched
        let guard = conn.lock().expect("lock");

        let existing_receipt: String = guard
            .query_row(
                "SELECT work_id FROM projection_receipts WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .expect("existing receipt query");
        assert_eq!(existing_receipt, "existing-work");

        let existing_comment: String = guard
            .query_row(
                "SELECT work_id FROM comment_receipts WHERE receipt_id = 'r-001'",
                [],
                |row| row.get(0),
            )
            .expect("existing comment query");
        assert_eq!(existing_comment, "existing-work");
    }

    #[test]
    fn test_schema_is_idempotent() {
        let conn = Connection::open_in_memory().expect("open");
        let conn = Arc::new(Mutex::new(conn));

        // Create buffer twice — should not error
        let buf1 = IntentBuffer::new(conn.clone()).expect("first creation");
        drop(buf1);
        let _buf2 = IntentBuffer::new(conn).expect("second creation");
    }

    // =========================================================================
    // Full Round-Trip Test
    // =========================================================================

    #[test]
    fn test_full_intent_lifecycle() {
        let buf = make_buffer();

        // 1. Insert
        buf.insert(
            "intent-001",
            "work-001",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        )
        .expect("insert");

        // 2. Add to backlog
        buf.insert_backlog("intent-001", "work-001", &make_digest(0xDD), 500)
            .expect("backlog");

        // 3. Verify pending state
        let intent = buf.get_intent("intent-001").expect("get").expect("exists");
        assert_eq!(intent.verdict, IntentVerdict::Pending);

        // 4. Admit
        buf.admit("intent-001", 2_000_000).expect("admit");

        // 5. Verify admitted
        let intent = buf.get_intent("intent-001").expect("get").expect("exists");
        assert_eq!(intent.verdict, IntentVerdict::Admitted);
        assert_eq!(intent.admitted_at, 2_000_000);

        // 6. Mark replayed
        buf.mark_replayed("intent-001", 3_000_000)
            .expect("replayed");

        // 7. Mark converged
        buf.mark_converged("intent-001").expect("converged");

        // 8. Verify final state
        let entry = buf
            .get_backlog_entry("intent-001")
            .expect("get")
            .expect("exists");
        assert_eq!(entry.replayed_at, 3_000_000);
        assert!(entry.converged);
    }

    // =========================================================================
    // Stress / Boundary Tests
    // =========================================================================

    #[test]
    fn test_backlog_boundary_65535_ok() {
        let buf = make_buffer();
        fill_backlog(&buf, 65_535);
        assert_eq!(buf.backlog_count().expect("count"), 65_535);
    }

    #[test]
    fn test_backlog_boundary_65536_ok() {
        let buf = make_buffer();
        fill_backlog(&buf, 65_536);
        assert_eq!(buf.backlog_count().expect("count"), 65_536);
    }

    #[test]
    fn test_backlog_boundary_65537_triggers_eviction() {
        let buf = make_buffer();
        fill_backlog(&buf, 65_536);

        // The 65537th insert should trigger eviction
        let id = format!("intent-{:06}", 65_536);
        let wid = format!("work-{:06}", 65_536);
        buf.insert(
            &id,
            &wid,
            &make_digest(0xFE),
            &make_digest(0xAB),
            "pending",
            999_999,
            1_000_000,
        )
        .expect("insert intent");

        let result = buf.insert_backlog(&id, &wid, &make_digest(0xFE), 999_999);
        match result {
            Err(IntentBufferError::BacklogEviction { evicted_count, .. }) => {
                assert_eq!(evicted_count, 1);
            },
            other => panic!("expected BacklogEviction, got: {other:?}"),
        }

        assert_eq!(buf.backlog_count().expect("count"), 65_536);
    }

    // =========================================================================
    // Backlog entry mark_replayed idempotency
    // =========================================================================

    #[test]
    fn test_mark_replayed_idempotent() {
        let buf = make_buffer();
        buf.insert(
            "intent-001",
            "work-001",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        )
        .expect("insert intent");
        buf.insert_backlog("intent-001", "work-001", &make_digest(0xDD), 500)
            .expect("insert backlog");

        let first = buf.mark_replayed("intent-001", 3_000_000).expect("first");
        assert!(first);

        // Second mark should be no-op (already replayed)
        let second = buf.mark_replayed("intent-001", 4_000_000).expect("second");
        assert!(!second, "already replayed");

        // Original replayed_at should be preserved
        let entry = buf
            .get_backlog_entry("intent-001")
            .expect("get")
            .expect("exists");
        assert_eq!(entry.replayed_at, 3_000_000);
    }

    // =========================================================================
    // Deny reason validation tests
    // =========================================================================

    #[test]
    fn test_deny_rejects_empty_reason() {
        let buf = make_buffer();
        buf.insert(
            "intent-001",
            "work-001",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        )
        .expect("insert");

        let result = buf.deny("intent-001", "");
        assert!(
            matches!(result, Err(IntentBufferError::MissingField("deny_reason"))),
            "empty deny reason must be rejected"
        );
    }

    #[test]
    fn test_deny_rejects_oversized_reason() {
        let buf = make_buffer();
        buf.insert(
            "intent-001",
            "work-001",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        )
        .expect("insert");

        let long_reason = "x".repeat(MAX_FIELD_LENGTH + 1);
        let result = buf.deny("intent-001", &long_reason);
        assert!(
            matches!(
                result,
                Err(IntentBufferError::FieldTooLong {
                    field: "deny_reason",
                    ..
                })
            ),
            "oversized deny reason must be rejected"
        );
    }

    // =========================================================================
    // Identifier validation on getters/setters tests
    // =========================================================================

    #[test]
    fn test_get_intent_rejects_empty_id() {
        let buf = make_buffer();
        let result = buf.get_intent("");
        assert!(matches!(
            result,
            Err(IntentBufferError::MissingField("intent_id"))
        ));
    }

    #[test]
    fn test_get_intent_rejects_oversized_id() {
        let buf = make_buffer();
        let long_id = "x".repeat(MAX_FIELD_LENGTH + 1);
        let result = buf.get_intent(&long_id);
        assert!(matches!(
            result,
            Err(IntentBufferError::FieldTooLong {
                field: "intent_id",
                ..
            })
        ));
    }

    #[test]
    fn test_mark_replayed_rejects_empty_id() {
        let buf = make_buffer();
        let result = buf.mark_replayed("", 1_000);
        assert!(matches!(
            result,
            Err(IntentBufferError::MissingField("intent_id"))
        ));
    }

    #[test]
    fn test_mark_converged_rejects_empty_id() {
        let buf = make_buffer();
        let result = buf.mark_converged("");
        assert!(matches!(
            result,
            Err(IntentBufferError::MissingField("intent_id"))
        ));
    }

    #[test]
    fn test_get_backlog_entry_rejects_empty_id() {
        let buf = make_buffer();
        let result = buf.get_backlog_entry("");
        assert!(matches!(
            result,
            Err(IntentBufferError::MissingField("intent_id"))
        ));
    }

    // =========================================================================
    // Blob deserialization corruption detection tests
    // =========================================================================

    #[test]
    fn test_corrupt_changeset_blob_detected() {
        let buf = make_buffer();
        // Insert a valid intent first.
        buf.insert(
            "intent-001",
            "work-001",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        )
        .expect("insert");

        // Manually corrupt the changeset_digest blob to wrong length.
        {
            let guard = buf.conn.lock().expect("lock");
            guard
                .execute(
                    "UPDATE projection_intents SET changeset_digest = X'DEADBEEF' WHERE intent_id = 'intent-001'",
                    [],
                )
                .expect("corrupt");
        }

        let result = buf.get_intent("intent-001");
        assert!(
            result.is_err(),
            "corrupt blob must produce an error, not a zero-fill"
        );
    }

    #[test]
    fn test_corrupt_backlog_blob_detected() {
        let buf = make_buffer();
        buf.insert(
            "intent-001",
            "work-001",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        )
        .expect("insert intent");
        buf.insert_backlog("intent-001", "work-001", &make_digest(0xDD), 500)
            .expect("insert backlog");

        // Manually corrupt the backlog_digest blob to wrong length.
        {
            let guard = buf.conn.lock().expect("lock");
            guard
                .execute(
                    "UPDATE deferred_replay_backlog SET backlog_digest = X'CAFE' WHERE intent_id = 'intent-001'",
                    [],
                )
                .expect("corrupt");
        }

        let result = buf.get_backlog_entry("intent-001");
        assert!(
            result.is_err(),
            "corrupt backlog blob must produce an error, not a zero-fill"
        );
    }

    // =========================================================================
    // Transactional eviction + insertion test
    // =========================================================================

    #[test]
    fn test_insert_backlog_eviction_is_transactional() {
        // Verify that after a successful eviction+insert, the count is
        // correct and evicted entries are gone. This confirms the
        // transaction committed atomically.
        let buf = make_buffer();
        fill_backlog(&buf, MAX_BACKLOG_ITEMS);
        assert_eq!(buf.backlog_count().expect("count"), MAX_BACKLOG_ITEMS);

        let n = MAX_BACKLOG_ITEMS;
        let id = format!("intent-{n:06}");
        let wid = format!("work-{n:06}");
        buf.insert(
            &id,
            &wid,
            &make_digest(0xFE),
            &make_digest(0xAB),
            "pending",
            999_999,
            1_000_000,
        )
        .expect("insert intent");

        let result = buf.insert_backlog(&id, &wid, &make_digest(0xFE), 999_999);
        match &result {
            Err(IntentBufferError::BacklogEviction {
                evicted_count,
                evicted_intent_ids,
            }) => {
                assert_eq!(*evicted_count, 1);
                // The evicted entry must actually be gone from the DB
                // (transaction committed).
                for evicted_id in evicted_intent_ids {
                    let entry = buf.get_backlog_entry(evicted_id).expect("get");
                    assert!(
                        entry.is_none(),
                        "evicted entry {evicted_id} should be deleted"
                    );
                }
                // The new entry must exist.
                let entry = buf.get_backlog_entry(&id).expect("get");
                assert!(entry.is_some(), "new entry should exist after txn commit");
            },
            other => panic!("expected BacklogEviction, got: {other:?}"),
        }

        // Count must be exactly MAX (evicted 1, inserted 1).
        assert_eq!(buf.backlog_count().expect("count"), MAX_BACKLOG_ITEMS);
    }

    #[test]
    fn test_attach_lifecycle_artifacts_updates_intent_row() {
        let buf = make_buffer();
        buf.insert(
            "intent-lifecycle-001",
            "work-001",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        )
        .expect("insert intent");

        let artifacts = IntentLifecycleArtifacts {
            ajc_id: make_digest(0xA1),
            intent_digest: make_digest(0xB2),
            consume_selector_digest: make_digest(0xC3),
            consume_tick: 4242,
            time_envelope_ref: make_digest(0xD4),
        };

        let updated = buf
            .attach_lifecycle_artifacts("intent-lifecycle-001", &artifacts)
            .expect("attach lifecycle artifacts");
        assert!(updated, "intent row should be updated");

        let guard = buf.conn.lock().expect("lock");
        let (ajc_id, intent_digest, selector_digest, consume_tick, time_envelope_ref): (
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            i64,
            Vec<u8>,
        ) = guard
            .query_row(
                "SELECT lifecycle_ajc_id,
                        lifecycle_intent_digest,
                        lifecycle_consume_selector_digest,
                        lifecycle_consume_tick,
                        lifecycle_time_envelope_ref
                 FROM projection_intents
                 WHERE intent_id = ?1",
                params!["intent-lifecycle-001"],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("read lifecycle columns");

        assert_eq!(ajc_id, artifacts.ajc_id);
        assert_eq!(intent_digest, artifacts.intent_digest);
        assert_eq!(selector_digest, artifacts.consume_selector_digest);
        let expected_consume_tick =
            i64::try_from(artifacts.consume_tick).expect("consume tick fits i64");
        assert_eq!(consume_tick, expected_consume_tick);
        assert_eq!(time_envelope_ref, artifacts.time_envelope_ref);
    }

    #[test]
    fn test_new_adds_missing_lifecycle_columns_for_legacy_schema() {
        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("sqlite open"),
        ));
        {
            let guard = conn.lock().expect("lock");
            guard
                .execute_batch(
                    "CREATE TABLE projection_intents (
                         intent_id TEXT PRIMARY KEY,
                         work_id TEXT NOT NULL,
                         changeset_digest BLOB NOT NULL,
                         ledger_head BLOB NOT NULL,
                         projected_status TEXT NOT NULL,
                         eval_tick INTEGER NOT NULL,
                         verdict TEXT NOT NULL DEFAULT 'pending',
                         deny_reason TEXT NOT NULL DEFAULT '',
                         created_at INTEGER NOT NULL,
                         admitted_at INTEGER NOT NULL DEFAULT 0,
                         UNIQUE(work_id, changeset_digest)
                     );
                     CREATE TABLE deferred_replay_backlog (
                         intent_id TEXT PRIMARY KEY,
                         work_id TEXT NOT NULL,
                         backlog_digest BLOB NOT NULL,
                         replay_horizon_tick INTEGER NOT NULL,
                         replayed_at INTEGER NOT NULL DEFAULT 0,
                         converged INTEGER NOT NULL DEFAULT 0
                     );",
                )
                .expect("legacy schema init");
        }

        let _buf = IntentBuffer::new(Arc::clone(&conn)).expect("intent buffer init");

        let guard = conn.lock().expect("lock");
        let mut stmt = guard
            .prepare("PRAGMA table_info(projection_intents)")
            .expect("table_info");
        let mut columns = std::collections::HashSet::new();
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query table_info");
        for col in rows {
            columns.insert(col.expect("column name"));
        }

        for expected in [
            "lifecycle_ajc_id",
            "lifecycle_intent_digest",
            "lifecycle_consume_selector_digest",
            "lifecycle_consume_tick",
            "lifecycle_time_envelope_ref",
        ] {
            assert!(
                columns.contains(expected),
                "missing expected migrated column: {expected}"
            );
        }
    }

    // =========================================================================
    // get_lifecycle_artifacts Tests
    // =========================================================================

    #[test]
    fn test_get_lifecycle_artifacts_returns_none_without_artifacts() {
        let buf = make_buffer();
        buf.insert(
            "intent-001",
            "work-001",
            &make_digest(0x42),
            &make_digest(0xAB),
            "pending",
            100,
            1_000_000,
        )
        .expect("insert");

        // No artifacts attached yet.
        let result = buf.get_lifecycle_artifacts("intent-001").expect("query");
        assert!(result.is_none(), "no artifacts should mean None");
    }

    #[test]
    fn test_get_lifecycle_artifacts_returns_some_after_attach() {
        let buf = make_buffer();
        buf.insert(
            "intent-002",
            "work-002",
            &make_digest(0x43),
            &make_digest(0xAB),
            "pending",
            200,
            2_000_000,
        )
        .expect("insert");

        let artifacts = IntentLifecycleArtifacts {
            ajc_id: make_digest(0xC1),
            intent_digest: make_digest(0xC2),
            consume_selector_digest: make_digest(0xC3),
            consume_tick: 9999,
            time_envelope_ref: make_digest(0xC4),
        };
        buf.attach_lifecycle_artifacts("intent-002", &artifacts)
            .expect("attach");

        let retrieved = buf
            .get_lifecycle_artifacts("intent-002")
            .expect("query")
            .expect("should be Some");
        assert_eq!(retrieved.ajc_id, artifacts.ajc_id);
        assert_eq!(retrieved.intent_digest, artifacts.intent_digest);
        assert_eq!(
            retrieved.consume_selector_digest,
            artifacts.consume_selector_digest
        );
        assert_eq!(retrieved.consume_tick, 9999);
        assert_eq!(retrieved.time_envelope_ref, artifacts.time_envelope_ref);
    }

    #[test]
    fn test_get_lifecycle_artifacts_returns_none_for_denied_intent() {
        let buf = make_buffer();
        buf.insert(
            "intent-003",
            "work-003",
            &make_digest(0x44),
            &make_digest(0xAB),
            "pending",
            300,
            3_000_000,
        )
        .expect("insert");

        let artifacts = IntentLifecycleArtifacts {
            ajc_id: make_digest(0xD1),
            intent_digest: make_digest(0xD2),
            consume_selector_digest: make_digest(0xD3),
            consume_tick: 5555,
            time_envelope_ref: make_digest(0xD4),
        };
        buf.attach_lifecycle_artifacts("intent-003", &artifacts)
            .expect("attach");

        // Deny the intent.
        buf.deny("intent-003", "test deny reason").expect("deny");

        // Lifecycle artifacts should not be returned for a denied intent
        // (only pending intents are eligible for retry).
        let result = buf.get_lifecycle_artifacts("intent-003").expect("query");
        assert!(
            result.is_none(),
            "denied intent must not return lifecycle artifacts"
        );
    }

    #[test]
    fn test_get_lifecycle_artifacts_returns_none_for_admitted_intent() {
        let buf = make_buffer();
        buf.insert(
            "intent-004",
            "work-004",
            &make_digest(0x45),
            &make_digest(0xAB),
            "pending",
            400,
            4_000_000,
        )
        .expect("insert");

        let artifacts = IntentLifecycleArtifacts {
            ajc_id: make_digest(0xE1),
            intent_digest: make_digest(0xE2),
            consume_selector_digest: make_digest(0xE3),
            consume_tick: 7777,
            time_envelope_ref: make_digest(0xE4),
        };
        buf.attach_lifecycle_artifacts("intent-004", &artifacts)
            .expect("attach");

        // Admit the intent.
        buf.admit("intent-004", 5_000_000).expect("admit");

        // Lifecycle artifacts should not be returned for admitted intents.
        let result = buf.get_lifecycle_artifacts("intent-004").expect("query");
        assert!(
            result.is_none(),
            "admitted intent must not return lifecycle artifacts"
        );
    }

    #[test]
    fn test_get_lifecycle_artifacts_nonexistent_returns_none() {
        let buf = make_buffer();
        let result = buf.get_lifecycle_artifacts("nonexistent").expect("query");
        assert!(result.is_none());
    }

    #[test]
    fn test_get_lifecycle_artifacts_rejects_empty_id() {
        let buf = make_buffer();
        let result = buf.get_lifecycle_artifacts("");
        assert!(matches!(
            result,
            Err(IntentBufferError::MissingField("intent_id"))
        ));
    }

    // =========================================================================
    // Helper: fill backlog to N entries
    // =========================================================================

    fn fill_backlog(buf: &IntentBuffer, count: usize) {
        for i in 0..count {
            let id = format!("intent-{i:06}");
            let wid = format!("work-{i:06}");
            // Use different bytes for each changeset to avoid UNIQUE constraint
            let byte = (i % 256) as u8;
            let mut digest = [0u8; 32];
            digest[0] = byte;
            digest[1] = ((i >> 8) % 256) as u8;
            digest[2] = ((i >> 16) % 256) as u8;

            buf.insert(
                &id,
                &wid,
                &digest,
                &make_digest(0xAB),
                "pending",
                i as u64,
                1_000_000,
            )
            .expect("insert intent");

            // insert_backlog may return BacklogEviction error at capacity,
            // but we're only filling below or at MAX so this should be Ok.
            let _ = buf.insert_backlog(&id, &wid, &digest, i as u64);
        }
    }
}

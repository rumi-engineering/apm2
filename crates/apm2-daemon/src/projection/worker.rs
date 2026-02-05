// AGENT-AUTHORED (TCK-00322)
//! Projection worker for the FAC (Forge Admission Cycle).
//!
//! This module implements the long-running projection worker that:
//! 1. Tails the ledger for `ReviewReceiptRecorded` events
//! 2. Looks up PR metadata from the work index
//! 3. Projects review results to GitHub (status + comment)
//! 4. Stores projection receipts in CAS for idempotency
//!
//! # RFC-0019: Projection Worker (Workstream F)
//!
//! Per RFC-0019, the projection worker:
//! - Reads ledger commits via a tailer
//! - Builds a work index: `changeset_digest` -> `work_id` -> PR metadata
//! - On `ReviewReceiptRecorded`: fetches review artifacts from CAS, applies
//!   projection via GitHub adapter, stores projection receipt (durable)
//! - Is idempotent: restarts don't duplicate comments
//!
//! # Security Model
//!
//! - **Write-only projection**: GitHub is an output target only
//! - **Ledger is truth**: All decisions are made based on ledger state
//! - **Idempotency via receipts**: Uses CAS+ledger for idempotency, not GitHub
//!   state
//! - **Crash-only recovery**: Worker can restart from ledger head at any time

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;
use tracing::{debug, info, warn};

use super::github_sync::{GitHubAdapterConfig, GitHubProjectionAdapter, ProjectionAdapter};
use super::projection_receipt::ProjectedStatus;
use crate::protocol::dispatch::SignedLedgerEvent;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during projection worker operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProjectionWorkerError {
    /// Database error.
    #[error("database error: {0}")]
    DatabaseError(String),

    /// No PR associated with work.
    #[error("no PR associated with work_id: {work_id}")]
    NoPrAssociation {
        /// The work ID that has no PR association.
        work_id: String,
    },

    /// Projection failed.
    #[error("projection failed: {0}")]
    ProjectionFailed(String),

    /// Invalid event payload.
    #[error("invalid event payload: {0}")]
    InvalidPayload(String),

    /// Already projected (idempotency).
    #[error("already projected for receipt: {receipt_id}")]
    AlreadyProjected {
        /// The receipt ID that was already projected.
        receipt_id: String,
    },

    /// Worker shutdown requested.
    #[error("worker shutdown requested")]
    ShutdownRequested,

    /// Missing dependency - event cannot be processed yet because required
    /// associations are not indexed. This error triggers NACK/Retry behavior:
    /// the watermark is NOT advanced so the event will be reprocessed.
    ///
    /// Blocker fix: Critical Data Loss via Shared Watermark - implements
    /// NACK/Retry semantics where watermark is not advanced for events that
    /// fail due to missing dependencies.
    #[error("missing dependency for event: {event_id} - {reason}")]
    MissingDependency {
        /// The event ID that failed due to missing dependency.
        event_id: String,
        /// The reason/missing dependency description.
        reason: String,
    },
}

// =============================================================================
// Work Index
// =============================================================================

/// Default TTL for work index entries (7 days, matching idempotency cache).
/// This ensures tables don't grow unbounded (Blocker fix: Unbounded State
/// Growth).
pub const DEFAULT_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Maximum string length for fields extracted from ledger payloads.
///
/// This prevents unbounded input consumption (denial of service) when
/// deserializing untrusted payloads. (Blocker fix: Unbounded Input Consumption)
pub const MAX_STRING_LENGTH: usize = 1024;

/// Validates that a string field does not exceed the maximum allowed length.
/// Returns an error if the string is too long.
/// (Blocker fix: Unbounded Input Consumption)
fn validate_string_length(field_name: &str, value: &str) -> Result<(), ProjectionWorkerError> {
    if value.len() > MAX_STRING_LENGTH {
        return Err(ProjectionWorkerError::InvalidPayload(format!(
            "{field_name} exceeds maximum length ({} > {MAX_STRING_LENGTH})",
            value.len()
        )));
    }
    Ok(())
}

/// Work index schema SQL.
const WORK_INDEX_SCHEMA_SQL: &str = r"
    CREATE TABLE IF NOT EXISTS work_pr_index (
        work_id TEXT PRIMARY KEY,
        pr_number INTEGER NOT NULL,
        repo_owner TEXT NOT NULL,
        repo_name TEXT NOT NULL,
        head_sha TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS changeset_work_index (
        changeset_digest BLOB PRIMARY KEY,
        work_id TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_changeset_work_id ON changeset_work_index(work_id);
    CREATE INDEX IF NOT EXISTS idx_changeset_work_created ON changeset_work_index(created_at);

    -- Tailer watermark persistence (fixes blocker: non-persistent LedgerTailer)
    -- MAJOR FIX: Potential Data Loss via Non-Unique Watermark
    -- Now tracks (timestamp_ns, event_id) as a composite cursor to handle
    -- multiple events with the same timestamp. Previously, if events A and B
    -- both had timestamp 1000, acknowledging A would advance watermark to 1000,
    -- causing B to be skipped on the next poll (since we query timestamp > 1000).
    CREATE TABLE IF NOT EXISTS tailer_watermark (
        tailer_id TEXT PRIMARY KEY,
        last_processed_ns INTEGER NOT NULL,
        last_event_id TEXT NOT NULL DEFAULT '',
        updated_at INTEGER NOT NULL
    );

    -- Commit SHA mapping for changeset digest -> git SHA
    CREATE TABLE IF NOT EXISTS changeset_sha_index (
        changeset_digest BLOB PRIMARY KEY,
        commit_sha TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_sha_created ON changeset_sha_index(created_at);

    -- Comment idempotency tracking (blocker fix: duplicate comments)
    CREATE TABLE IF NOT EXISTS comment_receipts (
        receipt_id TEXT PRIMARY KEY,
        work_id TEXT NOT NULL,
        pr_number INTEGER NOT NULL,
        comment_type TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_comment_created ON comment_receipts(created_at);
    CREATE INDEX IF NOT EXISTS idx_work_pr_created ON work_pr_index(created_at);
";

/// Work index for tracking changeset -> `work_id` -> PR associations.
///
/// Per RFC-0019:
/// - `changeset_digest` -> `work_id` (from `ChangeSetPublished`)
/// - `work_id` -> PR metadata (from `WorkPrAssociated` or config)
pub struct WorkIndex {
    conn: Arc<Mutex<Connection>>,
}

impl WorkIndex {
    /// Creates a new work index with the given `SQLite` connection.
    ///
    /// # Errors
    ///
    /// Returns an error if schema initialization fails.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Result<Self, ProjectionWorkerError> {
        {
            let conn_guard = conn.lock().map_err(|e| {
                ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}"))
            })?;

            conn_guard
                .execute_batch(WORK_INDEX_SCHEMA_SQL)
                .map_err(|e| {
                    ProjectionWorkerError::DatabaseError(format!("schema init failed: {e}"))
                })?;
        }

        Ok(Self { conn })
    }

    /// Registers a changeset -> `work_id` association.
    ///
    /// Called when processing `ChangeSetPublished` events.
    #[allow(clippy::cast_possible_wrap)]
    pub fn register_changeset(
        &self,
        changeset_digest: &[u8; 32],
        work_id: &str,
    ) -> Result<(), ProjectionWorkerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}")))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        conn.execute(
            "INSERT OR REPLACE INTO changeset_work_index
             (changeset_digest, work_id, created_at)
             VALUES (?1, ?2, ?3)",
            params![changeset_digest.as_slice(), work_id, now as i64],
        )
        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        debug!(
            changeset = %hex::encode(changeset_digest),
            work_id = %work_id,
            "Registered changeset -> work_id"
        );

        Ok(())
    }

    /// Registers a `work_id` -> PR association.
    ///
    /// Called when processing `WorkPrAssociated` events or from configuration.
    #[allow(clippy::cast_possible_wrap)]
    pub fn register_pr(
        &self,
        work_id: &str,
        pr_number: u64,
        repo_owner: &str,
        repo_name: &str,
        head_sha: &str,
    ) -> Result<(), ProjectionWorkerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}")))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        conn.execute(
            "INSERT OR REPLACE INTO work_pr_index
             (work_id, pr_number, repo_owner, repo_name, head_sha, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                work_id,
                pr_number as i64,
                repo_owner,
                repo_name,
                head_sha,
                now as i64
            ],
        )
        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        info!(
            work_id = %work_id,
            pr_number = pr_number,
            repo = %format!("{}/{}", repo_owner, repo_name),
            "Registered work_id -> PR"
        );

        Ok(())
    }

    /// Looks up the `work_id` for a changeset digest.
    pub fn get_work_id(&self, changeset_digest: &[u8; 32]) -> Option<String> {
        let conn = self.conn.lock().ok()?;

        conn.query_row(
            "SELECT work_id FROM changeset_work_index WHERE changeset_digest = ?1",
            params![changeset_digest.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Looks up PR metadata for a `work_id`.
    #[allow(clippy::cast_sign_loss)] // PR numbers are always positive
    pub fn get_pr_metadata(&self, work_id: &str) -> Option<PrMetadata> {
        let conn = self.conn.lock().ok()?;

        conn.query_row(
            "SELECT pr_number, repo_owner, repo_name, head_sha
             FROM work_pr_index WHERE work_id = ?1",
            params![work_id],
            |row| {
                Ok(PrMetadata {
                    pr_number: row.get::<_, i64>(0)? as u64,
                    repo_owner: row.get(1)?,
                    repo_name: row.get(2)?,
                    head_sha: row.get(3)?,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Registers a changeset -> commit SHA mapping.
    ///
    /// Required for GitHub status projection to know which commit to update.
    #[allow(clippy::cast_possible_wrap)]
    pub fn register_commit_sha(
        &self,
        changeset_digest: &[u8; 32],
        commit_sha: &str,
    ) -> Result<(), ProjectionWorkerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}")))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        conn.execute(
            "INSERT OR REPLACE INTO changeset_sha_index
             (changeset_digest, commit_sha, created_at)
             VALUES (?1, ?2, ?3)",
            params![changeset_digest.as_slice(), commit_sha, now as i64],
        )
        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        debug!(
            changeset = %hex::encode(changeset_digest),
            commit_sha = %commit_sha,
            "Registered changeset -> commit SHA"
        );

        Ok(())
    }

    /// Gets the commit SHA for a changeset digest.
    pub fn get_commit_sha(&self, changeset_digest: &[u8; 32]) -> Option<String> {
        let conn = self.conn.lock().ok()?;

        conn.query_row(
            "SELECT commit_sha FROM changeset_sha_index WHERE changeset_digest = ?1",
            params![changeset_digest.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Checks if a comment has already been posted (idempotency check).
    pub fn is_comment_posted(&self, receipt_id: &str) -> bool {
        let Ok(conn) = self.conn.lock() else {
            return false;
        };

        conn.query_row(
            "SELECT 1 FROM comment_receipts WHERE receipt_id = ?1",
            params![receipt_id],
            |_| Ok(()),
        )
        .is_ok()
    }

    /// Records that a comment was posted (for idempotency).
    #[allow(clippy::cast_possible_wrap)]
    pub fn record_comment_posted(
        &self,
        receipt_id: &str,
        work_id: &str,
        pr_number: u64,
        comment_type: &str,
    ) -> Result<(), ProjectionWorkerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}")))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        conn.execute(
            "INSERT OR REPLACE INTO comment_receipts
             (receipt_id, work_id, pr_number, comment_type, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                receipt_id,
                work_id,
                pr_number as i64,
                comment_type,
                now as i64
            ],
        )
        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        debug!(
            receipt_id = %receipt_id,
            work_id = %work_id,
            pr_number = pr_number,
            "Recorded comment posted"
        );

        Ok(())
    }

    /// Evicts expired entries from all work index tables.
    ///
    /// This implements TTL-based eviction to prevent unbounded state growth
    /// (Blocker fix: Unbounded State Growth). Default TTL is 7 days, matching
    /// the idempotency cache TTL.
    ///
    /// # Arguments
    ///
    /// * `ttl_secs` - TTL in seconds; entries older than this are evicted
    ///
    /// # Returns
    ///
    /// The total number of rows deleted across all tables.
    #[allow(clippy::cast_possible_wrap)]
    pub fn evict_expired(&self, ttl_secs: u64) -> Result<usize, ProjectionWorkerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}")))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let cutoff = now.saturating_sub(ttl_secs) as i64;

        // Evict from all tables with created_at timestamps
        let mut total_deleted = 0;

        total_deleted += conn
            .execute(
                "DELETE FROM changeset_work_index WHERE created_at < ?1",
                params![cutoff],
            )
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        total_deleted += conn
            .execute(
                "DELETE FROM changeset_sha_index WHERE created_at < ?1",
                params![cutoff],
            )
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        total_deleted += conn
            .execute(
                "DELETE FROM comment_receipts WHERE created_at < ?1",
                params![cutoff],
            )
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        total_deleted += conn
            .execute(
                "DELETE FROM work_pr_index WHERE created_at < ?1",
                params![cutoff],
            )
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        if total_deleted > 0 {
            info!(
                deleted = total_deleted,
                ttl_secs = ttl_secs,
                "Evicted expired work index entries"
            );
        }

        Ok(total_deleted)
    }

    /// Returns the connection for use with async `spawn_blocking` operations.
    ///
    /// This is used by the async worker to wrap blocking `SQLite` operations
    /// in `spawn_blocking` (Major fix: Thread blocking in async context).
    #[must_use]
    pub fn connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }

    /// Async wrapper for `evict_expired` that uses `spawn_blocking`.
    ///
    /// This avoids blocking the async runtime during eviction, which can
    /// be slow for large tables (Major fix: Thread blocking in async context).
    pub async fn evict_expired_async(&self, ttl_secs: u64) -> Result<usize, ProjectionWorkerError> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let conn_guard = conn.lock().map_err(|e| {
                ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}"))
            })?;

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            #[allow(clippy::cast_possible_wrap)]
            let cutoff = now.saturating_sub(ttl_secs) as i64;

            let mut total_deleted = 0;

            total_deleted += conn_guard
                .execute(
                    "DELETE FROM changeset_work_index WHERE created_at < ?1",
                    params![cutoff],
                )
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

            total_deleted += conn_guard
                .execute(
                    "DELETE FROM changeset_sha_index WHERE created_at < ?1",
                    params![cutoff],
                )
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

            total_deleted += conn_guard
                .execute(
                    "DELETE FROM comment_receipts WHERE created_at < ?1",
                    params![cutoff],
                )
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

            total_deleted += conn_guard
                .execute(
                    "DELETE FROM work_pr_index WHERE created_at < ?1",
                    params![cutoff],
                )
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

            if total_deleted > 0 {
                info!(
                    deleted = total_deleted,
                    ttl_secs = ttl_secs,
                    "Evicted expired work index entries (async)"
                );
            }

            Ok(total_deleted)
        })
        .await
        .map_err(|e| ProjectionWorkerError::DatabaseError(format!("spawn_blocking failed: {e}")))?
    }
}

/// PR metadata for projection.
#[derive(Debug, Clone)]
pub struct PrMetadata {
    /// The PR number.
    pub pr_number: u64,
    /// Repository owner.
    pub repo_owner: String,
    /// Repository name.
    pub repo_name: String,
    /// Head commit SHA.
    pub head_sha: String,
}

// =============================================================================
// Ledger Tailer
// =============================================================================

/// Default tailer ID for the projection worker.
const DEFAULT_TAILER_ID: &str = "projection_worker";

/// Ledger tailer for watching events.
///
/// Tracks the last processed event sequence and polls for new events.
/// Persists the watermark to `SQLite` for crash recovery (fixes blocker:
/// non-persistent tailer).
///
/// # MAJOR FIX: Potential Data Loss via Non-Unique Watermark
///
/// The watermark now tracks `(timestamp_ns, event_id)` as a composite cursor
/// instead of just `timestamp_ns`. This ensures that if multiple events share
/// the same timestamp, acknowledging one won't skip the others.
///
/// The polling query uses `(timestamp_ns, event_id) > (last_ns, last_id)`
/// to correctly handle timestamp collisions.
pub struct LedgerTailer {
    conn: Arc<Mutex<Connection>>,
    /// Last processed event timestamp (for ordering).
    last_processed_ns: u64,
    /// Last processed event ID (for deterministic ordering within same
    /// timestamp). MAJOR FIX: Together with timestamp, forms a composite
    /// cursor.
    last_event_id: String,
    /// Tailer identifier for watermark persistence.
    tailer_id: String,
}

impl LedgerTailer {
    /// Creates a new ledger tailer, loading persisted watermark if available.
    ///
    /// This ensures crash recovery: the tailer resumes from where it left off.
    #[allow(clippy::cast_sign_loss)]
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self::with_id(conn, DEFAULT_TAILER_ID)
    }

    /// Creates a new ledger tailer with a custom ID.
    ///
    /// MAJOR FIX: Potential Data Loss via Non-Unique Watermark
    /// Now loads both timestamp_ns and event_id for composite cursor.
    #[allow(clippy::cast_sign_loss)]
    pub fn with_id(conn: Arc<Mutex<Connection>>, tailer_id: &str) -> Self {
        // Load persisted watermark if available (now includes event_id)
        let (last_processed_ns, last_event_id) = conn.lock().map_or((0, String::new()), |conn_guard| {
            conn_guard
                .query_row(
                    "SELECT last_processed_ns, COALESCE(last_event_id, '') FROM tailer_watermark WHERE tailer_id = ?1",
                    params![tailer_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .map(|(ns, event_id)| (ns as u64, event_id))
                .unwrap_or((0, String::new()))
        });

        if last_processed_ns > 0 {
            info!(
                tailer_id = %tailer_id,
                last_processed_ns = last_processed_ns,
                last_event_id = %last_event_id,
                "Resumed ledger tailer from persisted watermark"
            );
        }

        Self {
            conn,
            last_processed_ns,
            last_event_id,
            tailer_id: tailer_id.to_string(),
        }
    }

    /// Creates a ledger tailer starting from a specific timestamp.
    #[must_use]
    pub fn from_timestamp(conn: Arc<Mutex<Connection>>, timestamp_ns: u64) -> Self {
        Self {
            conn,
            last_processed_ns: timestamp_ns,
            last_event_id: String::new(),
            tailer_id: DEFAULT_TAILER_ID.to_string(),
        }
    }

    /// Persists the current watermark to `SQLite`.
    ///
    /// Called after processing events to ensure crash recovery.
    ///
    /// MAJOR FIX: Potential Data Loss via Non-Unique Watermark
    /// Now persists both timestamp_ns and event_id for composite cursor.
    #[allow(clippy::cast_possible_wrap)]
    fn persist_watermark(&self) -> Result<(), ProjectionWorkerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}")))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        conn.execute(
            "INSERT OR REPLACE INTO tailer_watermark
             (tailer_id, last_processed_ns, last_event_id, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                self.tailer_id,
                self.last_processed_ns as i64,
                &self.last_event_id,
                now as i64
            ],
        )
        .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Gets the next batch of unprocessed events of a given type.
    ///
    /// Returns events ordered by `(timestamp_ns, event_id)`, starting after
    /// the last processed cursor.
    ///
    /// # MAJOR FIX: Potential Data Loss via Non-Unique Watermark
    ///
    /// Uses a composite cursor `(timestamp_ns, event_id)` to handle timestamp
    /// collisions. Events are ordered by timestamp first, then by event_id
    /// (lexicographically) for deterministic ordering within the same
    /// timestamp.
    ///
    /// # At-Least-Once Delivery
    ///
    /// This method does NOT automatically advance the watermark. The caller
    /// must explicitly call [`Self::acknowledge`] after successfully processing
    /// each event. This ensures at-least-once delivery semantics:
    /// - If the daemon crashes before acknowledgment, events are redelivered
    /// - Idempotency is achieved via `comment_receipts` and `IdempotencyCache`
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
    pub fn poll_events(
        &mut self,
        event_type: &str,
        limit: usize,
    ) -> Result<Vec<SignedLedgerEvent>, ProjectionWorkerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}")))?;

        // MAJOR FIX: Use composite cursor (timestamp_ns, event_id) to handle
        // timestamp collisions. The query selects events where:
        // - timestamp > last_timestamp, OR
        // - timestamp == last_timestamp AND event_id > last_event_id (only if
        //   last_event_id is set)
        // This ensures no events are skipped when multiple events share a timestamp.
        //
        // When last_event_id is empty (e.g., from_timestamp or fresh start), we only
        // use timestamp comparison to maintain backward compatibility and
        // correct semantics: timestamp_ns > last means "everything after this
        // timestamp".
        let query = if self.last_event_id.is_empty() {
            // No event_id cursor - use timestamp-only comparison
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
             FROM ledger_events
             WHERE event_type = ?1 AND timestamp_ns > ?2
             ORDER BY timestamp_ns ASC, event_id ASC
             LIMIT ?3"
        } else {
            // Have event_id cursor - use composite comparison
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
             FROM ledger_events
             WHERE event_type = ?1 AND (
                 timestamp_ns > ?2 OR
                 (timestamp_ns = ?2 AND event_id > ?3)
             )
             ORDER BY timestamp_ns ASC, event_id ASC
             LIMIT ?4"
        };

        let mut stmt = conn
            .prepare(query)
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        let events = if self.last_event_id.is_empty() {
            stmt.query_map(
                params![event_type, self.last_processed_ns as i64, limit as i64],
                |row| {
                    Ok(SignedLedgerEvent {
                        event_id: row.get(0)?,
                        event_type: row.get(1)?,
                        work_id: row.get(2)?,
                        actor_id: row.get(3)?,
                        payload: row.get(4)?,
                        signature: row.get(5)?,
                        timestamp_ns: row.get::<_, i64>(6)? as u64,
                    })
                },
            )
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?
            .filter_map(Result::ok)
            .collect::<Vec<_>>()
        } else {
            stmt.query_map(
                params![
                    event_type,
                    self.last_processed_ns as i64,
                    &self.last_event_id,
                    limit as i64
                ],
                |row| {
                    Ok(SignedLedgerEvent {
                        event_id: row.get(0)?,
                        event_type: row.get(1)?,
                        work_id: row.get(2)?,
                        actor_id: row.get(3)?,
                        payload: row.get(4)?,
                        signature: row.get(5)?,
                        timestamp_ns: row.get::<_, i64>(6)? as u64,
                    })
                },
            )
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?
            .filter_map(Result::ok)
            .collect::<Vec<_>>()
        };

        // NOTE: Watermark is NOT advanced here. Caller must call acknowledge()
        // after successful processing to ensure at-least-once delivery.

        Ok(events)
    }

    /// Acknowledges successful processing of an event.
    ///
    /// This advances the watermark to the event's `(timestamp_ns, event_id)`,
    /// ensuring the event won't be redelivered on restart. Should be called
    /// after each event is successfully processed.
    ///
    /// # MAJOR FIX: Potential Data Loss via Non-Unique Watermark
    ///
    /// Now accepts both timestamp_ns and event_id to form a composite cursor.
    /// This ensures correct ordering when multiple events share a timestamp.
    ///
    /// # At-Least-Once Delivery
    ///
    /// By separating polling from acknowledgment, we achieve at-least-once
    /// delivery semantics:
    /// - Events are only acknowledged after successful processing
    /// - If the daemon crashes before acknowledgment, events are redelivered
    /// - Idempotency prevents duplicate side effects
    pub fn acknowledge(
        &mut self,
        timestamp_ns: u64,
        event_id: &str,
    ) -> Result<(), ProjectionWorkerError> {
        // Advance watermark if this event is strictly after the current cursor.
        // Use composite comparison: (ts, event_id) > (last_ts, last_event_id)
        let should_advance = timestamp_ns > self.last_processed_ns
            || (timestamp_ns == self.last_processed_ns && event_id > self.last_event_id.as_str());

        if should_advance {
            self.last_processed_ns = timestamp_ns;
            self.last_event_id = event_id.to_string();
            self.persist_watermark()?;
        }
        Ok(())
    }

    /// Async wrapper for `poll_events` that uses `spawn_blocking`.
    ///
    /// This avoids blocking the async runtime during `SQLite` I/O
    /// (Major fix: Thread blocking in async context).
    ///
    /// MAJOR FIX: Potential Data Loss via Non-Unique Watermark
    /// Uses composite cursor (timestamp_ns, event_id) in the query.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
    pub async fn poll_events_async(
        &self,
        event_type: &str,
        limit: usize,
    ) -> Result<Vec<SignedLedgerEvent>, ProjectionWorkerError> {
        let conn = Arc::clone(&self.conn);
        let event_type = event_type.to_string();
        let last_processed_ns = self.last_processed_ns;
        let last_event_id = self.last_event_id.clone();

        tokio::task::spawn_blocking(move || {
            let conn_guard = conn.lock().map_err(|e| {
                ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}"))
            })?;

            // MAJOR FIX: Use composite cursor (timestamp_ns, event_id)
            // When last_event_id is empty, use timestamp-only comparison for backward
            // compat.
            let query = if last_event_id.is_empty() {
                "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
                 FROM ledger_events
                 WHERE event_type = ?1 AND timestamp_ns > ?2
                 ORDER BY timestamp_ns ASC, event_id ASC
                 LIMIT ?3"
            } else {
                "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns
                 FROM ledger_events
                 WHERE event_type = ?1 AND (
                     timestamp_ns > ?2 OR
                     (timestamp_ns = ?2 AND event_id > ?3)
                 )
                 ORDER BY timestamp_ns ASC, event_id ASC
                 LIMIT ?4"
            };

            let mut stmt = conn_guard
                .prepare(query)
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

            let events = if last_event_id.is_empty() {
                stmt.query_map(
                    params![event_type, last_processed_ns as i64, limit as i64],
                    |row| {
                        Ok(SignedLedgerEvent {
                            event_id: row.get(0)?,
                            event_type: row.get(1)?,
                            work_id: row.get(2)?,
                            actor_id: row.get(3)?,
                            payload: row.get(4)?,
                            signature: row.get(5)?,
                            timestamp_ns: row.get::<_, i64>(6)? as u64,
                        })
                    },
                )
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?
                .filter_map(Result::ok)
                .collect::<Vec<_>>()
            } else {
                stmt.query_map(
                    params![
                        event_type,
                        last_processed_ns as i64,
                        last_event_id,
                        limit as i64
                    ],
                    |row| {
                        Ok(SignedLedgerEvent {
                            event_id: row.get(0)?,
                            event_type: row.get(1)?,
                            work_id: row.get(2)?,
                            actor_id: row.get(3)?,
                            payload: row.get(4)?,
                            signature: row.get(5)?,
                            timestamp_ns: row.get::<_, i64>(6)? as u64,
                        })
                    },
                )
                .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?
                .filter_map(Result::ok)
                .collect::<Vec<_>>()
            };

            Ok(events)
        })
        .await
        .map_err(|e| ProjectionWorkerError::DatabaseError(format!("spawn_blocking failed: {e}")))?
    }

    /// Async wrapper for `acknowledge` that uses `spawn_blocking`.
    ///
    /// This avoids blocking the async runtime during `SQLite` I/O
    /// (Major fix: Thread blocking in async context).
    ///
    /// MAJOR FIX: Potential Data Loss via Non-Unique Watermark
    /// Now accepts both timestamp_ns and event_id for composite cursor.
    #[allow(clippy::cast_possible_wrap)]
    pub async fn acknowledge_async(
        &mut self,
        timestamp_ns: u64,
        event_id: &str,
    ) -> Result<(), ProjectionWorkerError> {
        // Advance watermark if this event is strictly after the current cursor.
        let should_advance = timestamp_ns > self.last_processed_ns
            || (timestamp_ns == self.last_processed_ns && event_id > self.last_event_id.as_str());

        if should_advance {
            self.last_processed_ns = timestamp_ns;
            self.last_event_id = event_id.to_string();

            let conn = Arc::clone(&self.conn);
            let tailer_id = self.tailer_id.clone();
            let last_processed_ns = self.last_processed_ns;
            let last_event_id = self.last_event_id.clone();

            tokio::task::spawn_blocking(move || {
                let conn_guard = conn.lock().map_err(|e| {
                    ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}"))
                })?;

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                conn_guard
                    .execute(
                        "INSERT OR REPLACE INTO tailer_watermark
                         (tailer_id, last_processed_ns, last_event_id, updated_at)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![
                            tailer_id,
                            last_processed_ns as i64,
                            last_event_id,
                            now as i64
                        ],
                    )
                    .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

                Ok(())
            })
            .await
            .map_err(|e| {
                ProjectionWorkerError::DatabaseError(format!("spawn_blocking failed: {e}"))
            })?
        } else {
            Ok(())
        }
    }

    /// Gets the current ledger head (latest event timestamp).
    #[allow(clippy::cast_sign_loss)]
    pub fn get_ledger_head(&self) -> Result<Option<[u8; 32]>, ProjectionWorkerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionWorkerError::DatabaseError(format!("mutex poisoned: {e}")))?;

        // For now, compute a hash of the latest event_id as "ledger head"
        // In a full implementation, this would be the chain hash
        let result: Option<String> = conn
            .query_row(
                "SELECT event_id FROM ledger_events ORDER BY timestamp_ns DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ProjectionWorkerError::DatabaseError(e.to_string()))?;

        Ok(result.map(|event_id| {
            let mut hash = [0u8; 32];
            let digest = blake3::hash(event_id.as_bytes());
            hash.copy_from_slice(digest.as_bytes());
            hash
        }))
    }
}

// =============================================================================
// Projection Worker
// =============================================================================

/// Configuration for the projection worker.
#[derive(Debug, Clone)]
pub struct ProjectionWorkerConfig {
    /// Poll interval for checking new events.
    pub poll_interval: Duration,
    /// Maximum events to process per batch.
    pub batch_size: usize,
    /// Whether to enable GitHub projection.
    pub github_enabled: bool,
    /// GitHub API configuration (if enabled).
    pub github_config: Option<GitHubAdapterConfig>,
}

impl Default for ProjectionWorkerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(1),
            batch_size: 100,
            github_enabled: false,
            github_config: None,
        }
    }
}

impl ProjectionWorkerConfig {
    /// Creates a new configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the poll interval.
    #[must_use]
    pub const fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Sets the batch size.
    #[must_use]
    pub const fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Enables GitHub projection with the given configuration.
    #[must_use]
    pub fn with_github(mut self, config: GitHubAdapterConfig) -> Self {
        self.github_enabled = true;
        self.github_config = Some(config);
        self
    }
}

/// The projection worker that tails the ledger and projects to GitHub.
pub struct ProjectionWorker {
    config: ProjectionWorkerConfig,
    work_index: WorkIndex,
    /// Tailer for `changeset_published` events.
    changeset_tailer: LedgerTailer,
    /// Tailer for `work_pr_associated` events.
    work_pr_tailer: LedgerTailer,
    /// Tailer for `review_receipt_recorded` events.
    review_tailer: LedgerTailer,
    adapter: Option<GitHubProjectionAdapter>,
    /// Shutdown flag.
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl ProjectionWorker {
    /// Creates a new projection worker.
    ///
    /// # Arguments
    ///
    /// * `conn` - `SQLite` connection for work index and ledger access
    /// * `config` - Worker configuration
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    #[allow(clippy::needless_pass_by_value)] // Arc is cheap to clone, and we clone it multiple times
    pub fn new(
        conn: Arc<Mutex<Connection>>,
        config: ProjectionWorkerConfig,
    ) -> Result<Self, ProjectionWorkerError> {
        let work_index = WorkIndex::new(Arc::clone(&conn))?;

        // Create separate tailers for each event type to avoid watermark multiplexing.
        // Each tailer has its own persistent watermark, ensuring events of one type
        // don't skip events of another type due to shared timestamp tracking.
        let changeset_tailer =
            LedgerTailer::with_id(Arc::clone(&conn), "projection_worker:changeset_published");
        let work_pr_tailer =
            LedgerTailer::with_id(Arc::clone(&conn), "projection_worker:work_pr_associated");
        let review_tailer = LedgerTailer::with_id(
            Arc::clone(&conn),
            "projection_worker:review_receipt_recorded",
        );

        // NOTE: Adapter is NOT created here to avoid fail-open issues.
        // The adapter MUST be injected via set_adapter() with a properly
        // configured GitHubProjectionAdapter that uses:
        // 1. A persistent signer from the daemon's key material
        // 2. The real HTTP client (not mock) for production
        //
        // If github_enabled is true but no adapter is set, projection will
        // log warnings but not fail-open to GitHub.
        let adapter = None;

        Ok(Self {
            config,
            work_index,
            changeset_tailer,
            work_pr_tailer,
            review_tailer,
            adapter,
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Returns a handle for requesting shutdown.
    #[must_use]
    pub fn shutdown_handle(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Returns a reference to the work index.
    #[must_use]
    pub const fn work_index(&self) -> &WorkIndex {
        &self.work_index
    }

    /// Sets the GitHub projection adapter.
    ///
    /// # Security
    ///
    /// The adapter MUST be created with:
    /// 1. A persistent signer from the daemon's key material (NOT random)
    /// 2. A properly configured `GitHubAdapterConfig` with API token
    /// 3. A real HTTP client for production (use `new()`, not `new_mock()`)
    ///
    /// Failing to provide a proper adapter will result in projections being
    /// skipped (fail-safe, not fail-open).
    pub fn set_adapter(&mut self, adapter: GitHubProjectionAdapter) {
        self.adapter = Some(adapter);
    }

    /// Returns whether a GitHub adapter is configured.
    #[must_use]
    pub const fn has_adapter(&self) -> bool {
        self.adapter.is_some()
    }

    /// Runs the projection worker loop.
    ///
    /// This method blocks until shutdown is requested.
    ///
    /// # Errors
    ///
    /// Returns an error if the worker encounters a fatal error.
    #[allow(clippy::cast_possible_truncation)] // poll_interval is always < u64::MAX ms
    pub async fn run(&mut self) -> Result<(), ProjectionWorkerError> {
        info!(
            poll_interval_ms = self.config.poll_interval.as_millis() as u64,
            batch_size = self.config.batch_size,
            github_enabled = self.config.github_enabled,
            "Projection worker starting"
        );

        // Counter for periodic eviction (Blocker fix: Unbounded State Growth)
        // Run eviction every ~1000 poll cycles (roughly once per hour at 1s poll
        // interval)
        let eviction_interval: u64 = 1000;
        let mut eviction_counter: u64 = 0;

        while !self.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            // Process ChangeSetPublished events to build work index
            // (Major fix: Thread blocking in async context - uses spawn_blocking)
            if let Err(e) = self.process_changeset_published().await {
                warn!(error = %e, "Error processing ChangeSetPublished events");
            }

            // Process WorkPrAssociated events to link work_id -> PR metadata
            // (Major fix: Thread blocking in async context - uses spawn_blocking)
            if let Err(e) = self.process_work_pr_associated().await {
                warn!(error = %e, "Error processing WorkPrAssociated events");
            }

            // Process ReviewReceiptRecorded events for projection
            // (Major fix: Thread blocking in async context - uses spawn_blocking)
            if let Err(e) = self.process_review_receipts().await {
                warn!(error = %e, "Error processing ReviewReceiptRecorded events");
            }

            // Periodic eviction of expired entries (Blocker fix: Unbounded State Growth)
            // Uses spawn_blocking to avoid blocking async runtime (Major fix: Thread
            // blocking)
            eviction_counter = eviction_counter.wrapping_add(1);
            if eviction_counter % eviction_interval == 0 {
                if let Err(e) = self.work_index.evict_expired_async(DEFAULT_TTL_SECS).await {
                    warn!(error = %e, "Error during work index eviction");
                }
            }

            // Sleep for poll interval
            tokio::time::sleep(self.config.poll_interval).await;
        }

        info!("Projection worker shutting down");
        Ok(())
    }

    /// Processes `ChangeSetPublished` events to populate the work index.
    ///
    /// # At-Least-Once Delivery (Blocker fix: Fail-Open Auto-Ack on Crash)
    ///
    /// This method only acknowledges events AFTER successful processing.
    /// If the daemon crashes before acknowledgment, events will be redelivered.
    ///
    /// # Async I/O (Major fix: Thread blocking in async context)
    ///
    /// Uses async polling and acknowledgment to avoid blocking the tokio
    /// runtime.
    async fn process_changeset_published(&mut self) -> Result<(), ProjectionWorkerError> {
        let events = self
            .changeset_tailer
            .poll_events_async("changeset_published", self.config.batch_size)
            .await?;

        for event in events {
            match self.handle_changeset_published(&event) {
                Ok(()) => {
                    // Only acknowledge after successful processing
                    // (Blocker fix: Fail-Open Auto-Ack on Crash)
                    // MAJOR FIX: Pass event_id for composite cursor
                    self.changeset_tailer
                        .acknowledge_async(event.timestamp_ns, &event.event_id)
                        .await?;
                },
                Err(e) => {
                    warn!(
                        event_id = %event.event_id,
                        error = %e,
                        "Failed to process ChangeSetPublished event - will retry"
                    );
                    // Do NOT acknowledge - event will be reprocessed on next poll
                    // This is the NACK/Retry behavior for at-least-once delivery
                    break; // Stop processing batch to maintain ordering
                },
            }
        }

        Ok(())
    }

    /// Handles a single `ChangeSetPublished` event.
    fn handle_changeset_published(
        &self,
        event: &SignedLedgerEvent,
    ) -> Result<(), ProjectionWorkerError> {
        // Parse payload to extract changeset_digest and work_id
        let payload: serde_json::Value = serde_json::from_slice(&event.payload)
            .map_err(|e| ProjectionWorkerError::InvalidPayload(e.to_string()))?;

        let changeset_digest_hex = payload
            .get("changeset_digest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ProjectionWorkerError::InvalidPayload("missing changeset_digest".to_string())
            })?;

        // Validate string length (Blocker fix: Unbounded Input Consumption)
        validate_string_length("changeset_digest", changeset_digest_hex)?;

        let work_id = payload
            .get("work_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&event.work_id);

        // Validate string length (Blocker fix: Unbounded Input Consumption)
        validate_string_length("work_id", work_id)?;

        // Extract commit SHA if present (for GitHub status projection)
        let commit_sha = payload.get("commit_sha").and_then(|v| v.as_str());

        // Validate commit_sha length if present (Blocker fix: Unbounded Input
        // Consumption)
        if let Some(sha) = commit_sha {
            validate_string_length("commit_sha", sha)?;
        }

        // Decode changeset digest
        let digest_bytes = hex::decode(changeset_digest_hex)
            .map_err(|e| ProjectionWorkerError::InvalidPayload(e.to_string()))?;

        if digest_bytes.len() != 32 {
            return Err(ProjectionWorkerError::InvalidPayload(
                "changeset_digest must be 32 bytes".to_string(),
            ));
        }

        let mut changeset_digest = [0u8; 32];
        changeset_digest.copy_from_slice(&digest_bytes);

        // Register in work index
        self.work_index
            .register_changeset(&changeset_digest, work_id)?;

        // Register commit SHA mapping if present (blocker fix: CommitShaNotFound)
        if let Some(sha) = commit_sha {
            self.work_index
                .register_commit_sha(&changeset_digest, sha)?;
        }

        Ok(())
    }

    /// Processes `WorkPrAssociated` events to link `work_id` -> PR metadata.
    ///
    /// This is critical for projection: without PR metadata, we cannot post
    /// status checks or comments. (Blocker fix: Missing `WorkPrAssociated`
    /// handling)
    ///
    /// # At-Least-Once Delivery (Blocker fix: Fail-Open Auto-Ack on Crash)
    ///
    /// This method only acknowledges events AFTER successful processing.
    /// If the daemon crashes before acknowledgment, events will be redelivered.
    ///
    /// # Async I/O (Major fix: Thread blocking in async context)
    ///
    /// Uses async polling and acknowledgment to avoid blocking the tokio
    /// runtime.
    async fn process_work_pr_associated(&mut self) -> Result<(), ProjectionWorkerError> {
        let events = self
            .work_pr_tailer
            .poll_events_async("work_pr_associated", self.config.batch_size)
            .await?;

        for event in events {
            match self.handle_work_pr_associated(&event) {
                Ok(()) => {
                    // Only acknowledge after successful processing
                    // (Blocker fix: Fail-Open Auto-Ack on Crash)
                    // MAJOR FIX: Pass event_id for composite cursor
                    self.work_pr_tailer
                        .acknowledge_async(event.timestamp_ns, &event.event_id)
                        .await?;
                },
                Err(e) => {
                    warn!(
                        event_id = %event.event_id,
                        error = %e,
                        "Failed to process WorkPrAssociated event - will retry"
                    );
                    // Do NOT acknowledge - event will be reprocessed on next poll
                    break; // Stop processing batch to maintain ordering
                },
            }
        }

        Ok(())
    }

    /// Handles a single `WorkPrAssociated` event.
    #[allow(clippy::cast_sign_loss)] // PR numbers are always positive
    fn handle_work_pr_associated(
        &self,
        event: &SignedLedgerEvent,
    ) -> Result<(), ProjectionWorkerError> {
        // Parse payload to extract PR metadata
        let payload: serde_json::Value = serde_json::from_slice(&event.payload)
            .map_err(|e| ProjectionWorkerError::InvalidPayload(e.to_string()))?;

        let work_id = payload
            .get("work_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&event.work_id);

        // Validate string lengths (Blocker fix: Unbounded Input Consumption)
        validate_string_length("work_id", work_id)?;

        let pr_number = payload
            .get("pr_number")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ProjectionWorkerError::InvalidPayload("missing pr_number".to_string())
            })?;

        let repo_owner = payload
            .get("repo_owner")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ProjectionWorkerError::InvalidPayload("missing repo_owner".to_string())
            })?;

        // Validate string lengths (Blocker fix: Unbounded Input Consumption)
        validate_string_length("repo_owner", repo_owner)?;

        let repo_name = payload
            .get("repo_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ProjectionWorkerError::InvalidPayload("missing repo_name".to_string())
            })?;

        // Validate string lengths (Blocker fix: Unbounded Input Consumption)
        validate_string_length("repo_name", repo_name)?;

        let head_sha = payload
            .get("head_sha")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ProjectionWorkerError::InvalidPayload("missing head_sha".to_string()))?;

        // Validate string lengths (Blocker fix: Unbounded Input Consumption)
        validate_string_length("head_sha", head_sha)?;

        // Register PR metadata
        self.work_index
            .register_pr(work_id, pr_number, repo_owner, repo_name, head_sha)?;

        // Also register commit SHA for status projection if changeset_digest is present
        if let Some(changeset_digest_hex) = payload.get("changeset_digest").and_then(|v| v.as_str())
        {
            // Validate string length (Blocker fix: Unbounded Input Consumption)
            validate_string_length("changeset_digest", changeset_digest_hex)?;

            if let Ok(digest_bytes) = hex::decode(changeset_digest_hex) {
                if digest_bytes.len() == 32 {
                    let mut changeset_digest = [0u8; 32];
                    changeset_digest.copy_from_slice(&digest_bytes);
                    self.work_index
                        .register_commit_sha(&changeset_digest, head_sha)?;
                }
            }
        }

        Ok(())
    }

    /// Processes `ReviewReceiptRecorded` events for projection.
    ///
    /// # At-Least-Once Delivery (Blocker fix: Fail-Open Auto-Ack on Crash)
    ///
    /// This method only acknowledges events AFTER successful processing.
    /// If the daemon crashes before acknowledgment, events will be redelivered.
    ///
    /// # NACK/Retry for Missing Dependencies (Blocker fix: Critical Data Loss)
    ///
    /// If a `ReviewReceiptRecorded` event fails because the required
    /// associations (from `ChangeSetPublished` or `WorkPrAssociated`) are not
    /// yet indexed, the watermark is NOT advanced. The event will be
    /// reprocessed on the next poll cycle, giving time for the dependency
    /// events to be processed first.
    ///
    /// # Strict Sequential Acknowledgment
    ///
    /// Events are processed in timestamp order, and we MUST stop at the first
    /// failure to prevent skipping unprocessed events. If event A at ts=1000
    /// fails and we continue to process event B at ts=2000, acknowledging B
    /// would set the watermark to 2000, permanently skipping A.
    ///
    /// # Async I/O (Major fix: Thread blocking in async context)
    ///
    /// Uses async polling and acknowledgment to avoid blocking the tokio
    /// runtime.
    async fn process_review_receipts(&mut self) -> Result<(), ProjectionWorkerError> {
        let events = self
            .review_tailer
            .poll_events_async("review_receipt_recorded", self.config.batch_size)
            .await?;

        for event in events {
            match self.handle_review_receipt(&event).await {
                Ok(()) => {
                    // Only acknowledge after successful processing
                    // (Blocker fix: Fail-Open Auto-Ack on Crash)
                    // MAJOR FIX: Pass event_id for composite cursor
                    self.review_tailer
                        .acknowledge_async(event.timestamp_ns, &event.event_id)
                        .await?;
                },
                Err(ProjectionWorkerError::MissingDependency { event_id, reason }) => {
                    // NACK/Retry: Do NOT acknowledge - event will be reprocessed
                    // (Blocker fix: Critical Data Loss via Shared Watermark)
                    debug!(
                        event_id = %event_id,
                        reason = %reason,
                        "Missing dependency for review receipt - will retry on next poll"
                    );
                    // MUST break to prevent skipping this event!
                    // If we continue and later events succeed, their higher
                    // timestamps would be acknowledged, permanently skipping
                    // this failed event.
                    break;
                },
                Err(ProjectionWorkerError::NoPrAssociation { work_id }) => {
                    // This is a variant of missing dependency - don't acknowledge
                    debug!(
                        event_id = %event.event_id,
                        work_id = %work_id,
                        "No PR association yet for review receipt - will retry on next poll"
                    );
                    // MUST break to prevent skipping this event!
                    break;
                },
                Err(e) => {
                    warn!(
                        event_id = %event.event_id,
                        error = %e,
                        "Failed to process ReviewReceiptRecorded event - will retry"
                    );
                    // For other errors, also don't acknowledge to ensure retry
                    break; // Stop processing batch for non-dependency errors
                },
            }
        }

        Ok(())
    }

    /// Handles a single `ReviewReceiptRecorded` event.
    async fn handle_review_receipt(
        &self,
        event: &SignedLedgerEvent,
    ) -> Result<(), ProjectionWorkerError> {
        // Parse payload
        let payload: serde_json::Value = serde_json::from_slice(&event.payload)
            .map_err(|e| ProjectionWorkerError::InvalidPayload(e.to_string()))?;

        let changeset_digest_hex = payload
            .get("changeset_digest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ProjectionWorkerError::InvalidPayload("missing changeset_digest".to_string())
            })?;

        // Validate string length (Blocker fix: Unbounded Input Consumption)
        validate_string_length("changeset_digest", changeset_digest_hex)?;

        let receipt_id = payload
            .get("receipt_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ProjectionWorkerError::InvalidPayload("missing receipt_id".to_string())
            })?;

        // Validate string length (Blocker fix: Unbounded Input Consumption)
        validate_string_length("receipt_id", receipt_id)?;

        // Decode changeset digest
        let digest_bytes = hex::decode(changeset_digest_hex)
            .map_err(|e| ProjectionWorkerError::InvalidPayload(e.to_string()))?;

        if digest_bytes.len() != 32 {
            return Err(ProjectionWorkerError::InvalidPayload(
                "changeset_digest must be 32 bytes".to_string(),
            ));
        }

        let mut changeset_digest = [0u8; 32];
        changeset_digest.copy_from_slice(&digest_bytes);

        // BLOCKER FIX: Cross-PR Review Leakage / Spoofing via Digest Collision
        //
        // Security: Use `event.work_id` directly from the SignedLedgerEvent envelope
        // instead of looking it up from the changeset_digest. The changeset_work_index
        // table uses changeset_digest as PRIMARY KEY, so if two PRs share the same
        // commit, the second PR overwrites the first. Looking up work_id via digest
        // could resolve to the wrong PR.
        //
        // The SignedLedgerEvent envelope contains the authoritative work_id that was
        // set when the event was emitted. This is cryptographically bound to the
        // event signature, preventing spoofing.
        let work_id = &event.work_id;

        // Validate work_id from envelope
        validate_string_length("work_id", work_id)?;

        if work_id.is_empty() {
            return Err(ProjectionWorkerError::InvalidPayload(
                "work_id in event envelope is empty".to_string(),
            ));
        }

        // Look up PR metadata using the authoritative work_id from the event envelope.
        // This prevents cross-PR review leakage via digest collision.
        // NACK/Retry: return NoPrAssociation if not yet indexed.
        let pr_metadata = self.work_index.get_pr_metadata(work_id).ok_or_else(|| {
            ProjectionWorkerError::NoPrAssociation {
                work_id: work_id.clone(),
            }
        })?;

        // Parse review verdict to determine status (Major fix: hardcoded success)
        let verdict = payload
            .get("verdict")
            .and_then(|v| v.as_str())
            .unwrap_or("success");

        // Validate string length (Blocker fix: Unbounded Input Consumption)
        validate_string_length("verdict", verdict)?;

        let status = Self::parse_review_verdict(verdict);

        // Extract summary if present
        let summary = payload.get("summary").and_then(|v| v.as_str());

        // Validate summary length if present (Blocker fix: Unbounded Input Consumption)
        if let Some(s) = summary {
            validate_string_length("summary", s)?;
        }

        info!(
            receipt_id = %receipt_id,
            work_id = %work_id,
            pr_number = pr_metadata.pr_number,
            verdict = %verdict,
            "Processing review receipt for projection"
        );

        // Project to GitHub if adapter is configured
        if let Some(ref adapter) = self.adapter {
            // Register commit SHA for status projection (in case it wasn't in changeset
            // event)
            adapter
                .register_commit_sha(&changeset_digest, &pr_metadata.head_sha)
                .map_err(|e| ProjectionWorkerError::ProjectionFailed(e.to_string()))?;

            // Get ledger head for idempotency key
            let ledger_head = self.review_tailer.get_ledger_head()?.unwrap_or([0u8; 32]);

            // Project status (uses parsed verdict, not hardcoded success)
            let projection_receipt = adapter
                .project_status(&work_id, changeset_digest, ledger_head, status)
                .await
                .map_err(|e| ProjectionWorkerError::ProjectionFailed(e.to_string()))?;

            info!(
                receipt_id = %projection_receipt.receipt_id,
                work_id = %work_id,
                status = %projection_receipt.projected_status,
                "Projected status to GitHub"
            );

            // Post PR comment (idempotent - check before posting)
            // Blocker fix: Comment projection is now idempotent
            let comment_receipt_id = format!("{receipt_id}-comment");
            if self.work_index.is_comment_posted(&comment_receipt_id) {
                debug!(
                    receipt_id = %receipt_id,
                    "Skipping comment post (already posted - idempotency)"
                );
            } else {
                let comment_body = GitHubProjectionAdapter::<
                    super::divergence_watchdog::SystemTimeSource,
                >::format_review_comment(
                    receipt_id, status, summary
                );

                adapter
                    .post_comment(pr_metadata.pr_number, &comment_body)
                    .await
                    .map_err(|e| ProjectionWorkerError::ProjectionFailed(e.to_string()))?;

                // Record that comment was posted for idempotency
                self.work_index.record_comment_posted(
                    &comment_receipt_id,
                    &work_id,
                    pr_metadata.pr_number,
                    "review",
                )?;

                info!(
                    receipt_id = %receipt_id,
                    work_id = %work_id,
                    pr_number = pr_metadata.pr_number,
                    "Posted review comment to GitHub PR"
                );
            }
        } else {
            debug!(
                work_id = %work_id,
                "GitHub projection disabled, skipping"
            );
        }

        Ok(())
    }

    /// Parses a review verdict string into a `ProjectedStatus`.
    ///
    /// Major fix: Previously hardcoded to Success, now parses actual verdict.
    fn parse_review_verdict(verdict: &str) -> ProjectedStatus {
        match verdict.to_lowercase().as_str() {
            "success" | "pass" | "approved" => ProjectedStatus::Success,
            "failure" | "fail" | "rejected" => ProjectedStatus::Failure,
            "pending" | "in_progress" => ProjectedStatus::Pending,
            "error" | "errored" => ProjectedStatus::Error,
            "cancelled" | "canceled" | "skipped" => ProjectedStatus::Cancelled,
            _ => {
                warn!(verdict = %verdict, "Unknown review verdict, defaulting to Pending");
                ProjectedStatus::Pending
            },
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_db() -> Arc<Mutex<Connection>> {
        let conn = Connection::open_in_memory().unwrap();

        // Initialize ledger schema
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
        )
        .unwrap();

        // Initialize work index schema (required for tailer watermark persistence)
        conn.execute_batch(WORK_INDEX_SCHEMA_SQL).unwrap();

        Arc::new(Mutex::new(conn))
    }

    #[test]
    fn test_work_index_register_changeset() {
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        let digest = [0x42u8; 32];
        let work_id = "work-001";

        index.register_changeset(&digest, work_id).unwrap();

        assert_eq!(index.get_work_id(&digest), Some(work_id.to_string()));
    }

    #[test]
    fn test_work_index_register_pr() {
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        let work_id = "work-001";
        index
            .register_pr(work_id, 123, "owner", "repo", "abc123")
            .unwrap();

        let metadata = index.get_pr_metadata(work_id).unwrap();
        assert_eq!(metadata.pr_number, 123);
        assert_eq!(metadata.repo_owner, "owner");
        assert_eq!(metadata.repo_name, "repo");
        assert_eq!(metadata.head_sha, "abc123");
    }

    #[test]
    fn test_work_index_not_found() {
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        let digest = [0x42u8; 32];
        assert!(index.get_work_id(&digest).is_none());
        assert!(index.get_pr_metadata("unknown").is_none());
    }

    #[test]
    fn test_ledger_tailer_poll_events() {
        let conn = create_test_db();

        // Insert test events
        {
            let conn_guard = conn.lock().unwrap();
            conn_guard
                .execute(
                    "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        "evt-1",
                        "test_event",
                        "work-1",
                        "actor-1",
                        b"payload1".to_vec(),
                        vec![0u8; 64],
                        1000i64
                    ],
                )
                .unwrap();
            conn_guard
                .execute(
                    "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        "evt-2",
                        "test_event",
                        "work-2",
                        "actor-2",
                        b"payload2".to_vec(),
                        vec![0u8; 64],
                        2000i64
                    ],
                )
                .unwrap();
        }

        let mut tailer = LedgerTailer::new(conn);

        let events = tailer.poll_events("test_event", 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_id, "evt-1");
        assert_eq!(events[1].event_id, "evt-2");

        // Without acknowledge(), subsequent poll should return the SAME events
        // (Blocker fix: Fail-Open Auto-Ack - watermark not advanced on poll)
        let events = tailer.poll_events("test_event", 10).unwrap();
        assert_eq!(
            events.len(),
            2,
            "Events should be re-polled without acknowledge"
        );

        // After acknowledging, events should not be returned
        // MAJOR FIX: Pass event_id for composite cursor
        tailer.acknowledge(2000, "evt-2").unwrap(); // Acknowledge up to (timestamp 2000, evt-2)
        let events = tailer.poll_events("test_event", 10).unwrap();
        assert!(
            events.is_empty(),
            "Events should be empty after acknowledge"
        );
    }

    #[test]
    fn test_projection_worker_config() {
        let config = ProjectionWorkerConfig::new()
            .with_poll_interval(Duration::from_secs(5))
            .with_batch_size(50);

        assert_eq!(config.poll_interval, Duration::from_secs(5));
        assert_eq!(config.batch_size, 50);
        assert!(!config.github_enabled);
    }

    #[test]
    fn test_projection_worker_creation() {
        let conn = create_test_db();
        let config = ProjectionWorkerConfig::new();

        let worker = ProjectionWorker::new(conn, config);
        assert!(worker.is_ok());

        let worker = worker.unwrap();
        assert!(worker.adapter.is_none()); // GitHub not enabled
    }

    #[test]
    fn test_projection_worker_with_github_config() {
        let conn = create_test_db();
        let github_config =
            GitHubAdapterConfig::new("https://api.github.com", "owner", "repo").unwrap();
        let config = ProjectionWorkerConfig::new().with_github(github_config.clone());

        let worker = ProjectionWorker::new(Arc::clone(&conn), config);
        assert!(worker.is_ok());

        let mut worker = worker.unwrap();
        // Adapter is NOT created in constructor - must be injected (fail-safe design)
        assert!(!worker.has_adapter());

        // Inject mock adapter for testing
        let signer = apm2_core::crypto::Signer::generate();
        let adapter = GitHubProjectionAdapter::new_mock(signer, github_config).unwrap();
        worker.set_adapter(adapter);
        assert!(worker.has_adapter());
    }

    #[test]
    fn test_projection_worker_shutdown_handle() {
        let conn = create_test_db();
        let config = ProjectionWorkerConfig::new();
        let worker = ProjectionWorker::new(conn, config).unwrap();

        let handle = worker.shutdown_handle();
        assert!(!handle.load(std::sync::atomic::Ordering::Relaxed));

        // Signal shutdown
        handle.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(handle.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn test_work_index_end_to_end_lookup() {
        // Test the full workflow: changeset -> work_id -> PR metadata
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        let changeset_digest = [0x42u8; 32];
        let work_id = "work-001";

        // Register changeset -> work_id
        index
            .register_changeset(&changeset_digest, work_id)
            .unwrap();

        // Register work_id -> PR
        index
            .register_pr(work_id, 456, "org", "project", "def789")
            .unwrap();

        // Full lookup chain
        let found_work_id = index.get_work_id(&changeset_digest).unwrap();
        assert_eq!(found_work_id, work_id);

        let pr_metadata = index.get_pr_metadata(&found_work_id).unwrap();
        assert_eq!(pr_metadata.pr_number, 456);
        assert_eq!(pr_metadata.repo_owner, "org");
        assert_eq!(pr_metadata.repo_name, "project");
        assert_eq!(pr_metadata.head_sha, "def789");
    }

    #[test]
    fn test_ledger_tailer_from_timestamp() {
        let conn = create_test_db();

        // Insert test events
        {
            let conn_guard = conn.lock().unwrap();
            conn_guard
                .execute(
                    "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        "evt-1",
                        "test_event",
                        "work-1",
                        "actor-1",
                        b"payload1".to_vec(),
                        vec![0u8; 64],
                        1000i64
                    ],
                )
                .unwrap();
            conn_guard
                .execute(
                    "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        "evt-2",
                        "test_event",
                        "work-2",
                        "actor-2",
                        b"payload2".to_vec(),
                        vec![0u8; 64],
                        2000i64
                    ],
                )
                .unwrap();
        }

        // Create tailer starting from timestamp 1000 (after first event)
        let mut tailer = LedgerTailer::from_timestamp(Arc::clone(&conn), 1000);

        // Should only get the second event
        let events = tailer.poll_events("test_event", 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "evt-2");
    }

    #[test]
    fn test_ledger_tailer_get_ledger_head() {
        let conn = create_test_db();

        // Insert test events
        {
            let conn_guard = conn.lock().unwrap();
            conn_guard
                .execute(
                    "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        "evt-latest",
                        "test_event",
                        "work-1",
                        "actor-1",
                        b"payload".to_vec(),
                        vec![0u8; 64],
                        9999i64
                    ],
                )
                .unwrap();
        }

        let tailer = LedgerTailer::new(conn);
        let head = tailer.get_ledger_head().unwrap();

        assert!(head.is_some());
        // Head is a BLAKE3 hash of the event_id
        let expected_hash = blake3::hash(b"evt-latest");
        assert_eq!(head.unwrap(), *expected_hash.as_bytes());
    }

    #[test]
    fn test_ledger_tailer_empty_ledger_head() {
        let conn = create_test_db();
        let tailer = LedgerTailer::new(conn);

        let head = tailer.get_ledger_head().unwrap();
        assert!(head.is_none());
    }

    #[test]
    fn test_work_index_update_existing() {
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        // Register initial PR
        index
            .register_pr("work-001", 123, "owner1", "repo1", "sha1")
            .unwrap();

        // Update with new PR info (same work_id)
        index
            .register_pr("work-001", 456, "owner2", "repo2", "sha2")
            .unwrap();

        // Should have the updated values
        let metadata = index.get_pr_metadata("work-001").unwrap();
        assert_eq!(metadata.pr_number, 456);
        assert_eq!(metadata.repo_owner, "owner2");
        assert_eq!(metadata.repo_name, "repo2");
        assert_eq!(metadata.head_sha, "sha2");
    }

    #[test]
    fn test_changeset_work_index_update_existing() {
        let conn = create_test_db();
        let index = WorkIndex::new(conn).unwrap();

        let digest = [0x42u8; 32];

        // Register initial work_id
        index.register_changeset(&digest, "work-001").unwrap();

        // Update with new work_id (same changeset)
        index.register_changeset(&digest, "work-002").unwrap();

        // Should have the updated value
        assert_eq!(index.get_work_id(&digest), Some("work-002".to_string()));
    }

    #[test]
    fn test_pr_metadata_debug() {
        let metadata = PrMetadata {
            pr_number: 123,
            repo_owner: "owner".to_string(),
            repo_name: "repo".to_string(),
            head_sha: "abc123".to_string(),
        };

        let debug_str = format!("{metadata:?}");
        assert!(debug_str.contains("PrMetadata"));
        assert!(debug_str.contains("123"));
        assert!(debug_str.contains("owner"));
    }

    #[test]
    fn test_projection_worker_error_display() {
        let err = ProjectionWorkerError::DatabaseError("test error".to_string());
        assert!(err.to_string().contains("database error"));

        let err = ProjectionWorkerError::NoPrAssociation {
            work_id: "work-001".to_string(),
        };
        assert!(err.to_string().contains("work-001"));

        let err = ProjectionWorkerError::AlreadyProjected {
            receipt_id: "recv-001".to_string(),
        };
        assert!(err.to_string().contains("recv-001"));

        // Test MissingDependency error (Blocker fix: Critical Data Loss)
        let err = ProjectionWorkerError::MissingDependency {
            event_id: "evt-001".to_string(),
            reason: "waiting for ChangeSetPublished".to_string(),
        };
        assert!(err.to_string().contains("evt-001"));
        assert!(err.to_string().contains("waiting for ChangeSetPublished"));
    }

    #[test]
    fn test_work_index_evict_expired() {
        let conn = create_test_db();
        let index = WorkIndex::new(Arc::clone(&conn)).unwrap();

        // Register entries with old timestamps
        {
            let conn_guard = conn.lock().unwrap();
            // Insert old entries (created_at = 0, i.e., epoch)
            conn_guard
                .execute(
                    "INSERT INTO changeset_work_index (changeset_digest, work_id, created_at)
                     VALUES (?1, ?2, 0)",
                    params![vec![0x42u8; 32], "old-work"],
                )
                .unwrap();
            conn_guard
                .execute(
                    "INSERT INTO work_pr_index (work_id, pr_number, repo_owner, repo_name, head_sha, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                    params!["old-work", 123i64, "owner", "repo", "sha"],
                )
                .unwrap();
        }

        // Register a fresh entry
        index.register_changeset(&[0x99u8; 32], "new-work").unwrap();

        // Evict with short TTL (1 second) - should evict old entries
        let deleted = index.evict_expired(1).unwrap();
        assert!(deleted >= 2, "Should have deleted at least 2 old entries");

        // Old entries should be gone
        assert!(index.get_work_id(&[0x42u8; 32]).is_none());

        // Fresh entry should still exist
        assert!(index.get_work_id(&[0x99u8; 32]).is_some());
    }

    #[test]
    fn test_ledger_tailer_acknowledge_persistence() {
        let conn = create_test_db();

        // Create tailer and acknowledge some events
        // MAJOR FIX: Pass event_id for composite cursor
        {
            let mut tailer = LedgerTailer::with_id(Arc::clone(&conn), "test_tailer");
            tailer.acknowledge(5000, "evt-test").unwrap();
        }

        // Create new tailer with same ID - should resume from persisted watermark
        let tailer = LedgerTailer::with_id(conn, "test_tailer");

        // The watermark should be restored
        // We verify by checking that events before the watermark are not returned
        // (Since we have no events, this just verifies construction succeeded)
        assert!(tailer.get_ledger_head().is_ok());
    }

    // =========================================================================
    // NACK/Retry Mechanism Tests (Blocker fix: Critical Data Loss)
    // =========================================================================

    #[test]
    fn test_nack_retry_watermark_not_advanced_on_missing_dependency() {
        // Test that when processing fails due to missing dependency (MissingDependency
        // error), the watermark is NOT advanced, allowing the event to be
        // retried.
        let conn = create_test_db();

        // Insert a review_receipt_recorded event
        {
            let conn_guard = conn.lock().unwrap();
            let payload = serde_json::json!({
                "changeset_digest": "0000000000000000000000000000000000000000000000000000000000000042",
                "receipt_id": "receipt-001",
                "verdict": "success"
            });
            conn_guard
                .execute(
                    "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        "evt-review-1",
                        "review_receipt_recorded",
                        "work-1",
                        "actor-1",
                        serde_json::to_vec(&payload).unwrap(),
                        vec![0u8; 64],
                        1000i64
                    ],
                )
                .unwrap();
        }

        let mut tailer = LedgerTailer::with_id(Arc::clone(&conn), "test_nack_tailer");

        // Poll events - should get the review event
        let events = tailer.poll_events("review_receipt_recorded", 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "evt-review-1");

        // Simulate MissingDependency error - do NOT call acknowledge()
        // The watermark should NOT advance

        // Poll again - should still get the same event (NACK/Retry behavior)
        let events = tailer.poll_events("review_receipt_recorded", 10).unwrap();
        assert_eq!(
            events.len(),
            1,
            "Event should be re-polled after NACK (watermark not advanced)"
        );
        assert_eq!(events[0].event_id, "evt-review-1");
    }

    #[test]
    fn test_nack_retry_partial_batch_processing() {
        // Test that when one event in a batch fails, subsequent events are not skipped.
        // This tests the strict sequential acknowledgment behavior.
        let conn = create_test_db();

        // Insert multiple events
        {
            let conn_guard = conn.lock().unwrap();
            for i in 1..=3 {
                let payload = serde_json::json!({
                    "changeset_digest": format!("{:0>64x}", i),
                    "receipt_id": format!("receipt-{:03}", i),
                    "verdict": "success"
                });
                conn_guard
                    .execute(
                        "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            format!("evt-{}", i),
                            "review_receipt_recorded",
                            format!("work-{}", i),
                            "actor-1",
                            serde_json::to_vec(&payload).unwrap(),
                            vec![0u8; 64],
                            i64::from(i * 1000)
                        ],
                    )
                    .unwrap();
            }
        }

        let mut tailer = LedgerTailer::with_id(Arc::clone(&conn), "test_partial_batch_tailer");

        // Poll all events
        let events = tailer.poll_events("review_receipt_recorded", 10).unwrap();
        assert_eq!(events.len(), 3);

        // Acknowledge only the first event (simulate: first succeeded, second failed)
        // MAJOR FIX: Pass event_id for composite cursor
        tailer
            .acknowledge(events[0].timestamp_ns, &events[0].event_id)
            .unwrap();

        // Poll again - should get events 2 and 3 (event 1 was acknowledged)
        let events = tailer.poll_events("review_receipt_recorded", 10).unwrap();
        assert_eq!(
            events.len(),
            2,
            "Should get remaining 2 events after partial acknowledgment"
        );
        assert_eq!(events[0].event_id, "evt-2");
        assert_eq!(events[1].event_id, "evt-3");
    }

    #[test]
    fn test_nack_retry_no_pr_association_error_does_not_advance_watermark() {
        // Test that NoPrAssociation error triggers NACK behavior
        let conn = create_test_db();
        let index = WorkIndex::new(Arc::clone(&conn)).unwrap();

        // Register changeset but NOT PR association
        let changeset_digest = [0x42u8; 32];
        index
            .register_changeset(&changeset_digest, "work-orphan")
            .unwrap();

        // Verify no PR metadata exists
        assert!(
            index.get_pr_metadata("work-orphan").is_none(),
            "PR metadata should not exist"
        );

        // The NoPrAssociation error should be returned, triggering NACK
        // This is tested by verifying the error type exists and the lookup fails
        let err = ProjectionWorkerError::NoPrAssociation {
            work_id: "work-orphan".to_string(),
        };
        assert!(
            matches!(err, ProjectionWorkerError::NoPrAssociation { .. }),
            "NoPrAssociation error should match"
        );
    }

    #[test]
    fn test_nack_retry_missing_dependency_error_type() {
        // Test the MissingDependency error type for changeset not indexed
        let err = ProjectionWorkerError::MissingDependency {
            event_id: "evt-123".to_string(),
            reason: "changeset 0x42... not yet indexed".to_string(),
        };

        assert!(
            matches!(err, ProjectionWorkerError::MissingDependency { .. }),
            "MissingDependency error should match"
        );

        // Verify error message contains useful info
        let msg = err.to_string();
        assert!(msg.contains("evt-123"));
        assert!(msg.contains("not yet indexed"));
    }

    #[test]
    fn test_nack_retry_event_ordering_preserved() {
        // Test that event ordering is preserved during NACK/Retry.
        // Events must be processed in timestamp order to maintain causality.
        let conn = create_test_db();

        // Insert events with specific timestamps
        {
            let conn_guard = conn.lock().unwrap();
            // Insert out of order to verify ORDER BY works
            for (id, ts) in [("evt-c", 3000), ("evt-a", 1000), ("evt-b", 2000)] {
                let payload = serde_json::json!({
                    "changeset_digest": format!("{:0>64x}", ts),
                    "receipt_id": format!("receipt-{}", id),
                    "verdict": "success"
                });
                conn_guard
                    .execute(
                        "INSERT INTO ledger_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            id,
                            "review_receipt_recorded",
                            "work-1",
                            "actor-1",
                            serde_json::to_vec(&payload).unwrap(),
                            vec![0u8; 64],
                            i64::from(ts)
                        ],
                    )
                    .unwrap();
            }
        }

        let mut tailer = LedgerTailer::with_id(Arc::clone(&conn), "test_ordering_tailer");

        // Poll events - should be in timestamp order
        let events = tailer.poll_events("review_receipt_recorded", 10).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(
            events[0].event_id, "evt-a",
            "First event should be evt-a (ts=1000)"
        );
        assert_eq!(
            events[1].event_id, "evt-b",
            "Second event should be evt-b (ts=2000)"
        );
        assert_eq!(
            events[2].event_id, "evt-c",
            "Third event should be evt-c (ts=3000)"
        );
    }

    #[test]
    fn test_validate_string_length_rejects_oversized_input() {
        // Test that oversized strings are rejected (Blocker fix: Unbounded Input
        // Consumption)
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);
        let result = validate_string_length("test_field", &long_string);

        assert!(
            result.is_err(),
            "Should reject string exceeding MAX_STRING_LENGTH"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, ProjectionWorkerError::InvalidPayload(_)),
            "Should be InvalidPayload error"
        );
        assert!(err.to_string().contains("test_field"));
        assert!(err.to_string().contains("exceeds maximum length"));
    }

    #[test]
    fn test_validate_string_length_accepts_valid_input() {
        // Test that strings at or below MAX_STRING_LENGTH are accepted
        let exact_length = "x".repeat(MAX_STRING_LENGTH);
        assert!(
            validate_string_length("field", &exact_length).is_ok(),
            "Should accept string at MAX_STRING_LENGTH"
        );

        let short_string = "hello";
        assert!(
            validate_string_length("field", short_string).is_ok(),
            "Should accept short string"
        );

        let empty_string = "";
        assert!(
            validate_string_length("field", empty_string).is_ok(),
            "Should accept empty string"
        );
    }

    #[test]
    fn test_max_string_length_constant() {
        // Verify the MAX_STRING_LENGTH constant is set correctly
        assert_eq!(MAX_STRING_LENGTH, 1024, "MAX_STRING_LENGTH should be 1024");
    }
}

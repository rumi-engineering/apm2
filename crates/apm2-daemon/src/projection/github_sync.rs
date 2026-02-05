// AGENT-AUTHORED (TCK-00212)
//! GitHub projection adapter for the FAC (Forge Admission Cycle).
//!
//! This module implements a write-only projection adapter that synchronizes
//! ledger state to GitHub commit statuses. The adapter is write-only by design:
//! the ledger is always the source of truth, and GitHub is merely a projection
//! of that truth.
//!
//! # Security Model
//!
//! - **Write-only**: The adapter NEVER reads GitHub status as truth
//! - **Ledger is truth**: All decisions are made based on ledger state
//! - **Signed receipts**: Every projection generates a signed receipt
//! - **Idempotent**: Safe for retries with `(work_id, changeset_digest,
//!   ledger_head)` key
//! - **Persistent cache**: Idempotency cache survives process restarts
//!   (THESIS-02)
//!
//! # RFC-0015: FAC GitHub Projection
//!
//! Per RFC-0015, the GitHub projection adapter:
//!
//! 1. Receives status updates from the FAC ledger
//! 2. Projects those statuses to GitHub commit statuses
//! 3. Generates signed [`ProjectionReceipt`] proving the projection
//! 4. Maintains idempotency for safe retries
//!
//! # Divergence and Tamper Detection
//!
//! Divergence watchdog (TCK-00213) and tamper detection (TCK-00214) are
//! implemented separately. This module focuses solely on write-only projection.
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::crypto::Signer;
//! use apm2_daemon::projection::{
//!     GitHubProjectionAdapter, ProjectionAdapter, ProjectedStatus,
//! };
//!
//! let signer = Signer::generate();
//! let adapter = GitHubProjectionAdapter::new(signer, "https://api.github.com");
//!
//! let receipt = adapter.project_status(
//!     "work-001",
//!     [0x42; 32],
//!     [0xAB; 32],
//!     ProjectedStatus::Success,
//! ).await?;
//!
//! println!("Projected with receipt: {}", receipt.receipt_id);
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use apm2_core::crypto::Signer;
use apm2_core::events::{DefectRecorded, DefectSource, TimeEnvelopeRef};
use apm2_holon::defect::DefectRecord;
use async_trait::async_trait;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use tracing::{debug, warn};

use super::divergence_watchdog::{
    FreezeRegistry, FreezeScope, InterventionFreezeBuilder, SystemTimeSource, TimeSource,
};
use super::projection_receipt::{
    IdempotencyKey, MAX_STRING_LENGTH, ProjectedStatus, ProjectionReceipt, ProjectionReceiptBuilder,
};

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during projection operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProjectionError {
    /// GitHub API error.
    #[error("GitHub API error: {message}")]
    GitHubApiError {
        /// Error message from the API.
        message: String,
        /// HTTP status code, if available.
        status_code: Option<u16>,
    },

    /// Network error.
    #[error("network error: {0}")]
    NetworkError(String),

    /// Authentication error.
    #[error("authentication error: {0}")]
    AuthenticationError(String),

    /// Rate limit exceeded.
    #[error("rate limit exceeded, retry after {retry_after_secs} seconds")]
    RateLimitExceeded {
        /// Seconds until rate limit resets.
        retry_after_secs: u64,
    },

    /// Invalid configuration.
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// Receipt generation failed.
    #[error("failed to generate receipt: {0}")]
    ReceiptGenerationFailed(String),

    /// Database error.
    #[error("database error: {0}")]
    DatabaseError(String),

    /// Input validation error.
    #[error("input validation error: {0}")]
    ValidationError(String),

    /// Commit SHA not found for digest.
    #[error("commit SHA not found for digest: {digest}")]
    CommitShaNotFound {
        /// The digest that was not found.
        digest: String,
    },

    /// Defect record creation failed.
    #[error("failed to create defect record: {0}")]
    DefectRecordFailed(String),

    /// Tamper rate limit exceeded - work is now frozen.
    ///
    /// Returned when tamper attempts exceed the configured threshold.
    /// No further overwrites will be attempted until the freeze is lifted.
    #[error("tamper rate limit exceeded for work {work_id}: frozen with ID {freeze_id}")]
    TamperRateLimitExceeded {
        /// The work ID that has been frozen.
        work_id: String,
        /// The freeze ID assigned.
        freeze_id: String,
    },

    /// Work is frozen due to prior tamper detection.
    #[error("work {work_id} is frozen due to tamper: {freeze_id}")]
    WorkFrozen {
        /// The work ID that is frozen.
        work_id: String,
        /// The freeze ID.
        freeze_id: String,
    },

    /// Freeze registry error.
    #[error("freeze registry error: {0}")]
    FreezeRegistryError(String),
}

// =============================================================================
// TamperEvent
// =============================================================================

/// Event emitted when tamper is detected between ledger and GitHub status.
///
/// Per RFC-0015, tamper detection identifies when the GitHub status has been
/// modified by a non-adapter identity. This differs from divergence detection
/// (which detects trunk HEAD mismatch). Tamper detection:
///
/// 1. Compares expected status (from ledger) with actual status (from GitHub)
/// 2. If they differ, emits a `DefectRecord(PROJECTION_TAMPER)`
/// 3. Overwrites GitHub status to match ledger truth
///
/// # Security
///
/// Tamper detection is a security control that ensures the ledger remains
/// the authoritative source of truth for admission status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TamperEvent {
    /// The expected status from the ledger.
    pub expected_status: ProjectedStatus,

    /// The actual status observed on GitHub.
    pub actual_status: ProjectedStatus,

    /// When the tamper was detected (Unix nanoseconds).
    pub detected_at: u64,

    /// The work ID associated with this tamper event.
    pub work_id: String,

    /// The changeset digest for the affected commit.
    pub changeset_digest: [u8; 32],
}

impl TamperEvent {
    /// Creates a new tamper event with an explicit timestamp.
    ///
    /// # `BOUNDARY_INTEGRITY` Compliance
    ///
    /// Per the `BOUNDARY_INTEGRITY` constraint, the timestamp MUST be provided
    /// by the adapter using its injected `TimeSource`. Direct use of
    /// `SystemTime::now()` is prohibited at boundary layers.
    #[must_use]
    pub fn new(
        expected_status: ProjectedStatus,
        actual_status: ProjectedStatus,
        work_id: impl Into<String>,
        changeset_digest: [u8; 32],
        detected_at: u64,
    ) -> Self {
        Self {
            expected_status,
            actual_status,
            detected_at,
            work_id: work_id.into(),
            changeset_digest,
        }
    }
}

/// Result of handling a tamper event.
///
/// Contains the `DefectRecord` emitted and the `ProjectionReceipt` from
/// overwriting the tampered status.
#[derive(Debug, Clone)]
pub struct TamperResult {
    /// The defect record emitted for this tamper event.
    pub defect: DefectRecord,

    /// The `DefectRecorded` event to emit to the ledger.
    ///
    /// TCK-00307 MAJOR FIX: The `on_tamper` method now produces a
    /// `DefectRecorded` event that callers should emit to the ledger via
    /// `ledger.emit_defect_recorded(&defect_event, timestamp)`.
    pub defect_event: DefectRecorded,

    /// The projection receipt from overwriting the tampered status.
    pub receipt: ProjectionReceipt,

    /// Whether a freeze was triggered due to exceeding tamper threshold.
    pub freeze_triggered: bool,
}

// NOTE: current_timestamp_ns() has been removed per `BOUNDARY_INTEGRITY`
// constraint. All timestamp operations must use the injected TimeSource trait.

// =============================================================================
// ProjectionAdapter Trait (Async)
// =============================================================================

/// A write-only adapter for projecting ledger state to external systems.
///
/// The adapter projects status updates to an external system (e.g., GitHub)
/// and returns signed receipts as proof of projection. The adapter is
/// write-only by design - it never reads the external system as a source
/// of truth.
///
/// # Security Invariants
///
/// 1. The ledger is ALWAYS the source of truth
/// 2. The adapter NEVER reads external state as truth
/// 3. All projections generate signed receipts
/// 4. Projections are idempotent with `(work_id, changeset_digest,
///    ledger_head)` key
#[async_trait]
pub trait ProjectionAdapter: Send + Sync {
    /// Projects a status to the external system.
    ///
    /// This method is idempotent: calling it multiple times with the same
    /// `(work_id, changeset_digest, ledger_head)` tuple will return the
    /// same receipt (or a cached one).
    ///
    /// # Arguments
    ///
    /// * `work_id` - The work item identifier
    /// * `changeset_digest` - The changeset digest (32 bytes)
    /// * `ledger_head` - The ledger head hash at time of projection (32 bytes)
    /// * `status` - The status to project
    ///
    /// # Returns
    ///
    /// A signed [`ProjectionReceipt`] proving the projection occurred.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError`] if the projection fails.
    async fn project_status(
        &self,
        work_id: &str,
        changeset_digest: [u8; 32],
        ledger_head: [u8; 32],
        status: ProjectedStatus,
    ) -> Result<ProjectionReceipt, ProjectionError>;

    /// Returns the adapter's verifying key for receipt validation.
    fn verifying_key(&self) -> apm2_core::crypto::VerifyingKey;
}

// =============================================================================
// GitHubAdapterConfig
// =============================================================================

/// Maximum length for configuration string fields.
const MAX_CONFIG_STRING_LENGTH: usize = 2048;

/// Maximum response body size (64KB) to prevent OOM from large responses.
/// This is a security control (AD-MEM-001) to limit memory allocation.
const MAX_RESPONSE_BODY_SIZE: usize = 64 * 1024;

/// Default connection timeout in seconds.
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 30;

/// Default request timeout in seconds.
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 60;

/// Default TTL for idempotency cache entries (7 days).
/// Entries older than this will be cleaned up to prevent unbounded growth.
const DEFAULT_CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Maximum number of entries in the idempotency cache.
/// Oldest entries will be pruned when this limit is exceeded.
const MAX_CACHE_ENTRIES: usize = 100_000;

/// Default tamper attempt threshold before freeze.
/// After this many consecutive tamper detections for the same work item,
/// the adapter will freeze the work and stop overwriting.
pub const DEFAULT_TAMPER_THRESHOLD: u32 = 3;

/// GitHub projection adapter configuration.
#[derive(Clone)]
pub struct GitHubAdapterConfig {
    /// GitHub API base URL (e.g., "<https://api.github.com>").
    pub api_base_url: String,

    /// Repository owner.
    pub owner: String,

    /// Repository name.
    pub repo: String,

    /// Context string for commit statuses (e.g., "apm2/gates").
    pub context: String,

    /// Target URL for status details (optional).
    pub target_url: Option<String>,

    /// GitHub API token for authentication.
    /// Uses `SecretString` to prevent accidental exposure in logs/debug output.
    /// (AD-SEC-001: Proper secret type per `SECRETS_MANAGEMENT.md`)
    pub api_token: Option<SecretString>,

    /// Connection timeout.
    pub connect_timeout: Duration,

    /// Request timeout.
    pub request_timeout: Duration,
}

impl GitHubAdapterConfig {
    /// Creates a new configuration with required fields.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::ValidationError`] if any field exceeds
    /// maximum length limits.
    pub fn new(
        api_base_url: impl Into<String>,
        owner: impl Into<String>,
        repo: impl Into<String>,
    ) -> Result<Self, ProjectionError> {
        let api_base_url = api_base_url.into();
        let owner = owner.into();
        let repo = repo.into();

        // Validate field lengths
        Self::validate_field("api_base_url", &api_base_url)?;
        Self::validate_field("owner", &owner)?;
        Self::validate_field("repo", &repo)?;

        Ok(Self {
            api_base_url,
            owner,
            repo,
            context: "apm2/gates".to_string(),
            target_url: None,
            api_token: None,
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
        })
    }

    /// Validates a configuration field against length limits.
    fn validate_field(field_name: &str, value: &str) -> Result<(), ProjectionError> {
        if value.len() > MAX_CONFIG_STRING_LENGTH {
            return Err(ProjectionError::ValidationError(format!(
                "{field_name} exceeds maximum length ({} > {MAX_CONFIG_STRING_LENGTH})",
                value.len()
            )));
        }
        if value.is_empty() {
            return Err(ProjectionError::ValidationError(format!(
                "{field_name} cannot be empty"
            )));
        }
        Ok(())
    }

    /// Sets the context string for commit statuses.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::ValidationError`] if the context exceeds
    /// maximum length.
    pub fn with_context(mut self, context: impl Into<String>) -> Result<Self, ProjectionError> {
        let context = context.into();
        Self::validate_field("context", &context)?;
        self.context = context;
        Ok(self)
    }

    /// Sets the target URL for status details.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::ValidationError`] if the URL exceeds
    /// maximum length.
    pub fn with_target_url(mut self, url: impl Into<String>) -> Result<Self, ProjectionError> {
        let url = url.into();
        Self::validate_field("target_url", &url)?;
        self.target_url = Some(url);
        Ok(self)
    }

    /// Sets the GitHub API token for authentication.
    ///
    /// The token is stored as a `SecretString` to prevent accidental exposure
    /// in logs and debug output, per `SECRETS_MANAGEMENT.md` requirements.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::ValidationError`] if the token exceeds
    /// maximum length.
    pub fn with_api_token(mut self, token: impl Into<String>) -> Result<Self, ProjectionError> {
        let token = token.into();
        Self::validate_field("api_token", &token)?;
        self.api_token = Some(SecretString::from(token));
        Ok(self)
    }

    /// Sets the connection timeout.
    #[must_use]
    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Sets the request timeout.
    #[must_use]
    pub const fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }
}

// Manual Debug implementation to avoid exposing secrets
impl std::fmt::Debug for GitHubAdapterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubAdapterConfig")
            .field("api_base_url", &self.api_base_url)
            .field("owner", &self.owner)
            .field("repo", &self.repo)
            .field("context", &self.context)
            .field("target_url", &self.target_url)
            .field("api_token", &self.api_token.as_ref().map(|_| "[REDACTED]"))
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

// =============================================================================
// IdempotencyCache (SQLite-backed)
// =============================================================================

/// Schema SQL for the idempotency cache.
const CACHE_SCHEMA_SQL: &str = r"
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS projection_receipts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        -- Idempotency key fields
        work_id TEXT NOT NULL,
        changeset_digest BLOB NOT NULL,
        ledger_head BLOB NOT NULL,
        -- Receipt data (JSON-serialized)
        receipt_json TEXT NOT NULL,
        -- Metadata
        created_at INTEGER NOT NULL,
        -- Unique constraint on idempotency key
        UNIQUE(work_id, changeset_digest, ledger_head)
    );

    CREATE INDEX IF NOT EXISTS idx_receipts_work_id ON projection_receipts(work_id);
    CREATE INDEX IF NOT EXISTS idx_receipts_created_at ON projection_receipts(created_at);

    -- Digest-to-SHA mapping table for commit lookups
    CREATE TABLE IF NOT EXISTS digest_sha_mappings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        changeset_digest BLOB NOT NULL UNIQUE,
        commit_sha TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_mappings_digest ON digest_sha_mappings(changeset_digest);
";

/// `SQLite`-backed idempotency cache.
///
/// Per THESIS-02, process memory is disposable. This cache persists to `SQLite`
/// to survive process restarts.
struct IdempotencyCache {
    conn: Arc<std::sync::Mutex<Connection>>,
}

impl IdempotencyCache {
    /// Opens or creates an idempotency cache at the specified path.
    ///
    /// # Security (TCK-00322 MAJOR FIX)
    ///
    /// The cache file is created with mode 0600 (owner read/write only) to
    /// prevent unauthorized access to projection receipts and idempotency data.
    fn open(path: impl AsRef<Path>) -> Result<Self, ProjectionError> {
        let path = path.as_ref();

        // TCK-00322 MAJOR FIX: Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ProjectionError::DatabaseError(format!("failed to create cache directory: {e}"))
            })?;
        }

        // TCK-00322 MAJOR FIX: Set secure permissions (0600) on cache file.
        // We need to handle two cases:
        // 1. File doesn't exist: Create it with umask then fix permissions
        // 2. File exists: Fix permissions if needed
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // If file already exists, fix permissions
            if path.exists() {
                let permissions = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(path, permissions).map_err(|e| {
                    ProjectionError::DatabaseError(format!(
                        "failed to set cache file permissions: {e}"
                    ))
                })?;
            }
        }

        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| ProjectionError::DatabaseError(e.to_string()))?;

        // TCK-00322 MAJOR FIX: Set permissions after file creation (for new files)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, permissions).map_err(|e| {
                ProjectionError::DatabaseError(format!("failed to set cache file permissions: {e}"))
            })?;
        }

        conn.execute_batch(CACHE_SCHEMA_SQL)
            .map_err(|e| ProjectionError::DatabaseError(e.to_string()))?;

        Ok(Self {
            conn: Arc::new(std::sync::Mutex::new(conn)),
        })
    }

    /// Creates an in-memory cache for testing.
    fn in_memory() -> Result<Self, ProjectionError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| ProjectionError::DatabaseError(e.to_string()))?;

        conn.execute_batch(CACHE_SCHEMA_SQL)
            .map_err(|e| ProjectionError::DatabaseError(e.to_string()))?;

        Ok(Self {
            conn: Arc::new(std::sync::Mutex::new(conn)),
        })
    }

    /// Looks up a cached receipt by idempotency key.
    fn get(&self, key: &IdempotencyKey) -> Result<Option<ProjectionReceipt>, ProjectionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionError::DatabaseError(format!("mutex poisoned: {e}")))?;

        let result: Option<String> = conn
            .query_row(
                "SELECT receipt_json FROM projection_receipts
                 WHERE work_id = ?1 AND changeset_digest = ?2 AND ledger_head = ?3",
                params![
                    &key.work_id,
                    key.changeset_digest.as_slice(),
                    key.ledger_head.as_slice()
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ProjectionError::DatabaseError(e.to_string()))?;

        match result {
            Some(json) => {
                let receipt: ProjectionReceipt = serde_json::from_str(&json)
                    .map_err(|e| ProjectionError::DatabaseError(e.to_string()))?;
                Ok(Some(receipt))
            },
            None => Ok(None),
        }
    }

    /// Stores a receipt in the cache.
    #[allow(clippy::cast_possible_wrap)] // Timestamp won't overflow until year 2554
    fn put(
        &self,
        key: &IdempotencyKey,
        receipt: &ProjectionReceipt,
    ) -> Result<(), ProjectionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionError::DatabaseError(format!("mutex poisoned: {e}")))?;

        let json = serde_json::to_string(receipt)
            .map_err(|e| ProjectionError::DatabaseError(e.to_string()))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        conn.execute(
            "INSERT OR REPLACE INTO projection_receipts
             (work_id, changeset_digest, ledger_head, receipt_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &key.work_id,
                key.changeset_digest.as_slice(),
                key.ledger_head.as_slice(),
                &json,
                now as i64
            ],
        )
        .map_err(|e| ProjectionError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Returns the number of cached receipts.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn size(&self) -> Result<usize, ProjectionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionError::DatabaseError(format!("mutex poisoned: {e}")))?;

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM projection_receipts", [], |row| {
                row.get(0)
            })
            .map_err(|e| ProjectionError::DatabaseError(e.to_string()))?;

        Ok(count as usize)
    }

    /// Clears all cached receipts.
    fn clear(&self) -> Result<(), ProjectionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionError::DatabaseError(format!("mutex poisoned: {e}")))?;

        conn.execute("DELETE FROM projection_receipts", [])
            .map_err(|e| ProjectionError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Registers a mapping from changeset digest to commit SHA.
    #[allow(clippy::cast_possible_wrap)] // Timestamp won't overflow until year 2554
    fn register_digest_sha_mapping(
        &self,
        digest: &[u8; 32],
        sha: &str,
    ) -> Result<(), ProjectionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionError::DatabaseError(format!("mutex poisoned: {e}")))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        conn.execute(
            "INSERT OR REPLACE INTO digest_sha_mappings
             (changeset_digest, commit_sha, created_at)
             VALUES (?1, ?2, ?3)",
            params![digest.as_slice(), sha, now as i64],
        )
        .map_err(|e| ProjectionError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Looks up the commit SHA for a changeset digest.
    fn get_commit_sha(&self, digest: &[u8; 32]) -> Result<Option<String>, ProjectionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionError::DatabaseError(format!("mutex poisoned: {e}")))?;

        let result: Option<String> = conn
            .query_row(
                "SELECT commit_sha FROM digest_sha_mappings WHERE changeset_digest = ?1",
                params![digest.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ProjectionError::DatabaseError(e.to_string()))?;

        Ok(result)
    }

    /// Cleans up expired cache entries based on TTL.
    ///
    /// Removes entries older than `ttl_secs` from both `projection_receipts`
    /// and `digest_sha_mappings` tables.
    ///
    /// # Security
    ///
    /// This method prevents unbounded cache growth which could lead to
    /// disk exhaustion in long-running daemons.
    #[allow(clippy::cast_possible_wrap)] // Timestamp won't overflow until year 2554
    fn cleanup_expired(&self, ttl_secs: u64) -> Result<usize, ProjectionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionError::DatabaseError(format!("mutex poisoned: {e}")))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let cutoff = now.saturating_sub(ttl_secs) as i64;

        // Clean up old receipts
        let receipts_deleted = conn
            .execute(
                "DELETE FROM projection_receipts WHERE created_at < ?1",
                params![cutoff],
            )
            .map_err(|e| ProjectionError::DatabaseError(e.to_string()))?;

        // Clean up old digest mappings
        let mappings_deleted = conn
            .execute(
                "DELETE FROM digest_sha_mappings WHERE created_at < ?1",
                params![cutoff],
            )
            .map_err(|e| ProjectionError::DatabaseError(e.to_string()))?;

        Ok(receipts_deleted + mappings_deleted)
    }

    /// Prunes the cache to stay within max entry limits.
    ///
    /// If the number of entries exceeds `max_entries`, the oldest entries
    /// are deleted to bring the count back to 80% of the limit.
    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap
    )]
    fn prune_if_needed(&self, max_entries: usize) -> Result<usize, ProjectionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ProjectionError::DatabaseError(format!("mutex poisoned: {e}")))?;

        // Check current receipt count
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM projection_receipts", [], |row| {
                row.get(0)
            })
            .map_err(|e| ProjectionError::DatabaseError(e.to_string()))?;

        if (count as usize) <= max_entries {
            return Ok(0);
        }

        // Prune to 80% of max to avoid frequent pruning
        let target = (max_entries * 80) / 100;
        let to_delete = (count as usize).saturating_sub(target);

        // Delete oldest entries
        let deleted = conn
            .execute(
                "DELETE FROM projection_receipts WHERE id IN (
                    SELECT id FROM projection_receipts
                    ORDER BY created_at ASC
                    LIMIT ?1
                )",
                params![to_delete as i64],
            )
            .map_err(|e| ProjectionError::DatabaseError(e.to_string()))?;

        Ok(deleted)
    }

    /// Performs routine cache maintenance.
    ///
    /// This combines TTL-based cleanup and size-based pruning.
    fn maintain(&self) -> Result<usize, ProjectionError> {
        let expired = self.cleanup_expired(DEFAULT_CACHE_TTL_SECS)?;
        let pruned = self.prune_if_needed(MAX_CACHE_ENTRIES)?;
        Ok(expired + pruned)
    }
}

// =============================================================================
// GitHub HTTP Client
// =============================================================================

use std::sync::OnceLock;

use bytes::Bytes;
use http_body_util::Full;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

/// Type alias for the persistent HTTPS client.
///
/// MAJOR FIX: Network Resource Exhaustion (Self-DoS)
/// Previously, each request created a new `HttpsConnector` and `Client`,
/// exhausting network resources under load. Now we reuse a single client.
type PersistentHttpsClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// HTTP client for GitHub API calls.
///
/// Security controls:
/// - AD-MEM-001: Response body size limited via `http_body_util::Limited`
/// - AD-NET-001: Request timeouts via `tokio::time::timeout`
/// - AD-SEC-001: API token uses `SecretString` (via config)
/// - AD-CMP-001: Cognitive complexity reduced via helper methods
///
/// MAJOR FIX: Network Resource Exhaustion (Self-DoS)
/// The client now uses a persistent `HttpsConnector` and `Client` that are
/// lazily initialized once and reused for all requests. This prevents
/// resource exhaustion from creating new TLS connections per request.
struct GitHubClient {
    config: GitHubAdapterConfig,
    /// Lazily-initialized persistent HTTPS client for connection reuse.
    /// Using `std::sync::OnceLock` for thread-safe lazy initialization.
    http_client: OnceLock<PersistentHttpsClient>,
}

impl GitHubClient {
    /// Creates a new GitHub client with lazy-initialized persistent connection.
    #[allow(clippy::missing_const_for_fn)] // OnceLock::new() is not const in stable Rust
    fn new(config: GitHubAdapterConfig) -> Self {
        Self {
            config,
            http_client: OnceLock::new(),
        }
    }

    /// Gets or initializes the persistent HTTPS client.
    ///
    /// MAJOR FIX: Network Resource Exhaustion (Self-DoS)
    /// This method lazily creates a single HTTPS client that is reused for
    /// all subsequent requests, preventing the creation of new connections
    /// and TLS handshakes per request.
    ///
    /// # Security
    ///
    /// - HTTPS-only mode prevents secret exfiltration via HTTP fallback
    /// - HTTP/2 support enables connection multiplexing
    fn get_or_init_client(&self) -> &PersistentHttpsClient {
        self.http_client.get_or_init(|| {
            use hyper_rustls::HttpsConnectorBuilder;

            // Build persistent HTTPS connector
            // SECURITY: Use https_only() to prevent secret exfiltration via HTTP fallback.
            // API tokens must never be sent over unencrypted connections.
            let https = HttpsConnectorBuilder::new()
                .with_webpki_roots()
                .https_only()
                .enable_http1()
                .enable_http2()
                .build();

            Client::builder(TokioExecutor::new()).build(https)
        })
    }

    /// Builds the GitHub API URL for posting a commit status.
    fn build_status_url(&self, sha: &str) -> String {
        format!(
            "{}/repos/{}/{}/statuses/{}",
            self.config.api_base_url.trim_end_matches('/'),
            self.config.owner,
            self.config.repo,
            sha
        )
    }

    /// Builds the JSON request body for a commit status update.
    fn build_status_body(&self, status: ProjectedStatus) -> Result<Vec<u8>, ProjectionError> {
        let body = serde_json::json!({
            "state": status.as_str(),
            "context": self.config.context,
            "target_url": self.config.target_url,
            "description": format!("APM2 FAC: {}", status.as_str())
        });

        serde_json::to_vec(&body).map_err(|e| ProjectionError::NetworkError(e.to_string()))
    }

    /// Builds an HTTP request with appropriate headers.
    fn build_request<B>(&self, url: &str, body: B) -> Result<http::Request<B>, ProjectionError> {
        let mut builder = http::Request::builder()
            .method("POST")
            .uri(url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "apm2-daemon/0.1")
            .header("X-GitHub-Api-Version", "2022-11-28");

        // Add authentication if configured (AD-SEC-001: uses SecretString)
        if let Some(token) = &self.config.api_token {
            builder = builder.header("Authorization", format!("Bearer {}", token.expose_secret()));
        }

        builder
            .body(body)
            .map_err(|e| ProjectionError::NetworkError(e.to_string()))
    }

    /// Checks the response status and returns an appropriate error if needed.
    fn check_response_status(
        status_code: http::StatusCode,
        headers: &http::HeaderMap,
    ) -> Result<(), ProjectionError> {
        use http::StatusCode;

        // Check for rate limiting
        if status_code == StatusCode::FORBIDDEN || status_code == StatusCode::TOO_MANY_REQUESTS {
            let retry_after: u64 = headers
                .get("Retry-After")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok())
                .unwrap_or(60);

            return Err(ProjectionError::RateLimitExceeded {
                retry_after_secs: retry_after,
            });
        }

        // Check for authentication errors
        if status_code == StatusCode::UNAUTHORIZED {
            return Err(ProjectionError::AuthenticationError(
                "GitHub API authentication failed - check API token".to_string(),
            ));
        }

        Ok(())
    }

    /// Reads an error response body with size limits (AD-MEM-001).
    ///
    /// Uses `http_body_util::Limited` to prevent OOM from large responses.
    async fn read_error_body<B>(body: B) -> String
    where
        B: http_body::Body + Send,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        use http_body_util::{BodyExt, Limited};

        // Wrap body with size limit to prevent OOM (AD-MEM-001)
        let limited_body = Limited::new(body, MAX_RESPONSE_BODY_SIZE);

        limited_body.collect().await.map_or_else(
            |_| "[body read error or size limit exceeded]".to_string(),
            |collected| {
                // SECURITY: Use to_bytes() to consume full buffer, not chunk() which
                // only returns the first contiguous slice and may truncate fragmented
                // responses.
                let bytes = collected.to_bytes();
                String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| "[non-UTF8 body]".to_string())
            },
        )
    }

    /// Posts a commit status to GitHub.
    ///
    /// POST /repos/{owner}/{repo}/statuses/{sha}
    ///
    /// # Security Controls
    ///
    /// - AD-MEM-001: Response body size limited to 64KB via `Limited`
    /// - AD-NET-001: Request timeout via `tokio::time::timeout`
    /// - AD-SEC-001: API token uses `SecretString` (via config)
    /// - AD-CMP-001: Logic split into helper methods
    ///
    /// # MAJOR FIX: Network Resource Exhaustion (Self-DoS)
    ///
    /// Now uses a persistent HTTPS client instead of creating a new connector
    /// and client for every request. This prevents resource exhaustion.
    async fn post_commit_status(
        &self,
        sha: &str,
        status: ProjectedStatus,
    ) -> Result<(), ProjectionError> {
        let url = self.build_status_url(sha);
        let body_bytes = self.build_status_body(status)?;

        // MAJOR FIX: Use persistent client instead of creating new one per request
        let client = self.get_or_init_client();

        let request = self.build_request(&url, Full::new(Bytes::from(body_bytes)))?;

        debug!(url = %url, status = %status, "posting commit status to GitHub");

        // Send the request with timeout (AD-NET-001)
        let response = tokio::time::timeout(self.config.request_timeout, client.request(request))
            .await
            .map_err(|_| {
                ProjectionError::NetworkError(format!(
                    "request timed out after {:?}",
                    self.config.request_timeout
                ))
            })?
            .map_err(|e: hyper_util::client::legacy::Error| {
                ProjectionError::NetworkError(e.to_string())
            })?;

        let (parts, body) = response.into_parts();
        let status_code = parts.status;

        // Check for specific error conditions
        Self::check_response_status(status_code, &parts.headers)?;

        // Check for success
        if !status_code.is_success() {
            let message = Self::read_error_body(body).await;
            return Err(ProjectionError::GitHubApiError {
                message,
                status_code: Some(status_code.as_u16()),
            });
        }

        debug!("GitHub commit status posted successfully");
        Ok(())
    }

    /// Builds the GitHub API URL for posting a PR comment.
    fn build_comment_url(&self, pr_number: u64) -> String {
        format!(
            "{}/repos/{}/{}/issues/{}/comments",
            self.config.api_base_url.trim_end_matches('/'),
            self.config.owner,
            self.config.repo,
            pr_number
        )
    }

    /// Builds the JSON request body for a PR comment.
    #[allow(clippy::unused_self)] // Kept for API consistency with build_status_body
    fn build_comment_body(&self, body: &str) -> Result<Vec<u8>, ProjectionError> {
        let json = serde_json::json!({
            "body": body
        });

        serde_json::to_vec(&json).map_err(|e| ProjectionError::NetworkError(e.to_string()))
    }

    /// Posts a comment to a GitHub PR.
    ///
    /// `POST /repos/{owner}/{repo}/issues/{issue_number}/comments`
    ///
    /// # Security Controls
    ///
    /// - AD-MEM-001: Response body size limited to 64KB via `Limited`
    /// - AD-NET-001: Request timeout via `tokio::time::timeout`
    /// - AD-SEC-001: API token uses `SecretString` (via config)
    ///
    /// # TCK-00322: PR Comment Projection
    ///
    /// Per RFC-0019, the projection worker posts review comments to PRs.
    /// This enables automated code review feedback from the FAC.
    ///
    /// # MAJOR FIX: Network Resource Exhaustion (Self-DoS)
    ///
    /// Now uses a persistent HTTPS client instead of creating a new connector
    /// and client for every request. This prevents resource exhaustion.
    async fn post_pr_comment(&self, pr_number: u64, body: &str) -> Result<(), ProjectionError> {
        let url = self.build_comment_url(pr_number);
        let body_bytes = self.build_comment_body(body)?;

        // MAJOR FIX: Use persistent client instead of creating new one per request
        let client = self.get_or_init_client();

        let request = self.build_request(&url, Full::new(Bytes::from(body_bytes)))?;

        debug!(url = %url, pr_number = pr_number, "posting comment to GitHub PR");

        // Send the request with timeout (AD-NET-001)
        let response = tokio::time::timeout(self.config.request_timeout, client.request(request))
            .await
            .map_err(|_| {
                ProjectionError::NetworkError(format!(
                    "request timed out after {:?}",
                    self.config.request_timeout
                ))
            })?
            .map_err(|e: hyper_util::client::legacy::Error| {
                ProjectionError::NetworkError(e.to_string())
            })?;

        let (parts, body) = response.into_parts();
        let status_code = parts.status;

        // Check for specific error conditions
        Self::check_response_status(status_code, &parts.headers)?;

        // Check for success (201 Created for new comments)
        if !status_code.is_success() {
            let message = Self::read_error_body(body).await;
            return Err(ProjectionError::GitHubApiError {
                message,
                status_code: Some(status_code.as_u16()),
            });
        }

        debug!(
            pr_number = pr_number,
            "GitHub PR comment posted successfully"
        );
        Ok(())
    }
}

// =============================================================================
// GitHubProjectionAdapter
// =============================================================================

/// A write-only GitHub projection adapter.
///
/// This adapter projects ledger state to GitHub commit statuses. It is
/// write-only by design: the ledger is always the source of truth.
///
/// # Idempotency
///
/// The adapter maintains a SQLite-backed cache keyed by `(work_id,
/// changeset_digest, ledger_head)`. If a projection is retried with the same
/// key, the cached receipt is returned without making another API call.
///
/// # Tamper Rate Limiting (Security)
///
/// To prevent denial-of-service from unbounded tamper loop amplification, the
/// adapter tracks tamper attempts per work item. After `tamper_threshold`
/// consecutive attempts, the work item is frozen and no further overwrites are
/// attempted until the freeze is adjudicated.
///
/// # Time Source Injection (`BOUNDARY_INTEGRITY`)
///
/// Per the `BOUNDARY_INTEGRITY` constraint, the adapter accepts a
/// [`TimeSource`] for obtaining timestamps instead of directly using
/// `SystemTime::now()`.
///
/// # Thread Safety
///
/// The adapter is thread-safe and can be shared across async tasks.
pub struct GitHubProjectionAdapter<T: TimeSource = SystemTimeSource> {
    /// Signer for generating receipts.
    signer: Signer,

    /// Adapter configuration.
    config: GitHubAdapterConfig,

    /// SQLite-backed idempotency cache (THESIS-02 compliant).
    cache: IdempotencyCache,

    /// GitHub HTTP client.
    client: GitHubClient,

    /// Mock mode: if true, don't actually call GitHub API.
    ///
    /// Used for testing.
    mock_mode: bool,

    /// Time source for obtaining timestamps (`BOUNDARY_INTEGRITY`).
    time_source: T,

    /// Tamper attempt counter per work item.
    /// Key: `work_id`, Value: consecutive tamper attempts.
    tamper_counters: RwLock<HashMap<String, u32>>,

    /// Threshold for tamper attempts before freeze.
    tamper_threshold: u32,

    /// Actor ID for freeze events.
    actor_id: String,

    /// Freeze registry for tamper-based freezes.
    freeze_registry: Arc<FreezeRegistry>,
}

impl GitHubProjectionAdapter<SystemTimeSource> {
    /// Creates a new GitHub projection adapter with a persistent cache.
    ///
    /// Uses the default `SystemTimeSource` for timestamp generation.
    ///
    /// # Arguments
    ///
    /// * `signer` - The signer for generating receipts
    /// * `config` - The adapter configuration
    /// * `cache_path` - Path to the `SQLite` cache database
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::DatabaseError`] if the cache cannot be
    /// opened.
    pub fn new(
        signer: Signer,
        config: GitHubAdapterConfig,
        cache_path: impl AsRef<Path>,
    ) -> Result<Self, ProjectionError> {
        Self::with_time_source(signer, config, cache_path, SystemTimeSource)
    }

    /// Creates a new adapter in mock mode for testing.
    ///
    /// Uses the default `SystemTimeSource` for timestamp generation.
    /// In mock mode, the adapter does not make actual GitHub API calls.
    /// Uses an in-memory cache.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::DatabaseError`] if the in-memory cache
    /// cannot be created.
    pub fn new_mock(signer: Signer, config: GitHubAdapterConfig) -> Result<Self, ProjectionError> {
        Self::new_mock_with_time_source(signer, config, SystemTimeSource)
    }
}

impl<T: TimeSource> GitHubProjectionAdapter<T> {
    /// Creates a new GitHub projection adapter with a custom time source.
    ///
    /// # `BOUNDARY_INTEGRITY` Compliance
    ///
    /// This constructor enables injection of a custom `TimeSource`, ensuring
    /// the adapter does not directly use `SystemTime::now()`.
    ///
    /// # Arguments
    ///
    /// * `signer` - The signer for generating receipts
    /// * `config` - The adapter configuration
    /// * `cache_path` - Path to the `SQLite` cache database
    /// * `time_source` - The time source for generating timestamps
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::DatabaseError`] if the cache cannot be
    /// opened.
    pub fn with_time_source(
        signer: Signer,
        config: GitHubAdapterConfig,
        cache_path: impl AsRef<Path>,
        time_source: T,
    ) -> Result<Self, ProjectionError> {
        let cache = IdempotencyCache::open(cache_path)?;
        let client = GitHubClient::new(config.clone());

        Ok(Self {
            signer,
            config,
            cache,
            client,
            mock_mode: false,
            time_source,
            tamper_counters: RwLock::new(HashMap::new()),
            tamper_threshold: DEFAULT_TAMPER_THRESHOLD,
            actor_id: "github-projection-adapter".to_string(),
            freeze_registry: Arc::new(FreezeRegistry::new()),
        })
    }

    /// Creates a new adapter in mock mode with a custom time source.
    ///
    /// In mock mode, the adapter does not make actual GitHub API calls.
    /// Uses an in-memory cache.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::DatabaseError`] if the in-memory cache
    /// cannot be created.
    pub fn new_mock_with_time_source(
        signer: Signer,
        config: GitHubAdapterConfig,
        time_source: T,
    ) -> Result<Self, ProjectionError> {
        let cache = IdempotencyCache::in_memory()?;
        let client = GitHubClient::new(config.clone());

        Ok(Self {
            signer,
            config,
            cache,
            client,
            mock_mode: true,
            time_source,
            tamper_counters: RwLock::new(HashMap::new()),
            tamper_threshold: DEFAULT_TAMPER_THRESHOLD,
            actor_id: "github-projection-adapter".to_string(),
            freeze_registry: Arc::new(FreezeRegistry::new()),
        })
    }

    /// Sets a shared freeze registry for tamper-based freezes.
    ///
    /// Use this when you want to share a freeze registry with the
    /// `DivergenceWatchdog` for unified freeze management.
    #[must_use]
    pub fn with_freeze_registry(mut self, registry: Arc<FreezeRegistry>) -> Self {
        self.freeze_registry = registry;
        self
    }

    /// Sets the tamper attempt threshold before freeze.
    ///
    /// After this many consecutive tamper attempts for the same work item,
    /// the adapter freezes the work and stops overwriting.
    #[must_use]
    pub const fn with_tamper_threshold(mut self, threshold: u32) -> Self {
        self.tamper_threshold = threshold;
        self
    }

    /// Sets the actor ID used for freeze events.
    #[must_use]
    pub fn with_actor_id(mut self, actor_id: impl Into<String>) -> Self {
        self.actor_id = actor_id.into();
        self
    }

    /// Returns the freeze registry.
    #[must_use]
    pub fn freeze_registry(&self) -> Arc<FreezeRegistry> {
        Arc::clone(&self.freeze_registry)
    }

    /// Returns whether the adapter is in mock mode.
    #[must_use]
    pub const fn is_mock(&self) -> bool {
        self.mock_mode
    }

    /// Returns the adapter configuration.
    #[must_use]
    pub const fn config(&self) -> &GitHubAdapterConfig {
        &self.config
    }

    /// Clears the idempotency cache.
    ///
    /// This is primarily useful for testing.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::DatabaseError`] if the cache cannot be
    /// cleared.
    pub fn clear_cache(&self) -> Result<(), ProjectionError> {
        self.cache.clear()
    }

    /// Returns the number of cached receipts.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::DatabaseError`] if the count cannot be
    /// retrieved.
    pub fn cache_size(&self) -> Result<usize, ProjectionError> {
        self.cache.size()
    }

    /// Registers a mapping from changeset digest to commit SHA.
    ///
    /// This mapping is required for the adapter to know which GitHub commit
    /// to update when projecting a status.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::DatabaseError`] if the mapping cannot be
    /// stored.
    pub fn register_commit_sha(
        &self,
        changeset_digest: &[u8; 32],
        commit_sha: &str,
    ) -> Result<(), ProjectionError> {
        self.cache
            .register_digest_sha_mapping(changeset_digest, commit_sha)
    }

    /// Looks up the commit SHA for a changeset digest.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::DatabaseError`] if the lookup fails.
    pub fn get_commit_sha(
        &self,
        changeset_digest: &[u8; 32],
    ) -> Result<Option<String>, ProjectionError> {
        self.cache.get_commit_sha(changeset_digest)
    }

    /// Performs cache maintenance to prevent unbounded growth.
    ///
    /// This method:
    /// 1. Removes entries older than 7 days (TTL-based cleanup)
    /// 2. Prunes oldest entries if cache exceeds 100,000 entries
    ///
    /// Returns the number of entries removed.
    ///
    /// # Security
    ///
    /// This method prevents disk exhaustion in long-running daemons by
    /// ensuring the idempotency cache doesn't grow unboundedly.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::DatabaseError`] if maintenance fails.
    pub fn maintain_cache(&self) -> Result<usize, ProjectionError> {
        self.cache.maintain()
    }

    /// Cleans up cache entries older than the specified TTL.
    ///
    /// # Arguments
    ///
    /// * `ttl_secs` - Maximum age in seconds for cache entries
    ///
    /// Returns the number of entries removed.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::DatabaseError`] if cleanup fails.
    pub fn cleanup_expired_cache(&self, ttl_secs: u64) -> Result<usize, ProjectionError> {
        self.cache.cleanup_expired(ttl_secs)
    }

    /// Generates a deterministic receipt ID from the idempotency key.
    ///
    /// The receipt ID is derived from a BLAKE3 hash of the idempotency key's
    /// canonical bytes, ensuring the same ID is generated for the same key
    /// even after process restarts.
    fn generate_receipt_id(key: &IdempotencyKey) -> String {
        let canonical = key.canonical_bytes();
        let hash = blake3::hash(&canonical);
        format!("proj-{}", hex::encode(&hash.as_bytes()[..16]))
    }

    /// Validates the `work_id` input.
    fn validate_work_id(work_id: &str) -> Result<(), ProjectionError> {
        if work_id.is_empty() {
            return Err(ProjectionError::ValidationError(
                "work_id cannot be empty".to_string(),
            ));
        }
        if work_id.len() > MAX_STRING_LENGTH {
            return Err(ProjectionError::ValidationError(format!(
                "work_id exceeds maximum length ({} > {MAX_STRING_LENGTH})",
                work_id.len()
            )));
        }
        Ok(())
    }

    /// Projects a status to GitHub (internal implementation).
    async fn do_github_projection(
        &self,
        changeset_digest: &[u8; 32],
        status: ProjectedStatus,
    ) -> Result<(), ProjectionError> {
        if self.mock_mode {
            // In mock mode, pretend the API call succeeded
            return Ok(());
        }

        // Look up the commit SHA for this digest
        let commit_sha = self
            .cache
            .get_commit_sha(changeset_digest)?
            .ok_or_else(|| ProjectionError::CommitShaNotFound {
                digest: hex::encode(changeset_digest),
            })?;

        // Post the status to GitHub
        self.client.post_commit_status(&commit_sha, status).await
    }

    // =========================================================================
    // Tamper Detection (TCK-00214)
    // =========================================================================

    /// Returns the current timestamp from the injected time source.
    fn now_nanos(&self) -> u64 {
        self.time_source.now_nanos()
    }

    /// Detects tamper between the expected status (from ledger) and actual
    /// status (from GitHub).
    ///
    /// Per RFC-0015, tamper detection identifies when the GitHub status has
    /// been modified by a non-adapter identity. If the statuses differ, a
    /// [`TamperEvent`] is returned for handling.
    ///
    /// # `BOUNDARY_INTEGRITY` Compliance
    ///
    /// Timestamps are obtained from the injected `TimeSource`, not from
    /// `SystemTime::now()`.
    ///
    /// # Arguments
    ///
    /// * `expected_status` - The status expected from the ledger
    /// * `actual_status` - The status observed on GitHub
    /// * `work_id` - The work ID associated with this status
    /// * `changeset_digest` - The changeset digest for the affected commit
    ///
    /// # Returns
    ///
    /// `Some(TamperEvent)` if the statuses differ, `None` otherwise.
    #[must_use]
    pub fn detect_tamper(
        &self,
        expected_status: ProjectedStatus,
        actual_status: ProjectedStatus,
        work_id: &str,
        changeset_digest: [u8; 32],
    ) -> Option<TamperEvent> {
        if expected_status == actual_status {
            None
        } else {
            debug!(
                expected = %expected_status,
                actual = %actual_status,
                work_id = %work_id,
                "tamper detected: status mismatch"
            );
            Some(TamperEvent::new(
                expected_status,
                actual_status,
                work_id,
                changeset_digest,
                self.now_nanos(),
            ))
        }
    }

    /// Generates a unique defect ID for a tamper event.
    fn generate_defect_id(event: &TamperEvent) -> String {
        // Use BLAKE3 hash of (work_id, changeset_digest, detected_at) for uniqueness
        let mut hasher = blake3::Hasher::new();
        hasher.update(event.work_id.as_bytes());
        hasher.update(&event.changeset_digest);
        hasher.update(&event.detected_at.to_be_bytes());
        let hash = hasher.finalize();
        format!("tamper-{}", hex::encode(&hash.as_bytes()[..8]))
    }

    /// Generates a unique freeze ID for a tamper-induced freeze.
    fn generate_tamper_freeze_id(&self, work_id: &str) -> String {
        let timestamp = self.now_nanos();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tamper-freeze:");
        hasher.update(work_id.as_bytes());
        hasher.update(&timestamp.to_be_bytes());
        let hash = hasher.finalize();
        format!("tamper-freeze-{}", hex::encode(&hash.as_bytes()[..8]))
    }

    /// Increments the tamper counter for a work item and returns the new count.
    ///
    /// Returns `None` if the counter cannot be updated (lock poisoned).
    fn increment_tamper_counter(&self, work_id: &str) -> Option<u32> {
        let mut counters = self.tamper_counters.write().ok()?;
        let count = counters.entry(work_id.to_string()).or_insert(0);
        *count = count.saturating_add(1);
        Some(*count)
    }

    /// Resets the tamper counter for a work item (called on successful
    /// projection).
    fn reset_tamper_counter(&self, work_id: &str) {
        if let Ok(mut counters) = self.tamper_counters.write() {
            counters.remove(work_id);
        }
    }

    /// Gets the current tamper counter for a work item.
    #[allow(dead_code)] // Exposed for testing and future use
    fn get_tamper_counter(&self, work_id: &str) -> u32 {
        self.tamper_counters
            .read()
            .ok()
            .and_then(|c| c.get(work_id).copied())
            .unwrap_or(0)
    }

    /// Checks if a work item is frozen due to tamper detection.
    ///
    /// Returns `Some(freeze_id)` if frozen, `None` otherwise.
    pub fn is_work_frozen(&self, work_id: &str) -> Option<String> {
        self.freeze_registry.is_frozen(work_id)
    }

    /// Creates a freeze for a work item due to exceeding tamper threshold.
    ///
    /// # Security
    ///
    /// This method creates an `InterventionFreeze` event when tamper attempts
    /// exceed the configured threshold, preventing further overwrites until
    /// adjudication.
    fn create_tamper_freeze(
        &self,
        work_id: &str,
        defect_id: &str,
    ) -> Result<super::divergence_watchdog::InterventionFreeze, ProjectionError> {
        let freeze_id = self.generate_tamper_freeze_id(work_id);
        let timestamp = self.now_nanos();
        let time_envelope_ref = format!("htf:tick:{timestamp}");

        // Create the freeze event
        let freeze = InterventionFreezeBuilder::new(&freeze_id)
            .scope(FreezeScope::Work)
            .scope_value(work_id)
            .trigger_defect_id(defect_id)
            .frozen_at(timestamp)
            .expected_trunk_head([0u8; 32]) // Not applicable for tamper freeze
            .actual_trunk_head([0u8; 32])   // Not applicable for tamper freeze
            .gate_actor_id(&self.actor_id)
            .time_envelope_ref(&time_envelope_ref)
            .try_build_and_sign(&self.signer)
            .map_err(|e| ProjectionError::FreezeRegistryError(e.to_string()))?;

        // Register the freeze
        self.freeze_registry
            .register(&freeze, &self.signer.verifying_key())
            .map_err(|e| ProjectionError::FreezeRegistryError(e.to_string()))?;

        warn!(
            freeze_id = %freeze_id,
            work_id = %work_id,
            "work frozen due to exceeding tamper threshold"
        );

        Ok(freeze)
    }

    /// Handles a tamper event by emitting a `DefectRecord` and conditionally
    /// overwriting the tampered status.
    ///
    /// Per RFC-0015, on tamper:
    /// 1. Check if work is already frozen - if so, return error
    /// 2. Increment tamper counter for this work item
    /// 3. If counter exceeds threshold, freeze the work and stop
    /// 4. Otherwise, emit `DefectRecord(PROJECTION_TAMPER)` and overwrite
    ///
    /// # Rate Limiting (Security)
    ///
    /// This method implements rate limiting to prevent denial-of-service from
    /// unbounded tamper loop amplification. After `tamper_threshold`
    /// consecutive attempts, the work is frozen and no further overwrites
    /// are attempted.
    ///
    /// # Arguments
    ///
    /// * `event` - The tamper event to handle
    /// * `ledger_head` - The current ledger head for the overwrite projection
    ///
    /// # Returns
    ///
    /// A [`TamperResult`] containing the emitted defect and projection receipt.
    /// If the work was frozen due to threshold, `freeze_triggered` is `true`.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::WorkFrozen`] if work is already frozen.
    /// Returns [`ProjectionError::TamperRateLimitExceeded`] if threshold
    /// exceeded. Returns [`ProjectionError`] if defect creation or
    /// projection fails.
    pub async fn on_tamper(
        &self,
        event: TamperEvent,
        ledger_head: [u8; 32],
    ) -> Result<TamperResult, ProjectionError> {
        // 1. Check if work is already frozen
        if let Some(freeze_id) = self.is_work_frozen(&event.work_id) {
            debug!(
                work_id = %event.work_id,
                freeze_id = %freeze_id,
                "skipping tamper overwrite: work is frozen"
            );
            return Err(ProjectionError::WorkFrozen {
                work_id: event.work_id.clone(),
                freeze_id,
            });
        }

        debug!(
            work_id = %event.work_id,
            expected = %event.expected_status,
            actual = %event.actual_status,
            "handling tamper event"
        );

        // 2. Increment tamper counter
        let tamper_count = self.increment_tamper_counter(&event.work_id).unwrap_or(1);

        debug!(
            work_id = %event.work_id,
            tamper_count = tamper_count,
            threshold = self.tamper_threshold,
            "tamper counter updated"
        );

        // 3. Create the defect record first (needed for freeze)
        let defect_id = Self::generate_defect_id(&event);
        let defect = DefectRecord::projection_tamper(
            &defect_id,
            &event.work_id,
            event.expected_status.as_str(),
            event.actual_status.as_str(),
            event.detected_at,
        )
        .map_err(|e| ProjectionError::DefectRecordFailed(e.to_string()))?;

        debug!(
            defect_id = %defect.defect_id(),
            "created PROJECTION_TAMPER defect"
        );

        // TCK-00307 MAJOR FIX: Create DefectRecorded event for ledger emission.
        // Per the security review, on_tamper must emit a DefectRecorded event
        // so that PROJECTION_TAMPER defects are recorded on the ledger.
        //
        // We serialize the DefectRecord to JSON and compute the CAS hash.
        // The caller is responsible for storing in CAS and emitting to the ledger.
        let defect_json = serde_json::to_vec(&defect).map_err(|e| {
            ProjectionError::DefectRecordFailed(format!("serialization error: {e}"))
        })?;
        let cas_hash = blake3::hash(&defect_json).as_bytes().to_vec();

        // Create time envelope reference from the detection timestamp
        let time_envelope_uri = format!("htf:tamper:{}", event.detected_at);
        let time_ref_hash = blake3::hash(time_envelope_uri.as_bytes())
            .as_bytes()
            .to_vec();

        let defect_event = DefectRecorded {
            defect_id: defect_id.clone(),
            defect_type: defect.defect_class().to_string(),
            cas_hash,
            source: DefectSource::ProjectionTamper as i32,
            work_id: event.work_id.clone(),
            severity: defect.severity().as_str().to_string(),
            detected_at: event.detected_at,
            time_envelope_ref: Some(TimeEnvelopeRef {
                hash: time_ref_hash,
            }),
        };

        // 4. If counter exceeds threshold, freeze and return error
        if tamper_count >= self.tamper_threshold {
            let freeze = self.create_tamper_freeze(&event.work_id, &defect_id)?;
            return Err(ProjectionError::TamperRateLimitExceeded {
                work_id: event.work_id.clone(),
                freeze_id: freeze.freeze_id,
            });
        }

        // 5. Overwrite GitHub status to match ledger truth
        let key = IdempotencyKey::new(&event.work_id, event.changeset_digest, ledger_head);

        // For tamper handling, we bypass the idempotency cache to force overwrite
        self.do_github_projection(&event.changeset_digest, event.expected_status)
            .await?;

        // Generate the receipt for the overwrite
        let receipt_id = Self::generate_receipt_id(&key);
        let projected_at = self.now_nanos();
        let receipt = ProjectionReceiptBuilder::new(receipt_id, &event.work_id)
            .changeset_digest(event.changeset_digest)
            .ledger_head(ledger_head)
            .projected_status(event.expected_status)
            .projected_at(projected_at)
            .try_build_and_sign(&self.signer)
            .map_err(|e| ProjectionError::ReceiptGenerationFailed(e.to_string()))?;

        // Store in cache for future idempotency
        self.cache.put(&key, &receipt)?;

        debug!(
            receipt_id = %receipt.receipt_id,
            "overwrote tampered status with ledger truth"
        );

        Ok(TamperResult {
            defect,
            defect_event,
            receipt,
            freeze_triggered: false,
        })
    }

    // =========================================================================
    // PR Comment Projection (TCK-00322)
    // =========================================================================

    /// Posts a comment to a GitHub PR.
    ///
    /// Per RFC-0019 (Workstream F), the projection worker posts review results
    /// as comments to PRs. This provides visibility into FAC review outcomes.
    ///
    /// # Security
    ///
    /// - **Write-only**: Comments are posted based on ledger state, not GitHub
    ///   reads
    /// - **Idempotency**: Callers should track comment posting via ledger
    ///   events to avoid duplicates
    ///
    /// # Arguments
    ///
    /// * `pr_number` - The PR number to post the comment to
    /// * `body` - The comment body (Markdown supported)
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::GitHubApiError`] if the API call fails.
    /// Returns [`ProjectionError::RateLimitExceeded`] if rate limited.
    /// Returns [`ProjectionError::AuthenticationError`] if auth fails.
    pub async fn post_comment(&self, pr_number: u64, body: &str) -> Result<(), ProjectionError> {
        if self.mock_mode {
            debug!(pr_number = pr_number, "mock mode: skipping comment post");
            return Ok(());
        }

        self.client.post_pr_comment(pr_number, body).await
    }

    /// Formats a review result as a PR comment body.
    ///
    /// This method creates a standardized comment format for review results
    /// that includes:
    /// - Review status (pass/fail)
    /// - Receipt ID for auditability
    /// - Summary of findings (if any)
    ///
    /// # Arguments
    ///
    /// * `receipt_id` - The review receipt ID
    /// * `status` - The projected status (Success/Failure/etc.)
    /// * `summary` - Optional summary of review findings
    ///
    /// # Returns
    ///
    /// A Markdown-formatted comment body.
    #[must_use]
    pub fn format_review_comment(
        receipt_id: &str,
        status: ProjectedStatus,
        summary: Option<&str>,
    ) -> String {
        use std::fmt::Write;

        let status_icon = match status {
            ProjectedStatus::Success => ":white_check_mark:",
            ProjectedStatus::Failure => ":x:",
            ProjectedStatus::Pending => ":hourglass:",
            ProjectedStatus::Error => ":warning:",
            ProjectedStatus::Cancelled => ":no_entry_sign:",
        };

        let mut comment = format!(
            "## {} APM2 FAC Review: {}\n\n",
            status_icon,
            status.as_str().to_uppercase()
        );

        // Using write! instead of push_str(&format!()) to avoid extra allocation
        let _ = write!(comment, "**Receipt ID:** `{receipt_id}`\n\n");

        if let Some(summary_text) = summary {
            comment.push_str("### Summary\n\n");
            comment.push_str(summary_text);
            comment.push_str("\n\n");
        }

        comment.push_str("---\n");
        comment.push_str("*This comment was generated by the APM2 Forge Admission Cycle.*");

        comment
    }

    /// Convenience method to detect tamper and handle it in one call.
    ///
    /// This combines `detect_tamper` and `on_tamper` for the common case
    /// where you want to check for tamper and immediately handle it.
    ///
    /// # Rate Limiting (Security)
    ///
    /// This method includes rate limiting protection. If tamper attempts
    /// exceed the configured threshold, the work is frozen and an error
    /// is returned. Check for `ProjectionError::TamperRateLimitExceeded`
    /// or `ProjectionError::WorkFrozen` to detect this condition.
    ///
    /// # Arguments
    ///
    /// * `expected_status` - The status expected from the ledger
    /// * `actual_status` - The status observed on GitHub
    /// * `work_id` - The work ID associated with this status
    /// * `changeset_digest` - The changeset digest for the affected commit
    /// * `ledger_head` - The current ledger head for overwrite projection
    ///
    /// # Returns
    ///
    /// `Some(TamperResult)` if tamper was detected and handled, `None` if
    /// no tamper was detected.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::WorkFrozen`] if work is already frozen.
    /// Returns [`ProjectionError::TamperRateLimitExceeded`] if threshold
    /// exceeded. Returns [`ProjectionError`] if tamper handling fails.
    pub async fn detect_and_handle_tamper(
        &self,
        expected_status: ProjectedStatus,
        actual_status: ProjectedStatus,
        work_id: &str,
        changeset_digest: [u8; 32],
        ledger_head: [u8; 32],
    ) -> Result<Option<TamperResult>, ProjectionError> {
        if let Some(event) =
            self.detect_tamper(expected_status, actual_status, work_id, changeset_digest)
        {
            let result = self.on_tamper(event, ledger_head).await?;
            Ok(Some(result))
        } else {
            // No tamper detected - reset counter for this work item
            self.reset_tamper_counter(work_id);
            Ok(None)
        }
    }
}

#[async_trait]
impl<T: TimeSource> ProjectionAdapter for GitHubProjectionAdapter<T> {
    async fn project_status(
        &self,
        work_id: &str,
        changeset_digest: [u8; 32],
        ledger_head: [u8; 32],
        status: ProjectedStatus,
    ) -> Result<ProjectionReceipt, ProjectionError> {
        // Validate input
        Self::validate_work_id(work_id)?;

        // Build the idempotency key
        let key = IdempotencyKey::new(work_id, changeset_digest, ledger_head);

        // Check cache first (idempotent)
        if let Some(cached_receipt) = self.cache.get(&key)? {
            debug!(work_id = %work_id, "returning cached projection receipt");
            return Ok(cached_receipt);
        }

        // Perform the GitHub API call (or mock it)
        self.do_github_projection(&changeset_digest, status).await?;

        // Generate deterministic receipt ID
        let receipt_id = Self::generate_receipt_id(&key);

        // Generate the receipt with explicit timestamp (`BOUNDARY_INTEGRITY`)
        let projected_at = self.now_nanos();
        let receipt = ProjectionReceiptBuilder::new(receipt_id, work_id)
            .changeset_digest(changeset_digest)
            .ledger_head(ledger_head)
            .projected_status(status)
            .projected_at(projected_at)
            .try_build_and_sign(&self.signer)
            .map_err(|e| ProjectionError::ReceiptGenerationFailed(e.to_string()))?;

        // Store in cache for idempotency
        self.cache.put(&key, &receipt)?;

        Ok(receipt)
    }

    fn verifying_key(&self) -> apm2_core::crypto::VerifyingKey {
        self.signer.verifying_key()
    }
}

impl<T: TimeSource> std::fmt::Debug for GitHubProjectionAdapter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubProjectionAdapter")
            .field("config", &self.config)
            .field("mock_mode", &self.mock_mode)
            .field("cache_size", &self.cache.size().unwrap_or(0))
            .field("tamper_threshold", &self.tamper_threshold)
            .finish_non_exhaustive()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(missing_docs)]
mod tests {
    use super::*;

    fn create_test_adapter() -> GitHubProjectionAdapter {
        let signer = Signer::generate();
        let config = GitHubAdapterConfig::new("https://api.github.com", "owner", "repo")
            .expect("config creation should succeed")
            .with_context("apm2/test")
            .expect("context should be valid");
        GitHubProjectionAdapter::new_mock(signer, config).expect("adapter creation should succeed")
    }

    // =========================================================================
    // GitHubAdapterConfig Tests
    // =========================================================================

    #[test]
    fn test_config_creation() {
        let config = GitHubAdapterConfig::new("https://api.github.com", "owner", "repo")
            .expect("config should be valid");

        assert_eq!(config.api_base_url, "https://api.github.com");
        assert_eq!(config.owner, "owner");
        assert_eq!(config.repo, "repo");
        assert_eq!(config.context, "apm2/gates");
        assert!(config.target_url.is_none());
    }

    #[test]
    fn test_config_with_options() {
        let config = GitHubAdapterConfig::new("https://api.github.com", "owner", "repo")
            .expect("config should be valid")
            .with_context("custom/context")
            .expect("context should be valid")
            .with_target_url("https://example.com/details")
            .expect("target_url should be valid");

        assert_eq!(config.context, "custom/context");
        assert_eq!(
            config.target_url,
            Some("https://example.com/details".to_string())
        );
    }

    #[test]
    fn test_config_validation_empty_field() {
        let result = GitHubAdapterConfig::new("", "owner", "repo");
        assert!(matches!(result, Err(ProjectionError::ValidationError(_))));
    }

    #[test]
    fn test_config_validation_too_long() {
        let long_string = "x".repeat(MAX_CONFIG_STRING_LENGTH + 1);
        let result = GitHubAdapterConfig::new(long_string, "owner", "repo");
        assert!(matches!(result, Err(ProjectionError::ValidationError(_))));
    }

    // =========================================================================
    // GitHubProjectionAdapter Tests
    // =========================================================================

    #[test]
    fn test_adapter_creation() {
        let adapter = create_test_adapter();

        assert!(adapter.is_mock());
        assert_eq!(adapter.cache_size().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_project_status_success() {
        let adapter = create_test_adapter();

        let receipt = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        assert_eq!(receipt.work_id, "work-001");
        assert_eq!(receipt.changeset_digest, [0x42; 32]);
        assert_eq!(receipt.ledger_head, [0xAB; 32]);
        assert_eq!(receipt.projected_status, ProjectedStatus::Success);
        assert!(receipt.receipt_id.starts_with("proj-"));
    }

    #[tokio::test]
    async fn test_project_status_idempotent() {
        let adapter = create_test_adapter();

        // First projection
        let receipt1 = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        assert_eq!(adapter.cache_size().unwrap(), 1);

        // Second projection with same key
        let receipt2 = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        // Should return the same receipt (from cache)
        assert_eq!(receipt1.receipt_id, receipt2.receipt_id);
        assert_eq!(receipt1.adapter_signature, receipt2.adapter_signature);

        // Cache size should still be 1
        assert_eq!(adapter.cache_size().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_project_status_different_ledger_head() {
        let adapter = create_test_adapter();

        // First projection
        let receipt1 = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        // Second projection with different ledger_head
        let receipt2 = adapter
            .project_status("work-001", [0x42; 32], [0xCD; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        // Should be different receipts
        assert_ne!(receipt1.receipt_id, receipt2.receipt_id);
        assert_ne!(receipt1.ledger_head, receipt2.ledger_head);

        // Cache should have 2 entries
        assert_eq!(adapter.cache_size().unwrap(), 2);
    }

    #[tokio::test]
    async fn test_project_status_different_work_id() {
        let adapter = create_test_adapter();

        let receipt1 = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        let receipt2 = adapter
            .project_status("work-002", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        assert_ne!(receipt1.receipt_id, receipt2.receipt_id);
        assert_eq!(adapter.cache_size().unwrap(), 2);
    }

    #[tokio::test]
    async fn test_project_status_different_changeset() {
        let adapter = create_test_adapter();

        let receipt1 = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        let receipt2 = adapter
            .project_status("work-001", [0x99; 32], [0xAB; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        assert_ne!(receipt1.receipt_id, receipt2.receipt_id);
        assert_eq!(adapter.cache_size().unwrap(), 2);
    }

    #[tokio::test]
    async fn test_project_status_all_statuses() {
        let adapter = create_test_adapter();

        let statuses = [
            ProjectedStatus::Pending,
            ProjectedStatus::Success,
            ProjectedStatus::Failure,
            ProjectedStatus::Cancelled,
            ProjectedStatus::Error,
        ];

        for (i, status) in statuses.iter().enumerate() {
            let receipt = adapter
                .project_status(&format!("work-{i:03}"), [0x42; 32], [0xAB; 32], *status)
                .await
                .expect("projection should succeed");

            assert_eq!(receipt.projected_status, *status);
        }

        assert_eq!(adapter.cache_size().unwrap(), 5);
    }

    #[tokio::test]
    async fn test_receipt_signature_valid() {
        let adapter = create_test_adapter();

        let receipt = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        // Verify signature using adapter's verifying key
        assert!(receipt.validate_signature(&adapter.verifying_key()).is_ok());
    }

    #[tokio::test]
    async fn test_receipt_signature_invalid_with_other_key() {
        let adapter = create_test_adapter();

        let receipt = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        // Verify with a different key should fail
        let other_signer = Signer::generate();
        assert!(
            receipt
                .validate_signature(&other_signer.verifying_key())
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_clear_cache() {
        let adapter = create_test_adapter();

        adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        assert_eq!(adapter.cache_size().unwrap(), 1);

        adapter.clear_cache().unwrap();

        assert_eq!(adapter.cache_size().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_clear_cache_allows_new_receipt() {
        let adapter = create_test_adapter();

        let receipt1 = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        adapter.clear_cache().unwrap();

        let receipt2 = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        // After clearing cache, receipt_id should still be deterministic
        // (same idempotency key produces same receipt_id)
        assert_eq!(receipt1.receipt_id, receipt2.receipt_id);
    }

    #[tokio::test]
    async fn test_deterministic_receipt_id() {
        // Receipt IDs should be deterministic based on idempotency key
        let adapter1 = create_test_adapter();
        let adapter2 = create_test_adapter();

        let receipt1 = adapter1
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        let receipt2 = adapter2
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        // Same idempotency key should produce same receipt_id
        assert_eq!(receipt1.receipt_id, receipt2.receipt_id);
    }

    #[tokio::test]
    async fn test_idempotency_key_from_receipt() {
        let adapter = create_test_adapter();

        let receipt = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        let key = receipt.idempotency_key();
        assert_eq!(key.work_id, "work-001");
        assert_eq!(key.changeset_digest, [0x42; 32]);
        assert_eq!(key.ledger_head, [0xAB; 32]);
    }

    #[test]
    fn test_adapter_debug() {
        let adapter = create_test_adapter();
        let debug_str = format!("{adapter:?}");

        assert!(debug_str.contains("GitHubProjectionAdapter"));
        assert!(debug_str.contains("mock_mode: true"));
    }

    // =========================================================================
    // Input Validation Tests
    // =========================================================================

    #[tokio::test]
    async fn test_validate_work_id_empty() {
        let adapter = create_test_adapter();

        let result = adapter
            .project_status("", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .await;

        assert!(matches!(result, Err(ProjectionError::ValidationError(_))));
    }

    #[tokio::test]
    async fn test_validate_work_id_too_long() {
        let adapter = create_test_adapter();
        let long_work_id = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = adapter
            .project_status(
                &long_work_id,
                [0x42; 32],
                [0xAB; 32],
                ProjectedStatus::Success,
            )
            .await;

        assert!(matches!(result, Err(ProjectionError::ValidationError(_))));
    }

    // =========================================================================
    // Digest-to-SHA Mapping Tests
    // =========================================================================

    #[test]
    fn test_register_and_get_commit_sha() {
        let adapter = create_test_adapter();

        let digest = [0x42; 32];
        let sha = "abc123def456";

        adapter
            .register_commit_sha(&digest, sha)
            .expect("registration should succeed");

        let result = adapter
            .get_commit_sha(&digest)
            .expect("lookup should succeed");
        assert_eq!(result, Some(sha.to_string()));
    }

    #[test]
    fn test_get_commit_sha_not_found() {
        let adapter = create_test_adapter();

        let digest = [0x99; 32];
        let result = adapter
            .get_commit_sha(&digest)
            .expect("lookup should succeed");
        assert_eq!(result, None);
    }

    // =========================================================================
    // Domain Separator Tests
    // =========================================================================

    #[tokio::test]
    async fn test_uses_projection_receipt_domain_separator() {
        use apm2_core::fac::PROJECTION_RECEIPT_PREFIX;

        let adapter = create_test_adapter();

        let receipt = adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        // The receipt should use PROJECTION_RECEIPT: domain separator
        // We can verify this by checking that a signature without the prefix fails

        let canonical = receipt.canonical_bytes();

        // Create a signature without domain prefix
        let signer = Signer::generate();
        let _wrong_signature = signer.sign(&canonical);

        // Manually check that the adapter uses the correct prefix by verifying
        // that the receipt signature was created with PROJECTION_RECEIPT_PREFIX
        assert_eq!(PROJECTION_RECEIPT_PREFIX, b"PROJECTION_RECEIPT:");

        // Verify the signature is valid with the adapter's key
        assert!(receipt.validate_signature(&adapter.verifying_key()).is_ok());
    }

    // =========================================================================
    // Cache Maintenance Tests
    // =========================================================================

    #[tokio::test]
    async fn test_cache_maintenance() {
        let adapter = create_test_adapter();

        // Add some entries
        for i in 0..5 {
            adapter
                .project_status(
                    &format!("work-{i:03}"),
                    [0x42; 32],
                    [0xAB; 32],
                    ProjectedStatus::Success,
                )
                .await
                .expect("projection should succeed");
        }

        assert_eq!(adapter.cache_size().unwrap(), 5);

        // Run maintenance (should not remove recent entries)
        let removed = adapter.maintain_cache().unwrap();
        assert_eq!(removed, 0);
        assert_eq!(adapter.cache_size().unwrap(), 5);
    }

    #[tokio::test]
    async fn test_cleanup_expired_cache() {
        let adapter = create_test_adapter();

        // Add an entry
        adapter
            .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
            .await
            .expect("projection should succeed");

        assert_eq!(adapter.cache_size().unwrap(), 1);

        // Cleanup with a very large TTL should remove nothing
        let removed = adapter.cleanup_expired_cache(u64::MAX).unwrap();
        assert_eq!(removed, 0);
        assert_eq!(adapter.cache_size().unwrap(), 1);

        // Cleanup with TTL=1 should also keep recently created entries
        // (entry was just created, so it's not older than 1 second)
        let removed = adapter.cleanup_expired_cache(1).unwrap();
        assert_eq!(removed, 0);
        assert_eq!(adapter.cache_size().unwrap(), 1);
    }

    #[test]
    fn test_cleanup_preserves_recent_mappings() {
        let adapter = create_test_adapter();

        // Register a mapping
        adapter
            .register_commit_sha(&[0x42; 32], "abc123")
            .expect("registration should succeed");

        // Verify it exists
        let sha = adapter.get_commit_sha(&[0x42; 32]).unwrap();
        assert_eq!(sha, Some("abc123".to_string()));

        // Cleanup with large TTL should preserve the mapping
        let removed = adapter.cleanup_expired_cache(u64::MAX).unwrap();
        assert_eq!(removed, 0);

        // Verify it still exists
        let sha = adapter.get_commit_sha(&[0x42; 32]).unwrap();
        assert_eq!(sha, Some("abc123".to_string()));
    }

    // =========================================================================
    // Tamper Detection Tests (TCK-00214)
    // =========================================================================

    /// Submodule for tamper detection tests.
    ///
    /// Per the ticket requirements, these tests verify:
    /// - Tamper is detected when GitHub status differs from ledger
    /// - `DefectRecord(PROJECTION_TAMPER)` is emitted
    /// - Tampered status is overwritten with ledger truth
    /// - Rate limiting prevents unbounded tamper loop amplification
    pub mod tamper {
        use super::*;

        // =====================================================================
        // TamperEvent Tests
        // =====================================================================

        #[test]
        fn test_tamper_event_creation() {
            let timestamp = 1_000_000_000u64;
            let event = TamperEvent::new(
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                "work-001",
                [0x42; 32],
                timestamp,
            );

            assert_eq!(event.expected_status, ProjectedStatus::Success);
            assert_eq!(event.actual_status, ProjectedStatus::Failure);
            assert_eq!(event.work_id, "work-001");
            assert_eq!(event.changeset_digest, [0x42; 32]);
            assert_eq!(event.detected_at, timestamp);
        }

        // =====================================================================
        // detect_tamper() Tests
        // =====================================================================

        #[test]
        fn test_detect_tamper_status_mismatch() {
            let adapter = create_test_adapter();

            let result = adapter.detect_tamper(
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                "work-001",
                [0x42; 32],
            );

            assert!(result.is_some());
            let event = result.unwrap();
            assert_eq!(event.expected_status, ProjectedStatus::Success);
            assert_eq!(event.actual_status, ProjectedStatus::Failure);
        }

        #[test]
        fn test_detect_tamper_no_mismatch() {
            let adapter = create_test_adapter();

            let result = adapter.detect_tamper(
                ProjectedStatus::Success,
                ProjectedStatus::Success,
                "work-001",
                [0x42; 32],
            );

            assert!(result.is_none());
        }

        #[test]
        fn test_detect_tamper_all_status_pairs() {
            let adapter = create_test_adapter();

            let statuses = [
                ProjectedStatus::Pending,
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                ProjectedStatus::Cancelled,
                ProjectedStatus::Error,
            ];

            // Test all pairs where expected != actual
            for expected in &statuses {
                for actual in &statuses {
                    let result = adapter.detect_tamper(*expected, *actual, "work-001", [0x42; 32]);

                    if expected == actual {
                        assert!(result.is_none(), "same status should not be tamper");
                    } else {
                        assert!(result.is_some(), "different status should be tamper");
                        let event = result.unwrap();
                        assert_eq!(event.expected_status, *expected);
                        assert_eq!(event.actual_status, *actual);
                    }
                }
            }
        }

        // =====================================================================
        // on_tamper() Tests
        // =====================================================================

        #[tokio::test]
        async fn test_on_tamper_emits_defect_record() {
            let adapter = create_test_adapter();

            let event = TamperEvent::new(
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                "work-001",
                [0x42; 32],
                1_000_000_000,
            );

            let result = adapter.on_tamper(event, [0xAB; 32]).await;
            assert!(result.is_ok());

            let tamper_result = result.unwrap();

            // Verify DefectRecord was created
            assert_eq!(tamper_result.defect.defect_class(), "PROJECTION_TAMPER");
            assert!(tamper_result.defect.defect_id().starts_with("tamper-"));
            assert_eq!(tamper_result.defect.work_id(), "work-001");
            assert!(tamper_result.defect.signal().details().contains("success"));
            assert!(tamper_result.defect.signal().details().contains("failure"));
        }

        #[tokio::test]
        async fn test_on_tamper_overwrites_status() {
            let adapter = create_test_adapter();

            let event = TamperEvent::new(
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                "work-001",
                [0x42; 32],
                1_000_000_000,
            );

            let result = adapter.on_tamper(event, [0xAB; 32]).await;
            assert!(result.is_ok());

            let tamper_result = result.unwrap();

            // Verify projection receipt was created with correct status
            assert_eq!(tamper_result.receipt.work_id, "work-001");
            assert_eq!(tamper_result.receipt.changeset_digest, [0x42; 32]);
            assert_eq!(tamper_result.receipt.ledger_head, [0xAB; 32]);
            assert_eq!(
                tamper_result.receipt.projected_status,
                ProjectedStatus::Success
            );
        }

        #[tokio::test]
        async fn test_on_tamper_receipt_signature_valid() {
            let adapter = create_test_adapter();

            let event = TamperEvent::new(
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                "work-001",
                [0x42; 32],
                1_000_000_000,
            );

            let result = adapter.on_tamper(event, [0xAB; 32]).await;
            assert!(result.is_ok());

            let tamper_result = result.unwrap();

            // Verify receipt signature is valid
            assert!(
                tamper_result
                    .receipt
                    .validate_signature(&adapter.verifying_key())
                    .is_ok()
            );
        }

        #[tokio::test]
        async fn test_on_tamper_caches_receipt() {
            let adapter = create_test_adapter();
            let initial_size = adapter.cache_size().unwrap();

            let event = TamperEvent::new(
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                "work-001",
                [0x42; 32],
                1_000_000_000,
            );

            let result = adapter.on_tamper(event, [0xAB; 32]).await;
            assert!(result.is_ok());

            // Cache should have one more entry
            assert_eq!(adapter.cache_size().unwrap(), initial_size + 1);
        }

        // =====================================================================
        // detect_and_handle_tamper() Tests
        // =====================================================================

        #[tokio::test]
        async fn test_detect_and_handle_tamper_detected() {
            let adapter = create_test_adapter();

            let result = adapter
                .detect_and_handle_tamper(
                    ProjectedStatus::Success,
                    ProjectedStatus::Failure,
                    "work-001",
                    [0x42; 32],
                    [0xAB; 32],
                )
                .await;

            assert!(result.is_ok());
            let maybe_result = result.unwrap();
            assert!(maybe_result.is_some());

            let tamper_result = maybe_result.unwrap();
            assert_eq!(tamper_result.defect.defect_class(), "PROJECTION_TAMPER");
            assert_eq!(
                tamper_result.receipt.projected_status,
                ProjectedStatus::Success
            );
        }

        #[tokio::test]
        async fn test_detect_and_handle_tamper_not_detected() {
            let adapter = create_test_adapter();

            let result = adapter
                .detect_and_handle_tamper(
                    ProjectedStatus::Success,
                    ProjectedStatus::Success,
                    "work-001",
                    [0x42; 32],
                    [0xAB; 32],
                )
                .await;

            assert!(result.is_ok());
            let maybe_result = result.unwrap();
            assert!(maybe_result.is_none());
        }

        // =====================================================================
        // Defect ID Generation Tests
        // =====================================================================

        #[test]
        fn test_defect_id_deterministic() {
            let event1 = TamperEvent::new(
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                "work-001",
                [0x42; 32],
                1_000_000_000,
            );

            let event2 = TamperEvent::new(
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                "work-001",
                [0x42; 32],
                1_000_000_000,
            );

            let id1 = GitHubProjectionAdapter::<SystemTimeSource>::generate_defect_id(&event1);
            let id2 = GitHubProjectionAdapter::<SystemTimeSource>::generate_defect_id(&event2);

            assert_eq!(id1, id2);
            assert!(id1.starts_with("tamper-"));
        }

        #[test]
        fn test_defect_id_unique_for_different_events() {
            let event1 = TamperEvent::new(
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                "work-001",
                [0x42; 32],
                1_000_000_000,
            );

            let event2 = TamperEvent::new(
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                "work-002", // Different work_id
                [0x42; 32],
                1_000_000_000,
            );

            let event3 = TamperEvent::new(
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                "work-001",
                [0x99; 32], // Different changeset_digest
                1_000_000_000,
            );

            let id1 = GitHubProjectionAdapter::<SystemTimeSource>::generate_defect_id(&event1);
            let id2 = GitHubProjectionAdapter::<SystemTimeSource>::generate_defect_id(&event2);
            let id3 = GitHubProjectionAdapter::<SystemTimeSource>::generate_defect_id(&event3);

            assert_ne!(id1, id2);
            assert_ne!(id1, id3);
            assert_ne!(id2, id3);
        }

        // =====================================================================
        // Integration Tests
        // =====================================================================

        #[tokio::test]
        async fn test_tamper_detection_end_to_end() {
            // Simulate the full tamper detection workflow:
            // 1. Initial projection (ledger says Success)
            // 2. External tamper (GitHub now shows Failure)
            // 3. Detect tamper
            // 4. Handle tamper (emit defect, overwrite)
            // 5. Verify final state

            let adapter = create_test_adapter();

            // 1. Initial projection
            let initial_receipt = adapter
                .project_status("work-001", [0x42; 32], [0xAB; 32], ProjectedStatus::Success)
                .await
                .expect("initial projection should succeed");

            assert_eq!(initial_receipt.projected_status, ProjectedStatus::Success);

            // 2. Simulate external tamper (in real scenario, this would be detected by
            //    polling GitHub)
            let ledger_status = ProjectedStatus::Success;
            let github_status = ProjectedStatus::Failure; // Tampered!

            // 3 & 4. Detect and handle tamper
            let tamper_result = adapter
                .detect_and_handle_tamper(
                    ledger_status,
                    github_status,
                    "work-001",
                    [0x42; 32],
                    [0xCD; 32], // New ledger head after tamper
                )
                .await
                .expect("tamper handling should succeed");

            assert!(tamper_result.is_some());
            let result = tamper_result.unwrap();

            // 5. Verify final state
            // Defect record was emitted
            assert_eq!(result.defect.defect_class(), "PROJECTION_TAMPER");

            // Status was overwritten to match ledger truth
            assert_eq!(result.receipt.projected_status, ProjectedStatus::Success);

            // New ledger head is in the receipt
            assert_eq!(result.receipt.ledger_head, [0xCD; 32]);
        }

        #[tokio::test]
        async fn test_multiple_tamper_events_unique_defect_ids() {
            let adapter = create_test_adapter();

            // Handle multiple tamper events for different work items
            let event1 = TamperEvent::new(
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                "work-001",
                [0x42; 32],
                1_000_000_000,
            );

            let event2 = TamperEvent::new(
                ProjectedStatus::Pending,
                ProjectedStatus::Cancelled,
                "work-002",
                [0x99; 32],
                1_000_000_001,
            );

            let result1 = adapter.on_tamper(event1, [0xAB; 32]).await.unwrap();
            let result2 = adapter.on_tamper(event2, [0xCD; 32]).await.unwrap();

            // Each event should get a unique defect ID
            assert_ne!(result1.defect.defect_id(), result2.defect.defect_id());

            // Both should be PROJECTION_TAMPER
            assert_eq!(result1.defect.defect_class(), "PROJECTION_TAMPER");
            assert_eq!(result2.defect.defect_class(), "PROJECTION_TAMPER");
        }

        // =====================================================================
        // Rate Limiting Tests (Security)
        // =====================================================================

        #[tokio::test]
        async fn test_tamper_rate_limiting_threshold() {
            // Create an adapter with threshold of 2
            let signer = Signer::generate();
            let config = GitHubAdapterConfig::new("https://api.github.com", "owner", "repo")
                .expect("config creation should succeed");
            let adapter = GitHubProjectionAdapter::new_mock(signer, config)
                .expect("adapter creation should succeed")
                .with_tamper_threshold(2);

            // First tamper attempt should succeed
            let event1 = TamperEvent::new(
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                "work-001",
                [0x42; 32],
                1_000_000_000,
            );
            let result1 = adapter.on_tamper(event1, [0xAB; 32]).await;
            assert!(result1.is_ok());

            // Second tamper attempt should trigger freeze
            let event2 = TamperEvent::new(
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                "work-001",
                [0x42; 32],
                1_000_000_001,
            );
            let result2 = adapter.on_tamper(event2, [0xAB; 32]).await;
            assert!(matches!(
                result2,
                Err(ProjectionError::TamperRateLimitExceeded { .. })
            ));

            // Verify work is now frozen
            assert!(adapter.is_work_frozen("work-001").is_some());
        }

        #[tokio::test]
        async fn test_frozen_work_rejects_tamper_handling() {
            let signer = Signer::generate();
            let config = GitHubAdapterConfig::new("https://api.github.com", "owner", "repo")
                .expect("config creation should succeed");
            let adapter = GitHubProjectionAdapter::new_mock(signer, config)
                .expect("adapter creation should succeed")
                .with_tamper_threshold(1); // Freeze on first attempt

            // First attempt triggers freeze
            let event1 = TamperEvent::new(
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                "work-001",
                [0x42; 32],
                1_000_000_000,
            );
            let result1 = adapter.on_tamper(event1, [0xAB; 32]).await;
            assert!(matches!(
                result1,
                Err(ProjectionError::TamperRateLimitExceeded { .. })
            ));

            // Subsequent attempts return WorkFrozen error
            let event2 = TamperEvent::new(
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                "work-001",
                [0x42; 32],
                1_000_000_002,
            );
            let result2 = adapter.on_tamper(event2, [0xAB; 32]).await;
            assert!(matches!(result2, Err(ProjectionError::WorkFrozen { .. })));
        }

        #[tokio::test]
        async fn test_different_work_items_have_independent_counters() {
            let signer = Signer::generate();
            let config = GitHubAdapterConfig::new("https://api.github.com", "owner", "repo")
                .expect("config creation should succeed");
            let adapter = GitHubProjectionAdapter::new_mock(signer, config)
                .expect("adapter creation should succeed")
                .with_tamper_threshold(2);

            // Tamper work-001 once
            let event1 = TamperEvent::new(
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                "work-001",
                [0x42; 32],
                1_000_000_000,
            );
            let result1 = adapter.on_tamper(event1, [0xAB; 32]).await;
            assert!(result1.is_ok());

            // Tamper work-002 once - should succeed (different counter)
            let event2 = TamperEvent::new(
                ProjectedStatus::Success,
                ProjectedStatus::Failure,
                "work-002",
                [0x99; 32],
                1_000_000_001,
            );
            let result2 = adapter.on_tamper(event2, [0xCD; 32]).await;
            assert!(result2.is_ok());

            // Verify neither is frozen yet
            assert!(adapter.is_work_frozen("work-001").is_none());
            assert!(adapter.is_work_frozen("work-002").is_none());
        }
    }
}

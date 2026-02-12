// AGENT-AUTHORED (TCK-00496)
//! Core quarantine store with priority-aware eviction, per-session quota,
//! saturation-safe insertion, and `SQLite` persistence.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};

use apm2_core::crypto::Hash;
use thiserror::Error;

use crate::admission_kernel::QuarantineGuard;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum global quarantine entries (denial-of-service protection).
pub const MAX_GLOBAL_ENTRIES: usize = 4096;

/// Maximum quarantine entries per session (quota isolation).
pub const MAX_PER_SESSION_ENTRIES: usize = 64;

/// Maximum session ID length in bytes.
pub const MAX_SESSION_ID_LENGTH: usize = 256;

/// Maximum reason string length in bytes.
pub const MAX_REASON_LENGTH: usize = 1024;

/// Maximum number of tracked sessions (denial-of-service protection).
pub const MAX_TRACKED_SESSIONS: usize = 4096;

// =============================================================================
// Error Types
// =============================================================================

/// Errors from quarantine store operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum QuarantineStoreError {
    /// Global capacity exhausted and no evictable entry exists.
    #[error("quarantine saturated: no evictable entry for priority {incoming_priority:?}")]
    Saturated {
        /// Priority of the entry that could not be inserted.
        incoming_priority: QuarantinePriority,
    },

    /// Per-session quota exhausted.
    #[error("per-session quota exceeded for session '{session_id}' ({count} >= {max})")]
    SessionQuotaExceeded {
        /// The session that hit its quota.
        session_id: String,
        /// Current count for that session.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Session ID too long.
    #[error("session_id exceeds max length ({len} > {max})")]
    SessionIdTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Reason string too long.
    #[error("reason exceeds max length ({len} > {max})")]
    ReasonTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Persistence backend error.
    #[error("persistence error: {reason}")]
    PersistenceError {
        /// Human-readable error description.
        reason: String,
    },

    /// Too many tracked sessions.
    #[error("too many tracked sessions ({count} >= {max})")]
    TooManySessions {
        /// Current session count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },
}

// =============================================================================
// Priority Type
// =============================================================================

/// Priority level for quarantine entries.
///
/// Higher values indicate higher priority. Entries with higher priority
/// are never evicted by entries with equal or lower priority when unexpired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum QuarantinePriority {
    /// Low priority — evictable by any higher priority entry.
    Low      = 0,
    /// Normal priority — default for standard quarantine entries.
    Normal   = 1,
    /// High priority — only evictable by Critical entries.
    High     = 2,
    /// Critical priority — never evicted by lower priority entries.
    Critical = 3,
}

impl QuarantinePriority {
    /// Convert from u8 tag, returning `None` for invalid values.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Low),
            1 => Some(Self::Normal),
            2 => Some(Self::High),
            3 => Some(Self::Critical),
            _ => None,
        }
    }

    /// Convert to u8 tag.
    #[must_use]
    pub const fn as_tag(self) -> u8 {
        self as u8
    }
}

// =============================================================================
// Entry Types
// =============================================================================

/// Unique identifier for a quarantine entry.
pub type QuarantineEntryId = u64;

/// A quarantine store entry with priority and expiry metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineEntry {
    /// Unique entry identifier (monotonically increasing).
    pub id: QuarantineEntryId,
    /// Session that owns this entry.
    pub session_id: String,
    /// Priority level for eviction decisions.
    pub priority: QuarantinePriority,
    /// Request ID that created this entry (audit binding).
    pub request_id: Hash,
    /// Admission bundle digest at insertion time (audit binding).
    pub bundle_digest: Hash,
    /// Reservation hash proving capacity was reserved.
    pub reservation_hash: Hash,
    /// HTF tick at which this entry was created.
    pub created_at_tick: u64,
    /// HTF tick at which this entry expires. Expired entries are
    /// evictable regardless of priority.
    pub expires_at_tick: u64,
    /// Human-readable reason for this quarantine reservation.
    pub reason: String,
}

impl QuarantineEntry {
    /// Returns `true` if this entry has expired at the given tick.
    #[must_use]
    pub const fn is_expired_at(&self, current_tick: u64) -> bool {
        current_tick >= self.expires_at_tick
    }
}

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the quarantine store.
#[derive(Debug, Clone)]
pub struct QuarantineStoreConfig {
    /// Maximum global entries.
    pub max_global_entries: usize,
    /// Maximum entries per session.
    pub max_per_session_entries: usize,
    /// Maximum tracked sessions.
    pub max_tracked_sessions: usize,
}

impl Default for QuarantineStoreConfig {
    fn default() -> Self {
        Self {
            max_global_entries: MAX_GLOBAL_ENTRIES,
            max_per_session_entries: MAX_PER_SESSION_ENTRIES,
            max_tracked_sessions: MAX_TRACKED_SESSIONS,
        }
    }
}

// =============================================================================
// In-Memory Store
// =============================================================================

/// In-memory quarantine store with priority-aware eviction and per-session
/// quota isolation.
///
/// # Synchronization Protocol
///
/// This type is NOT thread-safe. External synchronization (e.g., `Mutex`)
/// is required for concurrent access. The `DurableQuarantineGuard` wraps
/// this in a `Mutex` with documented happens-before edges.
///
/// # Eviction Strategy
///
/// When global capacity is reached and a new entry must be inserted:
/// 1. Evict expired entries first (any priority).
/// 2. Among non-expired entries, evict the lowest priority entry that is
///    strictly less than the incoming priority.
/// 3. If no evictable entry exists, deny insertion (fail-closed).
#[derive(Debug)]
pub struct QuarantineStore {
    /// Configuration.
    config: QuarantineStoreConfig,
    /// Entries indexed by ID for O(1) lookup.
    entries: BTreeMap<QuarantineEntryId, QuarantineEntry>,
    /// Per-session entry count for quota isolation.
    /// Protected data: entry counts per session.
    /// Mutation: only via insert/remove on entries map.
    /// Ordering: always update AFTER entries map mutation.
    session_counts: HashMap<String, usize>,
    /// Next entry ID (monotonically increasing).
    next_id: QuarantineEntryId,
}

impl QuarantineStore {
    /// Creates a new empty store with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(QuarantineStoreConfig::default())
    }

    /// Creates a new empty store with the given configuration.
    #[must_use]
    pub fn with_config(config: QuarantineStoreConfig) -> Self {
        Self {
            config,
            entries: BTreeMap::new(),
            session_counts: HashMap::new(),
            next_id: 1,
        }
    }

    /// Returns the number of entries in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the entry count for a specific session.
    #[must_use]
    pub fn session_count(&self, session_id: &str) -> usize {
        self.session_counts.get(session_id).copied().unwrap_or(0)
    }

    /// Inserts a new quarantine entry with priority-aware eviction.
    ///
    /// # Eviction Order
    ///
    /// 1. Expired entries (any priority) — evicted first.
    /// 2. Lowest priority entries strictly below incoming — evicted next.
    /// 3. If no evictable entry exists — denied (fail-closed).
    ///
    /// # Errors
    ///
    /// Returns `QuarantineStoreError` if:
    /// - Per-session quota exceeded
    /// - Global capacity saturated with no evictable entries
    /// - Input validation fails
    #[allow(clippy::too_many_arguments)] // quarantine insert requires all fields for audit binding
    pub fn insert(
        &mut self,
        session_id: &str,
        priority: QuarantinePriority,
        request_id: Hash,
        bundle_digest: Hash,
        reservation_hash: Hash,
        created_at_tick: u64,
        expires_at_tick: u64,
        reason: &str,
        current_tick: u64,
    ) -> Result<QuarantineEntryId, QuarantineStoreError> {
        // Input validation (DoS protection)
        if session_id.len() > MAX_SESSION_ID_LENGTH {
            return Err(QuarantineStoreError::SessionIdTooLong {
                len: session_id.len(),
                max: MAX_SESSION_ID_LENGTH,
            });
        }
        if reason.len() > MAX_REASON_LENGTH {
            return Err(QuarantineStoreError::ReasonTooLong {
                len: reason.len(),
                max: MAX_REASON_LENGTH,
            });
        }

        // Per-session quota check
        let session_count = self.session_counts.get(session_id).copied().unwrap_or(0);
        if session_count >= self.config.max_per_session_entries {
            return Err(QuarantineStoreError::SessionQuotaExceeded {
                session_id: session_id.to_string(),
                count: session_count,
                max: self.config.max_per_session_entries,
            });
        }

        // New session tracking bound check
        if session_count == 0 && self.session_counts.len() >= self.config.max_tracked_sessions {
            return Err(QuarantineStoreError::TooManySessions {
                count: self.session_counts.len(),
                max: self.config.max_tracked_sessions,
            });
        }

        // Global capacity check with priority-aware eviction
        if self.entries.len() >= self.config.max_global_entries
            && !self.try_evict_one(priority, current_tick)
        {
            return Err(QuarantineStoreError::Saturated {
                incoming_priority: priority,
            });
        }

        // Create and insert the entry
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);

        let entry = QuarantineEntry {
            id,
            session_id: session_id.to_string(),
            priority,
            request_id,
            bundle_digest,
            reservation_hash,
            created_at_tick,
            expires_at_tick,
            reason: reason.to_string(),
        };

        self.entries.insert(id, entry);
        *self
            .session_counts
            .entry(session_id.to_string())
            .or_insert(0) += 1;

        Ok(id)
    }

    /// Removes an entry by ID.
    ///
    /// Returns `true` if the entry existed and was removed.
    pub fn remove(&mut self, id: QuarantineEntryId) -> bool {
        if let Some(entry) = self.entries.remove(&id) {
            if let Some(count) = self.session_counts.get_mut(&entry.session_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.session_counts.remove(&entry.session_id);
                }
            }
            true
        } else {
            false
        }
    }

    /// Removes all expired entries at the given tick.
    ///
    /// Returns the number of entries removed.
    pub fn evict_expired(&mut self, current_tick: u64) -> usize {
        let expired_ids: Vec<QuarantineEntryId> = self
            .entries
            .iter()
            .filter(|(_, e)| e.is_expired_at(current_tick))
            .map(|(&id, _)| id)
            .collect();

        let count = expired_ids.len();
        for id in expired_ids {
            self.remove(id);
        }
        count
    }

    /// Looks up an entry by its reservation hash.
    #[must_use]
    pub fn find_by_reservation_hash(&self, hash: &Hash) -> Option<&QuarantineEntry> {
        self.entries.values().find(|e| e.reservation_hash == *hash)
    }

    /// Returns an iterator over all entries.
    pub fn entries(&self) -> impl Iterator<Item = &QuarantineEntry> {
        self.entries.values()
    }

    /// Restores an entry from persistent storage during recovery.
    ///
    /// This bypasses normal eviction logic and quota checks because we
    /// are reconstituting previously-persisted state. The `next_id` counter
    /// is advanced past the restored entry's ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the global capacity would be exceeded even
    /// for restoration (hard safety bound).
    pub fn restore_entry(&mut self, entry: QuarantineEntry) -> Result<(), QuarantineStoreError> {
        if self.entries.len() >= self.config.max_global_entries {
            return Err(QuarantineStoreError::Saturated {
                incoming_priority: entry.priority,
            });
        }

        // Advance next_id past restored entry
        if entry.id >= self.next_id {
            self.next_id = entry.id.saturating_add(1);
        }

        *self
            .session_counts
            .entry(entry.session_id.clone())
            .or_insert(0) += 1;
        self.entries.insert(entry.id, entry);
        Ok(())
    }

    /// Try to evict one entry to make room for an incoming entry with the
    /// given priority.
    ///
    /// # Eviction Order
    ///
    /// 1. Expired entries — any priority, oldest first (lowest ID).
    /// 2. Non-expired entries with priority strictly below incoming — lowest
    ///    priority first, then oldest (lowest ID) as tiebreaker.
    ///
    /// Returns `true` if an entry was evicted.
    fn try_evict_one(&mut self, incoming_priority: QuarantinePriority, current_tick: u64) -> bool {
        // Phase 1: Try to evict an expired entry (any priority)
        let expired_id = self
            .entries
            .iter()
            .filter(|(_, e)| e.is_expired_at(current_tick))
            .min_by_key(|(id, _)| **id)
            .map(|(id, _)| *id);

        if let Some(id) = expired_id {
            self.remove(id);
            return true;
        }

        // Phase 2: Try to evict the lowest-priority entry strictly below incoming
        let evictable_id = self
            .entries
            .iter()
            .filter(|(_, e)| e.priority < incoming_priority)
            .min_by(|(id_a, a), (id_b, b)| a.priority.cmp(&b.priority).then_with(|| id_a.cmp(id_b)))
            .map(|(id, _)| *id);

        if let Some(id) = evictable_id {
            self.remove(id);
            return true;
        }

        false
    }
}

impl Default for QuarantineStore {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// SQLite Backend
// =============================================================================

/// SQLite-backed persistence for quarantine entries.
///
/// # Synchronization Protocol
///
/// Access is serialized through the `Mutex<rusqlite::Connection>` inherited
/// from the daemon's shared connection. All write operations use transactions
/// for atomicity.
///
/// # Schema
///
/// ```sql
/// CREATE TABLE IF NOT EXISTS quarantine_entries (
///     id INTEGER PRIMARY KEY,
///     session_id TEXT NOT NULL,
///     priority INTEGER NOT NULL,
///     request_id BLOB NOT NULL,
///     bundle_digest BLOB NOT NULL,
///     reservation_hash BLOB NOT NULL,
///     created_at_tick INTEGER NOT NULL,
///     expires_at_tick INTEGER NOT NULL,
///     reason TEXT NOT NULL
/// );
/// ```
pub struct SqliteQuarantineBackend {
    /// Shared `SQLite` connection (`Mutex` for thread safety).
    /// Protected data: `quarantine_entries` table.
    /// Mutation: via SQL INSERT/DELETE/UPDATE within transactions.
    /// Ordering: caller holds `Mutex` for full transaction scope.
    conn: Arc<Mutex<rusqlite::Connection>>,
}

impl std::fmt::Debug for SqliteQuarantineBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteQuarantineBackend")
            .field("conn", &"<sqlite>")
            .finish()
    }
}

impl SqliteQuarantineBackend {
    /// Opens or creates the quarantine table in the given `SQLite` connection.
    ///
    /// # Errors
    ///
    /// Returns `QuarantineStoreError::PersistenceError` if table creation
    /// fails.
    pub fn new(conn: Arc<Mutex<rusqlite::Connection>>) -> Result<Self, QuarantineStoreError> {
        {
            let db = conn
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            db.execute_batch(
                "CREATE TABLE IF NOT EXISTS quarantine_entries (
                    id INTEGER PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    request_id BLOB NOT NULL,
                    bundle_digest BLOB NOT NULL,
                    reservation_hash BLOB NOT NULL,
                    created_at_tick INTEGER NOT NULL,
                    expires_at_tick INTEGER NOT NULL,
                    reason TEXT NOT NULL
                );",
            )
            .map_err(|e| QuarantineStoreError::PersistenceError {
                reason: format!("failed to create quarantine_entries table: {e}"),
            })?;
        }
        Ok(Self { conn })
    }

    /// Opens a standalone `SQLite` database at the given path for quarantine
    /// persistence.
    ///
    /// Uses WAL mode for concurrent read/write and durability.
    ///
    /// # Errors
    ///
    /// Returns `QuarantineStoreError::PersistenceError` if the database
    /// cannot be opened or configured.
    pub fn open(path: &Path) -> Result<Self, QuarantineStoreError> {
        let conn = rusqlite::Connection::open(path).map_err(|e| {
            QuarantineStoreError::PersistenceError {
                reason: format!(
                    "failed to open quarantine database at {}: {e}",
                    path.display()
                ),
            }
        })?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| QuarantineStoreError::PersistenceError {
                reason: format!("failed to set WAL mode: {e}"),
            })?;
        // Synchronous FULL for durability guarantees on fail-closed tiers
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| QuarantineStoreError::PersistenceError {
                reason: format!("failed to set synchronous mode: {e}"),
            })?;
        let conn = Arc::new(Mutex::new(conn));
        Self::new(conn)
    }

    /// Persists a quarantine entry to the database.
    ///
    /// # Errors
    ///
    /// Returns `QuarantineStoreError::PersistenceError` on SQL failure.
    #[allow(clippy::cast_possible_wrap)] // entry.id and tick values are within i64 range for practical use
    pub fn persist_entry(&self, entry: &QuarantineEntry) -> Result<(), QuarantineStoreError> {
        let db = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        db.execute(
            "INSERT OR REPLACE INTO quarantine_entries
             (id, session_id, priority, request_id, bundle_digest,
              reservation_hash, created_at_tick, expires_at_tick, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                entry.id as i64,
                entry.session_id,
                entry.priority.as_tag(),
                entry.request_id.as_slice(),
                entry.bundle_digest.as_slice(),
                entry.reservation_hash.as_slice(),
                entry.created_at_tick as i64,
                entry.expires_at_tick as i64,
                entry.reason,
            ],
        )
        .map_err(|e| QuarantineStoreError::PersistenceError {
            reason: format!("failed to persist quarantine entry {}: {e}", entry.id),
        })?;
        Ok(())
    }

    /// Removes a quarantine entry from the database.
    ///
    /// # Errors
    ///
    /// Returns `QuarantineStoreError::PersistenceError` on SQL failure.
    #[allow(clippy::cast_possible_wrap)]
    pub fn remove_entry(&self, id: QuarantineEntryId) -> Result<(), QuarantineStoreError> {
        let db = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        db.execute(
            "DELETE FROM quarantine_entries WHERE id = ?1",
            rusqlite::params![id as i64],
        )
        .map_err(|e| QuarantineStoreError::PersistenceError {
            reason: format!("failed to remove quarantine entry {id}: {e}"),
        })?;
        Ok(())
    }

    /// Removes all expired entries from the database.
    ///
    /// # Errors
    ///
    /// Returns `QuarantineStoreError::PersistenceError` on SQL failure.
    #[allow(clippy::cast_possible_wrap)]
    pub fn remove_expired(&self, current_tick: u64) -> Result<usize, QuarantineStoreError> {
        let db = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = db
            .execute(
                "DELETE FROM quarantine_entries WHERE expires_at_tick <= ?1",
                rusqlite::params![current_tick as i64],
            )
            .map_err(|e| QuarantineStoreError::PersistenceError {
                reason: format!("failed to remove expired entries: {e}"),
            })?;
        Ok(count)
    }

    /// Loads all persisted entries for restart recovery.
    ///
    /// Results are ordered by `id` (rowid tiebreaker for determinism).
    /// Bounded by `MAX_GLOBAL_ENTRIES` to prevent memory exhaustion from
    /// a corrupted database.
    ///
    /// # Errors
    ///
    /// Returns `QuarantineStoreError::PersistenceError` on SQL failure
    /// or data corruption.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)] // SQL integers are positive for our use cases; MAX_GLOBAL_ENTRIES fits in i64
    pub fn load_all(&self) -> Result<Vec<QuarantineEntry>, QuarantineStoreError> {
        let db = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut stmt = db
            .prepare(
                "SELECT id, session_id, priority, request_id, bundle_digest,
                        reservation_hash, created_at_tick, expires_at_tick, reason
                 FROM quarantine_entries
                 ORDER BY id ASC
                 LIMIT ?1",
            )
            .map_err(|e| QuarantineStoreError::PersistenceError {
                reason: format!("failed to prepare load query: {e}"),
            })?;

        let entries = stmt
            .query_map(rusqlite::params![MAX_GLOBAL_ENTRIES as i64], |row| {
                let id: i64 = row.get(0)?;
                let session_id: String = row.get(1)?;
                let priority_tag: u8 = row.get(2)?;
                let request_id_blob: Vec<u8> = row.get(3)?;
                let bundle_digest_blob: Vec<u8> = row.get(4)?;
                let reservation_hash_blob: Vec<u8> = row.get(5)?;
                let created_at_tick: i64 = row.get(6)?;
                let expires_at_tick: i64 = row.get(7)?;
                let reason: String = row.get(8)?;

                Ok((
                    id,
                    session_id,
                    priority_tag,
                    request_id_blob,
                    bundle_digest_blob,
                    reservation_hash_blob,
                    created_at_tick,
                    expires_at_tick,
                    reason,
                ))
            })
            .map_err(|e| QuarantineStoreError::PersistenceError {
                reason: format!("failed to execute load query: {e}"),
            })?;

        let mut result = Vec::new();
        for row_result in entries {
            let (
                id,
                session_id,
                priority_tag,
                request_id_blob,
                bundle_digest_blob,
                reservation_hash_blob,
                created_at_tick,
                expires_at_tick,
                reason,
            ) = row_result.map_err(|e| QuarantineStoreError::PersistenceError {
                reason: format!("failed to read quarantine entry row: {e}"),
            })?;

            let priority = QuarantinePriority::from_tag(priority_tag).ok_or_else(|| {
                QuarantineStoreError::PersistenceError {
                    reason: format!("invalid priority tag {priority_tag} in entry {id}"),
                }
            })?;

            let request_id: Hash =
                request_id_blob
                    .try_into()
                    .map_err(|_| QuarantineStoreError::PersistenceError {
                        reason: format!("invalid request_id length in entry {id}"),
                    })?;
            let bundle_digest: Hash = bundle_digest_blob.try_into().map_err(|_| {
                QuarantineStoreError::PersistenceError {
                    reason: format!("invalid bundle_digest length in entry {id}"),
                }
            })?;
            let reservation_hash: Hash = reservation_hash_blob.try_into().map_err(|_| {
                QuarantineStoreError::PersistenceError {
                    reason: format!("invalid reservation_hash length in entry {id}"),
                }
            })?;

            // Bounds check on string fields from DB (defense in depth)
            if session_id.len() > MAX_SESSION_ID_LENGTH {
                return Err(QuarantineStoreError::PersistenceError {
                    reason: format!(
                        "session_id too long in entry {id} ({} > {MAX_SESSION_ID_LENGTH})",
                        session_id.len()
                    ),
                });
            }
            if reason.len() > MAX_REASON_LENGTH {
                return Err(QuarantineStoreError::PersistenceError {
                    reason: format!(
                        "reason too long in entry {id} ({} > {MAX_REASON_LENGTH})",
                        reason.len()
                    ),
                });
            }
            if result.len() >= MAX_GLOBAL_ENTRIES {
                break;
            }

            result.push(QuarantineEntry {
                id: id as u64,
                session_id,
                priority,
                request_id,
                bundle_digest,
                reservation_hash,
                created_at_tick: created_at_tick as u64,
                expires_at_tick: expires_at_tick as u64,
                reason,
            });
        }

        Ok(result)
    }
}

// =============================================================================
// DurableQuarantineGuard
// =============================================================================

/// Durable quarantine guard implementing the `QuarantineGuard` trait with
/// `SQLite`-backed persistence, priority-aware eviction, and per-session quota.
///
/// # Synchronization Protocol
///
/// All mutable operations are serialized through `Mutex<Inner>`.
/// - Protected data: `QuarantineStore` (entries, session counts, `next_id`).
/// - Mutation: only via `reserve()` and `recover()`.
/// - Lock ordering: `Inner` lock is always acquired first; the `SQLite`
///   connection lock (inside `SqliteQuarantineBackend`) is acquired second. No
///   other locks are held while `Inner` is locked.
/// - Happens-before: the `Mutex` release at the end of `reserve()` establishes
///   happens-before with any subsequent `reserve()` call.
///
/// # Fail-Closed Contract
///
/// If the `SQLite` backend is unavailable (e.g., disk full, corruption),
/// `reserve()` returns `Err` and the admission kernel denies the request.
pub struct DurableQuarantineGuard {
    /// Inner mutable state behind a mutex.
    inner: Mutex<QuarantineStore>,
    /// `SQLite` persistence backend.
    backend: SqliteQuarantineBackend,
    /// Default `session_id` used when the guard is invoked without session
    /// context (the `QuarantineGuard` trait only provides `request_id` and
    /// `ajc_id`).
    default_session_id: String,
    /// Default priority for entries created via the trait interface.
    default_priority: QuarantinePriority,
    /// Default TTL in ticks for entry expiry.
    default_ttl_ticks: u64,
    /// Current tick provider (monotonically increasing).
    /// This is a function pointer to allow testing with injected ticks.
    tick_provider: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl std::fmt::Debug for DurableQuarantineGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableQuarantineGuard")
            .field("default_session_id", &self.default_session_id)
            .field("default_priority", &self.default_priority)
            .field("default_ttl_ticks", &self.default_ttl_ticks)
            .finish_non_exhaustive()
    }
}

/// Default TTL in ticks (1 hour at 1MHz tick rate).
pub const DEFAULT_TTL_TICKS: u64 = 3_600_000_000;

impl DurableQuarantineGuard {
    /// Creates a new durable quarantine guard with `SQLite` persistence.
    ///
    /// # Arguments
    ///
    /// * `backend` - `SQLite` persistence backend.
    /// * `config` - Store configuration.
    ///
    /// # Recovery
    ///
    /// On creation, this loads all persisted entries from the database.
    /// Entries that survived a restart are recovered into the in-memory store.
    ///
    /// # Errors
    ///
    /// Returns `QuarantineStoreError::PersistenceError` if recovery fails.
    pub fn new(
        backend: SqliteQuarantineBackend,
        config: QuarantineStoreConfig,
    ) -> Result<Self, QuarantineStoreError> {
        let mut store = QuarantineStore::with_config(config);

        // Recover persisted entries
        let persisted = backend.load_all()?;
        for entry in persisted {
            store.restore_entry(entry)?;
        }

        Ok(Self {
            inner: Mutex::new(store),
            backend,
            default_session_id: "kernel".to_string(),
            default_priority: QuarantinePriority::Normal,
            default_ttl_ticks: DEFAULT_TTL_TICKS,
            tick_provider: Box::new(default_tick_provider),
        })
    }

    /// Sets the default session ID for trait-level reservations.
    #[must_use]
    pub fn with_default_session_id(mut self, session_id: String) -> Self {
        self.default_session_id = session_id;
        self
    }

    /// Sets the default priority for trait-level reservations.
    #[must_use]
    pub const fn with_default_priority(mut self, priority: QuarantinePriority) -> Self {
        self.default_priority = priority;
        self
    }

    /// Sets the default TTL in ticks.
    #[must_use]
    pub const fn with_default_ttl_ticks(mut self, ttl: u64) -> Self {
        self.default_ttl_ticks = ttl;
        self
    }

    /// Sets a custom tick provider (for testing).
    #[must_use]
    pub fn with_tick_provider(mut self, provider: Box<dyn Fn() -> u64 + Send + Sync>) -> Self {
        self.tick_provider = provider;
        self
    }

    /// Inserts an entry with full parameters (bypassing trait-level defaults).
    ///
    /// # Errors
    ///
    /// Returns `QuarantineStoreError` on validation, saturation, or
    /// persistence failure.
    pub fn insert(
        &self,
        session_id: &str,
        priority: QuarantinePriority,
        request_id: Hash,
        bundle_digest: Hash,
        ttl_ticks: u64,
        reason: &str,
    ) -> Result<(QuarantineEntryId, Hash), QuarantineStoreError> {
        let current_tick = (self.tick_provider)();
        let expires_at_tick = current_tick.saturating_add(ttl_ticks);
        let reservation_hash = compute_reservation_hash(&request_id, &bundle_digest, current_tick);

        let mut store = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let id = store.insert(
            session_id,
            priority,
            request_id,
            bundle_digest,
            reservation_hash,
            current_tick,
            expires_at_tick,
            reason,
            current_tick,
        )?;

        // Persist to SQLite (fail-closed: if persistence fails, roll back)
        let entry = store.entries.get(&id).expect("just inserted");
        if let Err(e) = self.backend.persist_entry(entry) {
            // Roll back in-memory insertion
            store.remove(id);
            return Err(e);
        }

        Ok((id, reservation_hash))
    }

    /// Removes an entry and updates persistence.
    ///
    /// # Errors
    ///
    /// Returns `QuarantineStoreError::PersistenceError` if the database
    /// removal fails. The in-memory removal still proceeds to avoid
    /// inconsistency, but the error is reported.
    pub fn remove(&self, id: QuarantineEntryId) -> Result<bool, QuarantineStoreError> {
        let mut store = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let existed = store.remove(id);
        if existed {
            self.backend.remove_entry(id)?;
        }
        Ok(existed)
    }

    /// Evicts all expired entries from both in-memory store and database.
    ///
    /// # Errors
    ///
    /// Returns `QuarantineStoreError::PersistenceError` on database failure.
    pub fn evict_expired(&self) -> Result<usize, QuarantineStoreError> {
        let current_tick = (self.tick_provider)();
        let mut store = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = store.evict_expired(current_tick);
        if count > 0 {
            self.backend.remove_expired(current_tick)?;
        }
        Ok(count)
    }

    /// Returns the number of entries in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        let store = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        store.len()
    }

    /// Returns `true` if the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the entry count for a session.
    #[must_use]
    pub fn session_count(&self, session_id: &str) -> usize {
        let store = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        store.session_count(session_id)
    }
}

/// Default tick provider using `std::time::Instant` for monotonic time.
///
/// Returns microseconds since an arbitrary epoch (process start).
/// This is safe for relative comparisons within a single daemon lifecycle.
fn default_tick_provider() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;

    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    let elapsed = epoch.elapsed();
    // Microseconds fits in u64 for ~584,942 years; truncation is
    // unreachable within any daemon lifecycle.
    #[allow(clippy::cast_possible_truncation)]
    let ticks = elapsed.as_micros() as u64;
    ticks
}

/// Computes a reservation hash from `request_id`, `bundle_digest`, and tick.
///
/// Uses BLAKE3 with domain separation for collision resistance.
#[must_use]
pub fn compute_reservation_hash(request_id: &Hash, bundle_digest: &Hash, tick: u64) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"apm2-quarantine-reservation-v1");
    hasher.update(request_id);
    hasher.update(bundle_digest);
    hasher.update(&tick.to_le_bytes());
    *hasher.finalize().as_bytes()
}

// =============================================================================
// QuarantineGuard Trait Implementation
// =============================================================================

impl QuarantineGuard for DurableQuarantineGuard {
    fn reserve(&self, request_id: &Hash, ajc_id: &Hash) -> Result<Hash, String> {
        let current_tick = (self.tick_provider)();
        let expires_at_tick = current_tick.saturating_add(self.default_ttl_ticks);
        let reservation_hash = compute_reservation_hash(request_id, ajc_id, current_tick);

        let mut store = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let id = store
            .insert(
                &self.default_session_id,
                self.default_priority,
                *request_id,
                *ajc_id,
                reservation_hash,
                current_tick,
                expires_at_tick,
                "kernel_reservation",
                current_tick,
            )
            .map_err(|e| e.to_string())?;

        // Persist to SQLite (fail-closed)
        let entry = store.entries.get(&id).expect("just inserted");
        if let Err(e) = self.backend.persist_entry(entry) {
            store.remove(id);
            return Err(e.to_string());
        }

        Ok(reservation_hash)
    }
}

//! `SQLite`-backed ledger storage implementation.
//!
//! This module uses `SQLite` with WAL mode for the underlying storage.
//! The [`SqliteLedgerBackend`] struct implements the [`LedgerBackend`] trait,
//! providing a concrete storage backend for the APM2 event ledger.

// SQLite returns i64 for row IDs and counts, but they're always non-negative.
// Timestamps won't overflow u64 until the year 2554.
// Mutex poisoning indicates a panic in another thread, which is unrecoverable.
#![allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc
)]

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use thiserror::Error;

use super::backend::LedgerBackend;

/// Schema SQL embedded at compile time.
const SCHEMA_SQL: &str = include_str!("schema.sql");

/// Errors that can occur during ledger operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LedgerError {
    /// Database error from `SQLite`.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// I/O error during database operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Attempted to modify an existing event (violates append-only).
    #[error("cannot modify event {seq_id}: ledger is append-only")]
    AppendOnlyViolation {
        /// The sequence ID of the event that was attempted to be modified.
        seq_id: u64,
    },

    /// Invalid sequence number requested.
    #[error("invalid cursor position: {cursor}")]
    InvalidCursor {
        /// The invalid cursor value.
        cursor: u64,
    },

    /// Event not found.
    #[error("event not found: seq_id={seq_id}")]
    EventNotFound {
        /// The sequence ID that was not found.
        seq_id: u64,
    },

    /// Hash chain verification failed.
    #[error("hash chain broken at seq_id={seq_id}: {details}")]
    HashChainBroken {
        /// The sequence ID where the chain broke.
        seq_id: u64,
        /// Details about the failure.
        details: String,
    },

    /// Signature verification failed.
    #[error("signature verification failed at seq_id={seq_id}: {details}")]
    SignatureInvalid {
        /// The sequence ID with the invalid signature.
        seq_id: u64,
        /// Details about the failure.
        details: String,
    },

    /// Crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),
}

/// Current record version for the event schema.
pub const CURRENT_RECORD_VERSION: u32 = 1;

/// A single event record in the ledger.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EventRecord {
    /// Sequence ID (assigned by the ledger on append).
    pub seq_id: Option<u64>,

    /// Event type identifier.
    pub event_type: String,

    /// Session this event belongs to.
    pub session_id: String,

    /// Actor ID that signed this event (signer identity).
    pub actor_id: String,

    /// Record version for schema compatibility.
    pub record_version: u32,

    /// Event payload (typically JSON).
    pub payload: Vec<u8>,

    /// Timestamp in nanoseconds since Unix epoch.
    pub timestamp_ns: u64,

    /// Hash of the previous event (for hash chaining).
    pub prev_hash: Option<Vec<u8>>,

    /// Hash of this event's content.
    pub event_hash: Option<Vec<u8>>,

    /// Signature over the event.
    pub signature: Option<Vec<u8>>,
}

impl EventRecord {
    /// Creates a new event record with the current timestamp.
    ///
    /// The `seq_id`, `prev_hash`, `event_hash`, and `signature` fields
    /// are populated when the event is appended to the ledger or
    /// when using `append_signed()` for crypto integration.
    #[must_use]
    pub fn new(
        event_type: impl Into<String>,
        session_id: impl Into<String>,
        actor_id: impl Into<String>,
        payload: Vec<u8>,
    ) -> Self {
        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        Self {
            seq_id: None,
            event_type: event_type.into(),
            session_id: session_id.into(),
            actor_id: actor_id.into(),
            record_version: CURRENT_RECORD_VERSION,
            payload,
            timestamp_ns,
            prev_hash: None,
            event_hash: None,
            signature: None,
        }
    }

    /// Creates a new event record with a specific timestamp.
    #[must_use]
    pub fn with_timestamp(
        event_type: impl Into<String>,
        session_id: impl Into<String>,
        actor_id: impl Into<String>,
        payload: Vec<u8>,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            seq_id: None,
            event_type: event_type.into(),
            session_id: session_id.into(),
            actor_id: actor_id.into(),
            record_version: CURRENT_RECORD_VERSION,
            payload,
            timestamp_ns,
            prev_hash: None,
            event_hash: None,
            signature: None,
        }
    }

    /// Sets the sequence ID for this event record (builder pattern).
    #[must_use]
    pub const fn with_seq_id(mut self, seq_id: u64) -> Self {
        self.seq_id = Some(seq_id);
        self
    }
}

/// A reference to an artifact in content-addressable storage.
#[derive(Debug, Clone)]
pub struct ArtifactRef {
    /// Reference ID (assigned by the ledger).
    pub id: Option<u64>,

    /// Event sequence ID this artifact is associated with.
    pub event_seq_id: u64,

    /// SHA-256 hash of the artifact content.
    pub content_hash: Vec<u8>,

    /// MIME type of the artifact.
    pub content_type: String,

    /// Size of the artifact in bytes.
    pub size_bytes: u64,

    /// Path to the artifact in CAS.
    pub storage_path: String,

    /// Timestamp when the reference was created.
    pub created_at_ns: u64,
}

impl ArtifactRef {
    /// Creates a new artifact reference.
    #[must_use]
    pub fn new(
        event_seq_id: u64,
        content_hash: Vec<u8>,
        content_type: impl Into<String>,
        size_bytes: u64,
        storage_path: impl Into<String>,
    ) -> Self {
        let created_at_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        Self {
            id: None,
            event_seq_id,
            content_hash,
            content_type: content_type.into(),
            size_bytes,
            storage_path: storage_path.into(),
            created_at_ns,
        }
    }
}

/// Statistics about the ledger.
#[derive(Debug, Clone, Default)]
pub struct LedgerStats {
    /// Total number of events.
    pub event_count: u64,

    /// Total number of artifact references.
    pub artifact_count: u64,

    /// Highest sequence ID (0 if empty).
    pub max_seq_id: u64,

    /// Database file size in bytes.
    pub db_size_bytes: u64,
}

/// The append-only event ledger backed by `SQLite`.
///
/// The ledger uses `SQLite`'s WAL mode to allow concurrent reads while
/// writes are in progress. Events are stored with monotonically increasing
/// sequence numbers and can never be modified or deleted.
///
/// This struct implements the [`LedgerBackend`] trait, providing the core
/// storage operations for the APM2 event-sourcing architecture.
pub struct SqliteLedgerBackend {
    conn: Arc<std::sync::Mutex<Connection>>,
    #[allow(dead_code)]
    path: Option<std::path::PathBuf>,
}

/// Type alias for backward compatibility.
///
/// Existing code using `Ledger` will continue to work unchanged.
pub type Ledger = SqliteLedgerBackend;

impl SqliteLedgerBackend {
    /// Opens or creates a ledger at the specified path.
    ///
    /// If the database doesn't exist, it will be created with the
    /// appropriate schema. WAL mode is enabled for concurrent reads.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or initialized.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let path = path.as_ref();
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        Self::initialize_connection(&conn)?;

        Ok(Self {
            conn: Arc::new(std::sync::Mutex::new(conn)),
            path: Some(path.to_path_buf()),
        })
    }

    /// Creates an in-memory ledger for testing.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be initialized.
    pub fn in_memory() -> Result<Self, LedgerError> {
        let conn = Connection::open_in_memory()?;
        Self::initialize_connection(&conn)?;

        Ok(Self {
            conn: Arc::new(std::sync::Mutex::new(conn)),
            path: None,
        })
    }

    /// Initialize the connection with schema and pragmas.
    fn initialize_connection(conn: &Connection) -> Result<(), LedgerError> {
        // Execute schema (includes PRAGMA statements)
        conn.execute_batch(SCHEMA_SQL)?;
        Ok(())
    }

    /// Appends an event to the ledger.
    ///
    /// Returns the assigned sequence ID for the event.
    ///
    /// # Errors
    ///
    /// Returns an error if the event cannot be inserted.
    pub fn append(&self, event: &EventRecord) -> Result<u64, LedgerError> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT INTO events (event_type, session_id, actor_id, record_version, payload, timestamp_ns, prev_hash, event_hash, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                event.event_type,
                event.session_id,
                event.actor_id,
                event.record_version,
                event.payload,
                event.timestamp_ns,
                event.prev_hash,
                event.event_hash,
                event.signature,
            ],
        )?;

        Ok(conn.last_insert_rowid() as u64)
    }

    /// Appends multiple events in a single transaction.
    ///
    /// Returns the sequence IDs assigned to each event in order.
    ///
    /// # Errors
    ///
    /// Returns an error if any event cannot be inserted. On error,
    /// no events are inserted (atomic operation).
    pub fn append_batch(&self, events: &[EventRecord]) -> Result<Vec<u64>, LedgerError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let mut seq_ids = Vec::with_capacity(events.len());

        {
            let mut stmt = tx.prepare(
                "INSERT INTO events (event_type, session_id, actor_id, record_version, payload, timestamp_ns, prev_hash, event_hash, signature)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;

            for event in events {
                stmt.execute(params![
                    event.event_type,
                    event.session_id,
                    event.actor_id,
                    event.record_version,
                    event.payload,
                    event.timestamp_ns,
                    event.prev_hash,
                    event.event_hash,
                    event.signature,
                ])?;
                seq_ids.push(tx.last_insert_rowid() as u64);
            }
        }

        tx.commit()?;
        Ok(seq_ids)
    }

    /// Reads events starting from a cursor position.
    ///
    /// Returns up to `limit` events with sequence IDs >= `cursor`.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn read_from(&self, cursor: u64, limit: u64) -> Result<Vec<EventRecord>, LedgerError> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT seq_id, event_type, session_id, actor_id, record_version, payload, timestamp_ns, prev_hash, event_hash, signature
             FROM events
             WHERE seq_id >= ?1
             ORDER BY seq_id ASC
             LIMIT ?2",
        )?;

        let events = stmt
            .query_map(params![cursor, limit], |row| {
                Ok(EventRecord {
                    seq_id: Some(row.get::<_, i64>(0)? as u64),
                    event_type: row.get(1)?,
                    session_id: row.get(2)?,
                    actor_id: row.get(3)?,
                    record_version: row.get::<_, i64>(4)? as u32,
                    payload: row.get(5)?,
                    timestamp_ns: row.get::<_, i64>(6)? as u64,
                    prev_hash: row.get(7)?,
                    event_hash: row.get(8)?,
                    signature: row.get(9)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(events)
    }

    /// Reads a single event by sequence ID.
    ///
    /// # Errors
    ///
    /// Returns `EventNotFound` if no event exists with that sequence ID.
    pub fn read_one(&self, seq_id: u64) -> Result<EventRecord, LedgerError> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT seq_id, event_type, session_id, actor_id, record_version, payload, timestamp_ns, prev_hash, event_hash, signature
             FROM events
             WHERE seq_id = ?1",
        )?;

        stmt.query_row(params![seq_id], |row| {
            Ok(EventRecord {
                seq_id: Some(row.get::<_, i64>(0)? as u64),
                event_type: row.get(1)?,
                session_id: row.get(2)?,
                actor_id: row.get(3)?,
                record_version: row.get::<_, i64>(4)? as u32,
                payload: row.get(5)?,
                timestamp_ns: row.get::<_, i64>(6)? as u64,
                prev_hash: row.get(7)?,
                event_hash: row.get(8)?,
                signature: row.get(9)?,
            })
        })
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => LedgerError::EventNotFound { seq_id },
            other => LedgerError::Database(other),
        })
    }

    /// Reads events for a specific session.
    ///
    /// Returns events in sequence order.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn read_session(
        &self,
        session_id: &str,
        limit: u64,
    ) -> Result<Vec<EventRecord>, LedgerError> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT seq_id, event_type, session_id, actor_id, record_version, payload, timestamp_ns, prev_hash, event_hash, signature
             FROM events
             WHERE session_id = ?1
             ORDER BY seq_id ASC
             LIMIT ?2",
        )?;

        let events = stmt
            .query_map(params![session_id, limit], |row| {
                Ok(EventRecord {
                    seq_id: Some(row.get::<_, i64>(0)? as u64),
                    event_type: row.get(1)?,
                    session_id: row.get(2)?,
                    actor_id: row.get(3)?,
                    record_version: row.get::<_, i64>(4)? as u32,
                    payload: row.get(5)?,
                    timestamp_ns: row.get::<_, i64>(6)? as u64,
                    prev_hash: row.get(7)?,
                    event_hash: row.get(8)?,
                    signature: row.get(9)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(events)
    }

    /// Reads events by type.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn read_by_type(
        &self,
        event_type: &str,
        cursor: u64,
        limit: u64,
    ) -> Result<Vec<EventRecord>, LedgerError> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT seq_id, event_type, session_id, actor_id, record_version, payload, timestamp_ns, prev_hash, event_hash, signature
             FROM events
             WHERE event_type = ?1 AND seq_id >= ?2
             ORDER BY seq_id ASC
             LIMIT ?3",
        )?;

        let events = stmt
            .query_map(params![event_type, cursor, limit], |row| {
                Ok(EventRecord {
                    seq_id: Some(row.get::<_, i64>(0)? as u64),
                    event_type: row.get(1)?,
                    session_id: row.get(2)?,
                    actor_id: row.get(3)?,
                    record_version: row.get::<_, i64>(4)? as u32,
                    payload: row.get(5)?,
                    timestamp_ns: row.get::<_, i64>(6)? as u64,
                    prev_hash: row.get(7)?,
                    event_hash: row.get(8)?,
                    signature: row.get(9)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(events)
    }

    /// Adds an artifact reference.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference cannot be inserted.
    pub fn add_artifact_ref(&self, artifact: &ArtifactRef) -> Result<u64, LedgerError> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT INTO artifact_refs (event_seq_id, content_hash, content_type, size_bytes, storage_path, created_at_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                artifact.event_seq_id,
                artifact.content_hash,
                artifact.content_type,
                artifact.size_bytes,
                artifact.storage_path,
                artifact.created_at_ns,
            ],
        )?;

        Ok(conn.last_insert_rowid() as u64)
    }

    /// Gets artifact references for an event.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn get_artifacts_for_event(
        &self,
        event_seq_id: u64,
    ) -> Result<Vec<ArtifactRef>, LedgerError> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT id, event_seq_id, content_hash, content_type, size_bytes, storage_path, created_at_ns
             FROM artifact_refs
             WHERE event_seq_id = ?1
             ORDER BY id ASC",
        )?;

        let artifacts = stmt
            .query_map(params![event_seq_id], |row| {
                Ok(ArtifactRef {
                    id: Some(row.get::<_, i64>(0)? as u64),
                    event_seq_id: row.get::<_, i64>(1)? as u64,
                    content_hash: row.get(2)?,
                    content_type: row.get(3)?,
                    size_bytes: row.get::<_, i64>(4)? as u64,
                    storage_path: row.get(5)?,
                    created_at_ns: row.get::<_, i64>(6)? as u64,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(artifacts)
    }

    /// Looks up an artifact by content hash.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn find_artifact_by_hash(
        &self,
        content_hash: &[u8],
    ) -> Result<Option<ArtifactRef>, LedgerError> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT id, event_seq_id, content_hash, content_type, size_bytes, storage_path, created_at_ns
             FROM artifact_refs
             WHERE content_hash = ?1
             LIMIT 1",
        )?;

        let result = stmt
            .query_row(params![content_hash], |row| {
                Ok(ArtifactRef {
                    id: Some(row.get::<_, i64>(0)? as u64),
                    event_seq_id: row.get::<_, i64>(1)? as u64,
                    content_hash: row.get(2)?,
                    content_type: row.get(3)?,
                    size_bytes: row.get::<_, i64>(4)? as u64,
                    storage_path: row.get(5)?,
                    created_at_ns: row.get::<_, i64>(6)? as u64,
                })
            })
            .optional()?;

        Ok(result)
    }

    /// Gets the current maximum sequence ID (head of the ledger).
    ///
    /// Returns 0 if the ledger is empty.
    ///
    /// This is the synchronous version. For the async trait method, see
    /// [`LedgerBackend::head`].
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn head_sync(&self) -> Result<u64, LedgerError> {
        let conn = self.conn.lock().unwrap();

        let max: Option<i64> =
            conn.query_row("SELECT MAX(seq_id) FROM events", [], |row| row.get(0))?;

        Ok(max.unwrap_or(0) as u64)
    }

    /// Alias for `head_sync()` for backward compatibility.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    #[deprecated(since = "2.0.0", note = "Use head_sync() instead for clarity")]
    pub fn max_seq_id(&self) -> Result<u64, LedgerError> {
        self.head_sync()
    }

    /// Gets statistics about the ledger.
    ///
    /// # Errors
    ///
    /// Returns an error if statistics cannot be gathered.
    pub fn stats(&self) -> Result<LedgerStats, LedgerError> {
        let conn = self.conn.lock().unwrap();

        let event_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;

        let artifact_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM artifact_refs", [], |row| row.get(0))?;

        let max_seq_id: Option<i64> =
            conn.query_row("SELECT MAX(seq_id) FROM events", [], |row| row.get(0))?;

        // Get page count and page size to compute database size
        let page_count: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0))?;
        let page_size: i64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0))?;
        let db_size_bytes = (page_count * page_size) as u64;

        Ok(LedgerStats {
            event_count: event_count as u64,
            artifact_count: artifact_count as u64,
            max_seq_id: max_seq_id.unwrap_or(0) as u64,
            db_size_bytes,
        })
    }

    /// Verifies that WAL mode is enabled.
    ///
    /// # Errors
    ///
    /// Returns an error if the journal mode cannot be queried.
    pub fn verify_wal_mode(&self) -> Result<bool, LedgerError> {
        let conn = self.conn.lock().unwrap();

        let mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;

        Ok(mode.to_lowercase() == "wal")
    }

    /// Opens a read-only connection to the ledger for concurrent reads.
    ///
    /// This is useful for creating multiple readers that can read
    /// concurrently while writes are in progress.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is not set (in-memory database)
    /// or if the connection cannot be opened.
    pub fn open_reader(&self) -> Result<LedgerReader, LedgerError> {
        let path = self.path.as_ref().ok_or_else(|| {
            LedgerError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "cannot create reader for in-memory database",
            ))
        })?;

        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        Ok(LedgerReader {
            conn: Arc::new(std::sync::Mutex::new(conn)),
        })
    }

    /// Gets the hash of the last event in the ledger.
    ///
    /// Returns the genesis hash (32 zero bytes) if the ledger is empty.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn last_event_hash(&self) -> Result<Vec<u8>, LedgerError> {
        let conn = self.conn.lock().unwrap();

        let result: Option<Option<Vec<u8>>> = conn
            .query_row(
                "SELECT event_hash FROM events ORDER BY seq_id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;

        // If no events, or event_hash is NULL, return genesis hash
        Ok(result.flatten().unwrap_or_else(|| vec![0u8; 32]))
    }

    /// Appends a signed event to the ledger with full crypto integration.
    ///
    /// This method:
    /// 1. Fetches the previous event's hash (or genesis hash if empty)
    /// 2. Computes the event hash using `EventHasher`
    /// 3. Signs the hash using the provided `Signer`
    /// 4. Appends the event with all crypto fields populated
    ///
    /// # Arguments
    ///
    /// * `event` - The event to append (payload should already be
    ///   canonicalized)
    /// * `hasher_fn` - Function to compute the event hash
    /// * `sign_fn` - Function to sign the hash and return signature bytes
    ///
    /// # Returns
    ///
    /// The sequence ID assigned to the event.
    ///
    /// # Errors
    ///
    /// Returns an error if the event cannot be inserted or if crypto operations
    /// fail.
    pub fn append_signed<F, S>(
        &self,
        mut event: EventRecord,
        hasher_fn: F,
        sign_fn: S,
    ) -> Result<u64, LedgerError>
    where
        F: FnOnce(&[u8], &[u8]) -> Vec<u8>,
        S: FnOnce(&[u8]) -> Vec<u8>,
    {
        // Get the previous event's hash
        let prev_hash = self.last_event_hash()?;

        // Compute event hash
        let event_hash = hasher_fn(&event.payload, &prev_hash);

        // Sign the hash
        let signature = sign_fn(&event_hash);

        // Populate crypto fields
        event.prev_hash = Some(prev_hash);
        event.event_hash = Some(event_hash);
        event.signature = Some(signature);

        // Append the event
        self.append(&event)
    }

    /// Verifies a single event's hash and signature.
    ///
    /// # Arguments
    ///
    /// * `event` - The event to verify
    /// * `expected_prev_hash` - The expected previous hash
    /// * `verify_hash_fn` - Function to verify the event hash
    /// * `verify_sig_fn` - Function to verify the signature (returns true if
    ///   valid)
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails.
    pub fn verify_event<H, V>(
        &self,
        event: &EventRecord,
        expected_prev_hash: &[u8],
        verify_hash_fn: H,
        verify_sig_fn: V,
    ) -> Result<(), LedgerError>
    where
        H: FnOnce(&[u8], &[u8]) -> Vec<u8>,
        V: FnOnce(&[u8], &[u8]) -> bool,
    {
        let seq_id = event.seq_id.unwrap_or(0);

        // Verify prev_hash matches expected
        let actual_prev_hash = event.prev_hash.as_deref().unwrap_or(&[]);
        if actual_prev_hash != expected_prev_hash {
            return Err(LedgerError::HashChainBroken {
                seq_id,
                details: "prev_hash mismatch".to_string(),
            });
        }

        // Compute expected hash and verify
        let computed_hash = verify_hash_fn(&event.payload, expected_prev_hash);
        let actual_hash = event.event_hash.as_deref().unwrap_or(&[]);
        if computed_hash != actual_hash {
            return Err(LedgerError::HashChainBroken {
                seq_id,
                details: "event_hash mismatch".to_string(),
            });
        }

        // Verify signature if present
        if let Some(signature) = &event.signature {
            if !verify_sig_fn(&computed_hash, signature) {
                return Err(LedgerError::SignatureInvalid {
                    seq_id,
                    details: "signature verification failed".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Verifies the hash chain from a starting sequence ID.
    ///
    /// This version uses trait object function pointers for object safety,
    /// making it compatible with `Box<dyn LedgerBackend>`.
    ///
    /// # Arguments
    ///
    /// * `from_seq_id` - The sequence ID to start verification from (use 1 for
    ///   genesis).
    /// * `verify_hash_fn` - Function to compute event hash given payload and
    ///   `prev_hash`.
    /// * `verify_sig_fn` - Function to verify signature (returns true if
    ///   valid).
    ///
    /// # Errors
    ///
    /// Returns an error if any event fails verification.
    pub fn verify_chain_from(
        &self,
        from_seq_id: u64,
        verify_hash_fn: super::backend::HashFn<'_>,
        verify_sig_fn: super::backend::VerifyFn<'_>,
    ) -> Result<(), LedgerError> {
        // Genesis hash (32 zero bytes) or fetch the hash of the event before
        // from_seq_id
        let mut expected_prev_hash: Vec<u8> = if from_seq_id <= 1 {
            vec![0u8; 32]
        } else {
            // Get the previous event's hash
            let prev_event = self.read_one(from_seq_id - 1)?;
            prev_event.event_hash.unwrap_or_else(|| vec![0u8; 32])
        };

        // Read all events in batches starting from from_seq_id
        let mut cursor = from_seq_id;
        let batch_size = 1000u64;

        loop {
            let events = self.read_from(cursor, batch_size)?;
            if events.is_empty() {
                break;
            }

            for event in &events {
                // Verify this event
                self.verify_event(event, &expected_prev_hash, verify_hash_fn, verify_sig_fn)?;

                // Update expected_prev_hash for next event
                expected_prev_hash = event.event_hash.clone().unwrap_or_else(|| vec![0u8; 32]);
            }

            cursor = events.last().map_or(cursor, |e| e.seq_id.unwrap_or(0) + 1);
        }

        Ok(())
    }

    /// Verifies the entire hash chain from the beginning of the ledger.
    ///
    /// This is the generic version that works with closures. For the
    /// object-safe trait method, see [`LedgerBackend::verify_chain`].
    ///
    /// # Arguments
    ///
    /// * `verify_hash_fn` - Function to compute event hash given payload and
    ///   `prev_hash`
    /// * `verify_sig_fn` - Function to verify signature (returns true if valid)
    ///
    /// # Errors
    ///
    /// Returns an error if any event fails verification.
    pub fn verify_chain<H, V>(&self, verify_hash_fn: H, verify_sig_fn: V) -> Result<(), LedgerError>
    where
        H: Fn(&[u8], &[u8]) -> Vec<u8> + Send + Sync,
        V: Fn(&[u8], &[u8]) -> bool + Send + Sync,
    {
        self.verify_chain_from(1, &verify_hash_fn, &verify_sig_fn)
    }
}

// -----------------------------------------------------------------------------
// LedgerBackend Trait Implementation
// -----------------------------------------------------------------------------
//
// INTENTIONAL DESIGN: Namespace parameter is ignored in this implementation.
//
// This SqliteLedgerBackend is a direct extraction of the existing Ledger struct
// (TCK-00180 scope: "No behavioral changes to existing code"). The namespace
// parameter was added to the LedgerBackend trait API to enable future namespace
// isolation per RFC-0014's architectural design.
//
// The actual namespace isolation (table partitioning or separate databases per
// namespace) is intentionally deferred to a future ticket. This approach:
//
//   1. Preserves backward compatibility with all existing code
//   2. Enables incremental adoption of the trait abstraction
//   3. Allows namespace isolation to be implemented with proper schema
//      migration
//
// TODO(RFC-0014): Implement namespace isolation in a follow-up ticket. Options:
//   - Per-namespace table prefixes (e.g., `{namespace}_events`)
//   - Separate SQLite databases per namespace
//   - Namespace column with filtered queries
//
// See RFC-0014 section 02_design_decisions.yaml for namespace scoping design.
// -----------------------------------------------------------------------------

impl LedgerBackend for SqliteLedgerBackend {
    fn append<'a>(
        &'a self,
        _namespace: &'a str,
        event: &'a EventRecord,
    ) -> super::backend::BoxFuture<'a, Result<u64, LedgerError>> {
        // Namespace parameter intentionally ignored - see block comment above.
        Box::pin(async move { Self::append(self, event) })
    }

    fn read_from<'a>(
        &'a self,
        _namespace: &'a str,
        cursor: u64,
        limit: u64,
    ) -> super::backend::BoxFuture<'a, Result<Vec<EventRecord>, LedgerError>> {
        // Namespace parameter intentionally ignored - see block comment above.
        Box::pin(async move { Self::read_from(self, cursor, limit) })
    }

    fn head<'a>(
        &'a self,
        _namespace: &'a str,
    ) -> super::backend::BoxFuture<'a, Result<u64, LedgerError>> {
        // Namespace parameter intentionally ignored - see block comment above.
        Box::pin(async move { self.head_sync() })
    }

    fn verify_chain<'a>(
        &'a self,
        _namespace: &'a str,
        from_seq_id: u64,
        verify_hash_fn: super::backend::HashFn<'a>,
        verify_sig_fn: super::backend::VerifyFn<'a>,
    ) -> super::backend::BoxFuture<'a, Result<(), LedgerError>> {
        // Namespace parameter intentionally ignored - see block comment above.
        Box::pin(async move {
            Self::verify_chain_from(self, from_seq_id, verify_hash_fn, verify_sig_fn)
        })
    }
}

/// A read-only view of the ledger for concurrent reads.
pub struct LedgerReader {
    conn: Arc<std::sync::Mutex<Connection>>,
}

impl LedgerReader {
    /// Reads events starting from a cursor position.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn read_from(&self, cursor: u64, limit: u64) -> Result<Vec<EventRecord>, LedgerError> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT seq_id, event_type, session_id, actor_id, record_version, payload, timestamp_ns, prev_hash, event_hash, signature
             FROM events
             WHERE seq_id >= ?1
             ORDER BY seq_id ASC
             LIMIT ?2",
        )?;

        let events = stmt
            .query_map(params![cursor, limit], |row| {
                Ok(EventRecord {
                    seq_id: Some(row.get::<_, i64>(0)? as u64),
                    event_type: row.get(1)?,
                    session_id: row.get(2)?,
                    actor_id: row.get(3)?,
                    record_version: row.get::<_, i64>(4)? as u32,
                    payload: row.get(5)?,
                    timestamp_ns: row.get::<_, i64>(6)? as u64,
                    prev_hash: row.get(7)?,
                    event_hash: row.get(8)?,
                    signature: row.get(9)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(events)
    }

    /// Reads a single event by sequence ID.
    ///
    /// # Errors
    ///
    /// Returns `EventNotFound` if no event exists with that sequence ID.
    pub fn read_one(&self, seq_id: u64) -> Result<EventRecord, LedgerError> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT seq_id, event_type, session_id, actor_id, record_version, payload, timestamp_ns, prev_hash, event_hash, signature
             FROM events
             WHERE seq_id = ?1",
        )?;

        stmt.query_row(params![seq_id], |row| {
            Ok(EventRecord {
                seq_id: Some(row.get::<_, i64>(0)? as u64),
                event_type: row.get(1)?,
                session_id: row.get(2)?,
                actor_id: row.get(3)?,
                record_version: row.get::<_, i64>(4)? as u32,
                payload: row.get(5)?,
                timestamp_ns: row.get::<_, i64>(6)? as u64,
                prev_hash: row.get(7)?,
                event_hash: row.get(8)?,
                signature: row.get(9)?,
            })
        })
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => LedgerError::EventNotFound { seq_id },
            other => LedgerError::Database(other),
        })
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_event_record_new() {
        let event = EventRecord::new("test.event", "session-1", "actor-1", b"payload".to_vec());

        assert!(event.seq_id.is_none());
        assert_eq!(event.event_type, "test.event");
        assert_eq!(event.session_id, "session-1");
        assert_eq!(event.actor_id, "actor-1");
        assert_eq!(event.record_version, CURRENT_RECORD_VERSION);
        assert_eq!(event.payload, b"payload");
        assert!(event.timestamp_ns > 0);
    }

    #[test]
    fn test_artifact_ref_new() {
        let artifact = ArtifactRef::new(
            1,
            vec![0u8; 32],
            "application/json",
            1024,
            "/path/to/artifact",
        );

        assert!(artifact.id.is_none());
        assert_eq!(artifact.event_seq_id, 1);
        assert_eq!(artifact.content_hash.len(), 32);
        assert_eq!(artifact.content_type, "application/json");
        assert_eq!(artifact.size_bytes, 1024);
        assert!(artifact.created_at_ns > 0);
    }
}

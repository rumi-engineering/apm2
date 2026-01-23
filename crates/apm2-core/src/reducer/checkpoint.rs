//! Checkpoint storage for reducer state persistence.
//!
//! Checkpoints allow reducers to save their state at a specific ledger
//! position, enabling incremental replay from that point instead of replaying
//! from genesis.

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

/// Schema for checkpoint storage.
const CHECKPOINT_SCHEMA: &str = r"
-- Checkpoint storage
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reducer_name TEXT NOT NULL,
    seq_id INTEGER NOT NULL,
    state_data BLOB NOT NULL,
    created_at_ns INTEGER NOT NULL,
    UNIQUE(reducer_name, seq_id)
);

CREATE INDEX IF NOT EXISTS idx_checkpoints_reducer_seq
    ON checkpoints(reducer_name, seq_id DESC);
";

/// Errors that can occur during checkpoint operations.
#[derive(Debug, Error)]
pub enum CheckpointStoreError {
    /// Database error from `SQLite`.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// I/O error during database operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Checkpoint not found.
    #[error("no checkpoint found for reducer '{reducer_name}'")]
    NotFound {
        /// The reducer name that was not found.
        reducer_name: String,
    },
}

/// A saved checkpoint for a reducer.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Unique identifier for this checkpoint.
    pub id: Option<u64>,

    /// Name of the reducer this checkpoint belongs to.
    pub reducer_name: String,

    /// The sequence ID this checkpoint was taken at.
    pub seq_id: u64,

    /// Serialized state data.
    pub state_data: Vec<u8>,

    /// Timestamp when the checkpoint was created.
    pub created_at_ns: u64,
}

impl Checkpoint {
    /// Creates a new checkpoint with the current timestamp.
    #[must_use]
    pub fn new(reducer_name: impl Into<String>, seq_id: u64, state_data: Vec<u8>) -> Self {
        let created_at_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        Self {
            id: None,
            reducer_name: reducer_name.into(),
            seq_id,
            state_data,
            created_at_ns,
        }
    }
}

/// Storage for reducer checkpoints.
///
/// Checkpoints are stored in a `SQLite` database, separate from the event
/// ledger, allowing them to be recreated from the ledger if corrupted or lost.
pub struct CheckpointStore {
    conn: Arc<std::sync::Mutex<Connection>>,
}

impl CheckpointStore {
    /// Opens or creates a checkpoint store at the specified path.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or initialized.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CheckpointStoreError> {
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
        })
    }

    /// Creates an in-memory checkpoint store for testing.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be initialized.
    pub fn in_memory() -> Result<Self, CheckpointStoreError> {
        let conn = Connection::open_in_memory()?;
        Self::initialize_connection(&conn)?;

        Ok(Self {
            conn: Arc::new(std::sync::Mutex::new(conn)),
        })
    }

    /// Initialize the connection with schema.
    fn initialize_connection(conn: &Connection) -> Result<(), CheckpointStoreError> {
        conn.execute_batch(CHECKPOINT_SCHEMA)?;
        Ok(())
    }

    /// Saves a checkpoint for a reducer.
    ///
    /// If a checkpoint already exists for the same reducer at the same
    /// `seq_id`, it will be replaced.
    ///
    /// # Errors
    ///
    /// Returns an error if the checkpoint cannot be saved.
    pub fn save(&self, checkpoint: &Checkpoint) -> Result<u64, CheckpointStoreError> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO checkpoints (reducer_name, seq_id, state_data, created_at_ns)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                checkpoint.reducer_name,
                checkpoint.seq_id,
                checkpoint.state_data,
                checkpoint.created_at_ns,
            ],
        )?;

        Ok(conn.last_insert_rowid() as u64)
    }

    /// Loads the latest checkpoint for a reducer.
    ///
    /// Returns the checkpoint with the highest `seq_id` for the given reducer.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if no checkpoint exists for this reducer.
    pub fn load_latest(&self, reducer_name: &str) -> Result<Checkpoint, CheckpointStoreError> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT id, reducer_name, seq_id, state_data, created_at_ns
             FROM checkpoints
             WHERE reducer_name = ?1
             ORDER BY seq_id DESC
             LIMIT 1",
        )?;

        stmt.query_row(params![reducer_name], |row| {
            Ok(Checkpoint {
                id: Some(row.get::<_, i64>(0)? as u64),
                reducer_name: row.get(1)?,
                seq_id: row.get::<_, i64>(2)? as u64,
                state_data: row.get(3)?,
                created_at_ns: row.get::<_, i64>(4)? as u64,
            })
        })
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => CheckpointStoreError::NotFound {
                reducer_name: reducer_name.to_string(),
            },
            other => CheckpointStoreError::Database(other),
        })
    }

    /// Loads a checkpoint at a specific sequence ID.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if no checkpoint exists at that position.
    pub fn load_at(
        &self,
        reducer_name: &str,
        seq_id: u64,
    ) -> Result<Checkpoint, CheckpointStoreError> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT id, reducer_name, seq_id, state_data, created_at_ns
             FROM checkpoints
             WHERE reducer_name = ?1 AND seq_id = ?2",
        )?;

        stmt.query_row(params![reducer_name, seq_id], |row| {
            Ok(Checkpoint {
                id: Some(row.get::<_, i64>(0)? as u64),
                reducer_name: row.get(1)?,
                seq_id: row.get::<_, i64>(2)? as u64,
                state_data: row.get(3)?,
                created_at_ns: row.get::<_, i64>(4)? as u64,
            })
        })
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => CheckpointStoreError::NotFound {
                reducer_name: reducer_name.to_string(),
            },
            other => CheckpointStoreError::Database(other),
        })
    }

    /// Loads the checkpoint at or before a specific sequence ID.
    ///
    /// This is useful for finding the best checkpoint to replay from.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if no suitable checkpoint exists.
    pub fn load_at_or_before(
        &self,
        reducer_name: &str,
        seq_id: u64,
    ) -> Result<Checkpoint, CheckpointStoreError> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT id, reducer_name, seq_id, state_data, created_at_ns
             FROM checkpoints
             WHERE reducer_name = ?1 AND seq_id <= ?2
             ORDER BY seq_id DESC
             LIMIT 1",
        )?;

        stmt.query_row(params![reducer_name, seq_id], |row| {
            Ok(Checkpoint {
                id: Some(row.get::<_, i64>(0)? as u64),
                reducer_name: row.get(1)?,
                seq_id: row.get::<_, i64>(2)? as u64,
                state_data: row.get(3)?,
                created_at_ns: row.get::<_, i64>(4)? as u64,
            })
        })
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => CheckpointStoreError::NotFound {
                reducer_name: reducer_name.to_string(),
            },
            other => CheckpointStoreError::Database(other),
        })
    }

    /// Lists all checkpoints for a reducer.
    ///
    /// Returns checkpoints in descending `seq_id` order (newest first).
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn list(&self, reducer_name: &str) -> Result<Vec<Checkpoint>, CheckpointStoreError> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT id, reducer_name, seq_id, state_data, created_at_ns
             FROM checkpoints
             WHERE reducer_name = ?1
             ORDER BY seq_id DESC",
        )?;

        let checkpoints = stmt
            .query_map(params![reducer_name], |row| {
                Ok(Checkpoint {
                    id: Some(row.get::<_, i64>(0)? as u64),
                    reducer_name: row.get(1)?,
                    seq_id: row.get::<_, i64>(2)? as u64,
                    state_data: row.get(3)?,
                    created_at_ns: row.get::<_, i64>(4)? as u64,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(checkpoints)
    }

    /// Deletes checkpoints older than a specific sequence ID.
    ///
    /// Returns the number of checkpoints deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the deletion fails.
    pub fn prune(
        &self,
        reducer_name: &str,
        keep_after_seq_id: u64,
    ) -> Result<usize, CheckpointStoreError> {
        let conn = self.conn.lock().unwrap();

        let deleted = conn.execute(
            "DELETE FROM checkpoints WHERE reducer_name = ?1 AND seq_id < ?2",
            params![reducer_name, keep_after_seq_id],
        )?;

        Ok(deleted)
    }

    /// Deletes all checkpoints for a reducer.
    ///
    /// Returns the number of checkpoints deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the deletion fails.
    pub fn delete_all(&self, reducer_name: &str) -> Result<usize, CheckpointStoreError> {
        let conn = self.conn.lock().unwrap();

        let deleted = conn.execute(
            "DELETE FROM checkpoints WHERE reducer_name = ?1",
            params![reducer_name],
        )?;

        Ok(deleted)
    }

    /// Checks if any checkpoint exists for a reducer.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn exists(&self, reducer_name: &str) -> Result<bool, CheckpointStoreError> {
        let conn = self.conn.lock().unwrap();

        let exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM checkpoints WHERE reducer_name = ?1 LIMIT 1",
                params![reducer_name],
                |row| row.get(0),
            )
            .optional()?;

        Ok(exists.is_some())
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_checkpoint_new() {
        let checkpoint = Checkpoint::new("test-reducer", 42, vec![1, 2, 3]);

        assert!(checkpoint.id.is_none());
        assert_eq!(checkpoint.reducer_name, "test-reducer");
        assert_eq!(checkpoint.seq_id, 42);
        assert_eq!(checkpoint.state_data, vec![1, 2, 3]);
        assert!(checkpoint.created_at_ns > 0);
    }

    #[test]
    fn test_store_save_and_load_latest() {
        let store = CheckpointStore::in_memory().unwrap();

        let checkpoint1 = Checkpoint::new("reducer-a", 10, vec![1, 2, 3]);
        store.save(&checkpoint1).unwrap();

        let checkpoint2 = Checkpoint::new("reducer-a", 20, vec![4, 5, 6]);
        store.save(&checkpoint2).unwrap();

        let loaded = store.load_latest("reducer-a").unwrap();
        assert_eq!(loaded.seq_id, 20);
        assert_eq!(loaded.state_data, vec![4, 5, 6]);
    }

    #[test]
    fn test_store_load_at() {
        let store = CheckpointStore::in_memory().unwrap();

        let checkpoint = Checkpoint::new("reducer-b", 15, vec![7, 8, 9]);
        store.save(&checkpoint).unwrap();

        let loaded = store.load_at("reducer-b", 15).unwrap();
        assert_eq!(loaded.seq_id, 15);
        assert_eq!(loaded.state_data, vec![7, 8, 9]);
    }

    #[test]
    fn test_store_load_at_or_before() {
        let store = CheckpointStore::in_memory().unwrap();

        store
            .save(&Checkpoint::new("reducer-c", 10, vec![1]))
            .unwrap();
        store
            .save(&Checkpoint::new("reducer-c", 20, vec![2]))
            .unwrap();
        store
            .save(&Checkpoint::new("reducer-c", 30, vec![3]))
            .unwrap();

        // Exact match
        let loaded = store.load_at_or_before("reducer-c", 20).unwrap();
        assert_eq!(loaded.seq_id, 20);

        // Before - should get seq_id 20
        let loaded = store.load_at_or_before("reducer-c", 25).unwrap();
        assert_eq!(loaded.seq_id, 20);

        // Before first
        let result = store.load_at_or_before("reducer-c", 5);
        assert!(matches!(result, Err(CheckpointStoreError::NotFound { .. })));
    }

    #[test]
    fn test_store_list() {
        let store = CheckpointStore::in_memory().unwrap();

        store
            .save(&Checkpoint::new("reducer-d", 10, vec![1]))
            .unwrap();
        store
            .save(&Checkpoint::new("reducer-d", 20, vec![2]))
            .unwrap();
        store
            .save(&Checkpoint::new("reducer-d", 30, vec![3]))
            .unwrap();

        let checkpoints = store.list("reducer-d").unwrap();
        assert_eq!(checkpoints.len(), 3);
        // Should be in descending order
        assert_eq!(checkpoints[0].seq_id, 30);
        assert_eq!(checkpoints[1].seq_id, 20);
        assert_eq!(checkpoints[2].seq_id, 10);
    }

    #[test]
    fn test_store_prune() {
        let store = CheckpointStore::in_memory().unwrap();

        store
            .save(&Checkpoint::new("reducer-e", 10, vec![1]))
            .unwrap();
        store
            .save(&Checkpoint::new("reducer-e", 20, vec![2]))
            .unwrap();
        store
            .save(&Checkpoint::new("reducer-e", 30, vec![3]))
            .unwrap();

        let deleted = store.prune("reducer-e", 25).unwrap();
        assert_eq!(deleted, 2);

        let checkpoints = store.list("reducer-e").unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].seq_id, 30);
    }

    #[test]
    fn test_store_delete_all() {
        let store = CheckpointStore::in_memory().unwrap();

        store
            .save(&Checkpoint::new("reducer-f", 10, vec![1]))
            .unwrap();
        store
            .save(&Checkpoint::new("reducer-f", 20, vec![2]))
            .unwrap();

        let deleted = store.delete_all("reducer-f").unwrap();
        assert_eq!(deleted, 2);

        assert!(!store.exists("reducer-f").unwrap());
    }

    #[test]
    fn test_store_exists() {
        let store = CheckpointStore::in_memory().unwrap();

        assert!(!store.exists("reducer-g").unwrap());

        store
            .save(&Checkpoint::new("reducer-g", 10, vec![1]))
            .unwrap();

        assert!(store.exists("reducer-g").unwrap());
    }

    #[test]
    fn test_store_not_found() {
        let store = CheckpointStore::in_memory().unwrap();

        let result = store.load_latest("nonexistent");
        assert!(matches!(result, Err(CheckpointStoreError::NotFound { .. })));
    }

    #[test]
    fn test_store_replace_at_same_seq_id() {
        let store = CheckpointStore::in_memory().unwrap();

        store
            .save(&Checkpoint::new("reducer-h", 10, vec![1, 2, 3]))
            .unwrap();
        store
            .save(&Checkpoint::new("reducer-h", 10, vec![4, 5, 6]))
            .unwrap();

        let checkpoints = store.list("reducer-h").unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].state_data, vec![4, 5, 6]);
    }
}

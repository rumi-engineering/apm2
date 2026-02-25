//! `SQLite` adapters for orchestrator kernel storage traits.
//!
//! All adapters are keyed by `orchestrator_id` for multi-tenant use of a
//! single database. All async trait methods use `tokio::task::spawn_blocking`
//! to avoid blocking the tokio executor with rusqlite calls.

use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use apm2_core::events::Validate;
use apm2_core::orchestrator_kernel::{
    CursorStore, EffectExecutionState, EffectJournal, InDoubtResolution, IntentStore, KernelCursor,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Maximum number of intents returned by a single `dequeue_batch` call.
///
/// This bounds the in-memory allocation from a single SQL query result set.
const MAX_DEQUEUE_BATCH: usize = 4096;

/// Maximum number of intents that can be enqueued in a single `enqueue_many`
/// call. This bounds the transaction size and prevents unbounded write batches.
const MAX_ENQUEUE_BATCH: usize = 4096;

/// Maximum byte length for any JSON payload retrieved from `SQLite` before
/// deserialization. Prevents denial-of-service via oversized JSON strings
/// stored by a compromised or buggy writer.
const MAX_JSON_BYTES: usize = 65_536;

// ---------------------------------------------------------------------------
// Post-deserialization validation
// ---------------------------------------------------------------------------

/// Validates that a raw JSON string does not exceed `MAX_JSON_BYTES` before
/// deserialization. Returns `Err` with a descriptive message if oversized.
fn validate_json_size(json_str: &str, context: &str) -> Result<(), String> {
    if json_str.len() > MAX_JSON_BYTES {
        return Err(format!(
            "{context}: JSON payload length {} exceeds MAX_JSON_BYTES ({MAX_JSON_BYTES})",
            json_str.len()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Schema init
// ---------------------------------------------------------------------------

/// Initializes shared orchestrator kernel tables in the given `SQLite`
/// connection. Safe to call multiple times (idempotent `CREATE TABLE IF NOT
/// EXISTS`).
///
/// # Errors
///
/// Returns `Err` if any DDL statement fails.
pub fn init_orchestrator_runtime_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS orchestrator_kernel_cursors (
            orchestrator_id TEXT PRIMARY KEY,
            cursor_json TEXT NOT NULL,
            updated_at_ns INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS orchestrator_kernel_intents (
            orchestrator_id TEXT NOT NULL,
            intent_key TEXT NOT NULL,
            intent_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('pending','blocked','completed')),
            created_at_ns INTEGER NOT NULL,
            updated_at_ns INTEGER NOT NULL,
            blocked_reason TEXT,
            PRIMARY KEY(orchestrator_id, intent_key)
        );

        CREATE INDEX IF NOT EXISTS ok_intents_pending_idx
            ON orchestrator_kernel_intents(orchestrator_id, state, created_at_ns, intent_key);

        CREATE TABLE IF NOT EXISTS orchestrator_kernel_effect_journal (
            orchestrator_id TEXT NOT NULL,
            intent_key TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('started','completed','unknown')),
            updated_at_ns INTEGER NOT NULL,
            PRIMARY KEY(orchestrator_id, intent_key)
        );",
    )
    .map_err(|e| format!("failed to init orchestrator runtime schema: {e}"))
}

// ---------------------------------------------------------------------------
// Time helper
// ---------------------------------------------------------------------------

fn epoch_now_ns_i64() -> Result<i64, String> {
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    i64::try_from(ns).map_err(|_| "current epoch timestamp exceeds i64 range".to_string())
}

// ---------------------------------------------------------------------------
// SqliteCursorStore
// ---------------------------------------------------------------------------

/// `SQLite`-backed durable cursor store.
///
/// Stores cursor state as JSON in `orchestrator_kernel_cursors`, keyed by
/// `orchestrator_id`.
///
/// # Synchronization protocol
///
/// The inner `Arc<Mutex<Connection>>` is shared across all adapters for the
/// same orchestrator. The Mutex ensures exclusive access for the duration of
/// each `SQLite` operation. All async methods use `spawn_blocking` to avoid
/// holding the lock across `.await` points.
#[derive(Debug, Clone)]
pub struct SqliteCursorStore<C: KernelCursor> {
    conn: Arc<Mutex<Connection>>,
    orchestrator_id: String,
    _cursor: PhantomData<C>,
}

impl<C: KernelCursor> SqliteCursorStore<C> {
    /// Creates a new cursor store for the given orchestrator.
    #[must_use]
    pub fn new(conn: Arc<Mutex<Connection>>, orchestrator_id: &str) -> Self {
        Self {
            conn,
            orchestrator_id: orchestrator_id.to_string(),
            _cursor: PhantomData,
        }
    }

    fn load_sync(&self) -> Result<C, String> {
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("cursor store lock poisoned: {e}"))?;

        // SQL-side length predicate: filter out oversized payloads before
        // they are materialized as Rust strings (SEC finding: payload load
        // before size check). The post-load validate_json_size is kept as a
        // defence-in-depth safety net.
        let max_json_i64 = i64::try_from(MAX_JSON_BYTES).unwrap_or(i64::MAX);
        let row: Option<String> = guard
            .query_row(
                "SELECT cursor_json FROM orchestrator_kernel_cursors
                 WHERE orchestrator_id = ?1
                   AND length(cursor_json) <= ?2",
                params![&self.orchestrator_id, max_json_i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| format!("failed to load cursor for '{}': {e}", self.orchestrator_id))?;
        row.map_or_else(
            || Ok(C::default()),
            |json| {
                validate_json_size(&json, "cursor store load")?;
                let cursor: C = serde_json::from_str(&json).map_err(|e| {
                    format!(
                        "failed to decode cursor json for '{}': {e}",
                        self.orchestrator_id
                    )
                })?;
                Ok(cursor)
            },
        )
    }

    fn save_sync(&self, cursor: &C) -> Result<(), String> {
        let json = serde_json::to_string(cursor).map_err(|e| {
            format!(
                "failed to encode cursor json for '{}': {e}",
                self.orchestrator_id
            )
        })?;
        // FINDING-6: enforce MAX_JSON_BYTES on the write side to prevent
        // oversized cursor payloads from entering the store.
        validate_json_size(&json, "cursor store save")?;
        let now_ns = epoch_now_ns_i64()?;
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("cursor store lock poisoned: {e}"))?;
        guard
            .execute(
                "INSERT INTO orchestrator_kernel_cursors
                     (orchestrator_id, cursor_json, updated_at_ns)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(orchestrator_id) DO UPDATE SET
                     cursor_json = excluded.cursor_json,
                     updated_at_ns = excluded.updated_at_ns",
                params![&self.orchestrator_id, &json, now_ns],
            )
            .map_err(|e| format!("failed to save cursor for '{}': {e}", self.orchestrator_id))?;
        Ok(())
    }
}

impl<C: KernelCursor> CursorStore<C> for SqliteCursorStore<C> {
    type Error = String;

    async fn load(&self) -> Result<C, Self::Error> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.load_sync())
            .await
            .map_err(|e| format!("cursor store spawn_blocking join failed: {e}"))?
    }

    async fn save(&self, cursor: &C) -> Result<(), Self::Error> {
        let this = self.clone();
        let cursor = cursor.clone();
        tokio::task::spawn_blocking(move || this.save_sync(&cursor))
            .await
            .map_err(|e| format!("cursor store spawn_blocking join failed: {e}"))?
    }
}

// ---------------------------------------------------------------------------
// SqliteIntentStore
// ---------------------------------------------------------------------------

/// Intent key extraction trait.
///
/// Types implementing `IntentKeyed` expose a stable string key used for
/// idempotency (INSERT OR IGNORE) and queue management.
pub trait IntentKeyed {
    /// Returns the stable intent key for this intent.
    fn intent_key(&self) -> String;
}

/// `SQLite`-backed durable intent queue.
///
/// Stores intents as JSON in `orchestrator_kernel_intents`, keyed by
/// `(orchestrator_id, intent_key)`.
///
/// # Synchronization protocol
///
/// Same as [`SqliteCursorStore`]: shared `Arc<Mutex<Connection>>`, Mutex for
/// exclusive access, `spawn_blocking` for all async methods.
#[derive(Debug, Clone)]
pub struct SqliteIntentStore<I>
where
    I: Serialize + DeserializeOwned + IntentKeyed + Validate + Send + Sync + 'static,
{
    conn: Arc<Mutex<Connection>>,
    orchestrator_id: String,
    _intent: PhantomData<I>,
}

impl<I> SqliteIntentStore<I>
where
    I: Serialize + DeserializeOwned + IntentKeyed + Validate + Send + Sync + 'static,
{
    /// Creates a new intent store for the given orchestrator.
    #[must_use]
    pub fn new(conn: Arc<Mutex<Connection>>, orchestrator_id: &str) -> Self {
        Self {
            conn,
            orchestrator_id: orchestrator_id.to_string(),
            _intent: PhantomData,
        }
    }

    fn enqueue_many_sync(&self, intents: &[I]) -> Result<usize, String> {
        // Auto-chunk: process at most MAX_ENQUEUE_BATCH intents per
        // transaction to prevent kernel deadlock when catch-up produces
        // more intents than a single batch limit.
        let mut guard = self
            .conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        let mut total_inserted = 0usize;
        for chunk in intents.chunks(MAX_ENQUEUE_BATCH) {
            let now_ns = epoch_now_ns_i64()?;
            let tx = guard
                .transaction()
                .map_err(|e| format!("failed to begin intent enqueue transaction: {e}"))?;
            for intent in chunk {
                let key = intent.intent_key();
                let json = serde_json::to_string(intent)
                    .map_err(|e| format!("failed to encode intent json: {e}"))?;
                // FINDING-6: enforce MAX_JSON_BYTES on the write side to
                // prevent oversized payloads from entering the store.
                validate_json_size(&json, "intent store enqueue")?;
                let rows = tx
                    .execute(
                        "INSERT OR IGNORE INTO orchestrator_kernel_intents
                         (orchestrator_id, intent_key, intent_json, state,
                          created_at_ns, updated_at_ns, blocked_reason)
                         VALUES (?1, ?2, ?3, 'pending', ?4, ?5, NULL)",
                        params![&self.orchestrator_id, &key, &json, now_ns, now_ns],
                    )
                    .map_err(|e| format!("failed to enqueue intent: {e}"))?;
                total_inserted = total_inserted.saturating_add(rows);
            }
            tx.commit()
                .map_err(|e| format!("failed to commit intent enqueue transaction: {e}"))?;
        }
        Ok(total_inserted)
    }

    fn dequeue_batch_sync(&self, limit: usize) -> Result<Vec<I>, String> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let capped_limit = limit.min(MAX_DEQUEUE_BATCH);
        let limit_i64 = i64::try_from(capped_limit)
            .map_err(|_| "dequeue limit exceeds i64 range".to_string())?;
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        // SQL-side length predicate: filter out oversized payloads before
        // they are materialized as Rust strings (SEC finding: payload load
        // before size check). Oversized rows are quarantined below.
        let max_json_i64 = i64::try_from(MAX_JSON_BYTES).unwrap_or(i64::MAX);

        // Quarantine any oversized pending rows at the SQL level without
        // loading their payloads into memory.
        {
            let now_ns = epoch_now_ns_i64()?;
            let oversized_count = guard
                .execute(
                    "UPDATE orchestrator_kernel_intents
                     SET state = 'blocked',
                         blocked_reason = 'payload_exceeds_max_json_bytes',
                         updated_at_ns = ?3
                     WHERE orchestrator_id = ?1 AND state = 'pending'
                       AND length(intent_json) > ?2",
                    params![&self.orchestrator_id, max_json_i64, now_ns],
                )
                .map_err(|e| format!("failed to quarantine oversized intents in dequeue: {e}"))?;
            if oversized_count > 0 {
                tracing::warn!(
                    orchestrator_id = %self.orchestrator_id,
                    count = oversized_count,
                    "dequeue_batch: quarantined {oversized_count} oversized pending row(s)"
                );
            }
        }

        let mut stmt = guard
            .prepare(
                "SELECT intent_key, intent_json FROM orchestrator_kernel_intents
                 WHERE orchestrator_id = ?1 AND state = 'pending'
                   AND length(intent_json) <= ?3
                 ORDER BY created_at_ns ASC, intent_key ASC
                 LIMIT ?2",
            )
            .map_err(|e| format!("failed to prepare intent dequeue query: {e}"))?;
        let rows = stmt
            .query_map(
                params![&self.orchestrator_id, limit_i64, max_json_i64],
                |row| {
                    let key: String = row.get(0)?;
                    let json: String = row.get(1)?;
                    Ok((key, json))
                },
            )
            .map_err(|e| format!("failed to query pending intents: {e}"))?;

        // Collect rows first so we can drop the statement borrow before
        // executing quarantine UPDATEs on the same connection.
        let collected: Vec<(String, String)> = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("failed to decode intent row: {e}"))?;
        drop(stmt);

        let mut intents = Vec::new();
        let mut quarantine = Vec::new();

        for (key, json) in &collected {
            // Size check: quarantine oversized payloads instead of failing the
            // entire batch (FINDING-5 fix).
            if let Err(reason) = validate_json_size(json, "intent store dequeue") {
                quarantine.push((key.as_str(), reason));
                continue;
            }
            match serde_json::from_str::<I>(json) {
                Ok(intent) => {
                    // BEH-DAEMON-OKRT-011: post-deserialization validation to
                    // reject malformed intents before they reach domain execution.
                    if let Err(reason) = intent.validate() {
                        let msg =
                            format!("intent post-deserialization validation failed: {reason}");
                        quarantine.push((key.as_str(), msg));
                        continue;
                    }
                    intents.push(intent);
                },
                Err(e) => {
                    let msg = format!("failed to decode intent json: {e}");
                    quarantine.push((key.as_str(), msg));
                },
            }
        }

        // Quarantine malformed rows as 'blocked' so they never stall the
        // queue (FINDING-5: one bad row must not stall the entire batch).
        if !quarantine.is_empty() {
            let now_ns = epoch_now_ns_i64()?;
            for (key, reason) in &quarantine {
                guard
                    .execute(
                        "UPDATE orchestrator_kernel_intents
                         SET state = 'blocked', blocked_reason = ?3, updated_at_ns = ?4
                         WHERE orchestrator_id = ?1 AND intent_key = ?2",
                        params![&self.orchestrator_id, key, reason, now_ns],
                    )
                    .map_err(|e| format!("failed to quarantine malformed intent: {e}"))?;
                tracing::warn!(
                    orchestrator_id = %self.orchestrator_id,
                    intent_key = %key,
                    "dequeue_batch: quarantined malformed pending row: {reason}"
                );
            }
        }

        Ok(intents)
    }

    fn mark_done_sync(&self, key: &str) -> Result<(), String> {
        let now_ns = epoch_now_ns_i64()?;
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        guard
            .execute(
                "UPDATE orchestrator_kernel_intents
                 SET state = 'completed', blocked_reason = NULL, updated_at_ns = ?3
                 WHERE orchestrator_id = ?1 AND intent_key = ?2",
                params![&self.orchestrator_id, key, now_ns],
            )
            .map_err(|e| format!("failed to mark intent done: {e}"))?;
        Ok(())
    }

    fn mark_blocked_sync(&self, key: &str, reason: &str) -> Result<(), String> {
        let now_ns = epoch_now_ns_i64()?;
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        guard
            .execute(
                "UPDATE orchestrator_kernel_intents
                 SET state = 'blocked', blocked_reason = ?3, updated_at_ns = ?4
                 WHERE orchestrator_id = ?1 AND intent_key = ?2",
                params![&self.orchestrator_id, key, reason, now_ns],
            )
            .map_err(|e| format!("failed to mark intent blocked: {e}"))?;
        Ok(())
    }

    fn mark_retryable_sync(&self, key: &str, _reason: &str) -> Result<(), String> {
        let now_ns = epoch_now_ns_i64()?;
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        // Retryable MUST set created_at_ns = now to move to back of queue.
        guard
            .execute(
                "UPDATE orchestrator_kernel_intents
                 SET state = 'pending', blocked_reason = NULL,
                     created_at_ns = ?3, updated_at_ns = ?3
                 WHERE orchestrator_id = ?1 AND intent_key = ?2",
                params![&self.orchestrator_id, key, now_ns],
            )
            .map_err(|e| format!("failed to mark intent retryable: {e}"))?;
        Ok(())
    }
}

impl<I> IntentStore<I, String> for SqliteIntentStore<I>
where
    I: Serialize + DeserializeOwned + IntentKeyed + Validate + Clone + Send + Sync + 'static,
{
    type Error = String;

    async fn enqueue_many(&self, intents: &[I]) -> Result<usize, Self::Error> {
        let this = self.clone();
        let intents: Vec<I> = intents.to_vec();
        tokio::task::spawn_blocking(move || this.enqueue_many_sync(&intents))
            .await
            .map_err(|e| format!("intent store spawn_blocking join failed: {e}"))?
    }

    async fn dequeue_batch(&self, limit: usize) -> Result<Vec<I>, Self::Error> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.dequeue_batch_sync(limit))
            .await
            .map_err(|e| format!("intent store spawn_blocking join failed: {e}"))?
    }

    async fn mark_done(&self, key: &String) -> Result<(), Self::Error> {
        let this = self.clone();
        let key = key.clone();
        tokio::task::spawn_blocking(move || this.mark_done_sync(&key))
            .await
            .map_err(|e| format!("intent store spawn_blocking join failed: {e}"))?
    }

    async fn mark_blocked(&self, key: &String, reason: &str) -> Result<(), Self::Error> {
        let this = self.clone();
        let key = key.clone();
        let reason = reason.to_string();
        tokio::task::spawn_blocking(move || this.mark_blocked_sync(&key, &reason))
            .await
            .map_err(|e| format!("intent store spawn_blocking join failed: {e}"))?
    }

    async fn mark_retryable(&self, key: &String, reason: &str) -> Result<(), Self::Error> {
        let this = self.clone();
        let key = key.clone();
        let reason = reason.to_string();
        tokio::task::spawn_blocking(move || this.mark_retryable_sync(&key, &reason))
            .await
            .map_err(|e| format!("intent store spawn_blocking join failed: {e}"))?
    }
}

// ---------------------------------------------------------------------------
// SqliteEffectJournal
// ---------------------------------------------------------------------------

/// `SQLite`-backed effect idempotency journal.
///
/// Stores effect state in `orchestrator_kernel_effect_journal`, keyed by
/// `(orchestrator_id, intent_key)`.
///
/// # Synchronization protocol
///
/// Same as [`SqliteCursorStore`]: shared `Arc<Mutex<Connection>>`, Mutex for
/// exclusive access, `spawn_blocking` for all async methods.
#[derive(Debug, Clone)]
pub struct SqliteEffectJournal {
    conn: Arc<Mutex<Connection>>,
    orchestrator_id: String,
}

impl SqliteEffectJournal {
    /// Creates a new effect journal for the given orchestrator.
    #[must_use]
    pub fn new(conn: Arc<Mutex<Connection>>, orchestrator_id: &str) -> Self {
        Self {
            conn,
            orchestrator_id: orchestrator_id.to_string(),
        }
    }

    fn query_state_sync(&self, key: &str) -> Result<EffectExecutionState, String> {
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("effect journal lock poisoned: {e}"))?;
        let row: Option<String> = guard
            .query_row(
                "SELECT state FROM orchestrator_kernel_effect_journal
                 WHERE orchestrator_id = ?1 AND intent_key = ?2",
                params![&self.orchestrator_id, key],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| format!("failed to query effect state for '{key}': {e}"))?;
        Ok(match row.as_deref() {
            None => EffectExecutionState::NotStarted,
            Some("completed") => EffectExecutionState::Completed,
            // Any non-terminal marker is in-doubt and is handled fail-closed
            // via explicit `resolve_in_doubt`.
            Some(_) => EffectExecutionState::Unknown,
        })
    }

    fn record_started_sync(&self, key: &str) -> Result<(), String> {
        // Atomic UPSERT that guards against regressing from 'completed'.
        // The WHERE clause on the UPDATE arm prevents overwriting a completed
        // record, making this a single atomic SQL statement with no TOCTOU gap.
        let now_ns = epoch_now_ns_i64()?;
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("effect journal lock poisoned: {e}"))?;
        guard
            .execute(
                "INSERT INTO orchestrator_kernel_effect_journal
                     (orchestrator_id, intent_key, state, updated_at_ns)
                 VALUES (?1, ?2, 'started', ?3)
                 ON CONFLICT(orchestrator_id, intent_key) DO UPDATE SET
                     state = 'started',
                     updated_at_ns = excluded.updated_at_ns
                 WHERE state != 'completed'",
                params![&self.orchestrator_id, key, now_ns],
            )
            .map_err(|e| format!("failed to record_started for '{key}': {e}"))?;
        Ok(())
    }

    fn record_completed_sync(&self, key: &str) -> Result<(), String> {
        self.upsert_state(key, "completed")
    }

    fn record_retryable_sync(&self, key: &str) -> Result<(), String> {
        // Atomic conditional DELETE: only removes if state is NOT 'completed'.
        // If no row exists or is completed, `changes() == 0` tells us which
        // case applies without a separate read-then-write TOCTOU gap.
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("effect journal lock poisoned: {e}"))?;
        guard
            .execute(
                "DELETE FROM orchestrator_kernel_effect_journal
                 WHERE orchestrator_id = ?1 AND intent_key = ?2
                   AND state != 'completed'",
                params![&self.orchestrator_id, key],
            )
            .map_err(|e| format!("failed to record_retryable for '{key}': {e}"))?;
        let deleted = guard.changes();
        if deleted > 0 {
            // Successfully cleared a started/unknown fence.
            return Ok(());
        }
        // No row was deleted. Disambiguate: completed (reject) vs never existed
        // (reject).
        let exists: bool = guard
            .query_row(
                "SELECT 1 FROM orchestrator_kernel_effect_journal
                 WHERE orchestrator_id = ?1 AND intent_key = ?2",
                params![&self.orchestrator_id, key],
                |_| Ok(true),
            )
            .optional()
            .map_err(|e| format!("failed to check effect state for '{key}': {e}"))?
            .unwrap_or(false);
        if exists {
            Err(format!(
                "cannot mark effect retryable for completed key '{key}'"
            ))
        } else {
            Err(format!(
                "cannot mark effect retryable for unknown key '{key}'"
            ))
        }
    }

    fn resolve_in_doubt_sync(&self, key: &str) -> Result<InDoubtResolution, String> {
        // Fail-closed: mark the state as unknown and deny.
        self.upsert_state(key, "unknown")?;
        Ok(InDoubtResolution::Deny {
            reason: "effect execution state is in-doubt; manual reconciliation required"
                .to_string(),
        })
    }

    fn upsert_state(&self, key: &str, state: &str) -> Result<(), String> {
        let now_ns = epoch_now_ns_i64()?;
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("effect journal lock poisoned: {e}"))?;
        guard
            .execute(
                "INSERT INTO orchestrator_kernel_effect_journal
                     (orchestrator_id, intent_key, state, updated_at_ns)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(orchestrator_id, intent_key) DO UPDATE SET
                     state = excluded.state,
                     updated_at_ns = excluded.updated_at_ns",
                params![&self.orchestrator_id, key, state, now_ns],
            )
            .map_err(|e| format!("failed to upsert effect state='{state}' for '{key}': {e}"))?;
        Ok(())
    }
}

impl EffectJournal<String> for SqliteEffectJournal {
    type Error = String;

    async fn query_state(&self, key: &String) -> Result<EffectExecutionState, Self::Error> {
        let this = self.clone();
        let key = key.clone();
        tokio::task::spawn_blocking(move || this.query_state_sync(&key))
            .await
            .map_err(|e| format!("effect journal spawn_blocking join failed: {e}"))?
    }

    async fn record_started(&self, key: &String) -> Result<(), Self::Error> {
        let this = self.clone();
        let key = key.clone();
        tokio::task::spawn_blocking(move || this.record_started_sync(&key))
            .await
            .map_err(|e| format!("effect journal spawn_blocking join failed: {e}"))?
    }

    async fn record_completed(&self, key: &String) -> Result<(), Self::Error> {
        let this = self.clone();
        let key = key.clone();
        tokio::task::spawn_blocking(move || this.record_completed_sync(&key))
            .await
            .map_err(|e| format!("effect journal spawn_blocking join failed: {e}"))?
    }

    async fn record_retryable(&self, key: &String) -> Result<(), Self::Error> {
        let this = self.clone();
        let key = key.clone();
        tokio::task::spawn_blocking(move || this.record_retryable_sync(&key))
            .await
            .map_err(|e| format!("effect journal spawn_blocking join failed: {e}"))?
    }

    async fn resolve_in_doubt(&self, key: &String) -> Result<InDoubtResolution, Self::Error> {
        let this = self.clone();
        let key = key.clone();
        tokio::task::spawn_blocking(move || this.resolve_in_doubt_sync(&key))
            .await
            .map_err(|e| format!("effect journal spawn_blocking join failed: {e}"))?
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use apm2_core::orchestrator_kernel::CompositeCursor;

    use super::*;

    fn test_conn() -> Arc<Mutex<Connection>> {
        let conn =
            Connection::open_in_memory().expect("in-memory sqlite connection should succeed");
        init_orchestrator_runtime_schema(&conn).expect("schema init should succeed");
        Arc::new(Mutex::new(conn))
    }

    // -- IntentKeyed test type --

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
    struct TestIntent {
        key: String,
        data: String,
    }

    impl IntentKeyed for TestIntent {
        fn intent_key(&self) -> String {
            self.key.clone()
        }
    }

    impl Validate for TestIntent {
        fn validate(&self) -> Result<(), String> {
            Ok(())
        }
    }

    // -- Schema tests --

    #[test]
    fn test_migration_idempotent() {
        let conn =
            Connection::open_in_memory().expect("in-memory sqlite connection should succeed");
        init_orchestrator_runtime_schema(&conn).expect("first schema init should succeed");
        init_orchestrator_runtime_schema(&conn).expect("second schema init should succeed");
    }

    // -- Cursor store tests --

    #[tokio::test]
    async fn test_cursor_store_roundtrip() {
        let conn = test_conn();
        let store = SqliteCursorStore::<CompositeCursor>::new(conn, "test-cursor-orch");

        // Load default cursor
        let cursor = store.load().await.expect("load default cursor");
        assert_eq!(cursor, CompositeCursor::default());

        // Store a cursor
        let cursor = CompositeCursor {
            timestamp_ns: 42_000_000,
            event_id: "evt-cursor-test-001".to_string(),
        };
        store.save(&cursor).await.expect("save cursor");

        // Load it back
        let loaded = store.load().await.expect("load saved cursor");
        assert_eq!(loaded, cursor);

        // Update cursor
        let cursor2 = CompositeCursor {
            timestamp_ns: 99_000_000,
            event_id: "evt-cursor-test-002".to_string(),
        };
        store.save(&cursor2).await.expect("save updated cursor");
        let loaded2 = store.load().await.expect("load updated cursor");
        assert_eq!(loaded2, cursor2);
    }

    // -- Intent store tests --

    #[tokio::test]
    async fn test_intent_store_enqueue_idempotent() {
        let conn = test_conn();
        let store = SqliteIntentStore::<TestIntent>::new(conn, "test-intent-orch");

        let intent = TestIntent {
            key: "intent-A".to_string(),
            data: "first".to_string(),
        };
        let inserted1 = store
            .enqueue_many(std::slice::from_ref(&intent))
            .await
            .expect("first enqueue");
        assert_eq!(inserted1, 1, "first enqueue should insert 1 row");

        // Enqueue same key again: INSERT OR IGNORE should skip it
        let intent_dup = TestIntent {
            key: "intent-A".to_string(),
            data: "duplicate".to_string(),
        };
        let inserted2 = store
            .enqueue_many(&[intent_dup])
            .await
            .expect("second enqueue");
        assert_eq!(inserted2, 0, "duplicate enqueue should insert 0 rows");

        // Verify only one row in dequeue
        let batch = store.dequeue_batch(10).await.expect("dequeue after dup");
        assert_eq!(batch.len(), 1, "should have exactly 1 pending intent");
        assert_eq!(batch[0].data, "first", "original data should be preserved");
    }

    #[tokio::test]
    async fn test_intent_store_dequeue_ordering() {
        let conn = test_conn();
        let store = SqliteIntentStore::<TestIntent>::new(conn, "test-intent-order");

        let a = TestIntent {
            key: "intent-A".to_string(),
            data: "first".to_string(),
        };
        let b = TestIntent {
            key: "intent-B".to_string(),
            data: "second".to_string(),
        };
        // Enqueue A then B in same batch (same created_at_ns).
        // ORDER BY created_at_ns ASC, intent_key ASC should yield A first.
        store
            .enqueue_many(&[a.clone(), b.clone()])
            .await
            .expect("enqueue A+B");

        let batch = store.dequeue_batch(2).await.expect("dequeue 2");
        assert_eq!(batch.len(), 2, "should dequeue 2 intents");
        assert_eq!(
            batch[0].key, "intent-A",
            "A should come before B (lexicographic tiebreak)"
        );
        assert_eq!(batch[1].key, "intent-B");
    }

    #[tokio::test]
    async fn test_intent_store_retryable_moves_to_back() {
        let conn = test_conn();
        let store = SqliteIntentStore::<TestIntent>::new(conn, "test-intent-retry");

        let a = TestIntent {
            key: "intent-A".to_string(),
            data: "alpha".to_string(),
        };
        let b = TestIntent {
            key: "intent-B".to_string(),
            data: "beta".to_string(),
        };
        store
            .enqueue_many(&[a.clone(), b.clone()])
            .await
            .expect("enqueue A+B");

        // Small sleep to ensure time advances for `created_at_ns = now` in
        // mark_retryable. Without this, the retryable intent may get the same
        // timestamp as B and tie-break on key order.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        // Mark A retryable: sets created_at_ns = now, moving it to back of queue
        store
            .mark_retryable(&"intent-A".to_string(), "transient failure")
            .await
            .expect("mark A retryable");

        let batch = store.dequeue_batch(1).await.expect("dequeue 1");
        assert_eq!(batch.len(), 1, "should dequeue 1 intent");
        assert_eq!(
            batch[0].key, "intent-B",
            "B should come first because A was moved to back"
        );
    }

    #[tokio::test]
    async fn test_intent_store_mark_done_removes_from_pending() {
        let conn = test_conn();
        let store = SqliteIntentStore::<TestIntent>::new(conn, "test-intent-done");

        let a = TestIntent {
            key: "intent-A".to_string(),
            data: "alpha".to_string(),
        };
        store
            .enqueue_many(std::slice::from_ref(&a))
            .await
            .expect("enqueue A");
        store
            .mark_done(&"intent-A".to_string())
            .await
            .expect("mark A done");

        let batch = store.dequeue_batch(10).await.expect("dequeue after done");
        assert!(batch.is_empty(), "no pending intents after mark_done");
    }

    #[tokio::test]
    async fn test_intent_store_mark_blocked() {
        let conn = test_conn();
        let store = SqliteIntentStore::<TestIntent>::new(conn, "test-intent-blocked");

        let a = TestIntent {
            key: "intent-A".to_string(),
            data: "alpha".to_string(),
        };
        store
            .enqueue_many(std::slice::from_ref(&a))
            .await
            .expect("enqueue A");
        store
            .mark_blocked(&"intent-A".to_string(), "fail-closed reason")
            .await
            .expect("mark A blocked");

        let batch = store
            .dequeue_batch(10)
            .await
            .expect("dequeue after blocked");
        assert!(
            batch.is_empty(),
            "blocked intent should not appear in pending dequeue"
        );
    }

    // -- Effect journal tests --

    #[tokio::test]
    async fn test_effect_journal_resolve_in_doubt_fail_closed() {
        let conn = test_conn();
        let journal = SqliteEffectJournal::new(conn, "test-effect-orch");

        let key = "effect-A".to_string();

        // Record started
        journal.record_started(&key).await.expect("record_started");

        // Do NOT record_completed. Resolve in-doubt.
        let resolution = journal
            .resolve_in_doubt(&key)
            .await
            .expect("resolve_in_doubt");
        match resolution {
            InDoubtResolution::Deny { reason } => {
                assert!(
                    reason.contains("in-doubt"),
                    "deny reason should mention in-doubt: {reason}"
                );
            },
            InDoubtResolution::AllowReExecution => {
                panic!("resolve_in_doubt should return Deny, not AllowReExecution");
            },
        }
    }

    #[tokio::test]
    async fn test_effect_journal_full_lifecycle() {
        let conn = test_conn();
        let journal = SqliteEffectJournal::new(conn, "test-effect-lifecycle");

        let key = "effect-lifecycle".to_string();

        // Initial state: not started
        let state = journal.query_state(&key).await.expect("query initial");
        assert_eq!(state, EffectExecutionState::NotStarted);

        // Record started
        journal.record_started(&key).await.expect("record started");
        let state = journal
            .query_state(&key)
            .await
            .expect("query after started");
        // started maps to Unknown in our fail-closed model
        assert_eq!(state, EffectExecutionState::Unknown);

        // Record completed
        journal
            .record_completed(&key)
            .await
            .expect("record completed");
        let state = journal
            .query_state(&key)
            .await
            .expect("query after completed");
        assert_eq!(state, EffectExecutionState::Completed);

        // Record started on completed key: should be idempotent (no regress)
        journal
            .record_started(&key)
            .await
            .expect("record started on completed");
        let state = journal
            .query_state(&key)
            .await
            .expect("query still completed");
        assert_eq!(state, EffectExecutionState::Completed);
    }

    #[tokio::test]
    async fn test_effect_journal_retryable_clears_fence() {
        let conn = test_conn();
        let journal = SqliteEffectJournal::new(conn, "test-effect-retryable");

        let key = "effect-retry".to_string();

        // Record started then retryable
        journal.record_started(&key).await.expect("record started");
        journal
            .record_retryable(&key)
            .await
            .expect("record retryable");

        let state = journal
            .query_state(&key)
            .await
            .expect("query after retryable");
        assert_eq!(
            state,
            EffectExecutionState::NotStarted,
            "retryable should clear the fence"
        );
    }

    #[tokio::test]
    async fn test_effect_journal_retryable_rejects_completed() {
        let conn = test_conn();
        let journal = SqliteEffectJournal::new(conn, "test-effect-retry-completed");

        let key = "effect-completed".to_string();

        journal.record_started(&key).await.expect("record started");
        journal
            .record_completed(&key)
            .await
            .expect("record completed");

        let result = journal.record_retryable(&key).await;
        assert!(
            result.is_err(),
            "retryable on completed key should fail: {result:?}",
        );
    }

    #[tokio::test]
    async fn test_effect_journal_retryable_rejects_unknown_key() {
        let conn = test_conn();
        let journal = SqliteEffectJournal::new(conn, "test-effect-retry-unknown");

        let key = "effect-never-started".to_string();
        let result = journal.record_retryable(&key).await;
        assert!(
            result.is_err(),
            "retryable on unknown key should fail: {result:?}",
        );
    }

    // -- Multi-orchestrator isolation test --

    #[tokio::test]
    async fn test_multi_orchestrator_isolation() {
        let conn = test_conn();

        // Two cursor stores with different orchestrator IDs
        let store_a = SqliteCursorStore::<CompositeCursor>::new(conn.clone(), "orch-A");
        let store_b = SqliteCursorStore::<CompositeCursor>::new(conn, "orch-B");

        let cursor_a = CompositeCursor {
            timestamp_ns: 100,
            event_id: "A-evt".to_string(),
        };
        let cursor_b = CompositeCursor {
            timestamp_ns: 200,
            event_id: "B-evt".to_string(),
        };

        store_a.save(&cursor_a).await.expect("save A");
        store_b.save(&cursor_b).await.expect("save B");

        let loaded_a = store_a.load().await.expect("load A");
        let loaded_b = store_b.load().await.expect("load B");

        assert_eq!(loaded_a, cursor_a, "orchestrator A cursor isolated");
        assert_eq!(loaded_b, cursor_b, "orchestrator B cursor isolated");
    }

    // -- Oversized JSON rejection tests --

    #[tokio::test]
    async fn test_cursor_store_rejects_oversized_json_on_load() {
        let conn = test_conn();

        // Manually insert an oversized cursor JSON directly into SQLite.
        let oversized_event_id = "x".repeat(MAX_JSON_BYTES + 1);
        let oversized_json = format!(r#"{{"timestamp_ns":0,"event_id":"{oversized_event_id}"}}"#);
        {
            let guard = conn.lock().expect("lock");
            guard
                .execute(
                    "INSERT INTO orchestrator_kernel_cursors
                     (orchestrator_id, cursor_json, updated_at_ns)
                     VALUES (?1, ?2, 0)",
                    params!["orch-oversized", &oversized_json],
                )
                .expect("manual insert oversized cursor");
        }

        // With SQL-side length predicate, the oversized row is filtered out
        // at the query level and never materialized. load() returns the
        // default cursor instead of an error (SEC finding fix: SQL-side
        // length predicates before payload load).
        let store = SqliteCursorStore::<CompositeCursor>::new(conn, "orch-oversized");
        let result = store.load().await;
        assert!(
            result.is_ok(),
            "load must succeed (oversized row filtered at SQL level), got: {result:?}"
        );
        let cursor = result.unwrap();
        assert_eq!(
            cursor,
            CompositeCursor::default(),
            "oversized row filtered out; default cursor returned"
        );
    }

    #[tokio::test]
    async fn test_intent_store_quarantines_oversized_json_on_dequeue() {
        let conn = test_conn();

        // Manually insert an oversized intent JSON directly into SQLite.
        let oversized_data = "x".repeat(MAX_JSON_BYTES + 1);
        let oversized_json = format!(r#"{{"key":"oversized-intent","data":"{oversized_data}"}}"#);
        {
            let guard = conn.lock().expect("lock");
            guard
                .execute(
                    "INSERT INTO orchestrator_kernel_intents
                     (orchestrator_id, intent_key, intent_json, state,
                      created_at_ns, updated_at_ns, blocked_reason)
                     VALUES (?1, ?2, ?3, 'pending', 0, 0, NULL)",
                    params!["orch-oversized-intent", "oversized-intent", &oversized_json],
                )
                .expect("manual insert oversized intent");
        }

        let store =
            SqliteIntentStore::<TestIntent>::new(Arc::clone(&conn), "orch-oversized-intent");
        // Dequeue must succeed (not stall) — the oversized row is quarantined,
        // not returned in the batch (FINDING-5 fix).
        let result = store.dequeue_batch(10).await;
        assert!(
            result.is_ok(),
            "dequeue_batch must not fail due to one bad row: {result:?}"
        );
        let batch = result.unwrap();
        assert!(
            batch.is_empty(),
            "oversized row must not appear in dequeued batch, got {} items",
            batch.len()
        );

        // Verify the row was quarantined as 'blocked'.
        let guard = conn.lock().expect("lock");
        let (state, reason): (String, Option<String>) = guard
            .query_row(
                "SELECT state, blocked_reason FROM orchestrator_kernel_intents
                 WHERE orchestrator_id = 'orch-oversized-intent'
                   AND intent_key = 'oversized-intent'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("quarantined row should still exist");
        assert_eq!(
            state, "blocked",
            "oversized intent must be quarantined as blocked"
        );
        assert!(
            reason
                .as_deref()
                .unwrap_or("")
                .contains("payload_exceeds_max_json_bytes"),
            "blocked_reason should reference payload size exceeded: {reason:?}"
        );
    }

    // -- Auto-chunking tests (enqueue_many over MAX_ENQUEUE_BATCH) --

    #[tokio::test]
    async fn test_enqueue_many_auto_chunks_large_batch() {
        let conn = test_conn();
        let store = SqliteIntentStore::<TestIntent>::new(conn, "test-auto-chunk");

        // Create a batch larger than MAX_ENQUEUE_BATCH.
        let batch_size = MAX_ENQUEUE_BATCH + 100;
        let intents: Vec<TestIntent> = (0..batch_size)
            .map(|i| TestIntent {
                key: format!("intent-{i:05}"),
                data: format!("data-{i}"),
            })
            .collect();

        // Must succeed (auto-chunked), not return an error.
        let inserted = store
            .enqueue_many(&intents)
            .await
            .expect("auto-chunked enqueue should succeed");
        assert_eq!(
            inserted, batch_size,
            "all intents should be inserted across chunks"
        );

        // Verify dequeue returns correct data (capped at MAX_DEQUEUE_BATCH).
        let batch = store
            .dequeue_batch(batch_size)
            .await
            .expect("dequeue large batch");
        assert_eq!(
            batch.len(),
            MAX_DEQUEUE_BATCH,
            "dequeue should be capped at MAX_DEQUEUE_BATCH"
        );
    }

    // -- Atomic effect journal regression tests --

    #[tokio::test]
    async fn test_effect_journal_record_started_atomic_no_regress() {
        // Verify that record_started uses a single atomic UPSERT and does
        // not regress a completed effect back to started.
        let conn = test_conn();
        let journal = SqliteEffectJournal::new(conn.clone(), "test-atomic-started");
        let key = "effect-atomic".to_string();

        // Insert completed state directly to simulate prior completion.
        {
            let guard = conn.lock().expect("lock");
            guard
                .execute(
                    "INSERT INTO orchestrator_kernel_effect_journal
                     (orchestrator_id, intent_key, state, updated_at_ns)
                     VALUES (?1, ?2, 'completed', 0)",
                    params!["test-atomic-started", "effect-atomic"],
                )
                .expect("insert completed state");
        }

        // record_started must NOT regress.
        journal
            .record_started(&key)
            .await
            .expect("record_started on completed key");
        let state = journal
            .query_state(&key)
            .await
            .expect("query after started-on-completed");
        assert_eq!(
            state,
            EffectExecutionState::Completed,
            "completed state must not regress to started"
        );
    }

    #[tokio::test]
    async fn test_effect_journal_record_retryable_atomic_no_regress() {
        // Verify that record_retryable uses a conditional DELETE and
        // does not delete a completed effect.
        let conn = test_conn();
        let journal = SqliteEffectJournal::new(conn.clone(), "test-atomic-retry");
        let key = "effect-atomic-retry".to_string();

        // Insert completed state directly.
        {
            let guard = conn.lock().expect("lock");
            guard
                .execute(
                    "INSERT INTO orchestrator_kernel_effect_journal
                     (orchestrator_id, intent_key, state, updated_at_ns)
                     VALUES (?1, ?2, 'completed', 0)",
                    params!["test-atomic-retry", "effect-atomic-retry"],
                )
                .expect("insert completed state");
        }

        // record_retryable must reject completed keys.
        let result = journal.record_retryable(&key).await;
        assert!(
            result.is_err(),
            "record_retryable on completed must fail: {result:?}"
        );

        // Verify state is still completed (not deleted).
        let state = journal
            .query_state(&key)
            .await
            .expect("query after retryable-on-completed");
        assert_eq!(
            state,
            EffectExecutionState::Completed,
            "completed state must not be deleted by retryable"
        );
    }
}

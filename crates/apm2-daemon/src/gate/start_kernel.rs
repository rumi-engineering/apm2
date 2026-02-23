//! Orchestrator-kernel wiring for `ChangeSetPublished -> StartGates`.
//!
//! This module consumes authoritative `changeset_published` ledger events and
//! drives gate-start orchestration through the shared
//! `apm2_core::orchestrator_kernel` harness.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use apm2_core::events::{DefectRecorded, DefectSource};
use apm2_core::fac::{ChangeSetPublishedKernelEventPayload, ChangesetPublication, GateLease};
use apm2_core::orchestrator_kernel::{
    CompositeCursor, CursorEvent, CursorStore, EffectExecutionState, EffectJournal,
    ExecutionOutcome, InDoubtResolution, IntentStore, LedgerReader, OrchestratorDomain,
    ReceiptWriter, TickConfig, TickReport, run_tick,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::gate::{GateOrchestrator, GateOrchestratorEvent};
use crate::ledger::SqliteLedgerEventEmitter;
use crate::protocol::dispatch::LedgerEventEmitter;

const GATE_START_CURSOR_KEY: i64 = 1;
const GATE_START_PERSISTOR_SESSION_ID: &str = "gate-start-kernel";
const GATE_START_PERSISTOR_ACTOR_ID: &str = "orchestrator:gate-start-kernel";

/// Maximum payload size (in bytes) for `changeset_published` events before JSON
/// deserialization. Prevents denial-of-service via oversized `SQLite` payloads
/// (up to 1 GiB) exhausting daemon memory during `serde_json::from_slice`.
const MAX_PAYLOAD_BYTES: usize = 1_048_576; // 1 MiB

/// Kernel configuration for gate-start orchestration ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateStartKernelConfig {
    /// Maximum observe events per tick.
    pub observe_limit: usize,
    /// Maximum gate-start intents executed per tick.
    pub execute_limit: usize,
}

impl Default for GateStartKernelConfig {
    fn default() -> Self {
        Self {
            observe_limit: 256,
            execute_limit: 64,
        }
    }
}

/// Errors from gate-start kernel construction or tick execution.
#[derive(Debug, thiserror::Error)]
pub enum GateStartKernelError {
    /// Initialization failure.
    #[error("gate-start kernel init failed: {0}")]
    Init(String),
    /// Tick execution failure.
    #[error("gate-start kernel tick failed: {0}")]
    Tick(String),
}

/// Durable gate-start kernel runtime state.
pub struct GateStartKernel {
    domain: GateStartDomain,
    ledger_reader: GateStartLedgerReader,
    cursor_store: GateStartCursorStore,
    intent_store: GateStartIntentStore,
    effect_journal: GateStartEffectJournal,
    receipt_writer: GateStartReceiptWriter,
    tick_config: TickConfig,
}

impl GateStartKernel {
    /// Creates a new gate-start kernel instance.
    pub fn new(
        orchestrator: Arc<GateOrchestrator>,
        sqlite_conn: Option<&Arc<Mutex<Connection>>>,
        gate_start_ledger_emitter: Option<SqliteLedgerEventEmitter>,
        fac_root: &Path,
        config: GateStartKernelConfig,
    ) -> Result<Self, GateStartKernelError> {
        let cursor_store = if let Some(conn) = sqlite_conn {
            GateStartCursorStore::Sqlite(
                SqliteGateStartCursorStore::new(Arc::clone(conn)).map_err(|e| {
                    GateStartKernelError::Init(format!("cursor store setup failed: {e}"))
                })?,
            )
        } else {
            GateStartCursorStore::Memory(MemoryGateStartCursorStore::default())
        };

        let intent_store = if let Some(conn) = sqlite_conn {
            GateStartIntentStore::Sqlite(
                SqliteGateStartIntentStore::new(Arc::clone(conn)).map_err(|e| {
                    GateStartKernelError::Init(format!("intent store setup failed: {e}"))
                })?,
            )
        } else {
            GateStartIntentStore::Memory(MemoryGateStartIntentStore::default())
        };

        std::fs::create_dir_all(fac_root).map_err(|e| {
            GateStartKernelError::Init(format!(
                "failed to create FAC root '{}': {e}",
                fac_root.display()
            ))
        })?;
        let journal_path = fac_root.join("gate_start_effect_journal.sqlite");
        let effect_journal =
            GateStartEffectJournal::open(&journal_path).map_err(GateStartKernelError::Init)?;

        Ok(Self {
            domain: GateStartDomain::new(orchestrator),
            ledger_reader: sqlite_conn.map_or_else(
                || GateStartLedgerReader::Memory(MemoryGateStartLedgerReader),
                |conn| {
                    GateStartLedgerReader::Sqlite(SqliteGateStartLedgerReader::new(Arc::clone(
                        conn,
                    )))
                },
            ),
            cursor_store,
            intent_store,
            effect_journal,
            receipt_writer: GateStartReceiptWriter::new(gate_start_ledger_emitter),
            tick_config: TickConfig {
                observe_limit: config.observe_limit,
                execute_limit: config.execute_limit,
            },
        })
    }

    /// Runs one gate-start kernel tick.
    pub async fn tick(&mut self) -> Result<TickReport, GateStartKernelError> {
        run_tick(
            &mut self.domain,
            &self.ledger_reader,
            &self.cursor_store,
            &self.intent_store,
            &self.effect_journal,
            &self.receipt_writer,
            self.tick_config,
        )
        .await
        .map_err(|e| GateStartKernelError::Tick(e.to_string()))
    }

    /// Garbage-collects completed intent and effect-journal rows older than
    /// `cutoff_ns`. Returns `(intent_gc_count, effect_gc_count)`.
    ///
    /// This is a maintenance method intended to be called periodically by the
    /// daemon supervisor (e.g., once per hour). It is NOT called automatically
    /// during `tick()` to keep the hot path free of GC latency.
    pub async fn gc_completed(
        &self,
        cutoff_ns: i64,
    ) -> Result<(usize, usize), GateStartKernelError> {
        let intent_gc = match &self.intent_store {
            GateStartIntentStore::Sqlite(store) => {
                let conn = Arc::clone(&store.conn);
                tokio::task::spawn_blocking(move || {
                    SqliteGateStartIntentStore::gc_completed_before_with_conn(&conn, cutoff_ns)
                })
                .await
                .map_err(|e| {
                    GateStartKernelError::Tick(format!("spawn_blocking failed for intent GC: {e}"))
                })?
                .map_err(GateStartKernelError::Tick)?
            },
            GateStartIntentStore::Memory(_) => 0,
        };

        let effect_gc = GateStartEffectJournal::gc_completed_before_with_conn(
            &self.effect_journal.conn,
            cutoff_ns,
        )
        .map_err(GateStartKernelError::Tick)?;

        Ok((intent_gc, effect_gc))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateStartObservedEvent {
    timestamp_ns: u64,
    cursor_event_id: String,
    publication: ChangesetPublication,
}

impl CursorEvent for GateStartObservedEvent {
    fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    fn event_id(&self) -> &str {
        &self.cursor_event_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateStartIntent {
    publication: ChangesetPublication,
}

impl GateStartIntent {
    fn key(&self) -> String {
        gate_start_intent_key(
            &self.publication.work_id,
            &self.publication.changeset_digest,
        )
    }
}

#[derive(Debug, Clone)]
enum GateStartReceipt {
    OrchestratorEvent(GateOrchestratorEvent),
    GateLeaseIssued {
        lease: Box<GateLease>,
        timestamp_ns: u64,
    },
    Defect {
        defect: DefectRecorded,
        timestamp_ns: u64,
    },
}

struct GateStartDomain {
    orchestrator: Arc<GateOrchestrator>,
    pending_intents: HashMap<String, GateStartIntent>,
}

impl GateStartDomain {
    fn new(orchestrator: Arc<GateOrchestrator>) -> Self {
        Self {
            orchestrator,
            pending_intents: HashMap::new(),
        }
    }
}

impl OrchestratorDomain<GateStartObservedEvent, GateStartIntent, String, GateStartReceipt>
    for GateStartDomain
{
    type Error = String;

    fn intent_key(&self, intent: &GateStartIntent) -> String {
        intent.key()
    }

    async fn apply_events(&mut self, events: &[GateStartObservedEvent]) -> Result<(), Self::Error> {
        for event in events {
            let intent = GateStartIntent {
                publication: event.publication.clone(),
            };
            self.pending_intents.insert(intent.key(), intent);
        }
        Ok(())
    }

    async fn plan(&mut self) -> Result<Vec<GateStartIntent>, Self::Error> {
        let mut intents: Vec<GateStartIntent> =
            self.pending_intents.drain().map(|(_, v)| v).collect();
        intents.sort_by_key(GateStartIntent::key);
        Ok(intents)
    }

    async fn execute(
        &mut self,
        intent: &GateStartIntent,
    ) -> Result<ExecutionOutcome<GateStartReceipt>, Self::Error> {
        match self
            .orchestrator
            .start_for_changeset(intent.publication.clone())
            .await
        {
            Ok((_gate_types, _executor_signers, events)) => {
                let mut receipts = Vec::with_capacity(events.len());
                for event in events {
                    match &event {
                        GateOrchestratorEvent::GateLeaseIssued {
                            work_id,
                            gate_type,
                            timestamp_ms,
                            ..
                        } => {
                            let timestamp_ns = timestamp_ms.saturating_mul(1_000_000);
                            if let Some(lease) =
                                self.orchestrator.gate_lease(work_id, *gate_type).await
                            {
                                receipts.push(GateStartReceipt::GateLeaseIssued {
                                    lease: Box::new(lease),
                                    timestamp_ns,
                                });
                            } else {
                                receipts.push(GateStartReceipt::OrchestratorEvent(event));
                            }
                        },
                        _ => receipts.push(GateStartReceipt::OrchestratorEvent(event)),
                    }
                }
                Ok(ExecutionOutcome::Completed { receipts })
            },
            Err(error) => {
                let timestamp_ns = epoch_now_ns_u64();
                let defect =
                    build_gate_start_defect(&intent.publication, &error.to_string(), timestamp_ns);
                Ok(ExecutionOutcome::Completed {
                    receipts: vec![GateStartReceipt::Defect {
                        defect,
                        timestamp_ns,
                    }],
                })
            },
        }
    }
}

#[derive(Debug)]
enum GateStartLedgerReader {
    Sqlite(SqliteGateStartLedgerReader),
    Memory(MemoryGateStartLedgerReader),
}

impl LedgerReader<GateStartObservedEvent> for GateStartLedgerReader {
    type Error = String;

    async fn poll(
        &self,
        cursor: &CompositeCursor,
        limit: usize,
    ) -> Result<Vec<GateStartObservedEvent>, Self::Error> {
        match self {
            Self::Sqlite(reader) => {
                let conn = Arc::clone(&reader.conn);
                let cursor = cursor.clone();
                tokio::task::spawn_blocking(move || {
                    SqliteGateStartLedgerReader::poll_with_conn(&conn, &cursor, limit)
                })
                .await
                .map_err(|e| format!("spawn_blocking failed for ledger poll: {e}"))?
            },
            Self::Memory(_reader) => Ok(Vec::new()),
        }
    }
}

#[derive(Debug)]
struct SqliteGateStartLedgerReader {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteGateStartLedgerReader {
    const fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    /// Static `poll` — callable from `spawn_blocking`.
    fn poll_with_conn(
        conn: &Arc<Mutex<Connection>>,
        cursor: &CompositeCursor,
        limit: usize,
    ) -> Result<Vec<GateStartObservedEvent>, String> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let limit_i64 =
            i64::try_from(limit).map_err(|_| "observe limit exceeds i64 range".to_string())?;
        let cursor_ts_i64 = i64::try_from(cursor.timestamp_ns)
            .map_err(|_| "cursor timestamp exceeds i64 range".to_string())?;
        let guard = conn
            .lock()
            .map_err(|e| format!("ledger reader lock poisoned: {e}"))?;
        Self::query_changeset_published_unified(&guard, cursor_ts_i64, &cursor.event_id, limit_i64)
    }

    /// Instance poll for tests that use the reader directly.
    #[cfg(test)]
    fn poll(
        &self,
        cursor: &CompositeCursor,
        limit: usize,
    ) -> Result<Vec<GateStartObservedEvent>, String> {
        Self::poll_with_conn(&self.conn, cursor, limit)
    }

    fn query_changeset_published_unified(
        conn: &Connection,
        cursor_ts_i64: i64,
        cursor_event_id: &str,
        limit_i64: i64,
    ) -> Result<Vec<GateStartObservedEvent>, String> {
        let table_exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'events' LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("failed to detect canonical events table: {e}"))?;
        // MAJOR (Security): SELECT actor_id from both tables (verified
        // envelope identity) for identity spoofing prevention. Both
        // `ledger_events` and canonical `events` tables have an actor_id
        // column that stores the cryptographically verified envelope identity.
        let query = if table_exists.is_some() {
            // Ordering invariant:
            // - Every observed event has a deterministic `cursor_event_id` namespaced by
            //   source table (`legacy:` or `canonical:`).
            // - Observe ordering is total by `(timestamp_ns, cursor_event_id)`.
            // - The durable cursor stores this exact ordering key.
            //
            // This avoids mixed-table tie-break drift where legacy and
            // canonical rows sharing a timestamp could be skipped when each
            // table applied incompatible local ordering.
            if cursor_event_id.is_empty() {
                "SELECT cursor_event_id, source_event_id, payload, timestamp_ns, verified_actor_id
                 FROM (
                   SELECT ('legacy:' || event_id) AS cursor_event_id,
                          event_id AS source_event_id,
                          payload,
                          timestamp_ns,
                          actor_id AS verified_actor_id
                   FROM ledger_events
                   WHERE event_type = 'changeset_published'
                   UNION ALL
                   SELECT ('canonical:' || printf('%020d', seq_id)) AS cursor_event_id,
                          ('canonical-' || printf('%020d', seq_id)) AS source_event_id,
                          payload,
                          timestamp_ns,
                          actor_id AS verified_actor_id
                   FROM events
                   WHERE event_type = 'changeset_published'
                 )
                 WHERE timestamp_ns > ?1
                 ORDER BY timestamp_ns ASC, cursor_event_id ASC
                 LIMIT ?2"
            } else {
                "SELECT cursor_event_id, source_event_id, payload, timestamp_ns, verified_actor_id
                 FROM (
                   SELECT ('legacy:' || event_id) AS cursor_event_id,
                          event_id AS source_event_id,
                          payload,
                          timestamp_ns,
                          actor_id AS verified_actor_id
                   FROM ledger_events
                   WHERE event_type = 'changeset_published'
                   UNION ALL
                   SELECT ('canonical:' || printf('%020d', seq_id)) AS cursor_event_id,
                          ('canonical-' || printf('%020d', seq_id)) AS source_event_id,
                          payload,
                          timestamp_ns,
                          actor_id AS verified_actor_id
                   FROM events
                   WHERE event_type = 'changeset_published'
                 )
                 WHERE timestamp_ns > ?1
                    OR (timestamp_ns = ?1 AND cursor_event_id > ?2)
                 ORDER BY timestamp_ns ASC, cursor_event_id ASC
                 LIMIT ?3"
            }
        } else if cursor_event_id.is_empty() {
            "SELECT ('legacy:' || event_id) AS cursor_event_id,
                    event_id AS source_event_id,
                    payload,
                    timestamp_ns,
                    actor_id AS verified_actor_id
             FROM ledger_events
             WHERE event_type = 'changeset_published'
               AND timestamp_ns > ?1
             ORDER BY timestamp_ns ASC, cursor_event_id ASC
             LIMIT ?2"
        } else {
            "SELECT ('legacy:' || event_id) AS cursor_event_id,
                    event_id AS source_event_id,
                    payload,
                    timestamp_ns,
                    actor_id AS verified_actor_id
             FROM ledger_events
             WHERE event_type = 'changeset_published'
               AND (timestamp_ns > ?1 OR (timestamp_ns = ?1 AND ('legacy:' || event_id) > ?2))
             ORDER BY timestamp_ns ASC, cursor_event_id ASC
             LIMIT ?3"
        };
        let mut stmt = conn
            .prepare(query)
            .map_err(|e| format!("failed to prepare unified changeset query: {e}"))?;
        let mut rows = if cursor_event_id.is_empty() {
            stmt.query(params![cursor_ts_i64, limit_i64])
        } else {
            stmt.query(params![cursor_ts_i64, cursor_event_id, limit_i64])
        }
        .map_err(|e| format!("failed to execute unified changeset query: {e}"))?;

        let mut out = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| format!("failed to iterate unified changeset rows: {e}"))?
        {
            let cursor_event_id: String = row
                .get(0)
                .map_err(|e| format!("failed to decode unified cursor_event_id: {e}"))?;
            let source_event_id: String = row
                .get(1)
                .map_err(|e| format!("failed to decode unified source_event_id: {e}"))?;
            let payload: Vec<u8> = row
                .get(2)
                .map_err(|e| format!("failed to decode unified payload: {e}"))?;
            let ts_i64: i64 = row
                .get(3)
                .map_err(|e| format!("failed to decode unified timestamp: {e}"))?;
            let timestamp_ns =
                u64::try_from(ts_i64).map_err(|_| "unified timestamp is negative".to_string())?;
            // MAJOR (Security): Extract verified actor_id from ledger row.
            // NULL for canonical events table rows (no actor_id column).
            let verified_actor_id: Option<String> = row
                .get(4)
                .map_err(|e| format!("failed to decode verified_actor_id: {e}"))?;
            let publication = parse_changeset_publication_payload(
                &payload,
                timestamp_ns,
                &source_event_id,
                verified_actor_id.as_deref(),
            )?;
            out.push(GateStartObservedEvent {
                timestamp_ns,
                cursor_event_id,
                publication,
            });
        }
        Ok(out)
    }
}

#[derive(Debug)]
struct MemoryGateStartLedgerReader;

#[derive(Debug)]
enum GateStartCursorStore {
    Sqlite(SqliteGateStartCursorStore),
    Memory(MemoryGateStartCursorStore),
}

impl CursorStore for GateStartCursorStore {
    type Error = String;

    async fn load(&self) -> Result<CompositeCursor, Self::Error> {
        match self {
            Self::Sqlite(store) => {
                let conn = Arc::clone(&store.conn);
                tokio::task::spawn_blocking(move || {
                    SqliteGateStartCursorStore::load_with_conn(&conn)
                })
                .await
                .map_err(|e| format!("spawn_blocking failed for cursor load: {e}"))?
            },
            Self::Memory(store) => store.load(),
        }
    }

    async fn save(&self, cursor: &CompositeCursor) -> Result<(), Self::Error> {
        match self {
            Self::Sqlite(store) => {
                let conn = Arc::clone(&store.conn);
                let cursor = cursor.clone();
                tokio::task::spawn_blocking(move || {
                    SqliteGateStartCursorStore::save_with_conn(&conn, &cursor)
                })
                .await
                .map_err(|e| format!("spawn_blocking failed for cursor save: {e}"))?
            },
            Self::Memory(store) => store.save(cursor),
        }
    }
}

#[derive(Debug)]
struct SqliteGateStartCursorStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteGateStartCursorStore {
    fn new(conn: Arc<Mutex<Connection>>) -> Result<Self, String> {
        let guard = conn
            .lock()
            .map_err(|e| format!("cursor store lock poisoned: {e}"))?;
        guard
            .execute(
                "CREATE TABLE IF NOT EXISTS gate_start_kernel_cursor (
                    cursor_key INTEGER PRIMARY KEY CHECK (cursor_key = 1),
                    timestamp_ns INTEGER NOT NULL,
                    event_id TEXT NOT NULL
                )",
                [],
            )
            .map_err(|e| format!("failed to create gate_start_kernel_cursor: {e}"))?;
        drop(guard);
        Ok(Self { conn })
    }

    /// Static `load` — callable from `spawn_blocking`.
    fn load_with_conn(conn: &Arc<Mutex<Connection>>) -> Result<CompositeCursor, String> {
        let guard = conn
            .lock()
            .map_err(|e| format!("cursor store lock poisoned: {e}"))?;
        let row: Option<(i64, String)> = guard
            .query_row(
                "SELECT timestamp_ns, event_id
                 FROM gate_start_kernel_cursor
                 WHERE cursor_key = ?1",
                params![GATE_START_CURSOR_KEY],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| format!("failed to load gate-start cursor: {e}"))?;
        let Some((timestamp_ns, event_id)) = row else {
            return Ok(CompositeCursor::default());
        };
        let timestamp_ns = u64::try_from(timestamp_ns)
            .map_err(|_| "gate-start cursor timestamp is negative".to_string())?;
        Ok(CompositeCursor {
            timestamp_ns,
            event_id,
        })
    }

    /// Static `save` — callable from `spawn_blocking`.
    fn save_with_conn(
        conn: &Arc<Mutex<Connection>>,
        cursor: &CompositeCursor,
    ) -> Result<(), String> {
        let timestamp_ns = i64::try_from(cursor.timestamp_ns)
            .map_err(|_| "gate-start cursor timestamp exceeds i64 range".to_string())?;
        let guard = conn
            .lock()
            .map_err(|e| format!("cursor store lock poisoned: {e}"))?;
        guard
            .execute(
                "INSERT INTO gate_start_kernel_cursor (cursor_key, timestamp_ns, event_id)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(cursor_key) DO UPDATE SET
                   timestamp_ns = excluded.timestamp_ns,
                   event_id = excluded.event_id",
                params![GATE_START_CURSOR_KEY, timestamp_ns, &cursor.event_id],
            )
            .map_err(|e| format!("failed to save gate-start cursor: {e}"))?;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct MemoryGateStartCursorStore {
    cursor: Mutex<CompositeCursor>,
}

impl MemoryGateStartCursorStore {
    fn load(&self) -> Result<CompositeCursor, String> {
        Ok(self
            .cursor
            .lock()
            .map_err(|e| format!("memory cursor lock poisoned: {e}"))?
            .clone())
    }

    fn save(&self, cursor: &CompositeCursor) -> Result<(), String> {
        *self
            .cursor
            .lock()
            .map_err(|e| format!("memory cursor lock poisoned: {e}"))? = cursor.clone();
        Ok(())
    }
}

#[derive(Debug)]
enum GateStartIntentStore {
    Sqlite(SqliteGateStartIntentStore),
    Memory(MemoryGateStartIntentStore),
}

impl IntentStore<GateStartIntent, String> for GateStartIntentStore {
    type Error = String;

    async fn enqueue_many(&self, intents: &[GateStartIntent]) -> Result<usize, Self::Error> {
        match self {
            Self::Sqlite(store) => {
                let conn = Arc::clone(&store.conn);
                let intents = intents.to_vec();
                tokio::task::spawn_blocking(move || {
                    SqliteGateStartIntentStore::enqueue_many_with_conn(&conn, &intents)
                })
                .await
                .map_err(|e| format!("spawn_blocking failed for enqueue_many: {e}"))?
            },
            Self::Memory(store) => store.enqueue_many(intents),
        }
    }

    async fn dequeue_batch(&self, limit: usize) -> Result<Vec<GateStartIntent>, Self::Error> {
        match self {
            Self::Sqlite(store) => {
                let conn = Arc::clone(&store.conn);
                tokio::task::spawn_blocking(move || {
                    SqliteGateStartIntentStore::dequeue_batch_with_conn(&conn, limit)
                })
                .await
                .map_err(|e| format!("spawn_blocking failed for dequeue_batch: {e}"))?
            },
            Self::Memory(store) => store.dequeue_batch(limit),
        }
    }

    async fn mark_done(&self, key: &String) -> Result<(), Self::Error> {
        match self {
            Self::Sqlite(store) => {
                let conn = Arc::clone(&store.conn);
                let key = key.clone();
                tokio::task::spawn_blocking(move || {
                    SqliteGateStartIntentStore::mark_done_with_conn(&conn, &key)
                })
                .await
                .map_err(|e| format!("spawn_blocking failed for mark_done: {e}"))?
            },
            Self::Memory(store) => store.mark_done(key),
        }
    }

    async fn mark_blocked(&self, key: &String, reason: &str) -> Result<(), Self::Error> {
        match self {
            Self::Sqlite(store) => {
                let conn = Arc::clone(&store.conn);
                let key = key.clone();
                let reason = reason.to_string();
                tokio::task::spawn_blocking(move || {
                    SqliteGateStartIntentStore::mark_blocked_with_conn(&conn, &key, &reason)
                })
                .await
                .map_err(|e| format!("spawn_blocking failed for mark_blocked: {e}"))?
            },
            Self::Memory(store) => store.mark_blocked(key, reason),
        }
    }

    async fn mark_retryable(&self, key: &String, reason: &str) -> Result<(), Self::Error> {
        match self {
            Self::Sqlite(store) => {
                let conn = Arc::clone(&store.conn);
                let key = key.clone();
                let reason = reason.to_string();
                tokio::task::spawn_blocking(move || {
                    SqliteGateStartIntentStore::mark_retryable_with_conn(&conn, &key, &reason)
                })
                .await
                .map_err(|e| format!("spawn_blocking failed for mark_retryable: {e}"))?
            },
            Self::Memory(store) => store.mark_retryable(key, reason),
        }
    }
}

#[derive(Debug)]
struct SqliteGateStartIntentStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteGateStartIntentStore {
    fn new(conn: Arc<Mutex<Connection>>) -> Result<Self, String> {
        let guard = conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        guard
            .execute(
                "CREATE TABLE IF NOT EXISTS gate_start_intents (
                    intent_key TEXT PRIMARY KEY,
                    publication_json TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending', 'done', 'blocked')),
                    blocked_reason TEXT,
                    created_at_ns INTEGER NOT NULL,
                    updated_at_ns INTEGER NOT NULL,
                    completed_at_ns INTEGER
                )",
                [],
            )
            .map_err(|e| format!("failed to create gate_start_intents: {e}"))?;
        // Migration: add completed_at_ns column if the table predates the
        // TTL-bounded GC change (the column may already exist).
        let _ = guard.execute(
            "ALTER TABLE gate_start_intents ADD COLUMN completed_at_ns INTEGER",
            [],
        );
        guard
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_gate_start_intents_pending
                 ON gate_start_intents(state, created_at_ns, intent_key)",
                [],
            )
            .map_err(|e| format!("failed to create idx_gate_start_intents_pending: {e}"))?;
        drop(guard);
        Ok(Self { conn })
    }

    /// Static `enqueue` — callable from `spawn_blocking`.
    fn enqueue_many_with_conn(
        conn: &Arc<Mutex<Connection>>,
        intents: &[GateStartIntent],
    ) -> Result<usize, String> {
        let now_ns = epoch_now_ns_i64()?;
        let guard = conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        let tx = guard
            .unchecked_transaction()
            .map_err(|e| format!("failed to begin gate-start intent transaction: {e}"))?;
        let mut inserted = 0usize;
        for intent in intents {
            let key = intent.key();
            let publication_json = serde_json::to_string(&intent.publication)
                .map_err(|e| format!("failed to encode publication json: {e}"))?;
            let rows = tx
                .execute(
                    "INSERT OR IGNORE INTO gate_start_intents
                     (intent_key, publication_json, state, blocked_reason, created_at_ns, updated_at_ns)
                     VALUES (?1, ?2, 'pending', NULL, ?3, ?4)",
                    params![key, publication_json, now_ns, now_ns],
                )
                .map_err(|e| format!("failed to enqueue gate-start intent: {e}"))?;
            inserted = inserted.saturating_add(rows);
        }
        tx.commit()
            .map_err(|e| format!("failed to commit gate-start intent transaction: {e}"))?;
        Ok(inserted)
    }

    /// Static `dequeue` — callable from `spawn_blocking`.
    fn dequeue_batch_with_conn(
        conn: &Arc<Mutex<Connection>>,
        limit: usize,
    ) -> Result<Vec<GateStartIntent>, String> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit_i64 =
            i64::try_from(limit).map_err(|_| "execute limit exceeds i64 range".to_string())?;
        let guard = conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        let mut stmt = guard
            .prepare(
                "SELECT publication_json
                 FROM gate_start_intents
                 WHERE state = 'pending'
                 ORDER BY created_at_ns ASC, intent_key ASC
                 LIMIT ?1",
            )
            .map_err(|e| format!("failed to prepare gate-start dequeue query: {e}"))?;
        let rows = stmt
            .query_map(params![limit_i64], |row| row.get::<_, String>(0))
            .map_err(|e| format!("failed to query gate-start intents: {e}"))?;

        let mut intents = Vec::new();
        for row in rows {
            let publication_json =
                row.map_err(|e| format!("failed to decode gate-start intent row: {e}"))?;
            // Defense-in-depth: enforce size limit on stored intent payloads.
            if publication_json.len() > MAX_PAYLOAD_BYTES {
                return Err(format!(
                    "gate-start intent payload too large: {} bytes > {} max",
                    publication_json.len(),
                    MAX_PAYLOAD_BYTES
                ));
            }
            let publication: ChangesetPublication = serde_json::from_str(&publication_json)
                .map_err(|e| format!("failed to decode publication json: {e}"))?;
            intents.push(GateStartIntent { publication });
        }
        Ok(intents)
    }

    /// Static `mark_done` — callable from `spawn_blocking`.
    ///
    /// Retains the intent row with `state = 'done'` and a `completed_at_ns`
    /// timestamp so that a crash between `mark_done` and cursor save still
    /// finds the durable completion marker on restart. Use
    /// [`gc_completed_before_with_conn`] to reclaim space (TTL-bounded GC).
    fn mark_done_with_conn(conn: &Arc<Mutex<Connection>>, key: &str) -> Result<(), String> {
        let now_ns = epoch_now_ns_i64()?;
        let guard = conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        guard
            .execute(
                "UPDATE gate_start_intents
                 SET state = 'done', completed_at_ns = ?2, updated_at_ns = ?2
                 WHERE intent_key = ?1",
                params![key, now_ns],
            )
            .map_err(|e| format!("failed to mark gate-start intent done: {e}"))?;
        Ok(())
    }

    /// Deletes completed intent rows older than `cutoff_ns` (TTL-bounded GC).
    ///
    /// This is NOT part of the hot path — it runs infrequently to reclaim
    /// space without breaking restart idempotency.
    pub(crate) fn gc_completed_before_with_conn(
        conn: &Arc<Mutex<Connection>>,
        cutoff_ns: i64,
    ) -> Result<usize, String> {
        let guard = conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        let deleted = guard
            .execute(
                "DELETE FROM gate_start_intents
                 WHERE state = 'done' AND completed_at_ns < ?1",
                params![cutoff_ns],
            )
            .map_err(|e| format!("failed to gc completed gate-start intents: {e}"))?;
        Ok(deleted)
    }

    /// Static `mark_blocked` — callable from `spawn_blocking`.
    fn mark_blocked_with_conn(
        conn: &Arc<Mutex<Connection>>,
        key: &str,
        reason: &str,
    ) -> Result<(), String> {
        let now_ns = epoch_now_ns_i64()?;
        let guard = conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        guard
            .execute(
                "UPDATE gate_start_intents
                 SET state = 'blocked', blocked_reason = ?2, updated_at_ns = ?3
                 WHERE intent_key = ?1",
                params![key, reason, now_ns],
            )
            .map_err(|e| format!("failed to mark gate-start intent blocked: {e}"))?;
        Ok(())
    }

    /// Static `mark_retryable` — callable from `spawn_blocking`.
    fn mark_retryable_with_conn(
        conn: &Arc<Mutex<Connection>>,
        key: &str,
        _reason: &str,
    ) -> Result<(), String> {
        let now_ns = epoch_now_ns_i64()?;
        let guard = conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        guard
            .execute(
                "UPDATE gate_start_intents
                 SET state = 'pending', blocked_reason = NULL,
                     created_at_ns = ?2, updated_at_ns = ?2
                 WHERE intent_key = ?1",
                params![key, now_ns],
            )
            .map_err(|e| format!("failed to mark gate-start intent retryable: {e}"))?;
        Ok(())
    }

    /// Instance method for use in tests (delegates to static).
    #[cfg(test)]
    fn enqueue_many(&self, intents: &[GateStartIntent]) -> Result<usize, String> {
        Self::enqueue_many_with_conn(&self.conn, intents)
    }

    /// Instance method for use in tests (delegates to static).
    #[cfg(test)]
    fn dequeue_batch(&self, limit: usize) -> Result<Vec<GateStartIntent>, String> {
        Self::dequeue_batch_with_conn(&self.conn, limit)
    }

    /// Instance method for use in tests (delegates to static).
    #[cfg(test)]
    fn mark_done(&self, key: &str) -> Result<(), String> {
        Self::mark_done_with_conn(&self.conn, key)
    }
}

#[derive(Debug, Default)]
struct MemoryGateStartIntentStore {
    pending: Mutex<VecDeque<GateStartIntent>>,
    states: Mutex<HashMap<String, String>>,
    intents: Mutex<HashMap<String, GateStartIntent>>,
}

impl MemoryGateStartIntentStore {
    fn enqueue_many(&self, intents: &[GateStartIntent]) -> Result<usize, String> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|e| format!("memory intent pending lock poisoned: {e}"))?;
        let mut states = self
            .states
            .lock()
            .map_err(|e| format!("memory intent states lock poisoned: {e}"))?;
        let mut intents_by_key = self
            .intents
            .lock()
            .map_err(|e| format!("memory intent index lock poisoned: {e}"))?;
        let mut inserted = 0usize;
        for intent in intents {
            let key = intent.key();
            if states.contains_key(&key) {
                continue;
            }
            states.insert(key.clone(), "pending".to_string());
            intents_by_key.insert(key, intent.clone());
            pending.push_back(intent.clone());
            inserted = inserted.saturating_add(1);
        }
        Ok(inserted)
    }

    fn dequeue_batch(&self, limit: usize) -> Result<Vec<GateStartIntent>, String> {
        let pending = self
            .pending
            .lock()
            .map_err(|e| format!("memory intent pending lock poisoned: {e}"))?;
        Ok(pending.iter().take(limit).cloned().collect())
    }

    fn remove_pending(&self, key: &str) -> Result<(), String> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|e| format!("memory intent pending lock poisoned: {e}"))?;
        pending.retain(|intent| intent.key() != key);
        Ok(())
    }

    fn mark_done(&self, key: &str) -> Result<(), String> {
        self.remove_pending(key)?;
        // Retain the 'done' marker so restart idempotency is preserved
        // (CSID-003). A second enqueue for the same key will be treated
        // as a duplicate because `states` still maps the key.
        self.states
            .lock()
            .map_err(|e| format!("memory intent states lock poisoned: {e}"))?
            .insert(key.to_string(), "done".to_string());
        Ok(())
    }

    fn mark_blocked(&self, key: &str, _reason: &str) -> Result<(), String> {
        self.remove_pending(key)?;
        self.states
            .lock()
            .map_err(|e| format!("memory intent states lock poisoned: {e}"))?
            .insert(key.to_string(), "blocked".to_string());
        Ok(())
    }

    fn mark_retryable(&self, key: &str, _reason: &str) -> Result<(), String> {
        self.states
            .lock()
            .map_err(|e| format!("memory intent states lock poisoned: {e}"))?
            .insert(key.to_string(), "pending".to_string());
        let mut pending = self
            .pending
            .lock()
            .map_err(|e| format!("memory intent pending lock poisoned: {e}"))?;
        if pending.iter().any(|intent| intent.key() == key) {
            return Ok(());
        }
        let intent = self
            .intents
            .lock()
            .map_err(|e| format!("memory intent index lock poisoned: {e}"))?
            .get(key)
            .cloned()
            .ok_or_else(|| format!("missing memory gate-start intent for key '{key}'"))?;
        pending.push_back(intent);
        Ok(())
    }
}

#[derive(Debug)]
struct GateStartEffectJournal {
    conn: Arc<Mutex<Connection>>,
}

impl GateStartEffectJournal {
    fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path)
            .map_err(|e| format!("failed to open gate-start effect journal sqlite db: {e}"))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS gate_start_effect_journal_state (
                intent_key TEXT PRIMARY KEY,
                state TEXT NOT NULL CHECK (state IN ('started', 'completed', 'unknown')),
                updated_at_ns INTEGER NOT NULL
            )",
            [],
        )
        .map_err(|e| format!("failed to create gate_start_effect_journal_state table: {e}"))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Static `load` — callable from `spawn_blocking`.
    fn load_state_with_conn(
        conn: &Arc<Mutex<Connection>>,
        key: &str,
    ) -> Result<Option<String>, String> {
        let guard = conn
            .lock()
            .map_err(|e| format!("gate-start effect journal lock poisoned: {e}"))?;
        guard
            .query_row(
                "SELECT state
                 FROM gate_start_effect_journal_state
                 WHERE intent_key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("failed to load gate-start effect state for key '{key}': {e}"))
    }

    /// Static `upsert` — callable from `spawn_blocking`.
    fn upsert_state_with_conn(
        conn: &Arc<Mutex<Connection>>,
        key: &str,
        state: &str,
        updated_at_ns: i64,
    ) -> Result<(), String> {
        let guard = conn
            .lock()
            .map_err(|e| format!("gate-start effect journal lock poisoned: {e}"))?;
        guard
            .execute(
                "INSERT INTO gate_start_effect_journal_state (intent_key, state, updated_at_ns)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(intent_key) DO UPDATE SET
                     state = excluded.state,
                     updated_at_ns = excluded.updated_at_ns",
                params![key, state, updated_at_ns],
            )
            .map_err(|e| {
                format!("failed to upsert gate-start effect state='{state}' for key '{key}': {e}")
            })?;
        Ok(())
    }

    /// Static `delete` — callable from `spawn_blocking`.
    fn delete_state_with_conn(conn: &Arc<Mutex<Connection>>, key: &str) -> Result<(), String> {
        let guard = conn
            .lock()
            .map_err(|e| format!("gate-start effect journal lock poisoned: {e}"))?;
        guard
            .execute(
                "DELETE FROM gate_start_effect_journal_state WHERE intent_key = ?1",
                params![key],
            )
            .map_err(|e| {
                format!("failed to delete gate-start effect state for key '{key}': {e}")
            })?;
        Ok(())
    }

    /// Deletes completed effect journal rows older than `cutoff_ns`
    /// (TTL-bounded GC). Not part of the hot path.
    pub(crate) fn gc_completed_before_with_conn(
        conn: &Arc<Mutex<Connection>>,
        cutoff_ns: i64,
    ) -> Result<usize, String> {
        let guard = conn
            .lock()
            .map_err(|e| format!("gate-start effect journal lock poisoned: {e}"))?;
        let deleted = guard
            .execute(
                "DELETE FROM gate_start_effect_journal_state
                 WHERE state = 'completed' AND updated_at_ns < ?1",
                params![cutoff_ns],
            )
            .map_err(|e| format!("failed to gc completed effect journal entries: {e}"))?;
        Ok(deleted)
    }

    /// Instance load for tests (delegates to static).
    #[cfg(test)]
    fn load_state(&self, key: &str) -> Result<Option<String>, String> {
        Self::load_state_with_conn(&self.conn, key)
    }

    /// Instance upsert for tests (delegates to static).
    #[cfg(test)]
    fn upsert_state(&self, key: &str, state: &str, updated_at_ns: i64) -> Result<(), String> {
        Self::upsert_state_with_conn(&self.conn, key, state, updated_at_ns)
    }
}

impl EffectJournal<String> for GateStartEffectJournal {
    type Error = String;

    async fn query_state(&self, key: &String) -> Result<EffectExecutionState, Self::Error> {
        let conn = Arc::clone(&self.conn);
        let key = key.clone();
        tokio::task::spawn_blocking(move || {
            let state = Self::load_state_with_conn(&conn, &key)?;
            Ok(match state.as_deref() {
                None => EffectExecutionState::NotStarted,
                Some("completed") => EffectExecutionState::Completed,
                Some(_) => EffectExecutionState::Unknown,
            })
        })
        .await
        .map_err(|e| format!("spawn_blocking failed for query_state: {e}"))?
    }

    async fn record_started(&self, key: &String) -> Result<(), Self::Error> {
        let conn = Arc::clone(&self.conn);
        let key = key.clone();
        tokio::task::spawn_blocking(move || {
            if matches!(
                Self::load_state_with_conn(&conn, &key)?.as_deref(),
                Some("completed")
            ) {
                return Ok(());
            }
            Self::upsert_state_with_conn(&conn, &key, "started", epoch_now_ns_i64()?)
        })
        .await
        .map_err(|e| format!("spawn_blocking failed for record_started: {e}"))?
    }

    async fn record_completed(&self, key: &String) -> Result<(), Self::Error> {
        // Retain the 'completed' marker durably so that a crash between
        // record_completed and cursor save still finds the completion state
        // on restart (CSID-003 restart-safe idempotency). Use gc to reclaim.
        let conn = Arc::clone(&self.conn);
        let key = key.clone();
        tokio::task::spawn_blocking(move || {
            Self::upsert_state_with_conn(&conn, &key, "completed", epoch_now_ns_i64()?)
        })
        .await
        .map_err(|e| format!("spawn_blocking failed for record_completed: {e}"))?
    }

    async fn record_retryable(&self, key: &String) -> Result<(), Self::Error> {
        let conn = Arc::clone(&self.conn);
        let key = key.clone();
        tokio::task::spawn_blocking(move || {
            let state = Self::load_state_with_conn(&conn, &key)?;
            match state.as_deref() {
                Some("started") => Self::delete_state_with_conn(&conn, &key),
                Some("completed") => Err(format!(
                    "cannot mark gate-start effect retryable for completed key '{key}'"
                )),
                Some(other) => Err(format!(
                    "cannot mark gate-start effect retryable from state '{other}' for key '{key}'"
                )),
                None => Err(format!(
                    "cannot mark gate-start effect retryable for unknown key '{key}'"
                )),
            }
        })
        .await
        .map_err(|e| format!("spawn_blocking failed for record_retryable: {e}"))?
    }

    async fn resolve_in_doubt(&self, key: &String) -> Result<InDoubtResolution, Self::Error> {
        let conn = Arc::clone(&self.conn);
        let key = key.clone();
        tokio::task::spawn_blocking(move || {
            Self::upsert_state_with_conn(&conn, &key, "unknown", epoch_now_ns_i64()?)?;
            Ok(InDoubtResolution::Deny {
                reason: "gate-start effect state is in-doubt; manual reconciliation required"
                    .to_string(),
            })
        })
        .await
        .map_err(|e| format!("spawn_blocking failed for resolve_in_doubt: {e}"))?
    }
}

#[derive(Debug)]
struct GateStartReceiptWriter {
    /// Wrapped in `Arc` to allow cloning for `spawn_blocking` closures.
    ledger_emitter: Option<Arc<SqliteLedgerEventEmitter>>,
}

impl GateStartReceiptWriter {
    fn new(ledger_emitter: Option<SqliteLedgerEventEmitter>) -> Self {
        Self {
            ledger_emitter: ledger_emitter.map(Arc::new),
        }
    }

    /// Synchronous persist — callable from `spawn_blocking`.
    fn persist_many_sync(
        emitter: &SqliteLedgerEventEmitter,
        receipts: &[GateStartReceipt],
    ) -> Result<(), String> {
        for receipt in receipts {
            match receipt {
                GateStartReceipt::OrchestratorEvent(event) => {
                    let (event_type, timestamp_ns) = gate_start_event_persistence_fields(event);
                    let payload = serde_json::to_vec(event).map_err(|e| {
                        format!("failed to serialize gate-start orchestrator event: {e}")
                    })?;
                    emitter
                        .emit_session_event(
                            GATE_START_PERSISTOR_SESSION_ID,
                            event_type,
                            &payload,
                            GATE_START_PERSISTOR_ACTOR_ID,
                            timestamp_ns,
                        )
                        .map_err(|e| {
                            format!("failed to persist gate-start orchestrator event: {e}")
                        })?;
                },
                GateStartReceipt::GateLeaseIssued {
                    lease,
                    timestamp_ns,
                } => {
                    let payload = serde_json::json!({
                        "event_type": "gate_lease_issued",
                        "work_id": lease.work_id,
                        "lease_id": lease.lease_id,
                        "gate_id": lease.gate_id,
                        "executor_actor_id": lease.executor_actor_id,
                        "changeset_digest": hex::encode(lease.changeset_digest),
                        "full_lease": lease,
                    });
                    let payload_bytes = serde_json::to_vec(&payload).map_err(|e| {
                        format!("failed to serialize gate_lease_issued payload: {e}")
                    })?;
                    emitter
                        .emit_session_event(
                            GATE_START_PERSISTOR_SESSION_ID,
                            "gate_lease_issued",
                            &payload_bytes,
                            GATE_START_PERSISTOR_ACTOR_ID,
                            *timestamp_ns,
                        )
                        .map_err(|e| format!("failed to persist gate_lease_issued event: {e}"))?;
                },
                GateStartReceipt::Defect {
                    defect,
                    timestamp_ns,
                } => {
                    emitter
                        .emit_defect_recorded(defect, *timestamp_ns)
                        .map_err(|e| format!("failed to persist gate-start defect event: {e}"))?;
                },
            }
        }
        Ok(())
    }
}

impl ReceiptWriter<GateStartReceipt> for GateStartReceiptWriter {
    type Error = String;

    async fn persist_many(&self, receipts: &[GateStartReceipt]) -> Result<(), Self::Error> {
        let Some(emitter) = self.ledger_emitter.as_ref() else {
            return Ok(());
        };

        let emitter = Arc::clone(emitter);
        let receipts = receipts.to_vec();
        tokio::task::spawn_blocking(move || Self::persist_many_sync(&emitter, &receipts))
            .await
            .map_err(|e| format!("spawn_blocking failed for persist_many: {e}"))?
    }
}

/// Maps gate-start orchestrator events to persisted event type and timestamp.
#[must_use]
pub const fn gate_start_event_persistence_fields(
    event: &GateOrchestratorEvent,
) -> (&'static str, u64) {
    match event {
        GateOrchestratorEvent::PolicyResolved { timestamp_ms, .. } => (
            "gate.policy_resolved",
            timestamp_ms.saturating_mul(1_000_000),
        ),
        GateOrchestratorEvent::GateLeaseIssued { timestamp_ms, .. } => {
            ("gate.lease_issued", timestamp_ms.saturating_mul(1_000_000))
        },
        GateOrchestratorEvent::GateExecutorSpawned { timestamp_ms, .. } => (
            "gate.executor_spawned",
            timestamp_ms.saturating_mul(1_000_000),
        ),
        GateOrchestratorEvent::GateReceiptCollected { timestamp_ms, .. } => (
            "gate.receipt_collected",
            timestamp_ms.saturating_mul(1_000_000),
        ),
        GateOrchestratorEvent::GateTimedOut { timestamp_ms, .. } => {
            ("gate.timed_out", timestamp_ms.saturating_mul(1_000_000))
        },
        GateOrchestratorEvent::GateTimeoutReceiptGenerated { timestamp_ms, .. } => (
            "gate.timeout_receipt_generated",
            timestamp_ms.saturating_mul(1_000_000),
        ),
        GateOrchestratorEvent::AllGatesCompleted { timestamp_ms, .. } => {
            ("gate.all_completed", timestamp_ms.saturating_mul(1_000_000))
        },
    }
}

fn parse_changeset_publication_payload(
    payload: &[u8],
    fallback_timestamp_ns: u64,
    event_id: &str,
    verified_actor_id: Option<&str>,
) -> Result<ChangesetPublication, String> {
    // BLOCKER 1 (Security): Enforce strict max size BEFORE deserialization to
    // prevent DoS via oversized payloads exhausting daemon memory.
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(format!(
            "changeset_published payload too large: {} bytes > {} max",
            payload.len(),
            MAX_PAYLOAD_BYTES
        ));
    }
    let payload_json: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| format!("failed to decode changeset_published payload json: {e}"))?;
    let work_id = payload_json
        .get("work_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "changeset_published payload missing work_id".to_string())?;
    let changeset_digest_hex = payload_json
        .get("changeset_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "changeset_published payload missing changeset_digest".to_string())?;
    let cas_hash_hex = payload_json
        .get("cas_hash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "changeset_published payload missing cas_hash".to_string())?;
    // MAJOR (Security): Use the verified actor_id from the ledger row (the
    // signed envelope identity) as the authoritative publisher_actor_id.
    // Cross-validate against the payload's actor_id when both are available
    // to detect spoofing attempts.
    let payload_actor_id = payload_json
        .get("actor_id")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty());

    let publisher_actor_id = if let Some(verified) = verified_actor_id {
        // Ledger row provides verified identity — use it as authoritative.
        // Cross-validate: if the payload also declares an actor_id that
        // differs from the verified one, reject as spoofing attempt.
        if let Some(payload_aid) = payload_actor_id {
            if payload_aid != verified {
                return Err(format!(
                    "changeset_published identity spoofing: payload actor_id '{payload_aid}' \
                     does not match verified ledger actor_id '{verified}' (event_id={event_id})"
                ));
            }
        }
        verified
    } else {
        // No verified actor_id available (e.g. canonical events table lacks
        // the column). Fall back to payload but require it to be present.
        payload_actor_id.ok_or_else(|| {
            "changeset_published payload missing or empty actor_id (fail-closed)".to_string()
        })?
    };
    let published_at_ns = payload_json
        .get("timestamp_ns")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(fallback_timestamp_ns);
    let payload = ChangeSetPublishedKernelEventPayload {
        work_id: work_id.to_string(),
        changeset_digest: decode_hex_32(changeset_digest_hex)?,
        cas_hash: decode_hex_32(cas_hash_hex)?,
        published_at_ns,
        publisher_actor_id: publisher_actor_id.to_string(),
        event_id: event_id.to_string(),
    };
    ChangesetPublication::try_from(payload).map_err(|e| {
        format!("invalid authoritative changeset publication payload (event_id={event_id}): {e}")
    })
}

fn decode_hex_32(hex_value: &str) -> Result<[u8; 32], String> {
    let raw = hex::decode(hex_value)
        .map_err(|e| format!("failed to decode 32-byte hex digest '{hex_value}': {e}"))?;
    if raw.len() != 32 {
        return Err(format!(
            "digest must be 32 bytes, got {} for value '{hex_value}'",
            raw.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn gate_start_intent_key(work_id: &str, changeset_digest: &[u8; 32]) -> String {
    format!("gate_start:{work_id}:{}", hex::encode(changeset_digest))
}

fn build_gate_start_defect(
    publication: &ChangesetPublication,
    reason: &str,
    timestamp_ns: u64,
) -> DefectRecorded {
    let mut cas_preimage = Vec::new();
    cas_preimage.extend_from_slice(publication.work_id.as_bytes());
    cas_preimage.extend_from_slice(&publication.changeset_digest);
    cas_preimage.extend_from_slice(reason.as_bytes());
    let cas_hash = *blake3::hash(&cas_preimage).as_bytes();

    DefectRecorded {
        defect_id: format!("DEF-GATE-START-{}", uuid::Uuid::new_v4()),
        defect_type: "GATE_START_FAILED".to_string(),
        cas_hash: cas_hash.to_vec(),
        source: DefectSource::CapabilityUnavailable as i32,
        work_id: publication.work_id.clone(),
        severity: "S1".to_string(),
        detected_at: timestamp_ns,
        time_envelope_ref: None,
    }
}

fn epoch_now_ns_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn epoch_now_ns_i64() -> Result<i64, String> {
    i64::try_from(epoch_now_ns_u64())
        .map_err(|_| "current epoch timestamp exceeds i64 range".to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use apm2_core::orchestrator_kernel::CompositeCursor;
    use rusqlite::Connection;
    use serde_json::json;

    use super::{SqliteGateStartLedgerReader, gate_start_intent_key};

    #[test]
    fn gate_start_intent_key_matches_contract() {
        let key = gate_start_intent_key("W-123", &[0xAB; 32]);
        assert_eq!(key, format!("gate_start:W-123:{}", "ab".repeat(32)));
    }

    #[test]
    fn poll_same_timestamp_interleaving_does_not_skip_legacy_after_canonical_cursor() {
        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("open in-memory sqlite"),
        ));
        {
            let guard = conn.lock().expect("lock sqlite");
            guard
                .execute(
                    "CREATE TABLE ledger_events (
                        event_id TEXT PRIMARY KEY,
                        event_type TEXT NOT NULL,
                        actor_id TEXT NOT NULL DEFAULT '',
                        payload BLOB NOT NULL,
                        timestamp_ns INTEGER NOT NULL
                    )",
                    [],
                )
                .expect("create legacy table");
            guard
                .execute(
                    "CREATE TABLE events (
                        seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        actor_id TEXT NOT NULL DEFAULT '',
                        payload BLOB NOT NULL,
                        timestamp_ns INTEGER NOT NULL
                    )",
                    [],
                )
                .expect("create canonical table");
            let ts = 1_706_000_000_999_000_000_i64;
            let legacy_payload = serde_json::to_vec(&json!({
                "work_id": "work-legacy",
                "changeset_digest": hex::encode([0x11; 32]),
                "cas_hash": hex::encode([0x21; 32]),
                "actor_id": "actor:legacy",
                "timestamp_ns": ts,
            }))
            .expect("serialize legacy payload");
            let canonical_payload = serde_json::to_vec(&json!({
                "work_id": "work-canonical",
                "changeset_digest": hex::encode([0x12; 32]),
                "cas_hash": hex::encode([0x22; 32]),
                "actor_id": "actor:canonical",
                "timestamp_ns": ts,
            }))
            .expect("serialize canonical payload");
            guard
                .execute(
                    "INSERT INTO ledger_events (event_id, event_type, actor_id, payload, timestamp_ns)
                     VALUES (?1, 'changeset_published', ?2, ?3, ?4)",
                    rusqlite::params!["a-legacy", "actor:legacy", legacy_payload, ts],
                )
                .expect("insert legacy changeset");
            guard
                .execute(
                    "INSERT INTO events (event_type, actor_id, payload, timestamp_ns)
                     VALUES ('changeset_published', ?1, ?2, ?3)",
                    rusqlite::params!["actor:canonical", canonical_payload, ts],
                )
                .expect("insert canonical changeset");
        }

        let reader = SqliteGateStartLedgerReader::new(Arc::clone(&conn));
        let first = reader
            .poll(&CompositeCursor::default(), 1)
            .expect("first poll should succeed");
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].publication.work_id, "work-canonical");

        let cursor = CompositeCursor {
            timestamp_ns: first[0].timestamp_ns,
            event_id: first[0].cursor_event_id.clone(),
        };
        let second = reader
            .poll(&cursor, 10)
            .expect("second poll should succeed");
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].publication.work_id, "work-legacy");
    }

    #[test]
    fn oversized_payload_rejected_before_deserialization() {
        use super::{MAX_PAYLOAD_BYTES, parse_changeset_publication_payload};

        // Create a payload just over the limit
        let oversized = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let result = parse_changeset_publication_payload(&oversized, 0, "test-event", None);
        assert!(result.is_err(), "oversized payload should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("payload too large"),
            "error should mention 'payload too large', got: {err}"
        );
    }

    #[test]
    fn payload_at_limit_is_accepted_if_valid_json() {
        use super::{MAX_PAYLOAD_BYTES, parse_changeset_publication_payload};

        // A valid payload within the size limit should parse (or fail on JSON
        // validity, but not on size).
        let small_valid = serde_json::to_vec(&json!({
            "work_id": "W-1",
            "changeset_digest": hex::encode([0x01; 32]),
            "cas_hash": hex::encode([0x02; 32]),
            "actor_id": "actor:test",
            "timestamp_ns": 123_456_789_u64,
        }))
        .expect("serialize payload");
        assert!(small_valid.len() <= MAX_PAYLOAD_BYTES);
        let result = parse_changeset_publication_payload(&small_valid, 0, "test-event", None);
        assert!(result.is_ok(), "valid payload should parse: {result:?}");
    }

    #[test]
    fn identity_spoofing_rejected_when_payload_actor_mismatches_verified() {
        use super::parse_changeset_publication_payload;

        let payload = serde_json::to_vec(&json!({
            "work_id": "W-1",
            "changeset_digest": hex::encode([0x01; 32]),
            "cas_hash": hex::encode([0x02; 32]),
            "actor_id": "actor:attacker",
            "timestamp_ns": 123_456_789_u64,
        }))
        .expect("serialize payload");

        // Verified actor from ledger is different from payload actor
        let result = parse_changeset_publication_payload(
            &payload,
            0,
            "test-event",
            Some("actor:legitimate"),
        );
        assert!(result.is_err(), "mismatched actor_id should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("identity spoofing"),
            "error should mention 'identity spoofing', got: {err}"
        );
    }

    #[test]
    fn verified_actor_id_used_when_available() {
        use super::parse_changeset_publication_payload;

        let payload = serde_json::to_vec(&json!({
            "work_id": "W-1",
            "changeset_digest": hex::encode([0x01; 32]),
            "cas_hash": hex::encode([0x02; 32]),
            "actor_id": "actor:real",
            "timestamp_ns": 123_456_789_u64,
        }))
        .expect("serialize payload");

        // Verified matches payload — should succeed
        let result =
            parse_changeset_publication_payload(&payload, 0, "test-event", Some("actor:real"));
        assert!(
            result.is_ok(),
            "matching verified actor_id should succeed: {result:?}"
        );
        let pub_result = result.unwrap();
        assert_eq!(pub_result.publisher_actor_id, "actor:real");
    }

    /// CSID-003 restart-safe idempotency: after marking N intents done, the
    /// `SQLite` intent table must retain the row with `state = 'done'` so
    /// that a crash before cursor save still finds the completion marker.
    #[test]
    fn sqlite_intent_store_mark_done_retains_durable_marker() {
        use super::SqliteGateStartIntentStore;

        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("open in-memory sqlite"),
        ));
        let store = SqliteGateStartIntentStore::new(Arc::clone(&conn)).expect("init store");

        let publication = apm2_core::fac::ChangesetPublication {
            work_id: "W-done-test".to_string(),
            changeset_digest: [0xAA; 32],
            bundle_cas_hash: [0xBB; 32],
            published_at_ms: 1_000,
            publisher_actor_id: "actor:test".to_string(),
            changeset_published_event_id: "evt-1".to_string(),
        };
        let intent = super::GateStartIntent {
            publication: publication.clone(),
        };

        // Enqueue and verify it exists.
        let inserted = store.enqueue_many(&[intent]).expect("enqueue");
        assert_eq!(inserted, 1, "one intent should be inserted");
        let pending = store.dequeue_batch(10).expect("dequeue");
        assert_eq!(pending.len(), 1, "one intent should be pending");

        // Mark done — must UPDATE to 'done', not DELETE.
        let key = super::gate_start_intent_key(&publication.work_id, &publication.changeset_digest);
        store.mark_done(&key).expect("mark done");

        // Verify: the row exists with state = 'done'.
        {
            let guard = conn.lock().expect("lock");
            let (count, state): (i64, String) = guard
                .query_row(
                    "SELECT COUNT(*), state FROM gate_start_intents WHERE intent_key = ?1",
                    rusqlite::params![key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .expect("query done intent");
            assert_eq!(count, 1, "intent row must be retained after mark_done");
            assert_eq!(state, "done", "intent state must be 'done' after mark_done");
        }
        // guard dropped — subsequent store methods can acquire the lock.

        // A second enqueue for the same key must be treated as duplicate.
        let intent2 = super::GateStartIntent { publication };
        let inserted2 = store.enqueue_many(&[intent2]).expect("re-enqueue");
        assert_eq!(
            inserted2, 0,
            "re-enqueue of done intent must be treated as duplicate"
        );

        // Dequeue must return 0 pending (done rows are not pending).
        let pending2 = store.dequeue_batch(10).expect("dequeue after done");
        assert_eq!(pending2.len(), 0, "no pending intents after mark_done");

        // GC clears rows older than cutoff.
        let future_ns = i64::MAX - 1;
        let gc_count = SqliteGateStartIntentStore::gc_completed_before_with_conn(&conn, future_ns)
            .expect("gc");
        assert_eq!(gc_count, 1, "GC should delete the completed row");

        let count_after_gc: i64 = conn
            .lock()
            .expect("lock for gc count")
            .query_row("SELECT COUNT(*) FROM gate_start_intents", [], |r| r.get(0))
            .expect("count query");
        assert_eq!(count_after_gc, 0, "intent table must be empty after GC");
    }

    /// CSID-003 restart-safe idempotency: after marking N intents done, the
    /// in-memory intent store must retain the 'done' marker so a re-enqueue
    /// for the same key is treated as a duplicate.
    #[test]
    fn memory_intent_store_mark_done_retains_marker() {
        use super::MemoryGateStartIntentStore;

        let store = MemoryGateStartIntentStore::default();
        let publication = apm2_core::fac::ChangesetPublication {
            work_id: "W-mem-done".to_string(),
            changeset_digest: [0xCC; 32],
            bundle_cas_hash: [0xDD; 32],
            published_at_ms: 2_000,
            publisher_actor_id: "actor:mem".to_string(),
            changeset_published_event_id: "evt-2".to_string(),
        };
        let intent = super::GateStartIntent {
            publication: publication.clone(),
        };

        let inserted = store.enqueue_many(&[intent]).expect("enqueue");
        assert_eq!(inserted, 1);

        let key = super::gate_start_intent_key(&publication.work_id, &publication.changeset_digest);
        store.mark_done(&key).expect("mark done");

        // Pending queue must be empty (done intents are not pending).
        let pending_count = store.pending.lock().expect("lock").len();
        assert_eq!(
            pending_count, 0,
            "pending queue must be empty after mark_done"
        );

        // States map must retain the 'done' marker.
        let state = store.states.lock().expect("lock").get(&key).cloned();
        assert_eq!(
            state.as_deref(),
            Some("done"),
            "states map must retain 'done' marker after mark_done"
        );

        // A second enqueue must be treated as duplicate.
        let intent2 = super::GateStartIntent { publication };
        let inserted2 = store.enqueue_many(&[intent2]).expect("re-enqueue");
        assert_eq!(
            inserted2, 0,
            "re-enqueue of done intent must be treated as duplicate"
        );
    }

    /// CSID-003 restart-safe idempotency: effect journal retains 'completed'
    /// marker after `record_completed`. TTL-bounded GC reclaims space.
    #[test]
    fn effect_journal_record_completed_retains_marker() {
        use super::GateStartEffectJournal;

        let dir = tempfile::tempdir().expect("create tempdir");
        let journal_path = dir.path().join("test_journal.sqlite");
        let journal = GateStartEffectJournal::open(&journal_path).expect("open journal");

        let key = "gate_start:W-journal-test:aa".to_string() + &"bb".repeat(16);

        // Record started, then completed.
        journal
            .upsert_state(&key, "started", 1000)
            .expect("record started");
        let state = journal.load_state(&key).expect("load state");
        assert_eq!(state.as_deref(), Some("started"));

        // record_completed retains 'completed' marker.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");
        rt.block_on(async {
            use apm2_core::orchestrator_kernel::EffectJournal;
            let key_string = key.clone();
            journal
                .record_completed(&key_string)
                .await
                .expect("record completed");
        });

        // Verify: row exists with state = 'completed'.
        let state_after = journal.load_state(&key).expect("load state after");
        assert_eq!(
            state_after.as_deref(),
            Some("completed"),
            "effect journal entry must be 'completed' after record_completed"
        );

        // query_state returns Completed.
        rt.block_on(async {
            use apm2_core::orchestrator_kernel::EffectJournal as _;
            let key_string = key.clone();
            let ees = journal.query_state(&key_string).await.expect("query_state");
            assert_eq!(
                ees,
                apm2_core::orchestrator_kernel::EffectExecutionState::Completed,
                "query_state must return Completed"
            );
        });

        // GC clears completed entries older than cutoff.
        let future_ns = i64::MAX - 1;
        let gc_count =
            GateStartEffectJournal::gc_completed_before_with_conn(&journal.conn, future_ns)
                .expect("gc");
        assert_eq!(gc_count, 1, "GC should delete the completed row");

        let count_after_gc: i64 = journal
            .conn
            .lock()
            .expect("lock")
            .query_row(
                "SELECT COUNT(*) FROM gate_start_effect_journal_state",
                [],
                |r| r.get(0),
            )
            .expect("count query");
        assert_eq!(
            count_after_gc, 0,
            "effect journal table must be empty after GC"
        );
    }
}

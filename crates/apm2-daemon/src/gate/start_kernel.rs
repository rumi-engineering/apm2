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
    ReceiptWriter, TickConfig, TickReport, is_after_cursor, run_tick,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::gate::{GateOrchestrator, GateOrchestratorEvent};
use crate::ledger::SqliteLedgerEventEmitter;
use crate::protocol::dispatch::LedgerEventEmitter;

const GATE_START_CURSOR_KEY: i64 = 1;
const GATE_START_PERSISTOR_SESSION_ID: &str = "gate-start-kernel";
const GATE_START_PERSISTOR_ACTOR_ID: &str = "orchestrator:gate-start-kernel";

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateStartObservedEvent {
    timestamp_ns: u64,
    event_id: String,
    publication: ChangesetPublication,
}

impl CursorEvent for GateStartObservedEvent {
    fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    fn event_id(&self) -> &str {
        &self.event_id
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
            Self::Sqlite(reader) => reader.poll(cursor, limit),
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

    fn poll(
        &self,
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
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("ledger reader lock poisoned: {e}"))?;

        let mut out = Vec::new();
        out.extend(Self::query_changeset_published_legacy(
            &guard,
            cursor_ts_i64,
            &cursor.event_id,
            limit_i64,
        )?);
        out.extend(Self::query_changeset_published_canonical(
            &guard,
            cursor_ts_i64,
            &cursor.event_id,
            limit_i64,
        )?);
        out.retain(|event| is_after_cursor(event, cursor));
        out.sort_by(|a, b| {
            a.timestamp_ns
                .cmp(&b.timestamp_ns)
                .then_with(|| a.event_id.cmp(&b.event_id))
        });
        out.truncate(limit);
        Ok(out)
    }

    fn query_changeset_published_legacy(
        conn: &Connection,
        cursor_ts_i64: i64,
        cursor_event_id: &str,
        limit_i64: i64,
    ) -> Result<Vec<GateStartObservedEvent>, String> {
        let query = if cursor_event_id.is_empty() {
            "SELECT event_id, payload, timestamp_ns
             FROM ledger_events
             WHERE event_type = 'changeset_published' AND timestamp_ns > ?1
             ORDER BY timestamp_ns ASC, event_id ASC
             LIMIT ?2"
        } else {
            "SELECT event_id, payload, timestamp_ns
             FROM ledger_events
             WHERE event_type = 'changeset_published'
               AND (timestamp_ns > ?1 OR (timestamp_ns = ?1 AND event_id > ?2))
             ORDER BY timestamp_ns ASC, event_id ASC
             LIMIT ?3"
        };
        let mut stmt = conn
            .prepare(query)
            .map_err(|e| format!("failed to prepare legacy changeset query: {e}"))?;
        let mut rows = if cursor_event_id.is_empty() {
            stmt.query(params![cursor_ts_i64, limit_i64])
        } else {
            stmt.query(params![cursor_ts_i64, cursor_event_id, limit_i64])
        }
        .map_err(|e| format!("failed to execute legacy changeset query: {e}"))?;

        let mut out = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| format!("failed to iterate legacy changeset rows: {e}"))?
        {
            let event_id: String = row
                .get(0)
                .map_err(|e| format!("failed to decode legacy event_id: {e}"))?;
            let payload: Vec<u8> = row
                .get(1)
                .map_err(|e| format!("failed to decode legacy payload: {e}"))?;
            let ts_i64: i64 = row
                .get(2)
                .map_err(|e| format!("failed to decode legacy timestamp: {e}"))?;
            let timestamp_ns =
                u64::try_from(ts_i64).map_err(|_| "legacy timestamp is negative".to_string())?;
            let publication =
                parse_changeset_publication_payload(&payload, timestamp_ns, &event_id)?;
            out.push(GateStartObservedEvent {
                timestamp_ns,
                event_id,
                publication,
            });
        }
        Ok(out)
    }

    fn query_changeset_published_canonical(
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
        if table_exists.is_none() {
            return Ok(Vec::new());
        }

        let query = if cursor_event_id.is_empty() {
            "SELECT seq_id, payload, timestamp_ns
             FROM events
             WHERE event_type = 'changeset_published' AND timestamp_ns > ?1
             ORDER BY timestamp_ns ASC, seq_id ASC
             LIMIT ?2"
        } else {
            "SELECT seq_id, payload, timestamp_ns
             FROM events
             WHERE event_type = 'changeset_published'
               AND (
                 timestamp_ns > ?1 OR
                 (timestamp_ns = ?1 AND
                  ('canonical-' || SUBSTR('00000000000000000000', 1, 20 - LENGTH(CAST(seq_id AS TEXT))) || CAST(seq_id AS TEXT)) > ?2)
               )
             ORDER BY timestamp_ns ASC, seq_id ASC
             LIMIT ?3"
        };
        let mut stmt = conn
            .prepare(query)
            .map_err(|e| format!("failed to prepare canonical changeset query: {e}"))?;
        let mut rows = if cursor_event_id.is_empty() {
            stmt.query(params![cursor_ts_i64, limit_i64])
        } else {
            stmt.query(params![cursor_ts_i64, cursor_event_id, limit_i64])
        }
        .map_err(|e| format!("failed to execute canonical changeset query: {e}"))?;

        let mut out = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| format!("failed to iterate canonical changeset rows: {e}"))?
        {
            let seq_id: i64 = row
                .get(0)
                .map_err(|e| format!("failed to decode canonical seq_id: {e}"))?;
            let payload: Vec<u8> = row
                .get(1)
                .map_err(|e| format!("failed to decode canonical payload: {e}"))?;
            let ts_i64: i64 = row
                .get(2)
                .map_err(|e| format!("failed to decode canonical timestamp: {e}"))?;
            let timestamp_ns =
                u64::try_from(ts_i64).map_err(|_| "canonical timestamp is negative".to_string())?;
            let event_id = format!("canonical-{seq_id:020}");
            let publication =
                parse_changeset_publication_payload(&payload, timestamp_ns, &event_id)?;
            out.push(GateStartObservedEvent {
                timestamp_ns,
                event_id,
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
            Self::Sqlite(store) => store.load(),
            Self::Memory(store) => store.load(),
        }
    }

    async fn save(&self, cursor: &CompositeCursor) -> Result<(), Self::Error> {
        match self {
            Self::Sqlite(store) => store.save(cursor),
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

    fn load(&self) -> Result<CompositeCursor, String> {
        let guard = self
            .conn
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

    fn save(&self, cursor: &CompositeCursor) -> Result<(), String> {
        let timestamp_ns = i64::try_from(cursor.timestamp_ns)
            .map_err(|_| "gate-start cursor timestamp exceeds i64 range".to_string())?;
        let guard = self
            .conn
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
            Self::Sqlite(store) => store.enqueue_many(intents),
            Self::Memory(store) => store.enqueue_many(intents),
        }
    }

    async fn dequeue_batch(&self, limit: usize) -> Result<Vec<GateStartIntent>, Self::Error> {
        match self {
            Self::Sqlite(store) => store.dequeue_batch(limit),
            Self::Memory(store) => store.dequeue_batch(limit),
        }
    }

    async fn mark_done(&self, key: &String) -> Result<(), Self::Error> {
        match self {
            Self::Sqlite(store) => store.mark_done(key),
            Self::Memory(store) => store.mark_done(key),
        }
    }

    async fn mark_blocked(&self, key: &String, reason: &str) -> Result<(), Self::Error> {
        match self {
            Self::Sqlite(store) => store.mark_blocked(key, reason),
            Self::Memory(store) => store.mark_blocked(key, reason),
        }
    }

    async fn mark_retryable(&self, key: &String, reason: &str) -> Result<(), Self::Error> {
        match self {
            Self::Sqlite(store) => store.mark_retryable(key, reason),
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
                    updated_at_ns INTEGER NOT NULL
                )",
                [],
            )
            .map_err(|e| format!("failed to create gate_start_intents: {e}"))?;
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

    fn enqueue_many(&self, intents: &[GateStartIntent]) -> Result<usize, String> {
        let now_ns = epoch_now_ns_i64()?;
        let guard = self
            .conn
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

    fn dequeue_batch(&self, limit: usize) -> Result<Vec<GateStartIntent>, String> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit_i64 =
            i64::try_from(limit).map_err(|_| "execute limit exceeds i64 range".to_string())?;
        let guard = self
            .conn
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
            let publication: ChangesetPublication = serde_json::from_str(&publication_json)
                .map_err(|e| format!("failed to decode publication json: {e}"))?;
            intents.push(GateStartIntent { publication });
        }
        Ok(intents)
    }

    fn mark_done(&self, key: &str) -> Result<(), String> {
        let now_ns = epoch_now_ns_i64()?;
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        guard
            .execute(
                "UPDATE gate_start_intents
                 SET state = 'done', blocked_reason = NULL, updated_at_ns = ?2
                 WHERE intent_key = ?1",
                params![key, now_ns],
            )
            .map_err(|e| format!("failed to mark gate-start intent done: {e}"))?;
        Ok(())
    }

    fn mark_blocked(&self, key: &str, reason: &str) -> Result<(), String> {
        let now_ns = epoch_now_ns_i64()?;
        let guard = self
            .conn
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

    fn mark_retryable(&self, key: &str, _reason: &str) -> Result<(), String> {
        let now_ns = epoch_now_ns_i64()?;
        let guard = self
            .conn
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

    fn load_state(&self, key: &str) -> Result<Option<String>, String> {
        let guard = self
            .conn
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

    fn upsert_state(&self, key: &str, state: &str, updated_at_ns: i64) -> Result<(), String> {
        let guard = self
            .conn
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

    fn delete_state(&self, key: &str) -> Result<(), String> {
        let guard = self
            .conn
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
}

impl EffectJournal<String> for GateStartEffectJournal {
    type Error = String;

    async fn query_state(&self, key: &String) -> Result<EffectExecutionState, Self::Error> {
        let state = self.load_state(key.as_str())?;
        Ok(match state.as_deref() {
            None => EffectExecutionState::NotStarted,
            Some("completed") => EffectExecutionState::Completed,
            Some(_) => EffectExecutionState::Unknown,
        })
    }

    async fn record_started(&self, key: &String) -> Result<(), Self::Error> {
        if matches!(self.load_state(key.as_str())?.as_deref(), Some("completed")) {
            return Ok(());
        }
        self.upsert_state(key.as_str(), "started", epoch_now_ns_i64()?)
    }

    async fn record_completed(&self, key: &String) -> Result<(), Self::Error> {
        self.upsert_state(key.as_str(), "completed", epoch_now_ns_i64()?)
    }

    async fn record_retryable(&self, key: &String) -> Result<(), Self::Error> {
        let state = self.load_state(key.as_str())?;
        match state.as_deref() {
            Some("started") => self.delete_state(key.as_str()),
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
    }

    async fn resolve_in_doubt(&self, key: &String) -> Result<InDoubtResolution, Self::Error> {
        self.upsert_state(key.as_str(), "unknown", epoch_now_ns_i64()?)?;
        Ok(InDoubtResolution::Deny {
            reason: "gate-start effect state is in-doubt; manual reconciliation required"
                .to_string(),
        })
    }
}

#[derive(Debug)]
struct GateStartReceiptWriter {
    ledger_emitter: Option<SqliteLedgerEventEmitter>,
}

impl GateStartReceiptWriter {
    const fn new(ledger_emitter: Option<SqliteLedgerEventEmitter>) -> Self {
        Self { ledger_emitter }
    }
}

impl ReceiptWriter<GateStartReceipt> for GateStartReceiptWriter {
    type Error = String;

    async fn persist_many(&self, receipts: &[GateStartReceipt]) -> Result<(), Self::Error> {
        let Some(emitter) = self.ledger_emitter.as_ref() else {
            return Ok(());
        };

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
) -> Result<ChangesetPublication, String> {
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
    let publisher_actor_id = payload_json
        .get("actor_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
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
    use super::gate_start_intent_key;

    #[test]
    fn gate_start_intent_key_matches_contract() {
        let key = gate_start_intent_key("W-123", &[0xAB; 32]);
        assert_eq!(key, format!("gate_start:W-123:{}", "ab".repeat(32)));
    }
}

//! Orchestrator-kernel wiring for `ChangeSetPublished -> StartGates`.
//!
//! This module consumes authoritative `changeset_published` ledger events and
//! drives gate-start orchestration through the shared
//! `apm2_core::orchestrator_kernel` harness.

use std::collections::HashMap;
#[cfg(test)]
use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use apm2_core::events::{DefectRecorded, DefectSource, Validate};
use apm2_core::fac::{ChangeSetPublishedKernelEventPayload, ChangesetPublication, GateLease};
use apm2_core::orchestrator_kernel::{
    CompositeCursor, CursorEvent, CursorStore, EffectExecutionState, EffectJournal,
    ExecutionOutcome, InDoubtResolution, IntentStore, LedgerReader, OrchestratorDomain,
    ReceiptWriter, TickConfig, TickReport, run_tick,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::gate::{GateOrchestrator, GateOrchestratorEvent};
use crate::ledger::SqliteLedgerEventEmitter;
use crate::ledger_poll;
use crate::orchestrator_runtime::sqlite::{
    IntentKeyed, SqliteCursorStore, SqliteEffectJournal, SqliteIntentStore,
    init_orchestrator_runtime_schema,
};
use crate::orchestrator_runtime::{MemoryCursorStore, MemoryEffectJournal, MemoryIntentStore};
use crate::protocol::dispatch::{LedgerEventEmitter, SignedLedgerEvent};

const GATE_START_CURSOR_KEY: i64 = 1;
/// Durable namespace key for shared orchestrator runtime tables.
/// Changing this value resets durable cursor/intent/effect continuity.
const GATE_START_ORCHESTRATOR_ID: &str = "gate_start_kernel";
const GATE_START_EFFECT_JOURNAL_LEGACY_FILE: &str = "gate_start_effect_journal.sqlite";
const GATE_START_PERSISTOR_ACTOR_ID: &str = "orchestrator:gate-start-kernel";

/// Maximum payload size (in bytes) for `changeset_published` events before JSON
/// deserialization. Prevents denial-of-service via oversized `SQLite` payloads
/// (up to 1 GiB) exhausting daemon memory during `serde_json::from_slice`.
const MAX_PAYLOAD_BYTES: usize = 1_048_576; // 1 MiB

/// Detect whether a persisted cursor `event_id` is in the legacy gate-start
/// namespace format.
///
/// Legacy gate-start cursor rows were namespaced as `legacy:<event_id>` or
/// `canonical:<seq:020>`. The shared poller uses raw legacy IDs and canonical
/// IDs in the form `canonical-<seq:020>`.
fn is_legacy_cursor(event_id: &str) -> bool {
    event_id.starts_with("legacy:") || event_id.starts_with("canonical:")
}

fn normalize_legacy_cursor_event_id(event_id: &str) -> String {
    if let Some(raw) = event_id.strip_prefix("legacy:") {
        return raw.to_string();
    }
    if let Some(seq) = event_id.strip_prefix("canonical:") {
        return format!("canonical-{seq}");
    }
    event_id.to_string()
}

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
    sqlite_conn: Option<Arc<Mutex<Connection>>>,
    tick_config: TickConfig,
}

impl GateStartKernel {
    /// Creates a new gate-start kernel instance.
    pub async fn new_async(
        orchestrator: Arc<GateOrchestrator>,
        sqlite_conn: Option<&Arc<Mutex<Connection>>>,
        gate_start_ledger_emitter: Option<SqliteLedgerEventEmitter>,
        fac_root: &Path,
        config: GateStartKernelConfig,
    ) -> Result<Self, GateStartKernelError> {
        if let Some(conn) = sqlite_conn {
            std::fs::create_dir_all(fac_root).map_err(|e| {
                GateStartKernelError::Init(format!(
                    "failed to create FAC root '{}': {e}",
                    fac_root.display()
                ))
            })?;
            let conn = Arc::clone(conn);
            let legacy_journal_path = fac_root.join(GATE_START_EFFECT_JOURNAL_LEGACY_FILE);
            tokio::task::spawn_blocking(move || {
                let guard = conn.lock().map_err(|e| {
                    GateStartKernelError::Init(format!("sqlite lock poisoned: {e}"))
                })?;
                init_orchestrator_runtime_schema(&guard).map_err(GateStartKernelError::Init)?;
                drop(guard);
                migrate_legacy_gate_start_cursor(&conn).map_err(GateStartKernelError::Init)?;
                migrate_legacy_gate_start_intents(&conn).map_err(GateStartKernelError::Init)?;
                migrate_legacy_gate_start_effect_journal(&conn, &legacy_journal_path)
                    .map_err(GateStartKernelError::Init)?;
                Ok::<(), GateStartKernelError>(())
            })
            .await
            .map_err(|e| {
                GateStartKernelError::Init(format!("spawn_blocking join failed for init: {e}"))
            })??;
        }

        let cursor_store = sqlite_conn.map_or_else(
            || GateStartCursorStore::Memory(MemoryCursorStore::default()),
            |conn| {
                GateStartCursorStore::Sqlite(SqliteCursorStore::new(
                    Arc::clone(conn),
                    GATE_START_ORCHESTRATOR_ID,
                ))
            },
        );

        let intent_store = sqlite_conn.map_or_else(
            || GateStartIntentStore::Memory(MemoryIntentStore::default()),
            |conn| {
                GateStartIntentStore::Sqlite(SqliteIntentStore::new(
                    Arc::clone(conn),
                    GATE_START_ORCHESTRATOR_ID,
                ))
            },
        );

        let effect_journal = sqlite_conn.map_or_else(
            GateStartEffectJournal::new_memory,
            GateStartEffectJournal::new_shared,
        );

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
            sqlite_conn: sqlite_conn.map(Arc::clone),
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
        let Some(conn) = &self.sqlite_conn else {
            return Ok((0, 0));
        };
        let conn_for_intents = Arc::clone(conn);
        let intent_gc = tokio::task::spawn_blocking(move || {
            gc_shared_intents_before_with_conn(
                &conn_for_intents,
                GATE_START_ORCHESTRATOR_ID,
                cutoff_ns,
            )
        })
        .await
        .map_err(|e| {
            GateStartKernelError::Tick(format!("spawn_blocking failed for intent GC: {e}"))
        })?
        .map_err(GateStartKernelError::Tick)?;

        let conn_for_effect = Arc::clone(conn);
        let effect_gc = tokio::task::spawn_blocking(move || {
            gc_shared_effect_journal_before_with_conn(
                &conn_for_effect,
                GATE_START_ORCHESTRATOR_ID,
                cutoff_ns,
            )
        })
        .await
        .map_err(|e| {
            GateStartKernelError::Tick(format!("spawn_blocking failed for effect GC: {e}"))
        })?
        .map_err(GateStartKernelError::Tick)?;

        Ok((intent_gc, effect_gc))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateStartObservedEvent {
    timestamp_ns: u64,
    cursor_event_id: String,
    /// `None` when the row was present in the ledger but its payload was
    /// malformed and could not be parsed.  The event still carries valid
    /// cursor coordinates so the kernel advances past the defective row
    /// (preventing permanent deadlock).  A `DefectRecorded` is emitted at
    /// observe time for audit trail.
    publication: Option<ChangesetPublication>,
}

impl CursorEvent<CompositeCursor> for GateStartObservedEvent {
    fn cursor(&self) -> CompositeCursor {
        CompositeCursor {
            timestamp_ns: self.timestamp_ns,
            event_id: self.cursor_event_id.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GateStartIntent {
    publication: ChangesetPublication,
    /// Monotonic sequence number assigned when the intent is first observed,
    /// preserving ledger observation order across `plan()` calls.
    observed_seq: u64,
}

impl GateStartIntent {
    fn key(&self) -> String {
        gate_start_intent_key(
            &self.publication.work_id,
            &self.publication.changeset_digest,
        )
    }
}

impl IntentKeyed for GateStartIntent {
    fn intent_key(&self) -> String {
        self.key()
    }
}

impl Validate for GateStartIntent {
    fn validate(&self) -> Result<(), String> {
        if self.publication.work_id.is_empty() {
            return Err("GateStartIntent publication work_id must not be empty".to_string());
        }
        if self.publication.changeset_published_event_id.is_empty() {
            return Err(
                "GateStartIntent publication changeset_published_event_id must not be empty"
                    .to_string(),
            );
        }
        Ok(())
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
    /// Monotonic counter for preserving ledger observation order.
    next_observed_seq: u64,
}

impl GateStartDomain {
    fn new(orchestrator: Arc<GateOrchestrator>) -> Self {
        Self {
            orchestrator,
            pending_intents: HashMap::new(),
            next_observed_seq: 0,
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
            // Skip malformed rows — the cursor still advances past them
            // (the defect was already recorded at observe time).
            let Some(ref publication) = event.publication else {
                continue;
            };
            let seq = self.next_observed_seq;
            self.next_observed_seq = seq.saturating_add(1);
            let intent = GateStartIntent {
                publication: publication.clone(),
                observed_seq: seq,
            };
            self.pending_intents.insert(intent.key(), intent);
        }
        Ok(())
    }

    async fn plan(&mut self) -> Result<Vec<GateStartIntent>, Self::Error> {
        let mut intents: Vec<GateStartIntent> =
            self.pending_intents.drain().map(|(_, v)| v).collect();
        // Sort by ledger observation order, not by key.  This preserves the
        // deterministic ordering established by the cursor-driven poll, which
        // orders by (timestamp_ns, cursor_event_id).
        intents.sort_by_key(|i| i.observed_seq);
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
                            let Some(lease) =
                                self.orchestrator.gate_lease(work_id, *gate_type).await
                            else {
                                let defect = build_gate_start_defect(
                                    &intent.publication,
                                    &format!(
                                        "gate-start lease lookup failed (work_id={work_id}, gate_type={gate_type:?})",
                                    ),
                                    timestamp_ns,
                                );
                                receipts.push(GateStartReceipt::Defect {
                                    defect,
                                    timestamp_ns,
                                });
                                continue;
                            };
                            if lease.changeset_digest != intent.publication.changeset_digest {
                                let defect = build_gate_start_defect(
                                    &intent.publication,
                                    &format!(
                                        "gate-start lease digest mismatch (work_id={work_id}, gate_type={gate_type:?}, observed={}, expected={})",
                                        hex::encode(lease.changeset_digest),
                                        hex::encode(intent.publication.changeset_digest),
                                    ),
                                    timestamp_ns,
                                );
                                receipts.push(GateStartReceipt::Defect {
                                    defect,
                                    timestamp_ns,
                                });
                                continue;
                            }
                            receipts.push(GateStartReceipt::GateLeaseIssued {
                                lease: Box::new(lease),
                                timestamp_ns,
                            });
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
    type Cursor = CompositeCursor;
    type Error = String;

    async fn poll(
        &self,
        cursor: &CompositeCursor,
        limit: usize,
    ) -> Result<Vec<GateStartObservedEvent>, Self::Error> {
        match self {
            Self::Sqlite(reader) => reader.poll(cursor, limit).await,
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

    async fn poll(
        &self,
        cursor: &CompositeCursor,
        limit: usize,
    ) -> Result<Vec<GateStartObservedEvent>, String> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let cursor_ts_i64 = i64::try_from(cursor.timestamp_ns)
            .map_err(|_| "cursor timestamp exceeds i64 range".to_string())?;
        let signed = ledger_poll::poll_events_async(
            Arc::clone(&self.conn),
            vec!["changeset_published".to_string()],
            cursor_ts_i64,
            cursor.event_id.clone(),
            limit,
        )
        .await?;
        Ok(signed
            .into_iter()
            .map(map_signed_event_to_observed)
            .collect())
    }
}

#[derive(Debug)]
struct MemoryGateStartLedgerReader;

#[derive(Debug)]
enum GateStartCursorStore {
    Sqlite(SqliteCursorStore<CompositeCursor>),
    Memory(MemoryCursorStore<CompositeCursor>),
}

impl CursorStore<CompositeCursor> for GateStartCursorStore {
    type Error = String;

    async fn load(&self) -> Result<CompositeCursor, Self::Error> {
        match self {
            Self::Sqlite(store) => store.load().await,
            Self::Memory(store) => store.load().await,
        }
    }

    async fn save(&self, cursor: &CompositeCursor) -> Result<(), Self::Error> {
        match self {
            Self::Sqlite(store) => store.save(cursor).await,
            Self::Memory(store) => store.save(cursor).await,
        }
    }
}

#[cfg(test)]
#[derive(Debug)]
struct SqliteGateStartCursorStore {
    conn: Arc<Mutex<Connection>>,
}

#[cfg(test)]
impl SqliteGateStartCursorStore {
    fn new(conn: Arc<Mutex<Connection>>) -> Result<Self, String> {
        let guard = conn
            .lock()
            .map_err(|e| format!("cursor store lock poisoned: {e}"))?;
        init_orchestrator_runtime_schema(&guard)
            .map_err(|e| format!("failed to init shared orchestrator schema: {e}"))?;
        drop(guard);
        Ok(Self { conn })
    }

    /// Static `load` — callable from `spawn_blocking`.
    ///
    /// Migration safety: persisted legacy cursor IDs from pre-shared poller
    /// formats (`legacy:*` / `canonical:*`) are normalized to modern forms
    /// (`<legacy-event-id>` / `canonical-<seq:020>`) on load.
    fn load_with_conn(conn: &Arc<Mutex<Connection>>) -> Result<CompositeCursor, String> {
        let guard = conn
            .lock()
            .map_err(|e| format!("cursor store lock poisoned: {e}"))?;
        let row: Option<String> = guard
            .query_row(
                "SELECT cursor_json
                 FROM orchestrator_kernel_cursors
                 WHERE orchestrator_id = ?1",
                params![GATE_START_ORCHESTRATOR_ID],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| format!("failed to load gate-start cursor: {e}"))?;
        let Some(cursor_json) = row else {
            return Ok(CompositeCursor::default());
        };
        if cursor_json.len() > 65_536 {
            return Err(format!(
                "gate-start cursor json too large: {} bytes > 65536",
                cursor_json.len()
            ));
        }
        let mut cursor: CompositeCursor = serde_json::from_str(&cursor_json)
            .map_err(|e| format!("failed to decode gate-start cursor json: {e}"))?;
        if is_legacy_cursor(&cursor.event_id) {
            cursor.event_id = normalize_legacy_cursor_event_id(&cursor.event_id);
        }
        Ok(cursor)
    }

    /// Static `save` — callable from `spawn_blocking`.
    fn save_with_conn(
        conn: &Arc<Mutex<Connection>>,
        cursor: &CompositeCursor,
    ) -> Result<(), String> {
        let now_ns = epoch_now_ns_i64()?;
        let mut normalized = cursor.clone();
        if is_legacy_cursor(&normalized.event_id) {
            normalized.event_id = normalize_legacy_cursor_event_id(&normalized.event_id);
        }
        let cursor_json = serde_json::to_string(&normalized)
            .map_err(|e| format!("failed to encode gate-start cursor json: {e}"))?;
        if cursor_json.len() > 65_536 {
            return Err(format!(
                "gate-start cursor json too large to persist: {} bytes > 65536",
                cursor_json.len()
            ));
        }
        let guard = conn
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
                params![GATE_START_ORCHESTRATOR_ID, cursor_json, now_ns],
            )
            .map_err(|e| format!("failed to save gate-start cursor: {e}"))?;
        Ok(())
    }
}

#[derive(Debug)]
enum GateStartIntentStore {
    Sqlite(SqliteIntentStore<GateStartIntent>),
    Memory(MemoryIntentStore<GateStartIntent>),
}

impl IntentStore<GateStartIntent, String> for GateStartIntentStore {
    type Error = String;

    async fn enqueue_many(&self, intents: &[GateStartIntent]) -> Result<usize, Self::Error> {
        match self {
            Self::Sqlite(store) => store.enqueue_many(intents).await,
            Self::Memory(store) => store.enqueue_many(intents).await,
        }
    }

    async fn dequeue_batch(&self, limit: usize) -> Result<Vec<GateStartIntent>, Self::Error> {
        match self {
            Self::Sqlite(store) => store.dequeue_batch(limit).await,
            Self::Memory(store) => store.dequeue_batch(limit).await,
        }
    }

    async fn mark_done(&self, key: &String) -> Result<(), Self::Error> {
        match self {
            Self::Sqlite(store) => store.mark_done(key).await,
            Self::Memory(store) => store.mark_done(key).await,
        }
    }

    async fn mark_blocked(&self, key: &String, reason: &str) -> Result<(), Self::Error> {
        match self {
            Self::Sqlite(store) => store.mark_blocked(key, reason).await,
            Self::Memory(store) => store.mark_blocked(key, reason).await,
        }
    }

    async fn mark_retryable(&self, key: &String, reason: &str) -> Result<(), Self::Error> {
        match self {
            Self::Sqlite(store) => store.mark_retryable(key, reason).await,
            Self::Memory(store) => store.mark_retryable(key, reason).await,
        }
    }
}

#[cfg(test)]
#[derive(Debug)]
struct SqliteGateStartIntentStore {
    conn: Arc<Mutex<Connection>>,
}

#[cfg(test)]
impl SqliteGateStartIntentStore {
    fn new(conn: Arc<Mutex<Connection>>) -> Result<Self, String> {
        let guard = conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        init_orchestrator_runtime_schema(&guard)
            .map_err(|e| format!("failed to init shared orchestrator schema: {e}"))?;
        drop(guard);
        Ok(Self { conn })
    }

    /// Static `enqueue` — callable from `spawn_blocking`.
    ///
    /// Each intent is persisted with its `observed_seq` (ledger observation
    /// order). Dequeue ordering uses `observed_seq ASC, rowid ASC` to
    /// preserve deterministic publication order even when all intents in a
    /// batch share the same `created_at_ns` (Quality BLOCKER fix).
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
        for (idx, intent) in intents.iter().enumerate() {
            let key = intent.intent_key();
            let intent_json = serde_json::to_string(intent)
                .map_err(|e| format!("failed to encode gate-start intent json: {e}"))?;
            let created_at_ns = now_ns.saturating_add(i64::try_from(idx).unwrap_or(i64::MAX));
            let rows = tx
                .execute(
                    "INSERT OR IGNORE INTO orchestrator_kernel_intents
                        (orchestrator_id, intent_key, intent_json, state,
                         created_at_ns, updated_at_ns, blocked_reason)
                     VALUES (?1, ?2, ?3, 'pending', ?4, ?5, NULL)",
                    params![
                        GATE_START_ORCHESTRATOR_ID,
                        key,
                        intent_json,
                        created_at_ns,
                        now_ns
                    ],
                )
                .map_err(|e| format!("failed to enqueue gate-start intent: {e}"))?;
            inserted = inserted.saturating_add(rows);
        }
        tx.commit()
            .map_err(|e| format!("failed to commit gate-start intent transaction: {e}"))?;
        Ok(inserted)
    }

    /// Static `dequeue` — callable from `spawn_blocking`.
    ///
    /// Dequeues pending intents in deterministic ledger observation order
    /// (`observed_seq ASC, rowid ASC`). The `rowid` tiebreaker handles
    /// pre-migration rows that all have `observed_seq=0` and provides a
    /// stable secondary ordering within the same sequence number.
    ///
    /// # Quality BLOCKER fix
    ///
    /// Previously ordered by `created_at_ns ASC, intent_key ASC`, which
    /// shared one timestamp across the whole batch and fell back to
    /// lexical key order. Two same-work publications could be reordered
    /// when their digest lexical order differed from publish order,
    /// causing `start_for_publication` to supersede with an older digest.
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
                "SELECT intent_json
                 FROM orchestrator_kernel_intents
                 WHERE orchestrator_id = ?1 AND state = 'pending'
                 ORDER BY created_at_ns ASC, intent_key ASC
                 LIMIT ?2",
            )
            .map_err(|e| format!("failed to prepare gate-start dequeue query: {e}"))?;
        let rows = stmt
            .query_map(params![GATE_START_ORCHESTRATOR_ID, limit_i64], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|e| format!("failed to query gate-start intents: {e}"))?;

        let mut intents = Vec::new();
        for row in rows {
            let intent_json =
                row.map_err(|e| format!("failed to decode gate-start intent row: {e}"))?;
            // Defense-in-depth: enforce size limit on stored intent payloads.
            if intent_json.len() > MAX_PAYLOAD_BYTES {
                return Err(format!(
                    "gate-start intent payload too large: {} bytes > {} max",
                    intent_json.len(),
                    MAX_PAYLOAD_BYTES
                ));
            }
            let intent: GateStartIntent = serde_json::from_str(&intent_json)
                .map_err(|e| format!("failed to decode gate-start intent json: {e}"))?;
            intent
                .validate()
                .map_err(|e| format!("invalid gate-start intent from sqlite: {e}"))?;
            intents.push(intent);
        }
        Ok(intents)
    }

    /// Static `mark_done` — callable from `spawn_blocking`.
    ///
    /// Retains the intent row with `state = 'completed'` and an updated
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
                "UPDATE orchestrator_kernel_intents
                 SET state = 'completed', blocked_reason = NULL, updated_at_ns = ?3
                 WHERE orchestrator_id = ?1 AND intent_key = ?2",
                params![GATE_START_ORCHESTRATOR_ID, key, now_ns],
            )
            .map_err(|e| format!("failed to mark gate-start intent done: {e}"))?;
        Ok(())
    }

    /// Deletes completed intent rows older than `cutoff_ns` (TTL-bounded GC).
    ///
    /// This is NOT part of the hot path — it runs infrequently to reclaim
    /// space without breaking restart idempotency.
    #[cfg(test)]
    pub(crate) fn gc_completed_before_with_conn(
        conn: &Arc<Mutex<Connection>>,
        cutoff_ns: i64,
    ) -> Result<usize, String> {
        let guard = conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        let deleted = guard
            .execute(
                "DELETE FROM orchestrator_kernel_intents
                 WHERE orchestrator_id = ?1 AND state = 'completed' AND updated_at_ns < ?2",
                params![GATE_START_ORCHESTRATOR_ID, cutoff_ns],
            )
            .map_err(|e| format!("failed to gc completed gate-start intents: {e}"))?;
        Ok(deleted)
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

#[cfg(test)]
#[derive(Debug, Default)]
struct MemoryGateStartIntentStore {
    pending: Mutex<VecDeque<GateStartIntent>>,
    states: Mutex<HashMap<String, String>>,
    intents: Mutex<HashMap<String, GateStartIntent>>,
}

#[cfg(test)]
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
}

#[derive(Debug)]
struct GateStartEffectJournal {
    inner: GateStartEffectJournalInner,
    #[cfg(test)]
    conn: Arc<Mutex<Connection>>,
}

#[derive(Debug)]
enum GateStartEffectJournalInner {
    Sqlite(SqliteEffectJournal),
    Memory(MemoryEffectJournal),
}

impl GateStartEffectJournal {
    #[cfg(test)]
    fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path)
            .map_err(|e| format!("failed to open gate-start effect journal db: {e}"))?;
        init_orchestrator_runtime_schema(&conn)
            .map_err(|e| format!("failed to init shared orchestrator schema: {e}"))?;
        let conn = Arc::new(Mutex::new(conn));
        Ok(Self::new_shared(&conn))
    }

    fn new_shared(conn: &Arc<Mutex<Connection>>) -> Self {
        Self {
            inner: GateStartEffectJournalInner::Sqlite(SqliteEffectJournal::new(
                Arc::clone(conn),
                GATE_START_ORCHESTRATOR_ID,
            )),
            #[cfg(test)]
            conn: Arc::clone(conn),
        }
    }

    fn new_memory() -> Self {
        let conn = Connection::open_in_memory().expect("memory effect journal db should open");
        init_orchestrator_runtime_schema(&conn)
            .expect("memory effect journal schema init should succeed");
        Self {
            inner: GateStartEffectJournalInner::Memory(MemoryEffectJournal::new()),
            #[cfg(test)]
            conn: Arc::new(Mutex::new(conn)),
        }
    }

    /// Static `load` — callable from `spawn_blocking`.
    #[cfg(test)]
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
                 FROM orchestrator_kernel_effect_journal
                 WHERE orchestrator_id = ?1 AND intent_key = ?2",
                params![GATE_START_ORCHESTRATOR_ID, key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("failed to load gate-start effect state for key '{key}': {e}"))
    }

    /// Static `upsert` — callable from `spawn_blocking`.
    #[cfg(test)]
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
                "INSERT INTO orchestrator_kernel_effect_journal
                     (orchestrator_id, intent_key, state, updated_at_ns)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(orchestrator_id, intent_key) DO UPDATE SET
                     state = excluded.state,
                     updated_at_ns = excluded.updated_at_ns",
                params![GATE_START_ORCHESTRATOR_ID, key, state, updated_at_ns],
            )
            .map_err(|e| {
                format!("failed to upsert gate-start effect state='{state}' for key '{key}': {e}")
            })?;
        Ok(())
    }

    /// Deletes completed effect journal rows older than `cutoff_ns`
    /// (TTL-bounded GC). Not part of the hot path.
    #[cfg(test)]
    pub(crate) fn gc_completed_before_with_conn(
        conn: &Arc<Mutex<Connection>>,
        cutoff_ns: i64,
    ) -> Result<usize, String> {
        let guard = conn
            .lock()
            .map_err(|e| format!("gate-start effect journal lock poisoned: {e}"))?;
        let deleted = guard
            .execute(
                "DELETE FROM orchestrator_kernel_effect_journal
                 WHERE orchestrator_id = ?1 AND state = 'completed' AND updated_at_ns < ?2",
                params![GATE_START_ORCHESTRATOR_ID, cutoff_ns],
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
        match &self.inner {
            GateStartEffectJournalInner::Sqlite(j) => j.query_state(key).await,
            GateStartEffectJournalInner::Memory(j) => j.query_state(key).await,
        }
    }

    async fn record_started(&self, key: &String) -> Result<(), Self::Error> {
        match &self.inner {
            GateStartEffectJournalInner::Sqlite(j) => j.record_started(key).await,
            GateStartEffectJournalInner::Memory(j) => j.record_started(key).await,
        }
    }

    async fn record_completed(&self, key: &String) -> Result<(), Self::Error> {
        match &self.inner {
            GateStartEffectJournalInner::Sqlite(j) => j.record_completed(key).await,
            GateStartEffectJournalInner::Memory(j) => j.record_completed(key).await,
        }
    }

    async fn record_retryable(&self, key: &String) -> Result<(), Self::Error> {
        match &self.inner {
            GateStartEffectJournalInner::Sqlite(j) => j.record_retryable(key).await,
            GateStartEffectJournalInner::Memory(j) => j.record_retryable(key).await,
        }
    }

    async fn resolve_in_doubt(&self, key: &String) -> Result<InDoubtResolution, Self::Error> {
        match &self.inner {
            GateStartEffectJournalInner::Sqlite(j) => j.resolve_in_doubt(key).await,
            GateStartEffectJournalInner::Memory(j) => j.resolve_in_doubt(key).await,
        }
    }
}

fn map_signed_event_to_observed(event: SignedLedgerEvent) -> GateStartObservedEvent {
    let publication = match parse_changeset_publication_payload(
        &event.payload,
        event.timestamp_ns,
        &event.event_id,
        &event.actor_id,
        &event.work_id,
    ) {
        Ok(pub_ok) => Some(pub_ok),
        Err(parse_err) => {
            tracing::error!(
                cursor_event_id = %event.event_id,
                payload_len = event.payload.len(),
                error = %parse_err,
                "DEFECT: malformed changeset_published row skipped (cursor will advance past it)"
            );
            None
        },
    };

    GateStartObservedEvent {
        timestamp_ns: event.timestamp_ns,
        cursor_event_id: event.event_id,
        publication,
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
    ///
    /// # Session ID binding
    ///
    /// Events are emitted under the actual `work_id` from the orchestrator
    /// event or lease as the ledger `session_id`. The canonical `events` table
    /// uses `session_id` as the work-item binding (the `WorkReducer` treats
    /// `session_id` as `work_id`), so a hardcoded session ID would cause all
    /// gate events to be attributed to the wrong work item and rejected.
    fn persist_many_sync(
        emitter: &SqliteLedgerEventEmitter,
        receipts: &[GateStartReceipt],
    ) -> Result<(), String> {
        for receipt in receipts {
            match receipt {
                GateStartReceipt::OrchestratorEvent(event) => {
                    let (event_type, timestamp_ns) = gate_start_event_persistence_fields(event);
                    // Use the actual work_id from the event as the session_id
                    // (Security BLOCKER fix: replaces hardcoded
                    // GATE_START_PERSISTOR_SESSION_ID).
                    let session_id = event.work_id();
                    let payload = serde_json::to_vec(event).map_err(|e| {
                        format!("failed to serialize gate-start orchestrator event: {e}")
                    })?;
                    emitter
                        .emit_session_event(
                            session_id,
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
                    // Use the actual work_id from the lease as the session_id
                    // (Security BLOCKER fix: replaces hardcoded
                    // GATE_START_PERSISTOR_SESSION_ID).
                    emitter
                        .emit_session_event(
                            &lease.work_id,
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

/// Parse and validate a `changeset_published` payload from the ledger.
///
/// # Security
///
/// - `verified_actor_id` is the envelope `actor_id` from the ledger row
///   (mandatory NOT NULL column in both tables). Cross-validated against the
///   payload's `actor_id` when present.
/// - `verified_work_id` is the envelope `work_id`/`session_id` from the ledger
///   row. Cross-validated against the payload's `work_id` to prevent cross-work
///   identity spoofing.
/// - Both are fail-closed: mismatches are rejected.
fn parse_changeset_publication_payload(
    payload: &[u8],
    fallback_timestamp_ns: u64,
    event_id: &str,
    verified_actor_id: &str,
    verified_work_id: &str,
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
    let payload_work_id = payload_json
        .get("work_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "changeset_published payload missing work_id".to_string())?;

    // Security BLOCKER (fail-closed): Cross-validate payload work_id against
    // the verified envelope work_id/session_id from the ledger row.
    //
    // The `verified_work_id` comes from the ledger row's envelope identity
    // column (`work_id` for legacy table, `session_id` for canonical table).
    // Both columns are NOT NULL, so an empty string indicates a suspicious or
    // corrupt envelope — reject rather than fall back to the untrusted payload.
    if verified_work_id.is_empty() {
        return Err(format!(
            "changeset_published rejected: verified_work_id is empty in ledger envelope \
             (fail-closed, event_id={event_id}, payload_work_id='{payload_work_id}')"
        ));
    }
    if payload_work_id != verified_work_id {
        return Err(format!(
            "changeset_published work_id spoofing: payload work_id '{payload_work_id}' \
             does not match verified ledger work_id '{verified_work_id}' \
             (event_id={event_id})"
        ));
    }

    let changeset_digest_hex = payload_json
        .get("changeset_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "changeset_published payload missing changeset_digest".to_string())?;
    let cas_hash_hex = payload_json
        .get("cas_hash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "changeset_published payload missing cas_hash".to_string())?;

    // Security MINOR fix: Require verified_actor_id to be present (fail-closed).
    // No fallback to payload actor_id — if the verified actor_id is empty,
    // reject the event.
    if verified_actor_id.is_empty() {
        return Err(format!(
            "changeset_published missing verified_actor_id (fail-closed, event_id={event_id})"
        ));
    }

    // Cross-validate: if the payload also declares an actor_id that
    // differs from the verified one, reject as spoofing attempt.
    let payload_actor_id = payload_json
        .get("actor_id")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty());
    if let Some(payload_aid) = payload_actor_id {
        if payload_aid != verified_actor_id {
            return Err(format!(
                "changeset_published identity spoofing: payload actor_id '{payload_aid}' \
                 does not match verified ledger actor_id '{verified_actor_id}' \
                 (event_id={event_id})"
            ));
        }
    }

    let published_at_ns = payload_json
        .get("timestamp_ns")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(fallback_timestamp_ns);
    let cs_payload = ChangeSetPublishedKernelEventPayload {
        work_id: payload_work_id.to_string(),
        changeset_digest: decode_hex_32(changeset_digest_hex)?,
        cas_hash: decode_hex_32(cas_hash_hex)?,
        published_at_ns,
        publisher_actor_id: verified_actor_id.to_string(),
        event_id: event_id.to_string(),
    };
    ChangesetPublication::try_from(cs_payload).map_err(|e| {
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
    let cas_hash = apm2_core::work::hash_defect_preimage(
        publication.work_id.as_bytes(),
        &publication.changeset_digest,
        reason.as_bytes(),
    );

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

fn sqlite_table_exists(conn: &Connection, table_name: &str) -> Result<bool, String> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1 LIMIT 1",
            params![table_name],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| format!("failed to detect table '{table_name}': {e}"))?;
    Ok(exists.is_some())
}

fn migrate_legacy_gate_start_cursor(conn: &Arc<Mutex<Connection>>) -> Result<(), String> {
    let guard = conn
        .lock()
        .map_err(|e| format!("cursor migration lock poisoned: {e}"))?;

    if !sqlite_table_exists(&guard, "gate_start_kernel_cursor")? {
        return Ok(());
    }

    let already_migrated: i64 = guard
        .query_row(
            "SELECT COUNT(*) FROM orchestrator_kernel_cursors WHERE orchestrator_id = ?1",
            params![GATE_START_ORCHESTRATOR_ID],
            |row| row.get(0),
        )
        .map_err(|e| format!("failed to count shared cursor rows: {e}"))?;
    if already_migrated > 0 {
        return Ok(());
    }

    let legacy_row: Option<(i64, String)> = guard
        .query_row(
            "SELECT timestamp_ns, event_id
             FROM gate_start_kernel_cursor
             WHERE cursor_key = ?1",
            params![GATE_START_CURSOR_KEY],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| format!("failed to read legacy gate-start cursor row: {e}"))?;

    let Some((timestamp_ns_i64, event_id_raw)) = legacy_row else {
        return Ok(());
    };

    let mut event_id = event_id_raw;
    if is_legacy_cursor(&event_id) {
        event_id = normalize_legacy_cursor_event_id(&event_id);
    }
    let timestamp_ns = u64::try_from(timestamp_ns_i64).unwrap_or(0);
    let cursor_json = serde_json::to_string(&CompositeCursor {
        timestamp_ns,
        event_id,
    })
    .map_err(|e| format!("failed to encode shared gate-start cursor json: {e}"))?;
    let now_ns = epoch_now_ns_i64()?;

    guard
        .execute(
            "INSERT OR IGNORE INTO orchestrator_kernel_cursors
                 (orchestrator_id, cursor_json, updated_at_ns)
             VALUES (?1, ?2, ?3)",
            params![GATE_START_ORCHESTRATOR_ID, cursor_json, now_ns],
        )
        .map_err(|e| format!("failed to migrate legacy gate-start cursor: {e}"))?;
    Ok(())
}

fn migrate_legacy_gate_start_intents(conn: &Arc<Mutex<Connection>>) -> Result<(), String> {
    let guard = conn
        .lock()
        .map_err(|e| format!("intent migration lock poisoned: {e}"))?;

    if !sqlite_table_exists(&guard, "gate_start_intents")? {
        return Ok(());
    }

    let already_migrated: i64 = guard
        .query_row(
            "SELECT COUNT(*) FROM orchestrator_kernel_intents WHERE orchestrator_id = ?1",
            params![GATE_START_ORCHESTRATOR_ID],
            |row| row.get(0),
        )
        .map_err(|e| format!("failed to count shared gate-start intents: {e}"))?;
    if already_migrated > 0 {
        return Ok(());
    }

    let has_observed_seq = {
        let mut stmt = guard
            .prepare("PRAGMA table_info(gate_start_intents)")
            .map_err(|e| format!("failed to inspect gate_start_intents schema: {e}"))?;
        let cols = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|e| format!("failed to enumerate gate_start_intents columns: {e}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("failed to decode gate_start_intents columns: {e}"))?;
        cols.iter().any(|c| c == "observed_seq")
    };

    let query = if has_observed_seq {
        "SELECT intent_key, publication_json, state, blocked_reason,
                created_at_ns, updated_at_ns, observed_seq
         FROM gate_start_intents
         ORDER BY observed_seq ASC, created_at_ns ASC, intent_key ASC"
    } else {
        "SELECT intent_key, publication_json, state, blocked_reason,
                created_at_ns, updated_at_ns, 0 AS observed_seq
         FROM gate_start_intents
         ORDER BY created_at_ns ASC, intent_key ASC"
    };

    let mut stmt = guard
        .prepare(query)
        .map_err(|e| format!("failed to prepare legacy gate_start_intents query: {e}"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .map_err(|e| format!("failed to read legacy gate_start_intents rows: {e}"))?;

    let mut migrated_rows: Vec<(String, String, String, Option<String>, i64, i64)> = Vec::new();
    for row in rows {
        let (
            _intent_key,
            publication_json,
            legacy_state,
            blocked_reason,
            created_at_ns,
            updated_at_ns,
            observed_seq_i64,
        ) = row.map_err(|e| format!("failed to decode legacy gate_start_intents row: {e}"))?;
        let publication: ChangesetPublication = serde_json::from_str(&publication_json)
            .map_err(|e| format!("failed to decode legacy gate-start publication json: {e}"))?;
        let observed_seq = u64::try_from(observed_seq_i64).unwrap_or(0);
        let intent = GateStartIntent {
            publication,
            observed_seq,
        };
        let intent_key = intent.intent_key();
        let intent_json = serde_json::to_string(&intent)
            .map_err(|e| format!("failed to encode migrated gate-start intent json: {e}"))?;
        let state = match legacy_state.as_str() {
            "done" | "completed" => "completed",
            "blocked" => "blocked",
            _ => "pending",
        }
        .to_string();
        migrated_rows.push((
            intent_key,
            intent_json,
            state,
            blocked_reason,
            created_at_ns.max(0),
            updated_at_ns.max(0),
        ));
    }
    drop(stmt);

    let tx = guard
        .unchecked_transaction()
        .map_err(|e| format!("failed to open migration transaction for gate-start intents: {e}"))?;
    for (intent_key, intent_json, state, blocked_reason, created_at_ns, updated_at_ns) in
        migrated_rows
    {
        tx.execute(
            "INSERT OR IGNORE INTO orchestrator_kernel_intents
                (orchestrator_id, intent_key, intent_json, state,
                 created_at_ns, updated_at_ns, blocked_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                GATE_START_ORCHESTRATOR_ID,
                intent_key,
                intent_json,
                state,
                created_at_ns,
                updated_at_ns,
                blocked_reason
            ],
        )
        .map_err(|e| format!("failed to migrate legacy gate-start intent row: {e}"))?;
    }
    tx.commit()
        .map_err(|e| format!("failed to commit legacy gate-start intent migration: {e}"))?;
    Ok(())
}

fn migrate_legacy_gate_start_effect_journal(
    conn: &Arc<Mutex<Connection>>,
    legacy_journal_path: &Path,
) -> Result<(), String> {
    if !legacy_journal_path.exists() {
        return Ok(());
    }

    let guard = conn
        .lock()
        .map_err(|e| format!("effect journal migration lock poisoned: {e}"))?;
    let already_migrated: i64 = guard
        .query_row(
            "SELECT COUNT(*) FROM orchestrator_kernel_effect_journal WHERE orchestrator_id = ?1",
            params![GATE_START_ORCHESTRATOR_ID],
            |row| row.get(0),
        )
        .map_err(|e| format!("failed to count shared gate-start effect rows: {e}"))?;
    if already_migrated > 0 {
        return Ok(());
    }

    let legacy_conn = Connection::open(legacy_journal_path)
        .map_err(|e| format!("failed to open legacy gate-start effect journal: {e}"))?;
    if !sqlite_table_exists(&legacy_conn, "gate_start_effect_journal_state")? {
        return Ok(());
    }

    let mut legacy_stmt = legacy_conn
        .prepare(
            "SELECT intent_key, state, updated_at_ns
             FROM gate_start_effect_journal_state",
        )
        .map_err(|e| format!("failed to prepare legacy gate-start effect query: {e}"))?;
    let rows = legacy_stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|e| format!("failed to iterate legacy gate-start effect rows: {e}"))?;

    let tx = guard.unchecked_transaction().map_err(|e| {
        format!("failed to open shared effect migration transaction for gate-start: {e}")
    })?;
    for row in rows {
        let (intent_key, legacy_state, updated_at_ns) =
            row.map_err(|e| format!("failed to decode legacy gate-start effect row: {e}"))?;
        let state = match legacy_state.as_str() {
            "completed" => "completed",
            _ => "unknown",
        };
        tx.execute(
            "INSERT OR IGNORE INTO orchestrator_kernel_effect_journal
                (orchestrator_id, intent_key, state, updated_at_ns)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                GATE_START_ORCHESTRATOR_ID,
                intent_key,
                state,
                updated_at_ns.max(0)
            ],
        )
        .map_err(|e| format!("failed to migrate gate-start effect row: {e}"))?;
    }
    tx.commit()
        .map_err(|e| format!("failed to commit gate-start effect migration: {e}"))?;
    drop(guard);

    let migrated_path =
        std::path::PathBuf::from(format!("{}.migrated", legacy_journal_path.display()));
    if let Err(e) = std::fs::rename(legacy_journal_path, &migrated_path) {
        tracing::warn!(
            path = %legacy_journal_path.display(),
            error = %e,
            "gate-start: failed to rename legacy effect journal after migration"
        );
    }

    Ok(())
}

fn gc_shared_intents_before_with_conn(
    conn: &Arc<Mutex<Connection>>,
    orchestrator_id: &str,
    cutoff_ns: i64,
) -> Result<usize, String> {
    let guard = conn
        .lock()
        .map_err(|e| format!("intent GC lock poisoned: {e}"))?;
    let deleted = guard
        .execute(
            "DELETE FROM orchestrator_kernel_intents
             WHERE orchestrator_id = ?1 AND state = 'completed' AND updated_at_ns < ?2",
            params![orchestrator_id, cutoff_ns],
        )
        .map_err(|e| format!("failed to GC shared orchestrator intents: {e}"))?;
    Ok(deleted)
}

fn gc_shared_effect_journal_before_with_conn(
    conn: &Arc<Mutex<Connection>>,
    orchestrator_id: &str,
    cutoff_ns: i64,
) -> Result<usize, String> {
    let guard = conn
        .lock()
        .map_err(|e| format!("effect journal GC lock poisoned: {e}"))?;
    let deleted = guard
        .execute(
            "DELETE FROM orchestrator_kernel_effect_journal
             WHERE orchestrator_id = ?1 AND state = 'completed' AND updated_at_ns < ?2",
            params![orchestrator_id, cutoff_ns],
        )
        .map_err(|e| format!("failed to GC shared effect journal rows: {e}"))?;
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use apm2_core::orchestrator_kernel::CompositeCursor;
    use rusqlite::Connection;
    use serde_json::json;

    use super::{SqliteGateStartLedgerReader, gate_start_intent_key, is_legacy_cursor};

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
                        work_id TEXT NOT NULL DEFAULT '',
                        payload BLOB NOT NULL,
                        signature BLOB NOT NULL DEFAULT X'',
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
                        session_id TEXT NOT NULL DEFAULT '',
                        payload BLOB NOT NULL,
                        signature BLOB,
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
                    "INSERT INTO ledger_events (event_id, event_type, actor_id, work_id, payload, timestamp_ns)
                     VALUES (?1, 'changeset_published', ?2, ?3, ?4, ?5)",
                    rusqlite::params!["z-legacy", "actor:legacy", "work-legacy", legacy_payload, ts],
                )
                .expect("insert legacy changeset");
            guard
                .execute(
                    "INSERT INTO events (event_type, actor_id, session_id, payload, timestamp_ns)
                     VALUES ('changeset_published', ?1, ?2, ?3, ?4)",
                    rusqlite::params!["actor:canonical", "work-canonical", canonical_payload, ts],
                )
                .expect("insert canonical changeset");
        }

        let reader = SqliteGateStartLedgerReader::new(Arc::clone(&conn));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");
        let first = rt
            .block_on(reader.poll(&CompositeCursor::default(), 1))
            .expect("first poll should succeed");
        assert_eq!(first.len(), 1);
        let first_work_id = first[0]
            .publication
            .as_ref()
            .expect("valid publication")
            .work_id
            .clone();

        let cursor = CompositeCursor {
            timestamp_ns: first[0].timestamp_ns,
            event_id: first[0].cursor_event_id.clone(),
        };
        let second = rt
            .block_on(reader.poll(&cursor, 10))
            .expect("second poll should succeed");
        assert_eq!(second.len(), 1);
        let second_work_id = second[0]
            .publication
            .as_ref()
            .expect("valid publication")
            .work_id
            .clone();

        assert_ne!(
            first_work_id, second_work_id,
            "second poll must return the other event at same timestamp"
        );
        let mut observed = vec![first_work_id, second_work_id];
        observed.sort();
        assert_eq!(
            observed,
            vec!["work-canonical".to_string(), "work-legacy".to_string()],
            "cursor progression must return both rows without skip"
        );
    }

    #[test]
    fn oversized_payload_rejected_before_deserialization() {
        use super::{MAX_PAYLOAD_BYTES, parse_changeset_publication_payload};

        // Create a payload just over the limit
        let oversized = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let result =
            parse_changeset_publication_payload(&oversized, 0, "test-event", "actor:test", "W-1");
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
        let result =
            parse_changeset_publication_payload(&small_valid, 0, "test-event", "actor:test", "W-1");
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
            "actor:legitimate",
            "W-1",
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
            parse_changeset_publication_payload(&payload, 0, "test-event", "actor:real", "W-1");
        assert!(
            result.is_ok(),
            "matching verified actor_id should succeed: {result:?}"
        );
        let pub_result = result.unwrap();
        assert_eq!(pub_result.publisher_actor_id, "actor:real");
    }

    /// When the ledger envelope `verified_work_id` is empty, the event
    /// must be rejected (fail-closed) rather than falling back to the
    /// untrusted payload `work_id`.
    #[test]
    fn empty_verified_work_id_rejected_fail_closed() {
        use super::parse_changeset_publication_payload;

        let payload = serde_json::to_vec(&json!({
            "work_id": "W-1",
            "changeset_digest": hex::encode([0x01; 32]),
            "cas_hash": hex::encode([0x02; 32]),
            "timestamp_ns": 123_456_789_u64,
        }))
        .expect("serialize payload");

        // Empty verified_work_id — should be rejected, not fall-open.
        let result =
            parse_changeset_publication_payload(&payload, 0, "test-event", "actor:test", "");
        assert!(
            result.is_err(),
            "empty verified_work_id must be rejected (fail-closed)"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("verified_work_id is empty"),
            "error should mention empty verified_work_id, got: {err}"
        );
    }

    /// CSID-003 restart-safe idempotency: after marking N intents done, the
    /// `SQLite` intent table must retain the row with `state = 'completed'` so
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
            observed_seq: 0,
        };

        // Enqueue and verify it exists.
        let inserted = store.enqueue_many(&[intent]).expect("enqueue");
        assert_eq!(inserted, 1, "one intent should be inserted");
        let pending = store.dequeue_batch(10).expect("dequeue");
        assert_eq!(pending.len(), 1, "one intent should be pending");

        // Mark done — must UPDATE to 'completed', not DELETE.
        let key = super::gate_start_intent_key(&publication.work_id, &publication.changeset_digest);
        store.mark_done(&key).expect("mark done");

        // Verify: the row exists with state = 'completed'.
        {
            let guard = conn.lock().expect("lock");
            let (count, state): (i64, String) = guard
                .query_row(
                    "SELECT COUNT(*), state FROM orchestrator_kernel_intents
                     WHERE orchestrator_id = ?1 AND intent_key = ?2",
                    rusqlite::params![super::GATE_START_ORCHESTRATOR_ID, key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .expect("query done intent");
            assert_eq!(count, 1, "intent row must be retained after mark_done");
            assert_eq!(
                state, "completed",
                "intent state must be 'completed' after mark_done"
            );
        }
        // guard dropped — subsequent store methods can acquire the lock.

        // A second enqueue for the same key must be treated as duplicate.
        let intent2 = super::GateStartIntent {
            publication,
            observed_seq: 0,
        };
        let inserted2 = store.enqueue_many(&[intent2]).expect("re-enqueue");
        assert_eq!(
            inserted2, 0,
            "re-enqueue of done intent must be treated as duplicate"
        );

        // Dequeue must return 0 pending (completed rows are not pending).
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
            .query_row(
                "SELECT COUNT(*) FROM orchestrator_kernel_intents
                 WHERE orchestrator_id = ?1",
                rusqlite::params![super::GATE_START_ORCHESTRATOR_ID],
                |r| r.get(0),
            )
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
            observed_seq: 0,
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
        let intent2 = super::GateStartIntent {
            publication,
            observed_seq: 0,
        };
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
                "SELECT COUNT(*) FROM orchestrator_kernel_effect_journal
                 WHERE orchestrator_id = ?1",
                rusqlite::params![super::GATE_START_ORCHESTRATOR_ID],
                |r| r.get(0),
            )
            .expect("count query");
        assert_eq!(
            count_after_gc, 0,
            "effect journal table must be empty after GC"
        );
    }

    /// Tests for `is_legacy_cursor` — cursor format detection for migration
    /// safety. Legacy cursors are old prefixed forms (`legacy:*` and
    /// `canonical:*`).
    #[test]
    fn is_legacy_cursor_rejects_raw_event_ids() {
        // Raw event IDs are current shared-poller format and are not legacy.
        assert!(
            !is_legacy_cursor("evt-12345"),
            "raw event ID without prefix is not legacy"
        );
        assert!(
            !is_legacy_cursor("a-legacy"),
            "raw event ID 'a-legacy' is not legacy"
        );
        assert!(
            !is_legacy_cursor("uuid-style-event-id-abc"),
            "UUID-style raw event ID is not legacy"
        );
    }

    #[test]
    fn is_legacy_cursor_detects_namespaced_cursors() {
        // Old prefixed cursors are legacy and must be normalized.
        assert!(
            is_legacy_cursor("legacy:evt-12345"),
            "'legacy:' prefixed cursor is legacy"
        );
        assert!(
            is_legacy_cursor("canonical:00000000000000000001"),
            "'canonical:' prefixed cursor is legacy"
        );
    }

    #[test]
    fn is_legacy_cursor_empty_is_not_legacy() {
        // Empty string is the default (no cursor persisted yet), not legacy.
        assert!(
            !is_legacy_cursor(""),
            "empty event_id is not legacy (it is the default)"
        );
    }

    /// Raw cursor IDs are current shared-poller format and should be loaded
    /// without rewriting to default.
    #[test]
    fn sqlite_cursor_store_preserves_raw_cursor_ids() {
        use super::SqliteGateStartCursorStore;

        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("open in-memory sqlite"),
        ));
        let store = SqliteGateStartCursorStore::new(Arc::clone(&conn)).expect("init cursor store");

        let raw_cursor = CompositeCursor {
            timestamp_ns: 1_706_000_000_000_000_000,
            event_id: "raw-event-id-from-v1".to_string(),
        };
        SqliteGateStartCursorStore::save_with_conn(&store.conn, &raw_cursor)
            .expect("save raw cursor");

        // Load preserves raw cursor IDs as-is.
        let loaded =
            SqliteGateStartCursorStore::load_with_conn(&store.conn).expect("load should succeed");
        assert_eq!(loaded, raw_cursor, "raw cursor IDs should be preserved");
    }

    /// Verify that a cursor with the `legacy:` prefix is normalized to the
    /// shared-poller legacy event-id format (prefix removed).
    #[test]
    fn sqlite_cursor_store_normalizes_legacy_prefixed_cursor() {
        use super::SqliteGateStartCursorStore;

        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("open in-memory sqlite"),
        ));
        let store = SqliteGateStartCursorStore::new(Arc::clone(&conn)).expect("init cursor store");

        let valid_cursor = CompositeCursor {
            timestamp_ns: 1_706_000_000_000_000_000,
            event_id: "legacy:evt-12345".to_string(),
        };
        SqliteGateStartCursorStore::save_with_conn(&store.conn, &valid_cursor)
            .expect("save valid cursor");

        let loaded =
            SqliteGateStartCursorStore::load_with_conn(&store.conn).expect("load should succeed");
        assert_eq!(
            loaded.timestamp_ns, valid_cursor.timestamp_ns,
            "timestamp_ns must be preserved for valid cursor"
        );
        assert_eq!(
            loaded.event_id, "evt-12345",
            "legacy-prefixed event_id must be normalized to raw legacy event_id"
        );
    }

    /// Verify that a cursor with the `canonical:` prefix is normalized to
    /// `canonical-<seq:020>`.
    #[test]
    fn sqlite_cursor_store_normalizes_canonical_prefixed_cursor() {
        use super::SqliteGateStartCursorStore;

        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("open in-memory sqlite"),
        ));
        let store = SqliteGateStartCursorStore::new(Arc::clone(&conn)).expect("init cursor store");

        let valid_cursor = CompositeCursor {
            timestamp_ns: 1_706_000_000_000_000_000,
            event_id: "canonical:00000000000000000042".to_string(),
        };
        SqliteGateStartCursorStore::save_with_conn(&store.conn, &valid_cursor)
            .expect("save valid cursor");

        let loaded =
            SqliteGateStartCursorStore::load_with_conn(&store.conn).expect("load should succeed");
        assert_eq!(
            loaded.timestamp_ns, valid_cursor.timestamp_ns,
            "timestamp_ns must be preserved for valid cursor"
        );
        assert_eq!(
            loaded.event_id, "canonical-00000000000000000042",
            "canonical-prefixed event_id must be normalized"
        );
    }

    /// Verify that a fresh database (no cursor row) returns the default cursor
    /// (not treated as legacy).
    #[test]
    fn sqlite_cursor_store_returns_default_for_fresh_db() {
        use super::SqliteGateStartCursorStore;

        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("open in-memory sqlite"),
        ));
        let _store = SqliteGateStartCursorStore::new(Arc::clone(&conn)).expect("init cursor store");

        // No cursor saved — must return default.
        let loaded =
            SqliteGateStartCursorStore::load_with_conn(&conn).expect("load should succeed");
        assert_eq!(
            loaded,
            CompositeCursor::default(),
            "fresh database must return default cursor"
        );
    }

    /// BLOCKER fix: A malformed `changeset_published` row must not deadlock
    /// the kernel. The ledger reader must skip the malformed row (returning
    /// a cursor-advancing event with `publication = None`) so subsequent
    /// ticks are not permanently stuck re-reading the same bad row.
    #[test]
    fn malformed_changeset_published_row_skipped_not_deadlocked() {
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
                        work_id TEXT NOT NULL DEFAULT '',
                        payload BLOB NOT NULL,
                        signature BLOB NOT NULL DEFAULT X'',
                        timestamp_ns INTEGER NOT NULL
                    )",
                    [],
                )
                .expect("create legacy table");

            let ts = 1_706_000_000_999_000_000_i64;

            // Row 1: malformed payload (invalid JSON)
            guard
                .execute(
                    "INSERT INTO ledger_events \
                     (event_id, event_type, actor_id, work_id, payload, timestamp_ns) \
                     VALUES (?1, 'changeset_published', 'actor:test', 'W-bad', ?2, ?3)",
                    rusqlite::params!["evt-bad", b"NOT VALID JSON", ts],
                )
                .expect("insert malformed row");

            // Row 2: valid payload (should still be returned)
            let valid_payload = serde_json::to_vec(&json!({
                "work_id": "W-good",
                "changeset_digest": hex::encode([0x33; 32]),
                "cas_hash": hex::encode([0x44; 32]),
                "actor_id": "actor:good",
                "timestamp_ns": ts + 1,
            }))
            .expect("serialize valid payload");
            guard
                .execute(
                    "INSERT INTO ledger_events \
                     (event_id, event_type, actor_id, work_id, payload, timestamp_ns) \
                     VALUES (?1, 'changeset_published', 'actor:good', 'W-good', ?2, ?3)",
                    rusqlite::params!["evt-good", valid_payload, ts + 1],
                )
                .expect("insert valid row");
        }

        let reader = SqliteGateStartLedgerReader::new(Arc::clone(&conn));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");
        let results = rt
            .block_on(reader.poll(&CompositeCursor::default(), 10))
            .expect("poll must not fail on malformed row");

        // Both rows should be returned — the malformed one with publication = None.
        assert_eq!(
            results.len(),
            2,
            "both rows (malformed + valid) should be returned"
        );

        // First row (malformed): publication is None, cursor advances past it.
        assert!(
            results[0].publication.is_none(),
            "malformed row must have publication = None"
        );
        assert!(
            !results[0].cursor_event_id.is_empty(),
            "malformed row must still carry cursor_event_id for cursor advancement"
        );

        // Second row (valid): publication is Some.
        let valid_pub = results[1]
            .publication
            .as_ref()
            .expect("valid row must have publication");
        assert_eq!(valid_pub.work_id, "W-good");
    }

    /// BLOCKER fix: When ALL rows in a batch are malformed, the poll must
    /// still succeed (not deadlock). The returned events have
    /// `publication = None` but valid cursor coordinates so the kernel
    /// advances past all malformed rows.
    #[test]
    fn all_malformed_rows_still_advance_cursor() {
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
                        work_id TEXT NOT NULL DEFAULT '',
                        payload BLOB NOT NULL,
                        signature BLOB NOT NULL DEFAULT X'',
                        timestamp_ns INTEGER NOT NULL
                    )",
                    [],
                )
                .expect("create legacy table");

            let ts = 1_706_000_000_000_000_000_i64;
            // Insert two malformed rows
            guard
                .execute(
                    "INSERT INTO ledger_events \
                     (event_id, event_type, actor_id, work_id, payload, timestamp_ns) \
                     VALUES (?1, 'changeset_published', 'actor:t', 'W-1', ?2, ?3)",
                    rusqlite::params!["evt-1", b"broken-json-1", ts],
                )
                .expect("insert malformed row 1");
            guard
                .execute(
                    "INSERT INTO ledger_events \
                     (event_id, event_type, actor_id, work_id, payload, timestamp_ns) \
                     VALUES (?1, 'changeset_published', 'actor:t', 'W-2', ?2, ?3)",
                    rusqlite::params!["evt-2", b"broken-json-2", ts + 1],
                )
                .expect("insert malformed row 2");
        }

        let reader = SqliteGateStartLedgerReader::new(Arc::clone(&conn));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");
        let results = rt
            .block_on(reader.poll(&CompositeCursor::default(), 10))
            .expect("poll must succeed even when all rows are malformed");

        assert_eq!(results.len(), 2, "both malformed rows should be returned");
        assert!(results[0].publication.is_none());
        assert!(results[1].publication.is_none());

        // The cursor can advance to the last event's position.
        assert!(!results[1].cursor_event_id.is_empty());
    }

    /// Quality BLOCKER regression: batching two same-work
    /// `changeset_published` events whose digest lexical order is opposite
    /// to publish order must NOT reorder them. The surviving orchestration
    /// and emitted leases must remain bound to the newest publication.
    ///
    /// Before the fix, `enqueue_many` stamped one `now_ns` for the whole
    /// batch and `dequeue_batch` ordered by `created_at_ns ASC, intent_key
    /// ASC`, which fell back to lexical key order. Two same-work
    /// publications could be reordered, causing `start_for_publication` to
    /// supersede with an older digest.
    #[test]
    fn sqlite_dequeue_preserves_observation_order_not_key_lexical_order() {
        use super::SqliteGateStartIntentStore;

        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("open in-memory sqlite"),
        ));
        let store = SqliteGateStartIntentStore::new(Arc::clone(&conn)).expect("init store");

        // Digest 0xFF.. sorts lexically AFTER 0x00.., but we publish
        // 0xFF.. first (observed_seq=0) and 0x00.. second (observed_seq=1).
        let pub_first = apm2_core::fac::ChangesetPublication {
            work_id: "W-order-test".to_string(),
            changeset_digest: [0xFF; 32],
            bundle_cas_hash: [0xAA; 32],
            published_at_ms: 1_000,
            publisher_actor_id: "actor:test".to_string(),
            changeset_published_event_id: "evt-first".to_string(),
        };
        let pub_second = apm2_core::fac::ChangesetPublication {
            work_id: "W-order-test-2".to_string(),
            changeset_digest: [0x00; 32],
            bundle_cas_hash: [0xBB; 32],
            published_at_ms: 2_000,
            publisher_actor_id: "actor:test".to_string(),
            changeset_published_event_id: "evt-second".to_string(),
        };

        let intent_first = super::GateStartIntent {
            publication: pub_first,
            observed_seq: 0,
        };
        let intent_second = super::GateStartIntent {
            publication: pub_second,
            observed_seq: 1,
        };

        // Enqueue both in a single batch (same created_at_ns).
        let inserted = SqliteGateStartIntentStore::enqueue_many_with_conn(
            &store.conn,
            &[intent_first, intent_second],
        )
        .expect("enqueue");
        assert_eq!(inserted, 2);

        // Dequeue must return in observed_seq order (0xFF first, 0x00 second),
        // NOT lexical key order (which would put 0x00 first).
        let dequeued =
            SqliteGateStartIntentStore::dequeue_batch_with_conn(&store.conn, 10).expect("dequeue");
        assert_eq!(dequeued.len(), 2);
        assert_eq!(
            dequeued[0].publication.changeset_digest, [0xFF; 32],
            "first dequeued intent must be the first-observed publication (0xFF), \
             not the lexically-first key (0x00)"
        );
        assert_eq!(
            dequeued[1].publication.changeset_digest, [0x00; 32],
            "second dequeued intent must be the second-observed publication (0x00)"
        );
        // Verify observed_seq values are preserved through persistence.
        assert_eq!(dequeued[0].observed_seq, 0);
        assert_eq!(dequeued[1].observed_seq, 1);
    }

    /// Security MAJOR regression: serialized `GateOrchestratorEvent` variants
    /// must include `changeset_digest` in their JSON payload so that the
    /// `WorkReducer` can extract it via `find_work_id_and_digest`. Without
    /// `changeset_digest`, receipt events are silently dropped by the reducer
    /// and `ci_receipt_digest_by_work` never gets populated, causing
    /// downstream CI transitions to be denied indefinitely.
    #[test]
    fn gate_receipt_collected_event_serializes_with_changeset_digest() {
        use apm2_core::work::extract_work_id_and_digest_from_payload;

        use crate::gate::{GateOrchestratorEvent, GateType};

        let digest = [0x42; 32];
        let event = GateOrchestratorEvent::GateReceiptCollected {
            work_id: "W-digest-test".to_string(),
            gate_type: GateType::Quality,
            receipt_id: "receipt-1".to_string(),
            passed: true,
            changeset_digest: digest,
            timestamp_ms: 1_000,
        };

        let payload = serde_json::to_vec(&event).expect("serialize event");

        // The reducer's extraction function must be able to find both
        // work_id and changeset_digest in the serialized payload.
        let extracted = extract_work_id_and_digest_from_payload(&payload);
        assert!(
            extracted.is_some(),
            "reducer must be able to extract (work_id, changeset_digest) from \
             serialized GateReceiptCollected event"
        );
        let (work_id, extracted_digest) = extracted.unwrap();
        assert_eq!(work_id, "W-digest-test");
        assert_eq!(extracted_digest, digest);
    }

    /// Security MAJOR regression: all `GateOrchestratorEvent` variants
    /// that carry digest-bound semantics must serialize with
    /// `changeset_digest` extractable by the reducer.
    #[test]
    fn all_gate_event_variants_serialize_with_extractable_digest() {
        use apm2_core::work::extract_work_id_and_digest_from_payload;

        use crate::gate::{GateOrchestratorEvent, GateType};

        let digest = [0xAB; 32];

        let events: Vec<GateOrchestratorEvent> = vec![
            GateOrchestratorEvent::PolicyResolved {
                work_id: "W-1".to_string(),
                changeset_digest: digest,
                policy_hash: [0x01; 32],
                timestamp_ms: 1,
            },
            GateOrchestratorEvent::GateLeaseIssued {
                work_id: "W-1".to_string(),
                gate_type: GateType::Quality,
                lease_id: "L-1".to_string(),
                executor_actor_id: "actor:exec".to_string(),
                changeset_digest: digest,
                timestamp_ms: 2,
            },
            GateOrchestratorEvent::GateExecutorSpawned {
                work_id: "W-1".to_string(),
                gate_type: GateType::Quality,
                episode_id: "ep-1".to_string(),
                adapter_profile_id: "ap-1".to_string(),
                changeset_digest: digest,
                timestamp_ms: 3,
            },
            GateOrchestratorEvent::GateReceiptCollected {
                work_id: "W-1".to_string(),
                gate_type: GateType::Quality,
                receipt_id: "R-1".to_string(),
                passed: true,
                changeset_digest: digest,
                timestamp_ms: 4,
            },
            GateOrchestratorEvent::GateTimedOut {
                work_id: "W-1".to_string(),
                gate_type: GateType::Quality,
                lease_id: "L-1".to_string(),
                changeset_digest: digest,
                timestamp_ms: 5,
            },
            GateOrchestratorEvent::GateTimeoutReceiptGenerated {
                work_id: "W-1".to_string(),
                gate_type: GateType::Quality,
                receipt_id: "R-timeout".to_string(),
                changeset_digest: digest,
                timestamp_ms: 6,
            },
            GateOrchestratorEvent::AllGatesCompleted {
                work_id: "W-1".to_string(),
                all_passed: true,
                outcomes: vec![],
                changeset_digest: digest,
                timestamp_ms: 7,
            },
        ];

        for event in &events {
            let payload = serde_json::to_vec(event).expect("serialize event");
            let extracted = extract_work_id_and_digest_from_payload(&payload);
            assert!(
                extracted.is_some(),
                "reducer must extract (work_id, changeset_digest) from {:?}",
                std::mem::discriminant(event)
            );
            let (work_id, extracted_digest) = extracted.unwrap();
            assert_eq!(work_id, "W-1");
            assert_eq!(
                extracted_digest, digest,
                "changeset_digest mismatch in event variant"
            );
        }
    }
}

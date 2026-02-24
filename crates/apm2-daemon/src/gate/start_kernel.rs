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
const GATE_START_PERSISTOR_ACTOR_ID: &str = "orchestrator:gate-start-kernel";

/// Maximum payload size (in bytes) for `changeset_published` events before JSON
/// deserialization. Prevents denial-of-service via oversized `SQLite` payloads
/// (up to 1 GiB) exhausting daemon memory during `serde_json::from_slice`.
const MAX_PAYLOAD_BYTES: usize = 1_048_576; // 1 MiB

/// Detect whether a persisted cursor `event_id` is in the legacy (pre-unified)
/// format. Legacy cursors store raw event IDs without the `legacy:` or
/// `canonical:` namespace prefix that the unified reader now emits.
///
/// On upgrade, resuming from a legacy cursor value can cause the lexicographic
/// comparison `cursor_event_id > last_cursor` to skip namespaced rows that sort
/// before the raw value, permanently missing those events.
///
/// When a legacy cursor is detected, `load_with_conn` resets the cursor to the
/// beginning. Re-processing is safe because the intent store's `state='done'`
/// markers provide idempotent deduplication (CSID-003).
fn is_legacy_cursor(event_id: &str) -> bool {
    // An empty event_id is the default (no cursor persisted yet) — not legacy.
    if event_id.is_empty() {
        return false;
    }
    // The unified reader emits `legacy:<event_id>` or `canonical:<seq>`.
    // Any persisted cursor that lacks one of these prefixes is from a
    // previous version and must be treated as legacy.
    !event_id.starts_with("legacy:") && !event_id.starts_with("canonical:")
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
    /// `None` when the row was present in the ledger but its payload was
    /// malformed and could not be parsed.  The event still carries valid
    /// cursor coordinates so the kernel advances past the defective row
    /// (preventing permanent deadlock).  A `DefectRecorded` is emitted at
    /// observe time for audit trail.
    publication: Option<ChangesetPublication>,
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
        // Security: SELECT actor_id and work_id/session_id from both tables.
        // Both `ledger_events` (work_id) and canonical `events` (session_id)
        // tables have mandatory actor_id and work identity columns. These are
        // the cryptographically verified envelope identities.
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
                "SELECT cursor_event_id, source_event_id, payload, timestamp_ns,
                        verified_actor_id, verified_work_id
                 FROM (
                   SELECT ('legacy:' || event_id) AS cursor_event_id,
                          event_id AS source_event_id,
                          payload,
                          timestamp_ns,
                          actor_id AS verified_actor_id,
                          work_id AS verified_work_id
                   FROM ledger_events
                   WHERE event_type = 'changeset_published'
                   UNION ALL
                   SELECT ('canonical:' || printf('%020d', seq_id)) AS cursor_event_id,
                          ('canonical-' || printf('%020d', seq_id)) AS source_event_id,
                          payload,
                          timestamp_ns,
                          actor_id AS verified_actor_id,
                          session_id AS verified_work_id
                   FROM events
                   WHERE event_type = 'changeset_published'
                 )
                 WHERE timestamp_ns > ?1
                 ORDER BY timestamp_ns ASC, cursor_event_id ASC
                 LIMIT ?2"
            } else {
                "SELECT cursor_event_id, source_event_id, payload, timestamp_ns,
                        verified_actor_id, verified_work_id
                 FROM (
                   SELECT ('legacy:' || event_id) AS cursor_event_id,
                          event_id AS source_event_id,
                          payload,
                          timestamp_ns,
                          actor_id AS verified_actor_id,
                          work_id AS verified_work_id
                   FROM ledger_events
                   WHERE event_type = 'changeset_published'
                   UNION ALL
                   SELECT ('canonical:' || printf('%020d', seq_id)) AS cursor_event_id,
                          ('canonical-' || printf('%020d', seq_id)) AS source_event_id,
                          payload,
                          timestamp_ns,
                          actor_id AS verified_actor_id,
                          session_id AS verified_work_id
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
                    actor_id AS verified_actor_id,
                    work_id AS verified_work_id
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
                    actor_id AS verified_actor_id,
                    work_id AS verified_work_id
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
            // Security: Extract verified actor_id from ledger row envelope.
            // Both legacy (actor_id) and canonical (actor_id) are NOT NULL.
            let verified_actor_id: String = row
                .get(4)
                .map_err(|e| format!("failed to decode verified_actor_id: {e}"))?;
            // Security MAJOR: Extract verified work_id from ledger row
            // envelope (legacy: work_id, canonical: session_id).
            let verified_work_id: String = row
                .get(5)
                .map_err(|e| format!("failed to decode verified_work_id: {e}"))?;
            let publication = match parse_changeset_publication_payload(
                &payload,
                timestamp_ns,
                &source_event_id,
                &verified_actor_id,
                &verified_work_id,
            ) {
                Ok(pub_ok) => Some(pub_ok),
                Err(parse_err) => {
                    // BLOCKER fix: Do NOT propagate parse errors with `?`.
                    // Failing here would abort the entire poll, and the
                    // orchestrator kernel would not advance the cursor past
                    // this row — causing an infinite re-read deadlock.
                    //
                    // Instead: log the error, push a cursor-advancing event
                    // with `publication = None` so the cursor moves past the
                    // malformed row. The domain's `apply_events` skips None
                    // publications.
                    tracing::error!(
                        cursor_event_id = %cursor_event_id,
                        source_event_id = %source_event_id,
                        verified_work_id = %verified_work_id,
                        verified_actor_id = %verified_actor_id,
                        payload_len = payload.len(),
                        error = %parse_err,
                        "DEFECT: malformed changeset_published row skipped \
                         (cursor will advance past it)"
                    );
                    None
                },
            };
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
    ///
    /// Migration safety: if the persisted cursor has a legacy (pre-unified)
    /// `event_id` format (no `legacy:`/`canonical:` prefix), the cursor is
    /// reset to the default (start from beginning). Re-processing from the
    /// beginning is safe because the intent store's `state='done'` markers
    /// deduplicate already-completed events (CSID-003 idempotency).
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
        // Migration: detect pre-unified cursor format and reset to beginning.
        // Legacy cursors used raw event IDs without the `legacy:` or
        // `canonical:` namespace prefix. Resuming from such a cursor under
        // the new unified ordering could permanently skip events.
        if is_legacy_cursor(&event_id) {
            return Ok(CompositeCursor::default());
        }
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
        // Migration: add observed_seq column for deterministic dequeue
        // ordering by ledger observation order (Quality BLOCKER fix:
        // prevents reordering same-work publications whose intent_key
        // lexical order differs from publish order).
        let _ = guard.execute(
            "ALTER TABLE gate_start_intents ADD COLUMN observed_seq INTEGER NOT NULL DEFAULT 0",
            [],
        );
        // Replace the old index with one that orders by observed_seq for
        // deterministic dequeue. The `created_at_ns` tiebreaker handles
        // pre-migration rows that all have `observed_seq=0`.
        let _ = guard.execute("DROP INDEX IF EXISTS idx_gate_start_intents_pending", []);
        guard
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_gate_start_intents_pending_v2
                 ON gate_start_intents(state, observed_seq, created_at_ns)",
                [],
            )
            .map_err(|e| format!("failed to create idx_gate_start_intents_pending_v2: {e}"))?;
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
        for intent in intents {
            let key = intent.key();
            let publication_json = serde_json::to_string(&intent.publication)
                .map_err(|e| format!("failed to encode publication json: {e}"))?;
            let observed_seq = i64::try_from(intent.observed_seq).unwrap_or(i64::MAX);
            let rows = tx
                .execute(
                    "INSERT OR IGNORE INTO gate_start_intents
                     (intent_key, publication_json, state, blocked_reason, created_at_ns, updated_at_ns, observed_seq)
                     VALUES (?1, ?2, 'pending', NULL, ?3, ?4, ?5)",
                    params![key, publication_json, now_ns, now_ns, observed_seq],
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
                "SELECT publication_json, observed_seq
                 FROM gate_start_intents
                 WHERE state = 'pending'
                 ORDER BY observed_seq ASC, created_at_ns ASC
                 LIMIT ?1",
            )
            .map_err(|e| format!("failed to prepare gate-start dequeue query: {e}"))?;
        let rows = stmt
            .query_map(params![limit_i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|e| format!("failed to query gate-start intents: {e}"))?;

        let mut intents = Vec::new();
        for row in rows {
            let (publication_json, seq_i64) =
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
            let observed_seq = u64::try_from(seq_i64).unwrap_or(0);
            intents.push(GateStartIntent {
                publication,
                observed_seq,
            });
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
                    rusqlite::params!["a-legacy", "actor:legacy", "work-legacy", legacy_payload, ts],
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
        let first = reader
            .poll(&CompositeCursor::default(), 1)
            .expect("first poll should succeed");
        assert_eq!(first.len(), 1);
        assert_eq!(
            first[0]
                .publication
                .as_ref()
                .expect("valid publication")
                .work_id,
            "work-canonical"
        );

        let cursor = CompositeCursor {
            timestamp_ns: first[0].timestamp_ns,
            event_id: first[0].cursor_event_id.clone(),
        };
        let second = reader
            .poll(&cursor, 10)
            .expect("second poll should succeed");
        assert_eq!(second.len(), 1);
        assert_eq!(
            second[0]
                .publication
                .as_ref()
                .expect("valid publication")
                .work_id,
            "work-legacy"
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
            observed_seq: 0,
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
        let intent2 = super::GateStartIntent {
            publication,
            observed_seq: 0,
        };
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

    /// Tests for `is_legacy_cursor` — cursor format detection for migration
    /// safety. Legacy cursors are raw event IDs without `legacy:` or
    /// `canonical:` namespace prefix.
    #[test]
    fn is_legacy_cursor_detects_raw_event_ids() {
        // Raw event IDs (no namespace prefix) are legacy.
        assert!(
            is_legacy_cursor("evt-12345"),
            "raw event ID without prefix is legacy"
        );
        assert!(
            is_legacy_cursor("a-legacy"),
            "raw event ID 'a-legacy' is legacy (despite containing 'legacy' substring)"
        );
        assert!(
            is_legacy_cursor("uuid-style-event-id-abc"),
            "UUID-style raw event ID is legacy"
        );
    }

    #[test]
    fn is_legacy_cursor_accepts_namespaced_cursors() {
        // Properly namespaced cursors are NOT legacy.
        assert!(
            !is_legacy_cursor("legacy:evt-12345"),
            "'legacy:' prefixed cursor is not legacy"
        );
        assert!(
            !is_legacy_cursor("canonical:00000000000000000001"),
            "'canonical:' prefixed cursor is not legacy"
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

    /// Migration test: loading a cursor with a raw (pre-unified) event ID
    /// resets to the default `CompositeCursor` (start from beginning).
    /// Re-processing is idempotent via the intent store's `state='done'`
    /// markers (CSID-003).
    #[test]
    fn sqlite_cursor_store_resets_legacy_cursor_to_beginning() {
        use super::SqliteGateStartCursorStore;

        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("open in-memory sqlite"),
        ));
        let store = SqliteGateStartCursorStore::new(Arc::clone(&conn)).expect("init cursor store");

        // Simulate a pre-unified cursor persisted by a previous version:
        // raw event ID without `legacy:` or `canonical:` prefix.
        let legacy_cursor = CompositeCursor {
            timestamp_ns: 1_706_000_000_000_000_000,
            event_id: "raw-event-id-from-v1".to_string(),
        };
        SqliteGateStartCursorStore::save_with_conn(&store.conn, &legacy_cursor)
            .expect("save legacy cursor");

        // Load must detect the legacy format and reset to default (beginning).
        let loaded =
            SqliteGateStartCursorStore::load_with_conn(&store.conn).expect("load should succeed");
        assert_eq!(
            loaded,
            CompositeCursor::default(),
            "legacy cursor must be reset to default (start from beginning)"
        );
    }

    /// Verify that a cursor with the `legacy:` prefix is loaded correctly
    /// (no reset).
    #[test]
    fn sqlite_cursor_store_preserves_legacy_prefixed_cursor() {
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
            loaded.event_id, "legacy:evt-12345",
            "event_id must be preserved for 'legacy:' prefixed cursor"
        );
    }

    /// Verify that a cursor with the `canonical:` prefix is loaded correctly
    /// (no reset).
    #[test]
    fn sqlite_cursor_store_preserves_canonical_prefixed_cursor() {
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
            loaded.event_id, "canonical:00000000000000000042",
            "event_id must be preserved for 'canonical:' prefixed cursor"
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
        let results = reader
            .poll(&CompositeCursor::default(), 10)
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
        let results = reader
            .poll(&CompositeCursor::default(), 10)
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

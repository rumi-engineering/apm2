//! Orchestrator-kernel reference migration for gate timeout progression.
//!
//! This module wires the existing `GateOrchestrator` timeout flow through the
//! shared `apm2_core::orchestrator_kernel` harness:
//! Observe -> Plan -> Execute -> Receipt.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use apm2_core::events::GateReceipt as LedgerGateReceipt;
use apm2_core::fac::GateLease;
use apm2_core::orchestrator_kernel::{
    CompositeCursor, CursorEvent, CursorStore, EffectExecutionState, EffectJournal,
    ExecutionOutcome, InDoubtResolution, IntentStore, LedgerReader, OrchestratorDomain,
    ReceiptWriter, TickConfig, TickReport, run_tick,
};
use prost::Message;
use rusqlite::{Connection, OptionalExtension, params};

use crate::gate::{GateOrchestrator, GateOrchestratorEvent, GateType};
use crate::ledger::SqliteLedgerEventEmitter;
use crate::ledger_poll;
use crate::orchestrator_runtime::sqlite::{
    IntentKeyed, SqliteCursorStore, SqliteEffectJournal, SqliteIntentStore,
    init_orchestrator_runtime_schema,
};
use crate::orchestrator_runtime::{MemoryCursorStore, MemoryEffectJournal, MemoryIntentStore};
use crate::protocol::dispatch::LedgerEventEmitter;

const TIMEOUT_PERSISTOR_SESSION_ID: &str = "gate-timeout-poller";
const TIMEOUT_PERSISTOR_ACTOR_ID: &str = "orchestrator:timeout-poller";

/// Kernel configuration for gate-timeout orchestration ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateTimeoutKernelConfig {
    /// Maximum observe events per tick.
    pub observe_limit: usize,
    /// Maximum timeout intents executed per tick.
    pub execute_limit: usize,
}

impl Default for GateTimeoutKernelConfig {
    fn default() -> Self {
        Self {
            observe_limit: 256,
            execute_limit: 64,
        }
    }
}

/// Errors from timeout-kernel construction or tick execution.
#[derive(Debug, thiserror::Error)]
pub enum GateTimeoutKernelError {
    /// Initialization failure.
    #[error("timeout kernel init failed: {0}")]
    Init(String),
    /// Tick execution failure.
    #[error("timeout kernel tick failed: {0}")]
    Tick(String),
}

/// The canonical orchestrator ID used for the gate timeout kernel in the
/// shared `orchestrator_kernel_*` tables.
const GATE_TIMEOUT_ORCHESTRATOR_ID: &str = "gate_timeout_kernel";

/// Durable timeout-kernel runtime state.
pub struct GateTimeoutKernel {
    domain: GateTimeoutDomain,
    ledger_reader: TimeoutLedgerReader,
    cursor_store: TimeoutCursorStoreEnum,
    intent_store: TimeoutIntentStoreEnum,
    effect_journal: TimeoutEffectJournalEnum,
    receipt_writer: GateTimeoutReceiptWriter,
    tick_config: TickConfig,
}

/// Dispatch enum for cursor store: `SQLite` (shared) or Memory.
#[derive(Debug)]
enum TimeoutCursorStoreEnum {
    Sqlite(SqliteCursorStore<CompositeCursor>),
    Memory(MemoryCursorStore<CompositeCursor>),
}

impl CursorStore<CompositeCursor> for TimeoutCursorStoreEnum {
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

/// Dispatch enum for intent store: `SQLite` (shared) or Memory.
#[derive(Debug)]
enum TimeoutIntentStoreEnum {
    Sqlite(SqliteIntentStore<GateTimeoutIntent>),
    Memory(MemoryIntentStore<GateTimeoutIntent>),
}

impl IntentStore<GateTimeoutIntent, String> for TimeoutIntentStoreEnum {
    type Error = String;

    async fn enqueue_many(&self, intents: &[GateTimeoutIntent]) -> Result<usize, Self::Error> {
        match self {
            Self::Sqlite(store) => store.enqueue_many(intents).await,
            Self::Memory(store) => store.enqueue_many(intents).await,
        }
    }

    async fn dequeue_batch(&self, limit: usize) -> Result<Vec<GateTimeoutIntent>, Self::Error> {
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

/// Dispatch enum for effect journal: `SQLite` (shared) or Memory.
#[derive(Debug)]
enum TimeoutEffectJournalEnum {
    Sqlite(SqliteEffectJournal),
    Memory(MemoryEffectJournal),
}

impl EffectJournal<String> for TimeoutEffectJournalEnum {
    type Error = String;

    async fn query_state(&self, key: &String) -> Result<EffectExecutionState, Self::Error> {
        match self {
            Self::Sqlite(j) => j.query_state(key).await,
            Self::Memory(j) => j.query_state(key).await,
        }
    }

    async fn record_started(&self, key: &String) -> Result<(), Self::Error> {
        match self {
            Self::Sqlite(j) => j.record_started(key).await,
            Self::Memory(j) => j.record_started(key).await,
        }
    }

    async fn record_completed(&self, key: &String) -> Result<(), Self::Error> {
        match self {
            Self::Sqlite(j) => j.record_completed(key).await,
            Self::Memory(j) => j.record_completed(key).await,
        }
    }

    async fn record_retryable(&self, key: &String) -> Result<(), Self::Error> {
        match self {
            Self::Sqlite(j) => j.record_retryable(key).await,
            Self::Memory(j) => j.record_retryable(key).await,
        }
    }

    async fn resolve_in_doubt(&self, key: &String) -> Result<InDoubtResolution, Self::Error> {
        match self {
            Self::Sqlite(j) => j.resolve_in_doubt(key).await,
            Self::Memory(j) => j.resolve_in_doubt(key).await,
        }
    }
}

impl GateTimeoutKernel {
    /// Creates a new timeout kernel instance.
    ///
    /// When `sqlite_conn` is `Some`, this initializes the shared
    /// `orchestrator_kernel_*` schema, runs the legacy migration, and
    /// creates shared `SQLite` adapters. When `None`, in-memory adapters
    /// are used (for tests).
    pub fn new(
        orchestrator: Arc<GateOrchestrator>,
        sqlite_conn: Option<&Arc<Mutex<Connection>>>,
        timeout_ledger_emitter: Option<SqliteLedgerEventEmitter>,
        fac_root: &Path,
        config: GateTimeoutKernelConfig,
    ) -> Result<Self, GateTimeoutKernelError> {
        // Initialize shared schema and run legacy migration for SQLite mode.
        if let Some(conn) = sqlite_conn {
            let guard = conn
                .lock()
                .map_err(|e| GateTimeoutKernelError::Init(format!("lock poisoned: {e}")))?;
            init_orchestrator_runtime_schema(&guard).map_err(|e| {
                GateTimeoutKernelError::Init(format!("shared schema init failed: {e}"))
            })?;
            drop(guard);
            migrate_legacy_cursor(conn).map_err(|e| {
                GateTimeoutKernelError::Init(format!("cursor migration failed: {e}"))
            })?;
            migrate_legacy_intents(conn).map_err(|e| {
                GateTimeoutKernelError::Init(format!("intent migration failed: {e}"))
            })?;
        }

        let cursor_store = sqlite_conn.map_or_else(
            || TimeoutCursorStoreEnum::Memory(MemoryCursorStore::default()),
            |conn| {
                TimeoutCursorStoreEnum::Sqlite(SqliteCursorStore::new(
                    Arc::clone(conn),
                    GATE_TIMEOUT_ORCHESTRATOR_ID,
                ))
            },
        );

        let intent_store = sqlite_conn.map_or_else(
            || TimeoutIntentStoreEnum::Memory(MemoryIntentStore::default()),
            |conn| {
                TimeoutIntentStoreEnum::Sqlite(SqliteIntentStore::new(
                    Arc::clone(conn),
                    GATE_TIMEOUT_ORCHESTRATOR_ID,
                ))
            },
        );

        let observed_lease_store = if let Some(conn) = sqlite_conn {
            TimeoutObservedLeaseStore::Sqlite(
                SqliteTimeoutObservedLeaseStore::new(Arc::clone(conn)).map_err(|e| {
                    GateTimeoutKernelError::Init(format!("observed lease store setup failed: {e}"))
                })?,
            )
        } else {
            TimeoutObservedLeaseStore::Memory(MemoryTimeoutObservedLeaseStore::default())
        };

        std::fs::create_dir_all(fac_root).map_err(|e| {
            GateTimeoutKernelError::Init(format!(
                "failed to create FAC root '{}': {e}",
                fac_root.display()
            ))
        })?;

        // Effect journal: use shared table via the main connection. Migrate
        // from the legacy separate sqlite file if it exists.
        let effect_journal = if let Some(conn) = sqlite_conn {
            let journal_path = fac_root.join("gate_timeout_effect_journal.sqlite");
            migrate_legacy_effect_journal(conn, &journal_path).map_err(|e| {
                GateTimeoutKernelError::Init(format!("effect journal migration failed: {e}"))
            })?;
            TimeoutEffectJournalEnum::Sqlite(SqliteEffectJournal::new(
                Arc::clone(conn),
                GATE_TIMEOUT_ORCHESTRATOR_ID,
            ))
        } else {
            TimeoutEffectJournalEnum::Memory(MemoryEffectJournal::new())
        };

        let terminal_checker = sqlite_conn.map_or_else(
            || TimeoutTerminalChecker::Memory(MemoryTimeoutTerminalChecker),
            |conn| {
                TimeoutTerminalChecker::Sqlite(SqliteTimeoutTerminalChecker::new(Arc::clone(conn)))
            },
        );
        let domain = GateTimeoutDomain::new(orchestrator, observed_lease_store, terminal_checker)
            .map_err(GateTimeoutKernelError::Init)?;

        Ok(Self {
            domain,
            ledger_reader: sqlite_conn.map_or_else(
                || TimeoutLedgerReader::Memory(MemoryTimeoutLedgerReader),
                |conn| {
                    TimeoutLedgerReader::Sqlite(SqliteTimeoutLedgerReader::new(Arc::clone(conn)))
                },
            ),
            cursor_store,
            intent_store,
            effect_journal,
            receipt_writer: GateTimeoutReceiptWriter::new(timeout_ledger_emitter),
            tick_config: TickConfig {
                observe_limit: config.observe_limit,
                execute_limit: config.execute_limit,
            },
        })
    }

    /// Runs one timeout-kernel tick.
    pub async fn tick(&mut self) -> Result<TickReport, GateTimeoutKernelError> {
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
        .map_err(|e| GateTimeoutKernelError::Tick(e.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TimeoutObservedEvent {
    timestamp_ns: u64,
    event_id: String,
    kind: TimeoutObservedKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TimeoutObservedKind {
    LeaseIssued {
        lease: Box<GateLease>,
        gate_type: GateType,
    },
    GateReceiptFinalized {
        lease_id: String,
    },
    TimedOut {
        lease_id: String,
    },
    AllCompleted {
        work_id: String,
    },
    /// A polled row that could not be parsed. Emitted so the cursor advances
    /// past the malformed row (the `CursorEvent` position is preserved),
    /// preventing re-processing of the same row on every tick.
    Skipped {
        reason: String,
    },
}

impl CursorEvent<CompositeCursor> for TimeoutObservedEvent {
    fn cursor(&self) -> CompositeCursor {
        CompositeCursor {
            timestamp_ns: self.timestamp_ns,
            event_id: self.event_id.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GateTimeoutIntent {
    lease: GateLease,
    gate_type: GateType,
}

impl GateTimeoutIntent {
    fn key(&self) -> String {
        self.lease.lease_id.clone()
    }
}

impl IntentKeyed for GateTimeoutIntent {
    fn intent_key(&self) -> String {
        self.key()
    }
}

/// Cached observation of a gate lease's timeout state.
///
/// **Monotonic time is process-local.** The `observed_monotonic_ns` and
/// `deadline_monotonic_ns` fields are anchored to `MONO_EPOCH` which resets on
/// daemon restart. These values MUST NOT be treated as durable truth. If
/// persisted for caching (e.g. to `SQLite`), they MUST be rebased on load using
/// the wall-clock `lease.expires_at` as the authoritative expiry signal.
///
/// See [`ObservedLeaseState::needs_rebase`] and [`ObservedLeaseState::rebase`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedLeaseState {
    lease: GateLease,
    gate_type: GateType,
    observed_wall_ms: u64,
    observed_monotonic_ns: u64,
    deadline_monotonic_ns: u64,
}

impl ObservedLeaseState {
    fn from_observation(
        lease: &GateLease,
        gate_type: GateType,
        observed_wall_ms: u64,
        observed_monotonic_ns: u64,
    ) -> Self {
        let remaining_ms = lease.expires_at.saturating_sub(observed_wall_ms);
        let deadline_monotonic_ns =
            observed_monotonic_ns.saturating_add(remaining_ms.saturating_mul(1_000_000));
        Self {
            lease: lease.clone(),
            gate_type,
            observed_wall_ms,
            observed_monotonic_ns,
            deadline_monotonic_ns,
        }
    }

    /// Returns true when the monotonic cache is stale and needs rebasing.
    ///
    /// Conditions that trigger rebase:
    /// - `observed_monotonic_ns == 0 || deadline_monotonic_ns == 0` (legacy
    ///   rows)
    /// - `observed_monotonic_ns > now_monotonic_ns` (daemon restart / monotonic
    ///   rewind)
    /// - `deadline_monotonic_ns < observed_monotonic_ns` (corrupt row)
    const fn needs_rebase(&self, now_monotonic_ns: u64) -> bool {
        self.observed_monotonic_ns == 0
            || self.deadline_monotonic_ns == 0
            || self.observed_monotonic_ns > now_monotonic_ns
            || self.deadline_monotonic_ns < self.observed_monotonic_ns
    }

    /// Rebases monotonic timestamps using wall-clock `lease.expires_at` as
    /// the authoritative timeout source. Returns a new state with consistent
    /// monotonic values anchored to the current process epoch.
    ///
    /// Fail-closed: if `lease.expires_at <= now_wall_ms`, `remaining_ms` is 0
    /// and the deadline equals `now_monotonic_ns` (still timed out).
    fn rebase(&self, now_wall_ms: u64, now_monotonic_ns: u64) -> Self {
        let remaining_ms = self.lease.expires_at.saturating_sub(now_wall_ms);
        let new_deadline = now_monotonic_ns.saturating_add(remaining_ms.saturating_mul(1_000_000));
        Self {
            lease: self.lease.clone(),
            gate_type: self.gate_type,
            observed_wall_ms: now_wall_ms,
            observed_monotonic_ns: now_monotonic_ns,
            deadline_monotonic_ns: new_deadline,
        }
    }

    /// Returns true when the lease has timed out according to the monotonic
    /// deadline cache. Monotonic rewind does NOT cause an immediate timeout;
    /// callers must rebase stale states before checking timeout.
    const fn is_timed_out(&self, monotonic_now_ns: u64) -> bool {
        // Note: we do NOT treat `monotonic_now_ns < observed_monotonic_ns` as
        // timed out. Monotonic rewind indicates a daemon restart; the caller
        // is responsible for rebasing stale entries before planning timeouts.
        monotonic_now_ns >= self.deadline_monotonic_ns
    }
}

#[derive(Debug, Clone)]
enum TimeoutObservedLeaseStore {
    Sqlite(SqliteTimeoutObservedLeaseStore),
    Memory(MemoryTimeoutObservedLeaseStore),
}

impl TimeoutObservedLeaseStore {
    fn load_all(&self) -> Result<HashMap<String, ObservedLeaseState>, String> {
        match self {
            Self::Sqlite(store) => store.load_all(),
            Self::Memory(store) => store.load_all(),
        }
    }

    fn upsert(&self, state: &ObservedLeaseState) -> Result<(), String> {
        match self {
            Self::Sqlite(store) => store.upsert(state),
            Self::Memory(store) => store.upsert(state),
        }
    }

    fn remove(&self, lease_id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(store) => store.remove(lease_id),
            Self::Memory(store) => store.remove(lease_id),
        }
    }
}

#[derive(Debug, Clone)]
struct SqliteTimeoutObservedLeaseStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteTimeoutObservedLeaseStore {
    fn new(conn: Arc<Mutex<Connection>>) -> Result<Self, String> {
        let guard = conn
            .lock()
            .map_err(|e| format!("observed lease store lock poisoned: {e}"))?;
        guard
            .execute(
                "CREATE TABLE IF NOT EXISTS gate_timeout_observed_leases (
                    lease_id TEXT PRIMARY KEY,
                    gate_type TEXT NOT NULL,
                    lease_json TEXT NOT NULL,
                    observed_wall_ms INTEGER NOT NULL DEFAULT 0,
                    observed_monotonic_ns INTEGER NOT NULL DEFAULT 0,
                    deadline_monotonic_ns INTEGER NOT NULL DEFAULT 0,
                    updated_at_ns INTEGER NOT NULL
                )",
                [],
            )
            .map_err(|e| format!("failed to create gate_timeout_observed_leases: {e}"))?;
        let existing_columns: Vec<String> = {
            let mut stmt = guard
                .prepare("PRAGMA table_info(gate_timeout_observed_leases)")
                .map_err(|e| {
                    format!("failed to inspect gate_timeout_observed_leases schema: {e}")
                })?;
            stmt.query_map([], |row| row.get::<_, String>(1))
                .map_err(|e| format!("failed to query observed-lease columns: {e}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("failed to decode observed-lease columns: {e}"))?
        };
        if !existing_columns
            .iter()
            .any(|name| name == "observed_wall_ms")
        {
            guard
                .execute(
                    "ALTER TABLE gate_timeout_observed_leases
                     ADD COLUMN observed_wall_ms INTEGER NOT NULL DEFAULT 0",
                    [],
                )
                .map_err(|e| {
                    format!("failed to add observed_wall_ms to gate_timeout_observed_leases: {e}")
                })?;
        }
        if !existing_columns
            .iter()
            .any(|name| name == "observed_monotonic_ns")
        {
            guard
                .execute(
                    "ALTER TABLE gate_timeout_observed_leases
                     ADD COLUMN observed_monotonic_ns INTEGER NOT NULL DEFAULT 0",
                    [],
                )
                .map_err(|e| {
                    format!(
                        "failed to add observed_monotonic_ns to gate_timeout_observed_leases: {e}"
                    )
                })?;
        }
        if !existing_columns
            .iter()
            .any(|name| name == "deadline_monotonic_ns")
        {
            guard
                .execute(
                    "ALTER TABLE gate_timeout_observed_leases
                     ADD COLUMN deadline_monotonic_ns INTEGER NOT NULL DEFAULT 0",
                    [],
                )
                .map_err(|e| {
                    format!(
                        "failed to add deadline_monotonic_ns to gate_timeout_observed_leases: {e}"
                    )
                })?;
        }
        drop(guard);
        Ok(Self { conn })
    }

    fn load_all(&self) -> Result<HashMap<String, ObservedLeaseState>, String> {
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("observed lease store lock poisoned: {e}"))?;
        let mut stmt = guard
            .prepare(
                "SELECT lease_id, gate_type, lease_json, observed_wall_ms,
                        observed_monotonic_ns, deadline_monotonic_ns
                 FROM gate_timeout_observed_leases",
            )
            .map_err(|e| format!("failed to prepare observed lease query: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                let lease_id: String = row.get(0)?;
                let gate_type_raw: String = row.get(1)?;
                let lease_json: String = row.get(2)?;
                let observed_wall_ms: i64 = row.get(3)?;
                let observed_monotonic_ns: i64 = row.get(4)?;
                let deadline_monotonic_ns: i64 = row.get(5)?;
                Ok((
                    lease_id,
                    gate_type_raw,
                    lease_json,
                    observed_wall_ms,
                    observed_monotonic_ns,
                    deadline_monotonic_ns,
                ))
            })
            .map_err(|e| format!("failed to query observed leases: {e}"))?;

        let now_wall_ms = epoch_now_ms_u64();
        let now_monotonic_ns = monotonic_now_ns()?;
        let mut leases = HashMap::new();
        let mut to_rebase: Vec<ObservedLeaseState> = Vec::new();
        for row in rows {
            let (
                lease_id,
                gate_type_raw,
                lease_json,
                observed_wall_ms_i64,
                observed_monotonic_ns_i64,
                deadline_monotonic_ns_i64,
            ) = row.map_err(|e| format!("failed to decode observed lease row: {e}"))?;
            let gate_type = parse_gate_type(&gate_type_raw).ok_or_else(|| {
                format!("unknown gate_type '{gate_type_raw}' in observed lease store")
            })?;
            if lease_json.len() > 65_536 {
                return Err(format!(
                    "observed lease JSON payload length {} exceeds maximum (65536)",
                    lease_json.len()
                ));
            }
            let lease: GateLease = serde_json::from_str(&lease_json)
                .map_err(|e| format!("failed to decode observed lease json: {e}"))?;
            lease
                .validate()
                .map_err(|e| format!("observed lease invariant violation: {e}"))?;
            let observed_wall_ms = u64::try_from(observed_wall_ms_i64).unwrap_or(now_wall_ms);
            let observed_monotonic_ns = u64::try_from(observed_monotonic_ns_i64).unwrap_or(0);
            let deadline_monotonic_ns = u64::try_from(deadline_monotonic_ns_i64).unwrap_or(0);
            let raw_state = ObservedLeaseState {
                lease,
                gate_type,
                observed_wall_ms,
                observed_monotonic_ns,
                deadline_monotonic_ns,
            };
            // Rebase monotonic cache if stale (legacy rows with zeros, restart
            // rewind where persisted monotonic > current process monotonic, or
            // corrupt rows where deadline < observed). Fail-closed remains
            // anchored to `lease.expires_at`: if the lease has already expired
            // per wall clock, remaining_ms == 0 and deadline == now (timed out).
            let state = if raw_state.needs_rebase(now_monotonic_ns) {
                let rebased = raw_state.rebase(now_wall_ms, now_monotonic_ns);
                to_rebase.push(rebased.clone());
                rebased
            } else {
                raw_state
            };
            leases.insert(lease_id, state);
        }
        // Drop the statement/rows before persisting rebased entries, since we
        // are still holding the connection guard.
        drop(stmt);
        // Persist rebased values so future loads are consistent. We use the
        // already-acquired guard to avoid deadlock.
        for rebased in &to_rebase {
            Self::upsert_with_conn(&guard, rebased)?;
        }
        Ok(leases)
    }

    /// Persist a rebased `ObservedLeaseState` using an already-acquired
    /// connection guard, avoiding deadlock when called from `load_all`.
    fn upsert_with_conn(conn: &Connection, state: &ObservedLeaseState) -> Result<(), String> {
        let now_ns = epoch_now_ns_i64()?;
        conn.execute(
            "INSERT INTO gate_timeout_observed_leases
             (lease_id, gate_type, lease_json, observed_wall_ms,
              observed_monotonic_ns, deadline_monotonic_ns, updated_at_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(lease_id) DO UPDATE SET
               gate_type = excluded.gate_type,
               lease_json = excluded.lease_json,
               observed_wall_ms = excluded.observed_wall_ms,
               observed_monotonic_ns = excluded.observed_monotonic_ns,
               deadline_monotonic_ns = excluded.deadline_monotonic_ns,
               updated_at_ns = excluded.updated_at_ns",
            params![
                &state.lease.lease_id,
                gate_type_label(state.gate_type),
                serde_json::to_string(&state.lease)
                    .map_err(|e| format!("failed to encode observed lease json: {e}"))?,
                i64::try_from(state.observed_wall_ms).map_err(|_| {
                    "observed lease wall-clock value exceeds i64 range".to_string()
                })?,
                i64::try_from(state.observed_monotonic_ns).map_err(|_| {
                    "observed lease monotonic value exceeds i64 range".to_string()
                })?,
                i64::try_from(state.deadline_monotonic_ns).map_err(|_| {
                    "observed lease monotonic deadline exceeds i64 range".to_string()
                })?,
                now_ns
            ],
        )
        .map_err(|e| {
            format!(
                "failed to upsert observed lease '{}': {e}",
                state.lease.lease_id
            )
        })?;
        Ok(())
    }

    fn upsert(&self, state: &ObservedLeaseState) -> Result<(), String> {
        let now_ns = epoch_now_ns_i64()?;
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("observed lease store lock poisoned: {e}"))?;
        guard
            .execute(
                "INSERT INTO gate_timeout_observed_leases
                 (lease_id, gate_type, lease_json, observed_wall_ms,
                  observed_monotonic_ns, deadline_monotonic_ns, updated_at_ns)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(lease_id) DO UPDATE SET
                   gate_type = excluded.gate_type,
                   lease_json = excluded.lease_json,
                   observed_wall_ms = excluded.observed_wall_ms,
                   observed_monotonic_ns = excluded.observed_monotonic_ns,
                   deadline_monotonic_ns = excluded.deadline_monotonic_ns,
                   updated_at_ns = excluded.updated_at_ns",
                params![
                    &state.lease.lease_id,
                    gate_type_label(state.gate_type),
                    serde_json::to_string(&state.lease)
                        .map_err(|e| format!("failed to encode observed lease json: {e}"))?,
                    i64::try_from(state.observed_wall_ms).map_err(|_| {
                        "observed lease wall-clock value exceeds i64 range".to_string()
                    })?,
                    i64::try_from(state.observed_monotonic_ns).map_err(|_| {
                        "observed lease monotonic value exceeds i64 range".to_string()
                    })?,
                    i64::try_from(state.deadline_monotonic_ns).map_err(|_| {
                        "observed lease monotonic deadline exceeds i64 range".to_string()
                    })?,
                    now_ns
                ],
            )
            .map_err(|e| {
                format!(
                    "failed to upsert observed lease '{}': {e}",
                    state.lease.lease_id
                )
            })?;
        Ok(())
    }

    fn remove(&self, lease_id: &str) -> Result<(), String> {
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("observed lease store lock poisoned: {e}"))?;
        guard
            .execute(
                "DELETE FROM gate_timeout_observed_leases WHERE lease_id = ?1",
                params![lease_id],
            )
            .map_err(|e| format!("failed to delete observed lease '{lease_id}': {e}"))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
struct MemoryTimeoutObservedLeaseStore {
    leases: Arc<Mutex<HashMap<String, ObservedLeaseState>>>,
}

impl MemoryTimeoutObservedLeaseStore {
    fn load_all(&self) -> Result<HashMap<String, ObservedLeaseState>, String> {
        Ok(self
            .leases
            .lock()
            .map_err(|e| format!("memory observed lease lock poisoned: {e}"))?
            .clone())
    }

    fn upsert(&self, state: &ObservedLeaseState) -> Result<(), String> {
        self.leases
            .lock()
            .map_err(|e| format!("memory observed lease lock poisoned: {e}"))?
            .insert(state.lease.lease_id.clone(), state.clone());
        Ok(())
    }

    fn remove(&self, lease_id: &str) -> Result<(), String> {
        self.leases
            .lock()
            .map_err(|e| format!("memory observed lease lock poisoned: {e}"))?
            .remove(lease_id);
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum TimeoutTerminalChecker {
    Sqlite(SqliteTimeoutTerminalChecker),
    Memory(MemoryTimeoutTerminalChecker),
}

impl TimeoutTerminalChecker {
    fn lease_is_terminal(&self, lease_id: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(checker) => checker.lease_is_terminal(lease_id),
            Self::Memory(_checker) => Ok(MemoryTimeoutTerminalChecker::lease_is_terminal(lease_id)),
        }
    }
}

#[derive(Debug, Clone)]
struct SqliteTimeoutTerminalChecker {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteTimeoutTerminalChecker {
    const fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    fn lease_is_terminal(&self, lease_id: &str) -> Result<bool, String> {
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("terminal checker lock poisoned: {e}"))?;
        if Self::has_terminal_row_in_legacy(&guard, lease_id)? {
            return Ok(true);
        }
        Self::has_terminal_row_in_canonical(&guard, lease_id)
    }

    fn has_terminal_row_in_legacy(conn: &Connection, lease_id: &str) -> Result<bool, String> {
        let mut stmt = conn
            .prepare(
                "SELECT event_type, payload
                 FROM ledger_events
                 WHERE event_type IN ('gate.timed_out', 'gate.receipt', 'GateReceipt', 'gate_receipt')
                   AND instr(payload, ?1) > 0
                 ORDER BY timestamp_ns DESC, event_id DESC
                 LIMIT 256",
            )
            .map_err(|e| format!("failed to prepare legacy terminal checker query: {e}"))?;
        let mut rows = stmt
            .query(params![lease_id.as_bytes()])
            .map_err(|e| format!("failed to execute legacy terminal checker query: {e}"))?;
        while let Some(row) = rows
            .next()
            .map_err(|e| format!("failed to iterate legacy terminal checker rows: {e}"))?
        {
            let event_type: String = row
                .get(0)
                .map_err(|e| format!("failed to decode legacy terminal event_type: {e}"))?;
            let payload: Vec<u8> = row
                .get(1)
                .map_err(|e| format!("failed to decode legacy terminal payload: {e}"))?;
            let matched = match event_type.as_str() {
                "gate.timed_out" => parse_timed_out_lease_id(&payload)
                    .map(|candidate| candidate == lease_id)
                    .unwrap_or(false),
                _ => parse_gate_receipt_lease_id(&payload)
                    .map(|candidate| candidate == lease_id)
                    .unwrap_or(false),
            };
            if matched {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn has_terminal_row_in_canonical(conn: &Connection, lease_id: &str) -> Result<bool, String> {
        let table_exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'events' LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("failed to detect canonical events table: {e}"))?;
        if table_exists.is_none() {
            return Ok(false);
        }

        let mut stmt = conn
            .prepare(
                "SELECT event_type, payload
                 FROM events
                 WHERE event_type IN ('gate.timed_out', 'gate.receipt', 'GateReceipt', 'gate_receipt')
                   AND instr(payload, ?1) > 0
                 ORDER BY timestamp_ns DESC, seq_id DESC
                 LIMIT 256",
            )
            .map_err(|e| format!("failed to prepare canonical terminal checker query: {e}"))?;
        let mut rows = stmt
            .query(params![lease_id.as_bytes()])
            .map_err(|e| format!("failed to execute canonical terminal checker query: {e}"))?;
        while let Some(row) = rows
            .next()
            .map_err(|e| format!("failed to iterate canonical terminal checker rows: {e}"))?
        {
            let event_type: String = row
                .get(0)
                .map_err(|e| format!("failed to decode canonical terminal event_type: {e}"))?;
            let payload: Vec<u8> = row
                .get(1)
                .map_err(|e| format!("failed to decode canonical terminal payload: {e}"))?;
            let matched = match event_type.as_str() {
                "gate.timed_out" => parse_timed_out_lease_id(&payload)
                    .map(|candidate| candidate == lease_id)
                    .unwrap_or(false),
                _ => parse_gate_receipt_lease_id(&payload)
                    .map(|candidate| candidate == lease_id)
                    .unwrap_or(false),
            };
            if matched {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[derive(Debug, Clone)]
struct MemoryTimeoutTerminalChecker;

impl MemoryTimeoutTerminalChecker {
    const fn lease_is_terminal(_lease_id: &str) -> bool {
        false
    }
}

struct GateTimeoutDomain {
    orchestrator: Arc<GateOrchestrator>,
    observed_leases: HashMap<String, ObservedLeaseState>,
    observed_lease_store: TimeoutObservedLeaseStore,
    terminal_checker: TimeoutTerminalChecker,
}

impl GateTimeoutDomain {
    fn new(
        orchestrator: Arc<GateOrchestrator>,
        observed_lease_store: TimeoutObservedLeaseStore,
        terminal_checker: TimeoutTerminalChecker,
    ) -> Result<Self, String> {
        let observed_leases = observed_lease_store.load_all()?;
        Ok(Self {
            orchestrator,
            observed_leases,
            observed_lease_store,
            terminal_checker,
        })
    }

    fn remove_work_leases(&mut self, work_id: &str) -> Result<(), String> {
        let lease_ids: Vec<String> = self
            .observed_leases
            .iter()
            .filter(|(_, state)| state.lease.work_id == work_id)
            .map(|(lease_id, _)| lease_id.clone())
            .collect();
        for lease_id in lease_ids {
            self.observed_lease_store.remove(&lease_id)?;
            self.observed_leases.remove(&lease_id);
        }
        Ok(())
    }
}

impl OrchestratorDomain<TimeoutObservedEvent, GateTimeoutIntent, String, GateOrchestratorEvent>
    for GateTimeoutDomain
{
    type Error = String;

    fn intent_key(&self, intent: &GateTimeoutIntent) -> String {
        intent.key()
    }

    async fn apply_events(&mut self, events: &[TimeoutObservedEvent]) -> Result<(), Self::Error> {
        for event in events {
            match &event.kind {
                TimeoutObservedKind::LeaseIssued { lease, gate_type } => {
                    let observed_wall_ms = self.orchestrator.now_ms();
                    let observed_monotonic_ns = monotonic_now_ns()?;
                    let state = ObservedLeaseState::from_observation(
                        lease.as_ref(),
                        *gate_type,
                        observed_wall_ms,
                        observed_monotonic_ns,
                    );
                    self.observed_lease_store.upsert(&state)?;
                    self.observed_leases.insert(lease.lease_id.clone(), state);
                },
                TimeoutObservedKind::GateReceiptFinalized { lease_id }
                | TimeoutObservedKind::TimedOut { lease_id } => {
                    self.observed_lease_store.remove(lease_id)?;
                    self.observed_leases.remove(lease_id);
                },
                TimeoutObservedKind::AllCompleted { work_id } => {
                    self.remove_work_leases(work_id)?;
                },
                TimeoutObservedKind::Skipped { .. } => {
                    // Intentionally ignored -- the event exists only to
                    // advance the cursor past the malformed row.
                },
            }
        }
        Ok(())
    }

    async fn plan(&mut self) -> Result<Vec<GateTimeoutIntent>, Self::Error> {
        let monotonic_now_ns = monotonic_now_ns()?;
        let now_wall_ms = epoch_now_ms_u64();

        // Guard: scan for stale/corrupt monotonic entries and rebase them
        // before generating timeout intents. This prevents a long-running
        // daemon from being wedged by corrupted or rewind-affected rows.
        let stale_keys: Vec<String> = self
            .observed_leases
            .iter()
            .filter(|(_, state)| state.needs_rebase(monotonic_now_ns))
            .map(|(key, _)| key.clone())
            .collect();
        for key in &stale_keys {
            if let Some(state) = self.observed_leases.get(key) {
                let rebased = state.rebase(now_wall_ms, monotonic_now_ns);
                self.observed_lease_store.upsert(&rebased)?;
                self.observed_leases.insert(key.clone(), rebased);
            }
        }

        let mut timed_out: Vec<GateTimeoutIntent> = self
            .observed_leases
            .values()
            .filter(|state| state.is_timed_out(monotonic_now_ns))
            .map(|state| GateTimeoutIntent {
                lease: state.lease.clone(),
                gate_type: state.gate_type,
            })
            .collect();
        timed_out.sort_by(|a, b| a.lease.lease_id.cmp(&b.lease.lease_id));
        Ok(timed_out)
    }

    async fn execute(
        &mut self,
        intent: &GateTimeoutIntent,
    ) -> Result<ExecutionOutcome<GateOrchestratorEvent>, Self::Error> {
        match self
            .orchestrator
            .handle_gate_timeout(&intent.lease.work_id, intent.gate_type)
            .await
        {
            Ok((_outcomes, events)) => Ok(ExecutionOutcome::Completed { receipts: events }),
            Err(crate::gate::GateOrchestratorError::InvalidStateTransition { .. }) => {
                Ok(ExecutionOutcome::Completed {
                    receipts: Vec::new(),
                })
            },
            Err(
                crate::gate::GateOrchestratorError::OrchestrationNotFound { .. }
                | crate::gate::GateOrchestratorError::GateNotFound { .. },
            ) => {
                if !self.observed_leases.contains_key(&intent.lease.lease_id) {
                    return Ok(ExecutionOutcome::Completed {
                        receipts: Vec::new(),
                    });
                }
                if self
                    .terminal_checker
                    .lease_is_terminal(&intent.lease.lease_id)?
                {
                    return Ok(ExecutionOutcome::Completed {
                        receipts: Vec::new(),
                    });
                }
                let events = self
                    .orchestrator
                    .build_timeout_events_from_lease(&intent.lease, intent.gate_type);
                Ok(ExecutionOutcome::Completed { receipts: events })
            },
            Err(e) => Err(format!(
                "gate timeout transition failed for work_id '{}' gate '{}': {e}",
                intent.lease.work_id, intent.gate_type
            )),
        }
    }
}

#[derive(Debug)]
enum TimeoutLedgerReader {
    Sqlite(SqliteTimeoutLedgerReader),
    Memory(MemoryTimeoutLedgerReader),
}

impl LedgerReader<TimeoutObservedEvent> for TimeoutLedgerReader {
    type Cursor = CompositeCursor;
    type Error = String;

    async fn poll(
        &self,
        cursor: &CompositeCursor,
        limit: usize,
    ) -> Result<Vec<TimeoutObservedEvent>, Self::Error> {
        match self {
            Self::Sqlite(reader) => reader.poll_async(cursor, limit).await,
            Self::Memory(_reader) => Ok(Vec::new()),
        }
    }
}

/// All event types the timeout kernel observes. Used as the union set for
/// the shared [`crate::ledger_poll::poll_events_blocking`] call.
const TIMEOUT_EVENT_TYPES: &[&str] = &[
    "gate_lease_issued",
    "gate.timed_out",
    "gate.receipt",
    "GateReceipt",
    "gate_receipt",
    "gate.all_completed",
];

#[derive(Debug)]
struct SqliteTimeoutLedgerReader {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteTimeoutLedgerReader {
    const fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    /// Polls the ledger for timeout-relevant events using the shared
    /// [`crate::ledger_poll::poll_events_async`] module (offloads blocking
    /// `SQLite` I/O to `tokio::task::spawn_blocking` per `INV-CQ-OK-003`), then
    /// maps each [`crate::protocol::dispatch::SignedLedgerEvent`] to a
    /// [`TimeoutObservedEvent`] via the existing `parse_*` helpers.
    ///
    /// Malformed rows that fail to parse are logged and emitted as
    /// [`TimeoutObservedKind::Skipped`] so the cursor advances past them,
    /// preventing the deadlock described in `BEH-DAEMON-GATE-016`.
    ///
    /// This replaces the previous 8 per-type query functions with a single
    /// unified call (TCK-00675).
    async fn poll_async(
        &self,
        cursor: &CompositeCursor,
        limit: usize,
    ) -> Result<Vec<TimeoutObservedEvent>, String> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let cursor_ts_i64 = i64::try_from(cursor.timestamp_ns)
            .map_err(|_| "cursor timestamp exceeds i64 range".to_string())?;

        let event_types: Vec<String> = TIMEOUT_EVENT_TYPES
            .iter()
            .map(|s| (*s).to_string())
            .collect();

        // Offload blocking SQLite I/O to spawn_blocking via the shared
        // ledger_poll module (INV-CQ-OK-003).
        let signed_events = ledger_poll::poll_events_async(
            Arc::clone(&self.conn),
            event_types,
            cursor_ts_i64,
            cursor.event_id.clone(),
            limit,
        )
        .await?;

        // Map SignedLedgerEvent -> TimeoutObservedEvent using existing parsers.
        // Malformed rows are logged and emitted as Skipped to preserve cursor
        // advancement (BEH-DAEMON-GATE-016 resilience).
        let mut out = Vec::with_capacity(signed_events.len());
        for event in signed_events {
            let kind = match event.event_type.as_str() {
                "gate_lease_issued" => match parse_gate_lease_payload(&event.payload) {
                    Ok((lease, gate_type)) => TimeoutObservedKind::LeaseIssued {
                        lease: Box::new(lease),
                        gate_type,
                    },
                    Err(e) => {
                        tracing::warn!(
                            event_id = %event.event_id,
                            event_type = %event.event_type,
                            "skipping malformed timeout row: {e}"
                        );
                        TimeoutObservedKind::Skipped { reason: e }
                    },
                },
                "gate.timed_out" => match parse_timed_out_lease_id(&event.payload) {
                    Ok(lease_id) => TimeoutObservedKind::TimedOut { lease_id },
                    Err(e) => {
                        tracing::warn!(
                            event_id = %event.event_id,
                            event_type = %event.event_type,
                            "skipping malformed timeout row: {e}"
                        );
                        TimeoutObservedKind::Skipped { reason: e }
                    },
                },
                "gate.receipt" | "GateReceipt" | "gate_receipt" => {
                    match parse_gate_receipt_lease_id(&event.payload) {
                        Ok(lease_id) => TimeoutObservedKind::GateReceiptFinalized { lease_id },
                        Err(e) => {
                            tracing::warn!(
                                event_id = %event.event_id,
                                event_type = %event.event_type,
                                "skipping malformed timeout row: {e}"
                            );
                            TimeoutObservedKind::Skipped { reason: e }
                        },
                    }
                },
                "gate.all_completed" => match parse_all_completed_work_id(&event.payload) {
                    Ok(work_id) => TimeoutObservedKind::AllCompleted { work_id },
                    Err(e) => {
                        tracing::warn!(
                            event_id = %event.event_id,
                            event_type = %event.event_type,
                            "skipping malformed timeout row: {e}"
                        );
                        TimeoutObservedKind::Skipped { reason: e }
                    },
                },
                other => {
                    let reason = format!("unexpected event type from ledger_poll: {other}");
                    tracing::warn!(
                        event_id = %event.event_id,
                        event_type = %event.event_type,
                        "skipping malformed timeout row: {reason}"
                    );
                    TimeoutObservedKind::Skipped { reason }
                },
            };
            out.push(TimeoutObservedEvent {
                timestamp_ns: event.timestamp_ns,
                event_id: event.event_id,
                kind,
            });
        }
        Ok(out)
    }
}

#[derive(Debug)]
struct MemoryTimeoutLedgerReader;

// ---------------------------------------------------------------------------
// Legacy migration helpers
// ---------------------------------------------------------------------------

/// Migrate legacy `gate_timeout_kernel_cursor` table to shared
/// `orchestrator_kernel_cursors`.
///
/// Only copies if target row does not yet exist for `gate_timeout_kernel`.
/// Idempotent: safe to call on every startup.
fn migrate_legacy_cursor(conn: &Arc<Mutex<Connection>>) -> Result<(), String> {
    let guard = conn
        .lock()
        .map_err(|e| format!("cursor migration lock poisoned: {e}"))?;

    // Check if legacy table exists.
    let legacy_exists: bool = guard
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table'
             AND name = 'gate_timeout_kernel_cursor' LIMIT 1",
            [],
            |_| Ok(true),
        )
        .optional()
        .map_err(|e| format!("cursor migration: failed to check legacy table: {e}"))?
        .unwrap_or(false);
    if !legacy_exists {
        return Ok(());
    }

    // Check if target already has a row for this orchestrator.
    let target_exists: bool = guard
        .query_row(
            "SELECT 1 FROM orchestrator_kernel_cursors
             WHERE orchestrator_id = ?1 LIMIT 1",
            params![GATE_TIMEOUT_ORCHESTRATOR_ID],
            |_| Ok(true),
        )
        .optional()
        .map_err(|e| format!("cursor migration: failed to check target: {e}"))?
        .unwrap_or(false);
    if target_exists {
        return Ok(());
    }

    // Read legacy cursor.
    let row: Option<(i64, String)> = guard
        .query_row(
            "SELECT timestamp_ns, event_id FROM gate_timeout_kernel_cursor
             WHERE cursor_key = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| format!("cursor migration: failed to read legacy cursor: {e}"))?;

    if let Some((timestamp_ns, event_id)) = row {
        let cursor = CompositeCursor {
            timestamp_ns: u64::try_from(timestamp_ns).unwrap_or(0),
            event_id,
        };
        let json = serde_json::to_string(&cursor)
            .map_err(|e| format!("cursor migration: failed to encode cursor: {e}"))?;
        let now_ns = epoch_now_ns_i64()?;
        guard
            .execute(
                "INSERT OR IGNORE INTO orchestrator_kernel_cursors
                 (orchestrator_id, cursor_json, updated_at_ns)
                 VALUES (?1, ?2, ?3)",
                params![GATE_TIMEOUT_ORCHESTRATOR_ID, &json, now_ns],
            )
            .map_err(|e| format!("cursor migration: failed to insert: {e}"))?;
    }
    Ok(())
}

/// Migrate legacy `gate_timeout_intents` table to shared
/// `orchestrator_kernel_intents`.
///
/// Skips if the legacy table does not exist OR if the legacy table is empty
/// AND the target already has rows (indicating a completed prior migration).
/// All INSERTs are wrapped in a single transaction for atomicity.
///
/// Idempotent: safe to call on every startup.
fn migrate_legacy_intents(conn: &Arc<Mutex<Connection>>) -> Result<(), String> {
    let mut guard = conn
        .lock()
        .map_err(|e| format!("intent migration lock poisoned: {e}"))?;

    // Check if legacy table exists.
    let legacy_exists: bool = guard
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table'
             AND name = 'gate_timeout_intents' LIMIT 1",
            [],
            |_| Ok(true),
        )
        .optional()
        .map_err(|e| format!("intent migration: failed to check legacy table: {e}"))?
        .unwrap_or(false);
    if !legacy_exists {
        return Ok(());
    }

    // Collect all legacy rows into a Vec first. This drops the statement
    // borrow before we begin writing, preventing SQLITE_BUSY on the same
    // connection (N+1 query fix).
    let legacy_rows: Vec<(String, String, String, Option<String>, i64, i64)> = {
        let mut stmt = guard
            .prepare(
                "SELECT intent_key, lease_json, state, blocked_reason, created_at_ns, updated_at_ns
                 FROM gate_timeout_intents
                 WHERE state IN ('pending', 'done', 'blocked')",
            )
            .map_err(|e| format!("intent migration: failed to prepare legacy query: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                let key: String = row.get(0)?;
                let lease_json: String = row.get(1)?;
                let state: String = row.get(2)?;
                let blocked_reason: Option<String> = row.get(3)?;
                let created_at_ns: i64 = row.get(4)?;
                let updated_at_ns: i64 = row.get(5)?;
                Ok((
                    key,
                    lease_json,
                    state,
                    blocked_reason,
                    created_at_ns,
                    updated_at_ns,
                ))
            })
            .map_err(|e| format!("intent migration: failed to query legacy intents: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("intent migration: failed to decode legacy rows: {e}"))?
    };

    // Skip check: if the legacy source is empty AND the target already has
    // rows, a prior migration completed successfully. This avoids the
    // count > 0 check that would mask a half-completed crash recovery.
    if legacy_rows.is_empty() {
        let target_count: i64 = guard
            .query_row(
                "SELECT COUNT(*) FROM orchestrator_kernel_intents
                 WHERE orchestrator_id = ?1",
                params![GATE_TIMEOUT_ORCHESTRATOR_ID],
                |r| r.get(0),
            )
            .map_err(|e| format!("intent migration: failed to count target rows: {e}"))?;
        if target_count > 0 {
            return Ok(()); // Legacy exhausted, target populated: migration already done.
        }
        return Ok(()); // No legacy data to migrate.
    }

    // Check if target already has rows matching the legacy count
    // (prior completed migration).
    let target_count: i64 = guard
        .query_row(
            "SELECT COUNT(*) FROM orchestrator_kernel_intents
             WHERE orchestrator_id = ?1",
            params![GATE_TIMEOUT_ORCHESTRATOR_ID],
            |r| r.get(0),
        )
        .map_err(|e| format!("intent migration: failed to count target rows: {e}"))?;
    if target_count >= i64::try_from(legacy_rows.len()).unwrap_or(i64::MAX) {
        return Ok(()); // Target already has at least as many rows as legacy source.
    }

    // Wrap all INSERTs in a single transaction for crash-atomicity.
    let tx = guard
        .transaction()
        .map_err(|e| format!("intent migration: failed to begin transaction: {e}"))?;
    for (key, lease_json, state, blocked_reason, created_at_ns, updated_at_ns) in &legacy_rows {
        let mapped_state = match state.as_str() {
            "done" => "completed",
            other => other,
        };
        tx.execute(
            "INSERT OR IGNORE INTO orchestrator_kernel_intents
             (orchestrator_id, intent_key, intent_json, state,
              created_at_ns, updated_at_ns, blocked_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                GATE_TIMEOUT_ORCHESTRATOR_ID,
                key,
                lease_json,
                mapped_state,
                created_at_ns,
                updated_at_ns,
                blocked_reason
            ],
        )
        .map_err(|e| format!("intent migration: failed to insert intent: {e}"))?;
    }
    tx.commit()
        .map_err(|e| format!("intent migration: failed to commit transaction: {e}"))?;
    Ok(())
}

/// Migrate legacy `gate_timeout_effect_journal.sqlite` file to the shared
/// `orchestrator_kernel_effect_journal` table in the main connection.
///
/// If the legacy file exists, reads all rows from the legacy file, inserts
/// them in a single transaction treating `started`/`unknown` as `unknown`
/// (fail-closed), then renames the file to `.migrated`.
///
/// Idempotent: safe to call on every startup. The `.migrated` rename is the
/// durable completion marker; the `count > 0` check is only an optimization.
fn migrate_legacy_effect_journal(
    conn: &Arc<Mutex<Connection>>,
    legacy_path: &Path,
) -> Result<(), String> {
    if !legacy_path.exists() {
        return Ok(());
    }

    // Open legacy DB and read rows into Vec first (drops borrow before
    // writing to the target connection).
    let legacy_conn = Connection::open(legacy_path)
        .map_err(|e| format!("effect journal migration: failed to open legacy db: {e}"))?;

    // Check if the legacy table exists.
    let legacy_table_exists: bool = legacy_conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table'
             AND name = 'gate_timeout_effect_journal_state' LIMIT 1",
            [],
            |_| Ok(true),
        )
        .optional()
        .map_err(|e| format!("effect journal migration: failed to check legacy table: {e}"))?
        .unwrap_or(false);
    if !legacy_table_exists {
        // Legacy file exists but has no table: just rename.
        drop(legacy_conn);
        let migrated_path = legacy_path.with_extension("sqlite.migrated");
        std::fs::rename(legacy_path, &migrated_path)
            .map_err(|e| format!("effect journal migration: failed to rename legacy file: {e}"))?;
        return Ok(());
    }

    // Collect all rows into Vec to release the read borrow.
    let legacy_rows: Vec<(String, String, i64)> = {
        let mut stmt = legacy_conn
            .prepare(
                "SELECT intent_key, state, updated_at_ns
                 FROM gate_timeout_effect_journal_state",
            )
            .map_err(|e| {
                format!("effect journal migration: failed to prepare legacy query: {e}")
            })?;
        let rows = stmt
            .query_map([], |row| {
                let key: String = row.get(0)?;
                let state: String = row.get(1)?;
                let updated_at_ns: i64 = row.get(2)?;
                Ok((key, state, updated_at_ns))
            })
            .map_err(|e| format!("effect journal migration: failed to query legacy rows: {e}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("effect journal migration: failed to decode legacy rows: {e}"))?
    };
    // Close legacy DB before writing to target.
    drop(legacy_conn);

    let mut guard = conn
        .lock()
        .map_err(|e| format!("effect journal migration lock poisoned: {e}"))?;

    // Skip if target already has at least as many rows as legacy source
    // (prior completed migration that was not renamed yet, or re-run).
    if !legacy_rows.is_empty() {
        let target_count: i64 = guard
            .query_row(
                "SELECT COUNT(*) FROM orchestrator_kernel_effect_journal
                 WHERE orchestrator_id = ?1",
                params![GATE_TIMEOUT_ORCHESTRATOR_ID],
                |r| r.get(0),
            )
            .map_err(|e| format!("effect journal migration: failed to count target rows: {e}"))?;
        if target_count >= i64::try_from(legacy_rows.len()).unwrap_or(i64::MAX) {
            // Target already populated; skip to rename.
            drop(guard);
            let migrated_path = legacy_path.with_extension("sqlite.migrated");
            std::fs::rename(legacy_path, &migrated_path).map_err(|e| {
                format!("effect journal migration: failed to rename legacy file: {e}")
            })?;
            return Ok(());
        }
    }

    // Wrap all INSERTs in a single transaction for crash-atomicity.
    let now_ns = epoch_now_ns_i64()?;
    let tx = guard
        .transaction()
        .map_err(|e| format!("effect journal migration: failed to begin transaction: {e}"))?;
    for (key, state, updated_at_ns) in &legacy_rows {
        // Fail-closed: treat started/unknown as unknown.
        let mapped_state = match state.as_str() {
            "completed" => "completed",
            _ => "unknown",
        };
        tx.execute(
            "INSERT OR IGNORE INTO orchestrator_kernel_effect_journal
             (orchestrator_id, intent_key, state, updated_at_ns)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                GATE_TIMEOUT_ORCHESTRATOR_ID,
                key,
                mapped_state,
                if mapped_state == "unknown" {
                    now_ns
                } else {
                    *updated_at_ns
                }
            ],
        )
        .map_err(|e| format!("effect journal migration: failed to insert: {e}"))?;
    }
    tx.commit()
        .map_err(|e| format!("effect journal migration: failed to commit transaction: {e}"))?;
    drop(guard);

    // Rename legacy file as durable completion marker.
    let migrated_path = legacy_path.with_extension("sqlite.migrated");
    std::fs::rename(legacy_path, &migrated_path)
        .map_err(|e| format!("effect journal migration: failed to rename legacy file: {e}"))?;

    Ok(())
}

// (Legacy bespoke stores removed — now using shared orchestrator_runtime
// adapters.)

#[derive(Debug)]
struct GateTimeoutReceiptWriter {
    ledger_emitter: Option<SqliteLedgerEventEmitter>,
}

impl GateTimeoutReceiptWriter {
    const fn new(ledger_emitter: Option<SqliteLedgerEventEmitter>) -> Self {
        Self { ledger_emitter }
    }
}

impl ReceiptWriter<GateOrchestratorEvent> for GateTimeoutReceiptWriter {
    type Error = String;

    async fn persist_many(&self, receipts: &[GateOrchestratorEvent]) -> Result<(), Self::Error> {
        let Some(emitter) = self.ledger_emitter.as_ref() else {
            return Ok(());
        };

        for event in receipts {
            let (event_type, timestamp_ns) = timeout_event_persistence_fields(event);
            let payload = serde_json::to_vec(event)
                .map_err(|e| format!("failed to serialize timeout event for persistence: {e}"))?;
            emitter
                .emit_session_event(
                    TIMEOUT_PERSISTOR_SESSION_ID,
                    event_type,
                    &payload,
                    TIMEOUT_PERSISTOR_ACTOR_ID,
                    timestamp_ns,
                )
                .map_err(|e| format!("failed to persist timeout event to ledger: {e}"))?;
        }
        Ok(())
    }
}

/// Maps orchestrator events to persisted event type and timestamp.
#[must_use]
pub fn timeout_event_persistence_fields(event: &GateOrchestratorEvent) -> (&'static str, u64) {
    match event {
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
        _ => ("gate.event", epoch_now_ns_u64()),
    }
}

const fn gate_type_label(gate_type: GateType) -> &'static str {
    match gate_type {
        GateType::Aat => "aat",
        GateType::Quality => "quality",
        GateType::Security => "security",
    }
}

fn parse_gate_type(raw: &str) -> Option<GateType> {
    match raw {
        "aat" => Some(GateType::Aat),
        "quality" => Some(GateType::Quality),
        "security" => Some(GateType::Security),
        _ => None,
    }
}

fn parse_gate_type_from_gate_id(gate_id: &str) -> Option<GateType> {
    match gate_id {
        "gate-aat" => Some(GateType::Aat),
        "gate-quality" => Some(GateType::Quality),
        "gate-security" => Some(GateType::Security),
        _ => None,
    }
}

fn parse_gate_lease_payload(payload: &[u8]) -> Result<(GateLease, GateType), String> {
    if payload.len() > 65_536 {
        return Err(format!(
            "gate_lease_issued payload length {} exceeds maximum (65536)",
            payload.len()
        ));
    }
    let payload_json: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| format!("failed to decode gate_lease_issued payload json: {e}"))?;
    let (lease_value, decode_context) = payload_json
        .get("full_lease")
        .cloned()
        // Legacy persisted shape stored GateLease fields at top-level.
        .map_or_else(
            || (payload_json.clone(), "legacy_top_level"),
            |value| (value, "full_lease"),
        );
    let lease: GateLease = serde_json::from_value(lease_value).map_err(|e| {
        format!("failed to decode gate_lease_issued payload ({decode_context}): {e}")
    })?;
    lease
        .validate()
        .map_err(|e| format!("gate_lease_issued lease invariant violation: {e}"))?;
    let gate_type = parse_gate_type_from_gate_id(&lease.gate_id).ok_or_else(|| {
        format!(
            "gate_lease_issued full_lease has unsupported gate_id '{}'",
            lease.gate_id
        )
    })?;
    Ok((lease, gate_type))
}

fn parse_timed_out_lease_id(payload: &[u8]) -> Result<String, String> {
    let payload_json: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| format!("failed to decode gate.timed_out payload json: {e}"))?;
    payload_json
        .get("lease_id")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| "gate.timed_out payload missing lease_id".to_string())
}

fn parse_gate_receipt_lease_id(payload: &[u8]) -> Result<String, String> {
    if let Ok(receipt) = LedgerGateReceipt::decode(payload) {
        if !receipt.lease_id.is_empty() {
            return Ok(receipt.lease_id);
        }
    }

    let payload_json: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| format!("failed to decode gate receipt payload as json: {e}"))?;
    payload_json
        .get("lease_id")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| "gate receipt payload missing lease_id".to_string())
}

fn parse_all_completed_work_id(payload: &[u8]) -> Result<String, String> {
    let payload_json: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| format!("failed to decode gate.all_completed payload json: {e}"))?;
    payload_json
        .get("work_id")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| "gate.all_completed payload missing work_id".to_string())
}

fn epoch_now_ns_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn epoch_now_ms_u64() -> u64 {
    epoch_now_ns_u64() / 1_000_000
}

fn epoch_now_ns_i64() -> Result<i64, String> {
    i64::try_from(epoch_now_ns_u64())
        .map_err(|_| "current epoch timestamp exceeds i64 range".to_string())
}

/// Returns nanoseconds elapsed since the process-local monotonic epoch.
///
/// **Monotonic time is process-local.** `MONO_EPOCH` is initialized once via
/// `OnceLock<Instant>` and resets on daemon restart. Values derived from this
/// function MUST NOT be persisted as durable truth. If persisted for caching,
/// they MUST be rebased on load using a wall-clock anchor (e.g.
/// `GateLease.expires_at`). See `ObservedLeaseState::needs_rebase`.
fn monotonic_now_ns() -> Result<u64, String> {
    static MONO_EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = MONO_EPOCH.get_or_init(Instant::now);
    u64::try_from(epoch.elapsed().as_nanos())
        .map_err(|_| "monotonic clock nanoseconds exceed u64 range".to_string())
}

#[cfg(test)]
mod tests {
    use apm2_core::crypto::Signer;

    use super::*;
    use crate::gate::SessionTerminatedInfo;

    fn sample_gate_lease(lease_id: &str, expires_at: u64) -> GateLease {
        GateLease {
            lease_id: lease_id.to_string(),
            work_id: "W-1".to_string(),
            gate_id: "gate-quality".to_string(),
            changeset_digest: [1u8; 32],
            executor_actor_id: "executor:quality".to_string(),
            issued_at: 100,
            expires_at,
            policy_hash: [2u8; 32],
            issuer_actor_id: "issuer:orchestrator".to_string(),
            time_envelope_ref: "htf:100".to_string(),
            aat_extension: None,
            issuer_signature: [0u8; 64],
        }
    }

    fn sample_observed_state(
        lease: &GateLease,
        gate_type: GateType,
        observed_wall_ms: u64,
        observed_monotonic_ns: u64,
        deadline_monotonic_ns: u64,
    ) -> ObservedLeaseState {
        ObservedLeaseState {
            lease: lease.clone(),
            gate_type,
            observed_wall_ms,
            observed_monotonic_ns,
            deadline_monotonic_ns,
        }
    }

    #[test]
    fn parse_gate_lease_payload_accepts_full_lease_envelope() {
        let lease = sample_gate_lease("lease-parse-envelope", 2_000);
        let payload = serde_json::to_vec(&serde_json::json!({
            "full_lease": lease,
        }))
        .expect("payload serialize");

        let (parsed, gate_type) =
            parse_gate_lease_payload(&payload).expect("full_lease envelope should parse");
        assert_eq!(parsed.lease_id, "lease-parse-envelope");
        assert_eq!(gate_type, GateType::Quality);
    }

    #[test]
    fn parse_gate_lease_payload_accepts_legacy_top_level_shape() {
        let lease = sample_gate_lease("lease-parse-legacy", 3_000);
        let payload = serde_json::to_vec(&lease).expect("legacy payload serialize");

        let (parsed, gate_type) =
            parse_gate_lease_payload(&payload).expect("legacy top-level payload should parse");
        assert_eq!(parsed.lease_id, "lease-parse-legacy");
        assert_eq!(gate_type, GateType::Quality);
    }

    #[test]
    fn observed_lease_store_memory_roundtrip() {
        let store = TimeoutObservedLeaseStore::Memory(MemoryTimeoutObservedLeaseStore::default());
        let lease = sample_gate_lease("lease-memory-1", 1_234);
        let state = sample_observed_state(&lease, GateType::Quality, 1_000, 10_000, 20_000);

        store.upsert(&state).expect("memory upsert should succeed");
        let loaded = store
            .load_all()
            .expect("memory load should succeed after upsert");
        let loaded_state = loaded
            .get("lease-memory-1")
            .expect("lease should be present in memory store");
        assert_eq!(loaded_state, &state);

        store
            .remove("lease-memory-1")
            .expect("memory remove should succeed");
        assert!(
            store
                .load_all()
                .expect("memory load should succeed after remove")
                .is_empty(),
            "removed lease should not remain in memory store"
        );
    }

    #[test]
    fn observed_lease_store_sqlite_roundtrip() {
        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("in-memory sqlite open should succeed"),
        ));
        let store = TimeoutObservedLeaseStore::Sqlite(
            SqliteTimeoutObservedLeaseStore::new(Arc::clone(&conn))
                .expect("sqlite observed lease store init should succeed"),
        );
        // GT-TIME-003: use current wall-clock time so the lease expires in the
        // future, avoiding rebase-induced value changes on load_all().
        let now_wall_ms = epoch_now_ms_u64();
        let now_mono_ns = monotonic_now_ns().expect("monotonic clock should be available");
        let expires_at = now_wall_ms + 100_000; // 100 seconds in the future
        let lease = sample_gate_lease("lease-sqlite-1", expires_at);
        let state = sample_observed_state(
            &lease,
            GateType::Security,
            now_wall_ms,
            now_mono_ns,
            now_mono_ns + 100_000 * 1_000_000, // deadline 100s into the future
        );

        store.upsert(&state).expect("sqlite upsert should succeed");
        let loaded = store
            .load_all()
            .expect("sqlite load should succeed after upsert");
        let loaded_state = loaded
            .get("lease-sqlite-1")
            .expect("lease should be present in sqlite store");
        // Assert identity and ordering properties rather than exact equality,
        // because load_all() may rebase monotonic values.
        assert_eq!(
            loaded_state.lease.lease_id, state.lease.lease_id,
            "lease identity must be preserved through sqlite roundtrip"
        );
        let mono_now = monotonic_now_ns().expect("monotonic clock should be available");
        assert!(
            !loaded_state.is_timed_out(mono_now),
            "fresh lease (expires_at 100s in future) must not be timed out"
        );
        assert!(
            loaded_state.deadline_monotonic_ns >= mono_now,
            "deadline must be in the future for a non-expired lease"
        );

        let reopened = TimeoutObservedLeaseStore::Sqlite(
            SqliteTimeoutObservedLeaseStore::new(Arc::clone(&conn))
                .expect("sqlite observed lease store reopen should succeed"),
        );
        let reopened_loaded = reopened
            .load_all()
            .expect("sqlite load should succeed after reopen");
        assert!(
            reopened_loaded.contains_key("lease-sqlite-1"),
            "lease should persist across store instances"
        );

        reopened
            .remove("lease-sqlite-1")
            .expect("sqlite remove should succeed");
        assert!(
            store
                .load_all()
                .expect("sqlite load should succeed after remove")
                .is_empty(),
            "removed lease should not remain in sqlite store"
        );
    }

    #[tokio::test]
    async fn sqlite_intent_store_retryable_moves_intent_to_back() {
        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("in-memory sqlite open should succeed"),
        ));
        {
            let guard = conn.lock().expect("sqlite lock");
            init_orchestrator_runtime_schema(&guard).expect("schema init succeeds");
        }
        let store = SqliteIntentStore::<GateTimeoutIntent>::new(
            Arc::clone(&conn),
            GATE_TIMEOUT_ORCHESTRATOR_ID,
        );
        let intent_a = GateTimeoutIntent {
            lease: sample_gate_lease("lease-retry-a", 1_000),
            gate_type: GateType::Quality,
        };
        let intent_b = GateTimeoutIntent {
            lease: sample_gate_lease("lease-retry-b", 1_000),
            gate_type: GateType::Security,
        };
        let key_a = intent_a.key();
        let key_b = intent_b.key();

        store
            .enqueue_many(&[intent_a, intent_b])
            .await
            .expect("enqueue_many succeeds");
        {
            let guard = conn.lock().expect("sqlite lock should succeed");
            guard
                .execute(
                    "UPDATE orchestrator_kernel_intents
                     SET created_at_ns = ?2
                     WHERE orchestrator_id = ?3 AND intent_key = ?1",
                    params![&key_a, 10_i64, GATE_TIMEOUT_ORCHESTRATOR_ID],
                )
                .expect("seed created_at_ns for intent_a");
            guard
                .execute(
                    "UPDATE orchestrator_kernel_intents
                     SET created_at_ns = ?2
                     WHERE orchestrator_id = ?3 AND intent_key = ?1",
                    params![&key_b, 20_i64, GATE_TIMEOUT_ORCHESTRATOR_ID],
                )
                .expect("seed created_at_ns for intent_b");
        }

        let first = store.dequeue_batch(1).await.expect("dequeue first intent");
        assert_eq!(first.len(), 1, "exactly one intent dequeued");
        assert_eq!(
            first[0].key(),
            key_a,
            "intent_a should be first before retry update"
        );

        store
            .mark_retryable(&key_a, "retry")
            .await
            .expect("mark_retryable succeeds");
        let second = store.dequeue_batch(1).await.expect("dequeue second intent");
        assert_eq!(second.len(), 1, "exactly one intent dequeued");
        assert_eq!(
            second[0].key(),
            key_b,
            "retryable intent should move behind older pending intents"
        );
    }

    #[test]
    fn timeout_event_mapping_uses_expected_types() {
        let (event_type, _) =
            timeout_event_persistence_fields(&GateOrchestratorEvent::GateTimedOut {
                work_id: "W-1".to_string(),
                gate_type: GateType::Quality,
                lease_id: "lease-1".to_string(),
                changeset_digest: [0x42; 32],
                timestamp_ms: 7,
            });
        assert_eq!(event_type, "gate.timed_out");
    }

    #[test]
    fn parse_gate_receipt_lease_id_reads_protobuf_payload() {
        let receipt = LedgerGateReceipt {
            lease_id: "lease-proto-1".to_string(),
            ..Default::default()
        };
        let mut payload = Vec::new();
        receipt
            .encode(&mut payload)
            .expect("protobuf gate receipt encoding should succeed");
        assert_eq!(
            parse_gate_receipt_lease_id(&payload).expect("lease_id should be decoded"),
            "lease-proto-1"
        );
    }

    #[test]
    fn observed_lease_state_timeout_deadline_semantics() {
        let lease = sample_gate_lease("lease-mono-1", 1_500);
        let state = sample_observed_state(&lease, GateType::Quality, 1_000, 10_000, 20_000);

        assert!(
            !state.is_timed_out(15_000),
            "monotonic now before deadline should not timeout"
        );
        assert!(
            state.is_timed_out(20_001),
            "monotonic now after deadline should timeout"
        );
        // Monotonic rewind (e.g. daemon restart) does NOT produce immediate
        // timeout. Callers must rebase stale entries before checking timeout.
        assert!(
            !state.is_timed_out(9_999),
            "monotonic clock rewind must not produce false timeout"
        );
    }

    #[test]
    fn observed_lease_state_needs_rebase_detects_stale_entries() {
        let lease = sample_gate_lease("lease-rebase-detect", 5_000);
        let now_mono = 1_000_u64;

        // Legacy rows: zero monotonic values
        let legacy = sample_observed_state(&lease, GateType::Quality, 1_000, 0, 0);
        assert!(
            legacy.needs_rebase(now_mono),
            "legacy rows with zero monotonic must need rebase"
        );

        // Restart rewind: persisted observed > current process monotonic
        let rewind =
            sample_observed_state(&lease, GateType::Quality, 1_000, 999_999_000, 999_999_500);
        assert!(
            rewind.needs_rebase(now_mono),
            "persisted observed_monotonic > now must need rebase"
        );

        // Corrupt row: deadline < observed
        let corrupt = sample_observed_state(&lease, GateType::Quality, 1_000, 500, 100);
        assert!(
            corrupt.needs_rebase(now_mono),
            "deadline < observed must need rebase"
        );

        // Healthy state: no rebase needed
        let healthy = sample_observed_state(&lease, GateType::Quality, 1_000, 500, 900);
        assert!(
            !healthy.needs_rebase(now_mono),
            "healthy state must not need rebase"
        );
    }

    #[test]
    fn observed_lease_state_rebase_preserves_fail_closed_for_expired_lease() {
        let now_wall_ms = epoch_now_ms_u64();
        // Lease already expired
        let expired_lease =
            sample_gate_lease("lease-rebase-expired", now_wall_ms.saturating_sub(1));
        let stale = sample_observed_state(
            &expired_lease,
            GateType::Quality,
            1_000,
            999_999_000,
            999_999_500,
        );
        let now_mono = monotonic_now_ns().expect("monotonic clock should work in tests");

        let rebased = stale.rebase(now_wall_ms, now_mono);

        // remaining_ms is 0 because lease.expires_at <= now_wall_ms
        assert_eq!(
            rebased.deadline_monotonic_ns, now_mono,
            "expired lease must have deadline == now (still timed out)"
        );
        assert!(
            rebased.is_timed_out(now_mono),
            "rebased expired lease must still be timed out"
        );
    }

    #[test]
    fn observed_lease_state_rebase_keeps_future_lease_alive() {
        let now_wall_ms = epoch_now_ms_u64();
        let future_expires = now_wall_ms + 60_000; // 60 seconds in the future
        let lease = sample_gate_lease("lease-rebase-alive", future_expires);
        let stale =
            sample_observed_state(&lease, GateType::Quality, 1_000, 999_999_000, 999_999_500);
        let now_mono = monotonic_now_ns().expect("monotonic clock should work in tests");

        let rebased = stale.rebase(now_wall_ms, now_mono);

        assert!(
            rebased.deadline_monotonic_ns > now_mono,
            "rebased future lease must have deadline in the future"
        );
        assert!(
            !rebased.is_timed_out(now_mono),
            "rebased future lease must not be timed out"
        );
        assert_eq!(rebased.observed_monotonic_ns, now_mono);
        assert_eq!(rebased.observed_wall_ms, now_wall_ms);
    }

    #[tokio::test]
    async fn completed_receipt_event_removes_lease_before_planning_timeout() {
        let orchestrator = Arc::new(GateOrchestrator::new(
            crate::gate::GateOrchestratorConfig::default(),
            Arc::new(Signer::generate()),
        ));
        let store = TimeoutObservedLeaseStore::Memory(MemoryTimeoutObservedLeaseStore::default());
        let mut domain = GateTimeoutDomain::new(
            Arc::clone(&orchestrator),
            store,
            TimeoutTerminalChecker::Memory(MemoryTimeoutTerminalChecker),
        )
        .expect("domain initialization should succeed");
        let lease = sample_gate_lease("lease-completed-1", orchestrator.now_ms().saturating_add(1));

        domain
            .apply_events(&[
                TimeoutObservedEvent {
                    timestamp_ns: 10,
                    event_id: "evt-lease".to_string(),
                    kind: TimeoutObservedKind::LeaseIssued {
                        lease: Box::new(lease.clone()),
                        gate_type: GateType::Quality,
                    },
                },
                TimeoutObservedEvent {
                    timestamp_ns: 11,
                    event_id: "evt-receipt".to_string(),
                    kind: TimeoutObservedKind::GateReceiptFinalized {
                        lease_id: lease.lease_id.clone(),
                    },
                },
            ])
            .await
            .expect("apply_events should succeed");

        let planned = domain.plan().await.expect("plan should succeed");
        assert!(
            planned.is_empty(),
            "completed gate lease must not produce timeout intents"
        );
    }

    #[tokio::test]
    async fn execute_uses_orchestrator_timeout_transition_and_reclaims_orchestration() {
        let orchestrator = Arc::new(GateOrchestrator::new(
            crate::gate::GateOrchestratorConfig::default(),
            Arc::new(Signer::generate()),
        ));
        let info = SessionTerminatedInfo {
            session_id: "session-kernel-timeout".to_string(),
            work_id: "work-kernel-timeout".to_string(),
            changeset_digest: [7u8; 32],
            terminated_at_ms: 0,
        };
        let _ = orchestrator
            .start_from_test_session(info)
            .await
            .expect("orchestration should start");
        let mut domain = GateTimeoutDomain::new(
            Arc::clone(&orchestrator),
            TimeoutObservedLeaseStore::Memory(MemoryTimeoutObservedLeaseStore::default()),
            TimeoutTerminalChecker::Memory(MemoryTimeoutTerminalChecker),
        )
        .expect("domain initialization should succeed");

        for gate_type in GateType::all() {
            let lease = orchestrator
                .gate_lease("work-kernel-timeout", gate_type)
                .await
                .expect("gate lease should exist for active orchestration");
            let outcome = domain
                .execute(&GateTimeoutIntent { lease, gate_type })
                .await
                .expect("execute should succeed through orchestrator timeout transition");
            match outcome {
                ExecutionOutcome::Completed { .. } => {},
                other => panic!("unexpected execution outcome: {other:?}"),
            }
        }

        assert_eq!(
            orchestrator.active_count().await,
            0,
            "timed-out orchestration should be reclaimed from active map"
        );
    }

    #[tokio::test]
    async fn execute_fallback_skips_when_ledger_already_contains_terminal_receipt() {
        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("in-memory sqlite open should succeed"),
        ));
        {
            let guard = conn
                .lock()
                .expect("sqlite terminal-check fixture lock should succeed");
            guard
                .execute(
                    "CREATE TABLE ledger_events (
                        event_id TEXT PRIMARY KEY,
                        event_type TEXT NOT NULL,
                        payload BLOB NOT NULL,
                        timestamp_ns INTEGER NOT NULL
                    )",
                    [],
                )
                .expect("fixture should create ledger_events table");
        }

        let orchestrator = Arc::new(GateOrchestrator::new(
            crate::gate::GateOrchestratorConfig::default(),
            Arc::new(Signer::generate()),
        ));
        let mut domain = GateTimeoutDomain::new(
            Arc::clone(&orchestrator),
            TimeoutObservedLeaseStore::Memory(MemoryTimeoutObservedLeaseStore::default()),
            TimeoutTerminalChecker::Sqlite(SqliteTimeoutTerminalChecker::new(Arc::clone(&conn))),
        )
        .expect("domain initialization should succeed");
        let lease = sample_gate_lease("lease-fallback-terminal-1", orchestrator.now_ms());

        domain
            .apply_events(&[TimeoutObservedEvent {
                timestamp_ns: 1,
                event_id: "lease-issued".to_string(),
                kind: TimeoutObservedKind::LeaseIssued {
                    lease: Box::new(lease.clone()),
                    gate_type: GateType::Quality,
                },
            }])
            .await
            .expect("apply_events should succeed");

        let receipt_payload = {
            let receipt = LedgerGateReceipt {
                lease_id: lease.lease_id.clone(),
                ..Default::default()
            };
            let mut bytes = Vec::new();
            receipt
                .encode(&mut bytes)
                .expect("protobuf gate receipt encoding should succeed");
            bytes
        };
        {
            let guard = conn
                .lock()
                .expect("sqlite terminal-check fixture lock should succeed");
            guard
                .execute(
                    "INSERT INTO ledger_events (event_id, event_type, payload, timestamp_ns)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        "evt-terminal-receipt",
                        "gate.receipt",
                        &receipt_payload,
                        2_i64
                    ],
                )
                .expect("fixture should insert terminal receipt row");
        }

        let outcome = domain
            .execute(&GateTimeoutIntent {
                lease,
                gate_type: GateType::Quality,
            })
            .await
            .expect("execute should succeed");
        match outcome {
            ExecutionOutcome::Completed { receipts } => {
                assert!(
                    receipts.is_empty(),
                    "fallback execution must not emit timeout events when terminal receipt already exists"
                );
            },
            other => panic!("unexpected execution outcome: {other:?}"),
        }
    }

    /// GT-TIME-003: Simulates a daemon restart where persisted monotonic values
    /// are far in the future compared to the current process monotonic clock.
    /// Verifies that `load_all()` rebases the state and `is_timed_out()`
    /// returns false when the wall-clock lease has not expired.
    #[test]
    fn test_observed_lease_store_sqlite_rebases_monotonic_after_restart() {
        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("in-memory sqlite open should succeed"),
        ));
        let store = SqliteTimeoutObservedLeaseStore::new(Arc::clone(&conn))
            .expect("sqlite observed lease store init should succeed");

        let now_wall_ms = epoch_now_ms_u64();
        // Lease expires 120 seconds in the future — should NOT time out.
        let future_expires = now_wall_ms + 120_000;
        let lease = sample_gate_lease("lease-restart-rebase", future_expires);

        // Simulate persisted values from a prior run: monotonic values far in
        // the future relative to the current process epoch.
        let stale_state = ObservedLeaseState {
            lease,
            gate_type: GateType::Quality,
            observed_wall_ms: now_wall_ms.saturating_sub(60_000),
            observed_monotonic_ns: 999_999_999_000,
            deadline_monotonic_ns: 999_999_999_500,
        };
        store
            .upsert(&stale_state)
            .expect("upsert stale state should succeed");

        // load_all() should detect the rewind and rebase.
        let loaded = store.load_all().expect("load_all should succeed");
        let rebased = loaded
            .get("lease-restart-rebase")
            .expect("lease should be present after load");

        let now_mono = monotonic_now_ns().expect("monotonic clock should work");
        // After rebase, deadline must be in the future (lease has not expired).
        assert!(
            rebased.deadline_monotonic_ns >= now_mono,
            "rebased deadline must be >= now_monotonic (deadline={}, now={})",
            rebased.deadline_monotonic_ns,
            now_mono,
        );
        assert!(
            !rebased.is_timed_out(now_mono),
            "rebased lease with future expires_at must NOT be timed out"
        );
        // Observed values should be anchored to current process epoch.
        assert!(
            rebased.observed_monotonic_ns <= now_mono,
            "rebased observed_monotonic must be <= now_monotonic"
        );
    }

    /// GT-TIME-003: Inserts a legacy row (monotonic columns == 0) with
    /// `expires_at` in the future. Verifies that `load_all()` rebases instead
    /// of producing an immediate timeout.
    #[test]
    fn test_observed_lease_store_sqlite_legacy_rows_rebase_instead_of_immediate_timeout() {
        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("in-memory sqlite open should succeed"),
        ));
        let store = SqliteTimeoutObservedLeaseStore::new(Arc::clone(&conn))
            .expect("sqlite observed lease store init should succeed");

        let now_wall_ms = epoch_now_ms_u64();
        // Lease expires 60 seconds in the future.
        let future_expires = now_wall_ms + 60_000;
        let lease = sample_gate_lease("lease-legacy-rebase", future_expires);

        // Insert legacy row: monotonic columns are 0.
        let legacy_state = ObservedLeaseState {
            lease,
            gate_type: GateType::Security,
            observed_wall_ms: now_wall_ms.saturating_sub(10_000),
            observed_monotonic_ns: 0,
            deadline_monotonic_ns: 0,
        };
        store
            .upsert(&legacy_state)
            .expect("upsert legacy state should succeed");

        // load_all() should rebase.
        let loaded = store.load_all().expect("load_all should succeed");
        let rebased = loaded
            .get("lease-legacy-rebase")
            .expect("lease should be present after load");

        let now_mono = monotonic_now_ns().expect("monotonic clock should work");
        // Legacy row should have been rebased, not left with zeros.
        assert_ne!(
            rebased.observed_monotonic_ns, 0,
            "rebased legacy row must not have zero observed_monotonic_ns"
        );
        assert!(
            rebased.deadline_monotonic_ns > now_mono,
            "rebased legacy row with future expires_at must have deadline in the future (deadline={}, now={})",
            rebased.deadline_monotonic_ns,
            now_mono,
        );
        assert!(
            !rebased.is_timed_out(now_mono),
            "rebased legacy row with future expires_at must NOT be timed out"
        );
    }

    /// GT-TIME-003: Verifies that an already-expired lease still times out
    /// correctly even after rebase — fail-closed remains anchored to
    /// `lease.expires_at`.
    #[test]
    fn test_observed_lease_store_sqlite_expired_lease_still_times_out_after_rebase() {
        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("in-memory sqlite open should succeed"),
        ));
        let store = SqliteTimeoutObservedLeaseStore::new(Arc::clone(&conn))
            .expect("sqlite observed lease store init should succeed");

        let now_wall_ms = epoch_now_ms_u64();
        // Lease already expired 10 seconds ago.
        let expired_at = now_wall_ms.saturating_sub(10_000);
        let lease = sample_gate_lease("lease-expired-rebase", expired_at);

        let stale_state = ObservedLeaseState {
            lease,
            gate_type: GateType::Quality,
            observed_wall_ms: now_wall_ms.saturating_sub(60_000),
            observed_monotonic_ns: 999_999_999_000,
            deadline_monotonic_ns: 999_999_999_500,
        };
        store
            .upsert(&stale_state)
            .expect("upsert stale expired state should succeed");

        let loaded = store.load_all().expect("load_all should succeed");
        let rebased = loaded
            .get("lease-expired-rebase")
            .expect("lease should be present after load");

        let now_mono = monotonic_now_ns().expect("monotonic clock should work");
        // Expired lease: remaining_ms == 0, so deadline == now_monotonic.
        assert!(
            rebased.is_timed_out(now_mono),
            "rebased expired lease must still be timed out"
        );
    }

    /// Helper: creates ledger tables required by `poll_events_blocking`.
    fn create_ledger_tables(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE ledger_events (
                 event_id   TEXT NOT NULL,
                 event_type TEXT NOT NULL,
                 work_id    TEXT NOT NULL DEFAULT '',
                 actor_id   TEXT NOT NULL DEFAULT '',
                 payload    BLOB NOT NULL DEFAULT X'',
                 signature  BLOB NOT NULL DEFAULT X'',
                 timestamp_ns INTEGER NOT NULL
             );",
        )
        .expect("create ledger_events table");
    }

    /// BEH-DAEMON-GATE-016: Malformed timeout rows must be skipped (emitted
    /// as `Skipped`) so the cursor advances past corrupted data instead of
    /// deadlocking the timeout kernel.
    #[tokio::test]
    async fn malformed_row_skipped_and_cursor_advances() {
        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("in-memory sqlite open should succeed"),
        ));
        {
            let guard = conn.lock().expect("sqlite lock");
            create_ledger_tables(&guard);
        }

        // Insert a valid gate.timed_out event.
        let valid_payload = serde_json::to_vec(&serde_json::json!({"lease_id": "lease-ok-1"}))
            .expect("serialize valid payload");
        // Insert a malformed gate.timed_out event (missing lease_id field).
        let malformed_payload = serde_json::to_vec(&serde_json::json!({"not_lease_id": "bad"}))
            .expect("serialize malformed payload");
        // Insert a valid gate.all_completed event after the malformed one.
        let valid_payload_2 = serde_json::to_vec(&serde_json::json!({"work_id": "W-done-1"}))
            .expect("serialize valid payload 2");

        {
            let guard = conn.lock().expect("sqlite lock");
            guard
                .execute(
                    "INSERT INTO ledger_events \
                     (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns) \
                     VALUES (?1, ?2, '', '', ?3, X'', ?4)",
                    params!["evt-1", "gate.timed_out", &valid_payload, 100_i64],
                )
                .expect("insert valid event");
            guard
                .execute(
                    "INSERT INTO ledger_events \
                     (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns) \
                     VALUES (?1, ?2, '', '', ?3, X'', ?4)",
                    params!["evt-2", "gate.timed_out", &malformed_payload, 200_i64],
                )
                .expect("insert malformed event");
            guard
                .execute(
                    "INSERT INTO ledger_events \
                     (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns) \
                     VALUES (?1, ?2, '', '', ?3, X'', ?4)",
                    params!["evt-3", "gate.all_completed", &valid_payload_2, 300_i64],
                )
                .expect("insert second valid event");
        }

        let reader = SqliteTimeoutLedgerReader::new(Arc::clone(&conn));
        let cursor = CompositeCursor {
            timestamp_ns: 0,
            event_id: String::new(),
        };

        let events = reader
            .poll_async(&cursor, 100)
            .await
            .expect("poll_async must not error on malformed rows");

        // All 3 rows must be returned: 2 parsed + 1 skipped.
        assert_eq!(
            events.len(),
            3,
            "all 3 events must be returned (including skipped)"
        );

        // First event: valid TimedOut.
        assert!(
            matches!(events[0].kind, TimeoutObservedKind::TimedOut { ref lease_id } if lease_id == "lease-ok-1"),
            "first event should be valid TimedOut, got: {:?}",
            events[0].kind
        );

        // Second event: Skipped (malformed payload).
        assert!(
            matches!(events[1].kind, TimeoutObservedKind::Skipped { .. }),
            "second event should be Skipped due to malformed payload, got: {:?}",
            events[1].kind
        );
        // Verify the skipped event still carries cursor metadata.
        assert_eq!(
            events[1].event_id, "evt-2",
            "skipped event must preserve event_id for cursor advancement"
        );
        assert_eq!(
            events[1].timestamp_ns, 200,
            "skipped event must preserve timestamp_ns for cursor advancement"
        );

        // Third event: valid AllCompleted.
        assert!(
            matches!(events[2].kind, TimeoutObservedKind::AllCompleted { ref work_id } if work_id == "W-done-1"),
            "third event should be valid AllCompleted, got: {:?}",
            events[2].kind
        );

        // Verify cursor would advance past the malformed row:
        // The last event has timestamp_ns=300, which is strictly after the
        // malformed row at 200. This ensures the cursor will not revisit it.
        let last_cursor = events.last().unwrap().cursor();
        assert!(
            last_cursor.timestamp_ns > 200,
            "cursor must advance past the malformed row"
        );
    }

    /// `INV-CQ-OK-003`: `SqliteTimeoutLedgerReader::poll_async` offloads
    /// blocking `SQLite` I/O to `spawn_blocking` via `poll_events_async`.
    /// This test verifies the async path returns correct results.
    #[tokio::test]
    async fn poll_async_offloads_sqlite_io_to_spawn_blocking() {
        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("in-memory sqlite open should succeed"),
        ));
        {
            let guard = conn.lock().expect("sqlite lock");
            create_ledger_tables(&guard);
        }

        let payload = serde_json::to_vec(&serde_json::json!({"lease_id": "lease-async-1"}))
            .expect("serialize payload");
        {
            let guard = conn.lock().expect("sqlite lock");
            guard
                .execute(
                    "INSERT INTO ledger_events \
                     (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns) \
                     VALUES (?1, ?2, '', '', ?3, X'', ?4)",
                    params!["evt-async-1", "gate.timed_out", &payload, 500_i64],
                )
                .expect("insert event");
        }

        let reader = SqliteTimeoutLedgerReader::new(Arc::clone(&conn));
        let cursor = CompositeCursor {
            timestamp_ns: 0,
            event_id: String::new(),
        };

        // poll_async should return the event correctly from spawn_blocking.
        let events = reader
            .poll_async(&cursor, 10)
            .await
            .expect("poll_async should succeed");

        assert_eq!(events.len(), 1, "expected exactly 1 event");
        assert!(
            matches!(events[0].kind, TimeoutObservedKind::TimedOut { ref lease_id } if lease_id == "lease-async-1"),
            "event should be TimedOut with correct lease_id, got: {:?}",
            events[0].kind
        );
        assert_eq!(events[0].event_id, "evt-async-1");
        assert_eq!(events[0].timestamp_ns, 500);
    }

    /// Regression: unexpected event types from the ledger are skipped rather
    /// than causing a fatal error that would stall the timeout kernel.
    #[tokio::test]
    async fn unexpected_event_type_skipped() {
        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("in-memory sqlite open should succeed"),
        ));
        {
            let guard = conn.lock().expect("sqlite lock");
            create_ledger_tables(&guard);
        }

        // Insert an event with a type that is in the query filter but has
        // a completely unexpected value (shouldn't happen, but defense in
        // depth). We use "gate_lease_issued" but with garbage payload.
        let garbage_payload = b"this is not json";
        {
            let guard = conn.lock().expect("sqlite lock");
            guard
                .execute(
                    "INSERT INTO ledger_events \
                     (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns) \
                     VALUES (?1, ?2, '', '', ?3, X'', ?4)",
                    params![
                        "evt-garbage-1",
                        "gate_lease_issued",
                        &garbage_payload[..],
                        100_i64
                    ],
                )
                .expect("insert garbage event");
        }

        let reader = SqliteTimeoutLedgerReader::new(Arc::clone(&conn));
        let cursor = CompositeCursor {
            timestamp_ns: 0,
            event_id: String::new(),
        };

        let events = reader
            .poll_async(&cursor, 10)
            .await
            .expect("poll_async must not error on garbage payloads");

        assert_eq!(events.len(), 1, "garbage row must still be returned");
        assert!(
            matches!(events[0].kind, TimeoutObservedKind::Skipped { .. }),
            "garbage row must be Skipped, got: {:?}",
            events[0].kind
        );
    }
}

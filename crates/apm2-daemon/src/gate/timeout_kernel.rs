//! Orchestrator-kernel reference migration for gate timeout progression.
//!
//! This module wires the existing `GateOrchestrator` timeout flow through the
//! shared `apm2_core::orchestrator_kernel` harness:
//! Observe -> Plan -> Execute -> Receipt.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use apm2_core::events::GateReceipt as LedgerGateReceipt;
use apm2_core::fac::GateLease;
use apm2_core::orchestrator_kernel::{
    CompositeCursor, CursorEvent, CursorStore, EffectExecutionState, EffectJournal,
    ExecutionOutcome, InDoubtResolution, IntentStore, LedgerReader, OrchestratorDomain,
    ReceiptWriter, TickConfig, TickReport, is_after_cursor, run_tick,
};
use prost::Message;
use rusqlite::{Connection, OptionalExtension, params};

use crate::gate::{GateOrchestrator, GateOrchestratorEvent, GateType};
use crate::ledger::SqliteLedgerEventEmitter;
use crate::protocol::dispatch::LedgerEventEmitter;

const TIMEOUT_CURSOR_KEY: i64 = 1;
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

/// Durable timeout-kernel runtime state.
pub struct GateTimeoutKernel {
    domain: GateTimeoutDomain,
    ledger_reader: TimeoutLedgerReader,
    cursor_store: TimeoutCursorStore,
    intent_store: TimeoutIntentStore,
    effect_journal: GateTimeoutEffectJournal,
    receipt_writer: GateTimeoutReceiptWriter,
    tick_config: TickConfig,
}

impl GateTimeoutKernel {
    /// Creates a new timeout kernel instance.
    pub fn new(
        orchestrator: Arc<GateOrchestrator>,
        sqlite_conn: Option<&Arc<Mutex<Connection>>>,
        timeout_ledger_emitter: Option<SqliteLedgerEventEmitter>,
        fac_root: &Path,
        config: GateTimeoutKernelConfig,
    ) -> Result<Self, GateTimeoutKernelError> {
        let cursor_store = if let Some(conn) = sqlite_conn {
            TimeoutCursorStore::Sqlite(SqliteTimeoutCursorStore::new(Arc::clone(conn)).map_err(
                |e| GateTimeoutKernelError::Init(format!("cursor store setup failed: {e}")),
            )?)
        } else {
            TimeoutCursorStore::Memory(MemoryTimeoutCursorStore::default())
        };

        let intent_store = if let Some(conn) = sqlite_conn {
            TimeoutIntentStore::Sqlite(SqliteTimeoutIntentStore::new(Arc::clone(conn)).map_err(
                |e| GateTimeoutKernelError::Init(format!("intent store setup failed: {e}")),
            )?)
        } else {
            TimeoutIntentStore::Memory(MemoryTimeoutIntentStore::default())
        };
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
        let journal_path = fac_root.join("gate_timeout_effect_journal.sqlite");
        let effect_journal =
            GateTimeoutEffectJournal::open(&journal_path).map_err(GateTimeoutKernelError::Init)?;
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
}

impl CursorEvent for TimeoutObservedEvent {
    fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    fn event_id(&self) -> &str {
        &self.event_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateTimeoutIntent {
    lease: GateLease,
    gate_type: GateType,
}

impl GateTimeoutIntent {
    fn key(&self) -> String {
        self.lease.lease_id.clone()
    }
}

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

    const fn is_timed_out(&self, monotonic_now_ns: u64) -> bool {
        if monotonic_now_ns < self.observed_monotonic_ns {
            return true;
        }
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
            let lease: GateLease = serde_json::from_str(&lease_json)
                .map_err(|e| format!("failed to decode observed lease json: {e}"))?;
            let observed_wall_ms = u64::try_from(observed_wall_ms_i64).unwrap_or(now_wall_ms);
            let observed_monotonic_ns = u64::try_from(observed_monotonic_ns_i64).unwrap_or(0);
            let deadline_monotonic_ns = u64::try_from(deadline_monotonic_ns_i64).unwrap_or(0);
            let state = if observed_monotonic_ns == 0 || deadline_monotonic_ns == 0 {
                // Legacy rows did not persist monotonic state; fail-closed by
                // making them immediately eligible for timeout.
                ObservedLeaseState {
                    lease,
                    gate_type,
                    observed_wall_ms: now_wall_ms,
                    observed_monotonic_ns: now_monotonic_ns,
                    deadline_monotonic_ns: now_monotonic_ns,
                }
            } else {
                ObservedLeaseState {
                    lease,
                    gate_type,
                    observed_wall_ms,
                    observed_monotonic_ns,
                    deadline_monotonic_ns,
                }
            };
            leases.insert(lease_id, state);
        }
        Ok(leases)
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
            }
        }
        Ok(())
    }

    async fn plan(&mut self) -> Result<Vec<GateTimeoutIntent>, Self::Error> {
        let monotonic_now_ns = monotonic_now_ns()?;
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
        Ok(timed_out.into_iter().collect())
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
    type Error = String;

    async fn poll(
        &self,
        cursor: &CompositeCursor,
        limit: usize,
    ) -> Result<Vec<TimeoutObservedEvent>, Self::Error> {
        match self {
            Self::Sqlite(reader) => reader.poll(cursor, limit),
            Self::Memory(_reader) => Ok(Vec::new()),
        }
    }
}

#[derive(Debug)]
struct SqliteTimeoutLedgerReader {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteTimeoutLedgerReader {
    const fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    fn poll(
        &self,
        cursor: &CompositeCursor,
        limit: usize,
    ) -> Result<Vec<TimeoutObservedEvent>, String> {
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
        out.extend(Self::query_lease_issued_legacy(
            &guard,
            cursor_ts_i64,
            &cursor.event_id,
            limit_i64,
        )?);
        out.extend(Self::query_lease_issued_canonical(
            &guard,
            cursor_ts_i64,
            &cursor.event_id,
            limit_i64,
        )?);
        out.extend(Self::query_timed_out_legacy(
            &guard,
            cursor_ts_i64,
            &cursor.event_id,
            limit_i64,
        )?);
        out.extend(Self::query_timed_out_canonical(
            &guard,
            cursor_ts_i64,
            &cursor.event_id,
            limit_i64,
        )?);
        out.extend(Self::query_gate_receipt_legacy(
            &guard,
            cursor_ts_i64,
            &cursor.event_id,
            limit_i64,
        )?);
        out.extend(Self::query_gate_receipt_canonical(
            &guard,
            cursor_ts_i64,
            &cursor.event_id,
            limit_i64,
        )?);
        out.extend(Self::query_all_completed_legacy(
            &guard,
            cursor_ts_i64,
            &cursor.event_id,
            limit_i64,
        )?);
        out.extend(Self::query_all_completed_canonical(
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

    fn query_lease_issued_legacy(
        conn: &Connection,
        cursor_ts_i64: i64,
        cursor_event_id: &str,
        limit_i64: i64,
    ) -> Result<Vec<TimeoutObservedEvent>, String> {
        let query = if cursor_event_id.is_empty() {
            "SELECT event_id, payload, timestamp_ns
             FROM ledger_events
             WHERE event_type = 'gate_lease_issued' AND timestamp_ns > ?1
             ORDER BY timestamp_ns ASC, event_id ASC
             LIMIT ?2"
        } else {
            "SELECT event_id, payload, timestamp_ns
             FROM ledger_events
             WHERE event_type = 'gate_lease_issued'
               AND (timestamp_ns > ?1 OR (timestamp_ns = ?1 AND event_id > ?2))
             ORDER BY timestamp_ns ASC, event_id ASC
             LIMIT ?3"
        };
        let mut stmt = conn
            .prepare(query)
            .map_err(|e| format!("failed to prepare legacy lease query: {e}"))?;
        let mut rows = if cursor_event_id.is_empty() {
            stmt.query(params![cursor_ts_i64, limit_i64])
        } else {
            stmt.query(params![cursor_ts_i64, cursor_event_id, limit_i64])
        }
        .map_err(|e| format!("failed to execute legacy lease query: {e}"))?;

        let mut out = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| format!("failed to iterate legacy lease rows: {e}"))?
        {
            let event_id: String = row
                .get(0)
                .map_err(|e| format!("failed to decode legacy lease event_id: {e}"))?;
            let payload: Vec<u8> = row
                .get(1)
                .map_err(|e| format!("failed to decode legacy lease payload: {e}"))?;
            let ts_i64: i64 = row
                .get(2)
                .map_err(|e| format!("failed to decode legacy lease timestamp: {e}"))?;
            let timestamp_ns = u64::try_from(ts_i64)
                .map_err(|_| "legacy lease timestamp is negative".to_string())?;
            let (lease, gate_type) = parse_gate_lease_payload(&payload)?;
            out.push(TimeoutObservedEvent {
                timestamp_ns,
                event_id,
                kind: TimeoutObservedKind::LeaseIssued {
                    lease: Box::new(lease),
                    gate_type,
                },
            });
        }
        Ok(out)
    }

    fn query_lease_issued_canonical(
        conn: &Connection,
        cursor_ts_i64: i64,
        cursor_event_id: &str,
        limit_i64: i64,
    ) -> Result<Vec<TimeoutObservedEvent>, String> {
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
             WHERE event_type = 'gate_lease_issued' AND timestamp_ns > ?1
             ORDER BY timestamp_ns ASC, seq_id ASC
             LIMIT ?2"
        } else {
            "SELECT seq_id, payload, timestamp_ns
             FROM events
             WHERE event_type = 'gate_lease_issued'
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
            .map_err(|e| format!("failed to prepare canonical lease query: {e}"))?;
        let mut rows = if cursor_event_id.is_empty() {
            stmt.query(params![cursor_ts_i64, limit_i64])
        } else {
            stmt.query(params![cursor_ts_i64, cursor_event_id, limit_i64])
        }
        .map_err(|e| format!("failed to execute canonical lease query: {e}"))?;

        let mut out = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| format!("failed to iterate canonical lease rows: {e}"))?
        {
            let seq_id: i64 = row
                .get(0)
                .map_err(|e| format!("failed to decode canonical seq_id: {e}"))?;
            let payload: Vec<u8> = row
                .get(1)
                .map_err(|e| format!("failed to decode canonical lease payload: {e}"))?;
            let ts_i64: i64 = row
                .get(2)
                .map_err(|e| format!("failed to decode canonical lease timestamp: {e}"))?;
            let timestamp_ns = u64::try_from(ts_i64)
                .map_err(|_| "canonical lease timestamp is negative".to_string())?;
            let (lease, gate_type) = parse_gate_lease_payload(&payload)?;
            out.push(TimeoutObservedEvent {
                timestamp_ns,
                event_id: format!("canonical-{seq_id:020}"),
                kind: TimeoutObservedKind::LeaseIssued {
                    lease: Box::new(lease),
                    gate_type,
                },
            });
        }
        Ok(out)
    }

    fn query_timed_out_legacy(
        conn: &Connection,
        cursor_ts_i64: i64,
        cursor_event_id: &str,
        limit_i64: i64,
    ) -> Result<Vec<TimeoutObservedEvent>, String> {
        let query = if cursor_event_id.is_empty() {
            "SELECT event_id, payload, timestamp_ns
             FROM ledger_events
             WHERE event_type = 'gate.timed_out' AND timestamp_ns > ?1
             ORDER BY timestamp_ns ASC, event_id ASC
             LIMIT ?2"
        } else {
            "SELECT event_id, payload, timestamp_ns
             FROM ledger_events
             WHERE event_type = 'gate.timed_out'
               AND (timestamp_ns > ?1 OR (timestamp_ns = ?1 AND event_id > ?2))
             ORDER BY timestamp_ns ASC, event_id ASC
             LIMIT ?3"
        };
        let mut stmt = conn
            .prepare(query)
            .map_err(|e| format!("failed to prepare legacy timeout query: {e}"))?;
        let mut rows = if cursor_event_id.is_empty() {
            stmt.query(params![cursor_ts_i64, limit_i64])
        } else {
            stmt.query(params![cursor_ts_i64, cursor_event_id, limit_i64])
        }
        .map_err(|e| format!("failed to execute legacy timeout query: {e}"))?;

        let mut out = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| format!("failed to iterate legacy timeout rows: {e}"))?
        {
            let event_id: String = row
                .get(0)
                .map_err(|e| format!("failed to decode legacy timeout event_id: {e}"))?;
            let payload: Vec<u8> = row
                .get(1)
                .map_err(|e| format!("failed to decode legacy timeout payload: {e}"))?;
            let ts_i64: i64 = row
                .get(2)
                .map_err(|e| format!("failed to decode legacy timeout timestamp: {e}"))?;
            let timestamp_ns = u64::try_from(ts_i64)
                .map_err(|_| "legacy timeout timestamp is negative".to_string())?;
            let lease_id = parse_timed_out_lease_id(&payload)?;
            out.push(TimeoutObservedEvent {
                timestamp_ns,
                event_id,
                kind: TimeoutObservedKind::TimedOut { lease_id },
            });
        }
        Ok(out)
    }

    fn query_timed_out_canonical(
        conn: &Connection,
        cursor_ts_i64: i64,
        cursor_event_id: &str,
        limit_i64: i64,
    ) -> Result<Vec<TimeoutObservedEvent>, String> {
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
             WHERE event_type = 'gate.timed_out' AND timestamp_ns > ?1
             ORDER BY timestamp_ns ASC, seq_id ASC
             LIMIT ?2"
        } else {
            "SELECT seq_id, payload, timestamp_ns
             FROM events
             WHERE event_type = 'gate.timed_out'
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
            .map_err(|e| format!("failed to prepare canonical timeout query: {e}"))?;
        let mut rows = if cursor_event_id.is_empty() {
            stmt.query(params![cursor_ts_i64, limit_i64])
        } else {
            stmt.query(params![cursor_ts_i64, cursor_event_id, limit_i64])
        }
        .map_err(|e| format!("failed to execute canonical timeout query: {e}"))?;

        let mut out = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| format!("failed to iterate canonical timeout rows: {e}"))?
        {
            let seq_id: i64 = row
                .get(0)
                .map_err(|e| format!("failed to decode canonical timeout seq_id: {e}"))?;
            let payload: Vec<u8> = row
                .get(1)
                .map_err(|e| format!("failed to decode canonical timeout payload: {e}"))?;
            let ts_i64: i64 = row
                .get(2)
                .map_err(|e| format!("failed to decode canonical timeout timestamp: {e}"))?;
            let timestamp_ns = u64::try_from(ts_i64)
                .map_err(|_| "canonical timeout timestamp is negative".to_string())?;
            let lease_id = parse_timed_out_lease_id(&payload)?;
            out.push(TimeoutObservedEvent {
                timestamp_ns,
                event_id: format!("canonical-{seq_id:020}"),
                kind: TimeoutObservedKind::TimedOut { lease_id },
            });
        }
        Ok(out)
    }

    fn query_gate_receipt_legacy(
        conn: &Connection,
        cursor_ts_i64: i64,
        cursor_event_id: &str,
        limit_i64: i64,
    ) -> Result<Vec<TimeoutObservedEvent>, String> {
        let query = if cursor_event_id.is_empty() {
            "SELECT event_id, payload, timestamp_ns
             FROM ledger_events
             WHERE event_type IN ('gate.receipt', 'GateReceipt', 'gate_receipt')
               AND timestamp_ns > ?1
             ORDER BY timestamp_ns ASC, event_id ASC
             LIMIT ?2"
        } else {
            "SELECT event_id, payload, timestamp_ns
             FROM ledger_events
             WHERE event_type IN ('gate.receipt', 'GateReceipt', 'gate_receipt')
               AND (timestamp_ns > ?1 OR (timestamp_ns = ?1 AND event_id > ?2))
             ORDER BY timestamp_ns ASC, event_id ASC
             LIMIT ?3"
        };
        let mut stmt = conn
            .prepare(query)
            .map_err(|e| format!("failed to prepare legacy gate receipt query: {e}"))?;
        let mut rows = if cursor_event_id.is_empty() {
            stmt.query(params![cursor_ts_i64, limit_i64])
        } else {
            stmt.query(params![cursor_ts_i64, cursor_event_id, limit_i64])
        }
        .map_err(|e| format!("failed to execute legacy gate receipt query: {e}"))?;

        let mut out = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| format!("failed to iterate legacy gate receipt rows: {e}"))?
        {
            let event_id: String = row
                .get(0)
                .map_err(|e| format!("failed to decode legacy gate receipt event_id: {e}"))?;
            let payload: Vec<u8> = row
                .get(1)
                .map_err(|e| format!("failed to decode legacy gate receipt payload: {e}"))?;
            let ts_i64: i64 = row
                .get(2)
                .map_err(|e| format!("failed to decode legacy gate receipt timestamp: {e}"))?;
            let timestamp_ns = u64::try_from(ts_i64)
                .map_err(|_| "legacy gate receipt timestamp is negative".to_string())?;
            let lease_id = parse_gate_receipt_lease_id(&payload)?;
            out.push(TimeoutObservedEvent {
                timestamp_ns,
                event_id,
                kind: TimeoutObservedKind::GateReceiptFinalized { lease_id },
            });
        }
        Ok(out)
    }

    fn query_gate_receipt_canonical(
        conn: &Connection,
        cursor_ts_i64: i64,
        cursor_event_id: &str,
        limit_i64: i64,
    ) -> Result<Vec<TimeoutObservedEvent>, String> {
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
             WHERE event_type IN ('gate.receipt', 'GateReceipt', 'gate_receipt')
               AND timestamp_ns > ?1
             ORDER BY timestamp_ns ASC, seq_id ASC
             LIMIT ?2"
        } else {
            "SELECT seq_id, payload, timestamp_ns
             FROM events
             WHERE event_type IN ('gate.receipt', 'GateReceipt', 'gate_receipt')
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
            .map_err(|e| format!("failed to prepare canonical gate receipt query: {e}"))?;
        let mut rows = if cursor_event_id.is_empty() {
            stmt.query(params![cursor_ts_i64, limit_i64])
        } else {
            stmt.query(params![cursor_ts_i64, cursor_event_id, limit_i64])
        }
        .map_err(|e| format!("failed to execute canonical gate receipt query: {e}"))?;

        let mut out = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| format!("failed to iterate canonical gate receipt rows: {e}"))?
        {
            let seq_id: i64 = row
                .get(0)
                .map_err(|e| format!("failed to decode canonical gate receipt seq_id: {e}"))?;
            let payload: Vec<u8> = row
                .get(1)
                .map_err(|e| format!("failed to decode canonical gate receipt payload: {e}"))?;
            let ts_i64: i64 = row
                .get(2)
                .map_err(|e| format!("failed to decode canonical gate receipt timestamp: {e}"))?;
            let timestamp_ns = u64::try_from(ts_i64)
                .map_err(|_| "canonical gate receipt timestamp is negative".to_string())?;
            let lease_id = parse_gate_receipt_lease_id(&payload)?;
            out.push(TimeoutObservedEvent {
                timestamp_ns,
                event_id: format!("canonical-{seq_id:020}"),
                kind: TimeoutObservedKind::GateReceiptFinalized { lease_id },
            });
        }
        Ok(out)
    }

    fn query_all_completed_legacy(
        conn: &Connection,
        cursor_ts_i64: i64,
        cursor_event_id: &str,
        limit_i64: i64,
    ) -> Result<Vec<TimeoutObservedEvent>, String> {
        let query = if cursor_event_id.is_empty() {
            "SELECT event_id, payload, timestamp_ns
             FROM ledger_events
             WHERE event_type = 'gate.all_completed' AND timestamp_ns > ?1
             ORDER BY timestamp_ns ASC, event_id ASC
             LIMIT ?2"
        } else {
            "SELECT event_id, payload, timestamp_ns
             FROM ledger_events
             WHERE event_type = 'gate.all_completed'
               AND (timestamp_ns > ?1 OR (timestamp_ns = ?1 AND event_id > ?2))
             ORDER BY timestamp_ns ASC, event_id ASC
             LIMIT ?3"
        };
        let mut stmt = conn
            .prepare(query)
            .map_err(|e| format!("failed to prepare legacy all-completed query: {e}"))?;
        let mut rows = if cursor_event_id.is_empty() {
            stmt.query(params![cursor_ts_i64, limit_i64])
        } else {
            stmt.query(params![cursor_ts_i64, cursor_event_id, limit_i64])
        }
        .map_err(|e| format!("failed to execute legacy all-completed query: {e}"))?;

        let mut out = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| format!("failed to iterate legacy all-completed rows: {e}"))?
        {
            let event_id: String = row
                .get(0)
                .map_err(|e| format!("failed to decode legacy all-completed event_id: {e}"))?;
            let payload: Vec<u8> = row
                .get(1)
                .map_err(|e| format!("failed to decode legacy all-completed payload: {e}"))?;
            let ts_i64: i64 = row
                .get(2)
                .map_err(|e| format!("failed to decode legacy all-completed timestamp: {e}"))?;
            let timestamp_ns = u64::try_from(ts_i64)
                .map_err(|_| "legacy all-completed timestamp is negative".to_string())?;
            let work_id = parse_all_completed_work_id(&payload)?;
            out.push(TimeoutObservedEvent {
                timestamp_ns,
                event_id,
                kind: TimeoutObservedKind::AllCompleted { work_id },
            });
        }
        Ok(out)
    }

    fn query_all_completed_canonical(
        conn: &Connection,
        cursor_ts_i64: i64,
        cursor_event_id: &str,
        limit_i64: i64,
    ) -> Result<Vec<TimeoutObservedEvent>, String> {
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
             WHERE event_type = 'gate.all_completed' AND timestamp_ns > ?1
             ORDER BY timestamp_ns ASC, seq_id ASC
             LIMIT ?2"
        } else {
            "SELECT seq_id, payload, timestamp_ns
             FROM events
             WHERE event_type = 'gate.all_completed'
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
            .map_err(|e| format!("failed to prepare canonical all-completed query: {e}"))?;
        let mut rows = if cursor_event_id.is_empty() {
            stmt.query(params![cursor_ts_i64, limit_i64])
        } else {
            stmt.query(params![cursor_ts_i64, cursor_event_id, limit_i64])
        }
        .map_err(|e| format!("failed to execute canonical all-completed query: {e}"))?;

        let mut out = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| format!("failed to iterate canonical all-completed rows: {e}"))?
        {
            let seq_id: i64 = row
                .get(0)
                .map_err(|e| format!("failed to decode canonical all-completed seq_id: {e}"))?;
            let payload: Vec<u8> = row
                .get(1)
                .map_err(|e| format!("failed to decode canonical all-completed payload: {e}"))?;
            let ts_i64: i64 = row
                .get(2)
                .map_err(|e| format!("failed to decode canonical all-completed timestamp: {e}"))?;
            let timestamp_ns = u64::try_from(ts_i64)
                .map_err(|_| "canonical all-completed timestamp is negative".to_string())?;
            let work_id = parse_all_completed_work_id(&payload)?;
            out.push(TimeoutObservedEvent {
                timestamp_ns,
                event_id: format!("canonical-{seq_id:020}"),
                kind: TimeoutObservedKind::AllCompleted { work_id },
            });
        }
        Ok(out)
    }
}

#[derive(Debug)]
struct MemoryTimeoutLedgerReader;

#[derive(Debug)]
enum TimeoutCursorStore {
    Sqlite(SqliteTimeoutCursorStore),
    Memory(MemoryTimeoutCursorStore),
}

impl CursorStore for TimeoutCursorStore {
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
struct SqliteTimeoutCursorStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteTimeoutCursorStore {
    fn new(conn: Arc<Mutex<Connection>>) -> Result<Self, String> {
        let guard = conn
            .lock()
            .map_err(|e| format!("cursor store lock poisoned: {e}"))?;
        guard
            .execute(
                "CREATE TABLE IF NOT EXISTS gate_timeout_kernel_cursor (
                    cursor_key INTEGER PRIMARY KEY CHECK (cursor_key = 1),
                    timestamp_ns INTEGER NOT NULL,
                    event_id TEXT NOT NULL
                )",
                [],
            )
            .map_err(|e| format!("failed to create gate_timeout_kernel_cursor: {e}"))?;
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
                 FROM gate_timeout_kernel_cursor
                 WHERE cursor_key = ?1",
                params![TIMEOUT_CURSOR_KEY],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| format!("failed to load timeout cursor: {e}"))?;
        let Some((timestamp_ns, event_id)) = row else {
            return Ok(CompositeCursor::default());
        };
        let timestamp_ns = u64::try_from(timestamp_ns)
            .map_err(|_| "timeout cursor timestamp is negative".to_string())?;
        Ok(CompositeCursor {
            timestamp_ns,
            event_id,
        })
    }

    fn save(&self, cursor: &CompositeCursor) -> Result<(), String> {
        let timestamp_ns = i64::try_from(cursor.timestamp_ns)
            .map_err(|_| "timeout cursor timestamp exceeds i64 range".to_string())?;
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("cursor store lock poisoned: {e}"))?;
        guard
            .execute(
                "INSERT INTO gate_timeout_kernel_cursor (cursor_key, timestamp_ns, event_id)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(cursor_key) DO UPDATE SET
                   timestamp_ns = excluded.timestamp_ns,
                   event_id = excluded.event_id",
                params![TIMEOUT_CURSOR_KEY, timestamp_ns, &cursor.event_id],
            )
            .map_err(|e| format!("failed to save timeout cursor: {e}"))?;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct MemoryTimeoutCursorStore {
    cursor: Mutex<CompositeCursor>,
}

impl MemoryTimeoutCursorStore {
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
enum TimeoutIntentStore {
    Sqlite(SqliteTimeoutIntentStore),
    Memory(MemoryTimeoutIntentStore),
}

impl IntentStore<GateTimeoutIntent, String> for TimeoutIntentStore {
    type Error = String;

    async fn enqueue_many(&self, intents: &[GateTimeoutIntent]) -> Result<usize, Self::Error> {
        match self {
            Self::Sqlite(store) => store.enqueue_many(intents),
            Self::Memory(store) => store.enqueue_many(intents),
        }
    }

    async fn dequeue_batch(&self, limit: usize) -> Result<Vec<GateTimeoutIntent>, Self::Error> {
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
struct SqliteTimeoutIntentStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteTimeoutIntentStore {
    fn new(conn: Arc<Mutex<Connection>>) -> Result<Self, String> {
        {
            let guard = conn
                .lock()
                .map_err(|e| format!("intent store lock poisoned: {e}"))?;
            let column_names: Vec<String> = {
                let mut stmt = guard
                    .prepare("PRAGMA table_info(gate_timeout_intents)")
                    .map_err(|e| format!("failed to inspect gate_timeout_intents schema: {e}"))?;
                stmt.query_map([], |row| row.get::<_, String>(1))
                    .map_err(|e| format!("failed to query gate_timeout_intents columns: {e}"))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("failed to decode gate_timeout_intents columns: {e}"))?
            };
            if !column_names.is_empty() && !column_names.iter().any(|name| name == "lease_json") {
                guard
                    .execute("DROP TABLE gate_timeout_intents", [])
                    .map_err(|e| format!("failed to migrate gate_timeout_intents schema: {e}"))?;
            }
            guard
                .execute(
                    "CREATE TABLE IF NOT EXISTS gate_timeout_intents (
                        intent_key TEXT PRIMARY KEY,
                        work_id TEXT NOT NULL,
                        gate_type TEXT NOT NULL,
                        lease_json TEXT NOT NULL,
                        state TEXT NOT NULL CHECK(state IN ('pending', 'done', 'blocked')),
                        blocked_reason TEXT,
                        created_at_ns INTEGER NOT NULL,
                        updated_at_ns INTEGER NOT NULL
                    )",
                    [],
                )
                .map_err(|e| format!("failed to create gate_timeout_intents: {e}"))?;
            guard
                .execute(
                    "CREATE INDEX IF NOT EXISTS idx_gate_timeout_intents_pending
                     ON gate_timeout_intents(state, created_at_ns, intent_key)",
                    [],
                )
                .map_err(|e| format!("failed to create idx_gate_timeout_intents_pending: {e}"))?;
        }
        Ok(Self { conn })
    }

    fn enqueue_many(&self, intents: &[GateTimeoutIntent]) -> Result<usize, String> {
        let now_ns = epoch_now_ns_i64()?;
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("intent store lock poisoned: {e}"))?;
        let tx = guard
            .unchecked_transaction()
            .map_err(|e| format!("failed to begin timeout intent transaction: {e}"))?;
        let mut inserted = 0usize;
        for intent in intents {
            let key = intent.key();
            let gate_type = gate_type_label(intent.gate_type);
            let rows = tx
                .execute(
                    "INSERT OR IGNORE INTO gate_timeout_intents
                     (intent_key, work_id, gate_type, lease_json, state, blocked_reason, created_at_ns, updated_at_ns)
                     VALUES (?1, ?2, ?3, ?4, 'pending', NULL, ?5, ?6)",
                    params![
                        key,
                        &intent.lease.work_id,
                        gate_type,
                        serde_json::to_string(&intent.lease)
                            .map_err(|e| format!("failed to encode timeout lease intent: {e}"))?,
                        now_ns,
                        now_ns
                    ],
                )
                .map_err(|e| format!("failed to enqueue timeout intent: {e}"))?;
            inserted = inserted.saturating_add(rows);
        }
        tx.commit()
            .map_err(|e| format!("failed to commit timeout intent transaction: {e}"))?;
        Ok(inserted)
    }

    fn dequeue_batch(&self, limit: usize) -> Result<Vec<GateTimeoutIntent>, String> {
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
                "SELECT lease_json, gate_type
                 FROM gate_timeout_intents
                 WHERE state = 'pending'
                 ORDER BY created_at_ns ASC, intent_key ASC
                 LIMIT ?1",
            )
            .map_err(|e| format!("failed to prepare timeout dequeue query: {e}"))?;
        let rows = stmt
            .query_map(params![limit_i64], |row| {
                let lease_json: String = row.get(0)?;
                let gate_type_raw: String = row.get(1)?;
                Ok((lease_json, gate_type_raw))
            })
            .map_err(|e| format!("failed to query timeout intents: {e}"))?;

        let mut intents = Vec::new();
        for row in rows {
            let (lease_json, gate_type_raw) =
                row.map_err(|e| format!("failed to decode timeout intent row: {e}"))?;
            let Some(gate_type) = parse_gate_type(&gate_type_raw) else {
                return Err(format!(
                    "unknown gate_type '{gate_type_raw}' in timeout intents"
                ));
            };
            let lease: GateLease = serde_json::from_str(&lease_json)
                .map_err(|e| format!("failed to decode timeout lease intent json: {e}"))?;
            intents.push(GateTimeoutIntent { lease, gate_type });
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
                "UPDATE gate_timeout_intents
                 SET state = 'done', blocked_reason = NULL, updated_at_ns = ?2
                 WHERE intent_key = ?1",
                params![key, now_ns],
            )
            .map_err(|e| format!("failed to mark timeout intent done: {e}"))?;
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
                "UPDATE gate_timeout_intents
                 SET state = 'blocked', blocked_reason = ?2, updated_at_ns = ?3
                 WHERE intent_key = ?1",
                params![key, reason, now_ns],
            )
            .map_err(|e| format!("failed to mark timeout intent blocked: {e}"))?;
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
                "UPDATE gate_timeout_intents
                 SET state = 'pending', blocked_reason = NULL, updated_at_ns = ?2
                 WHERE intent_key = ?1",
                params![key, now_ns],
            )
            .map_err(|e| format!("failed to mark timeout intent retryable: {e}"))?;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct MemoryTimeoutIntentStore {
    pending: Mutex<VecDeque<GateTimeoutIntent>>,
    states: Mutex<HashMap<String, String>>,
    intents: Mutex<HashMap<String, GateTimeoutIntent>>,
}

impl MemoryTimeoutIntentStore {
    fn enqueue_many(&self, intents: &[GateTimeoutIntent]) -> Result<usize, String> {
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

    fn dequeue_batch(&self, limit: usize) -> Result<Vec<GateTimeoutIntent>, String> {
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
            .ok_or_else(|| format!("missing memory timeout intent for key '{key}'"))?;
        pending.push_back(intent);
        Ok(())
    }
}

#[derive(Debug)]
struct GateTimeoutEffectJournal {
    conn: Arc<Mutex<Connection>>,
}

impl GateTimeoutEffectJournal {
    fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path)
            .map_err(|e| format!("failed to open timeout effect journal sqlite db: {e}"))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS gate_timeout_effect_journal_state (
                intent_key TEXT PRIMARY KEY,
                state TEXT NOT NULL CHECK (state IN ('started', 'completed', 'unknown')),
                updated_at_ns INTEGER NOT NULL
            )",
            [],
        )
        .map_err(|e| format!("failed to create gate_timeout_effect_journal_state table: {e}"))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn load_state(&self, key: &str) -> Result<Option<String>, String> {
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("timeout effect journal lock poisoned: {e}"))?;
        guard
            .query_row(
                "SELECT state
                 FROM gate_timeout_effect_journal_state
                 WHERE intent_key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("failed to load timeout effect state for key '{key}': {e}"))
    }

    fn upsert_state(&self, key: &str, state: &str, updated_at_ns: i64) -> Result<(), String> {
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("timeout effect journal lock poisoned: {e}"))?;
        guard
            .execute(
                "INSERT INTO gate_timeout_effect_journal_state (intent_key, state, updated_at_ns)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(intent_key) DO UPDATE SET
                     state = excluded.state,
                     updated_at_ns = excluded.updated_at_ns",
                params![key, state, updated_at_ns],
            )
            .map_err(|e| {
                format!("failed to upsert timeout effect state='{state}' for key '{key}': {e}")
            })?;
        Ok(())
    }

    fn delete_state(&self, key: &str) -> Result<(), String> {
        let guard = self
            .conn
            .lock()
            .map_err(|e| format!("timeout effect journal lock poisoned: {e}"))?;
        guard
            .execute(
                "DELETE FROM gate_timeout_effect_journal_state WHERE intent_key = ?1",
                params![key],
            )
            .map_err(|e| format!("failed to delete timeout effect state for key '{key}': {e}"))?;
        Ok(())
    }
}

impl EffectJournal<String> for GateTimeoutEffectJournal {
    type Error = String;

    async fn query_state(&self, key: &String) -> Result<EffectExecutionState, Self::Error> {
        let state = self.load_state(key.as_str())?;
        Ok(match state.as_deref() {
            None => EffectExecutionState::NotStarted,
            Some("completed") => EffectExecutionState::Completed,
            // Any non-terminal marker is in-doubt for timeout effects and is
            // handled fail-closed via explicit `resolve_in_doubt`.
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
                "cannot mark timeout effect retryable for completed key '{key}'"
            )),
            Some(other) => Err(format!(
                "cannot mark timeout effect retryable from state '{other}' for key '{key}'"
            )),
            None => Err(format!(
                "cannot mark timeout effect retryable for unknown key '{key}'"
            )),
        }
    }

    async fn resolve_in_doubt(&self, key: &String) -> Result<InDoubtResolution, Self::Error> {
        self.upsert_state(key.as_str(), "unknown", epoch_now_ns_i64()?)?;
        Ok(InDoubtResolution::Deny {
            reason: "timeout effect state is in-doubt; manual reconciliation required".to_string(),
        })
    }
}

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
    let payload_json: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| format!("failed to decode gate_lease_issued payload json: {e}"))?;
    let full_lease = payload_json
        .get("full_lease")
        .ok_or_else(|| "gate_lease_issued payload missing full_lease".to_string())?;
    let lease: GateLease = serde_json::from_value(full_lease.clone())
        .map_err(|e| format!("failed to decode full_lease payload: {e}"))?;
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
        let lease = sample_gate_lease("lease-sqlite-1", 9_999);
        let state = sample_observed_state(&lease, GateType::Security, 2_000, 30_000, 40_000);

        store.upsert(&state).expect("sqlite upsert should succeed");
        let loaded = store
            .load_all()
            .expect("sqlite load should succeed after upsert");
        let loaded_state = loaded
            .get("lease-sqlite-1")
            .expect("lease should be present in sqlite store");
        assert_eq!(loaded_state, &state);

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

    #[test]
    fn timeout_event_mapping_uses_expected_types() {
        let (event_type, _) =
            timeout_event_persistence_fields(&GateOrchestratorEvent::GateTimedOut {
                work_id: "W-1".to_string(),
                gate_type: GateType::Quality,
                lease_id: "lease-1".to_string(),
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
    fn observed_lease_state_timeout_is_monotonic_and_fail_closed_on_clock_reset() {
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
        assert!(
            state.is_timed_out(9_999),
            "monotonic clock reset should fail closed"
        );
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
            .handle_session_terminated(info)
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
}
